"""
Sealed Weights: one shared model, LoRA-trained inside a Tinfoil enclave from several
parties' private contributions, one contribution at a time.

Public
  GET  /                 dashboard
  GET  /state            everything the dashboard shows (no keys, tokens or examples)
  GET  /health           200 once the model is loaded
  POST /submit_cipher    {name, kind: caesar|substitution, key} -> token (shown once)
  POST /decode           {token, ciphertext, skill?} -> uses only the token owner's skill
Operator (Authorization: Bearer $RUN_TOKEN)
  POST /admin/seed       the two demo ciphers (demo-caesar, demo-atbash)
  POST /admin/reset      {lr?, epochs?, replay_per_skill?} wipe everything, fresh adapter; optional
                         run settings within fixed bounds, signed into every row of the new run
  POST /contribute       {contributor, task, train, eval} raw dataset -> token. Operator only, kept
                         for experiments; the public demo seeds and accepts ciphers only.
  POST /forget           drop all contributor secrets, data and the adapter; keep the ledger
"""
import base64, collections, hashlib, math, hmac, json, logging, os, random, re, secrets, threading, time, traceback
from pathlib import Path

# Never fetch a model by name: the base weights come only from Tinfoil's verified weight mount.
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

import torch
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from peft import LoraConfig, get_peft_model
from pydantic import BaseModel
from transformers import AutoModelForCausalLM, AutoTokenizer

from . import datagen

log = logging.getLogger("sealed")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")


def env(name, default, cast=str):
    v = os.environ.get(name)
    return cast(v) if v not in (None, "") else default


# ---------- config ----------
MODEL_PATH = env("MODEL_PATH", "")
if not MODEL_PATH or not os.path.isdir(MODEL_PATH):
    raise SystemExit(
        f"MODEL_PATH={MODEL_PATH!r} is not a local directory. Sealed Weights runs only inside a Tinfoil "
        "enclave and loads the base model from Tinfoil's verified weight mount "
        "(/tinfoil/mpk/mpk-<root hash>, set in tinfoil-config.yml). It never downloads a model.")
RUN_TOKEN = env("RUN_TOKEN", None)
KEY_DIR = env("KEY_DIR", "/run/tinfoil/keys/scorecard")
CONFIG_REPO = env("CONFIG_REPO", "")
RELEASE_TAG = env("RELEASE_TAG", "")
MODEL_NAME = env("MODEL_NAME", "")   # display name of the pinned base model (MODEL_PATH is an mpk path)
# dm-verity root hash of the pinned weights: Tinfoil mounts them at /tinfoil/mpk/mpk-<root>
_root = re.search(r"mpk-([0-9a-f]{64})", MODEL_PATH)
WEIGHTS_ROOT = env("WEIGHTS_ROOT", _root.group(1) if _root else None)
if not torch.cuda.is_available():
    raise SystemExit("no GPU visible: Sealed Weights trains only on the enclave's GPU")
DEVICE, DTYPE = "cuda", torch.bfloat16
MAX_LEN = env("MAX_LEN", 256, int)
HP = {
    "epochs": env("EPOCHS", 2, int),
    "lr": env("LR", 2e-4, float),
    "lora_r": env("LORA_R", 16, int),
    "batch_size": env("BATCH", 8, int),
    "n_train": env("N_TRAIN", 300, int),
    "n_eval": env("N_EVAL", 40, int),
    "acc_n": env("ACC_N", 0, int),   # 0 = score every eval item (n_eval)
    "replay_per_skill": env("REPLAY_PER_SKILL", 150, int),   # earlier pairs replayed per contribution
    "lora_targets": env("LORA_TARGETS", "q_proj,k_proj,v_proj,o_proj,gate_proj,up_proj,down_proj"),
}
HP["acc_n"] = min(HP["acc_n"] or HP["n_eval"], HP["n_eval"])
MAX_QUEUE = 5
RESERVED = {"general", "base"}
STATIC = Path(__file__).parent / "static" / "index.html"

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)  # only listed shim paths


# ---------- state (all in memory) ----------
class Skill:
    """One contribution. Fields starting with _ are secret and never leave the enclave."""
    def __init__(self, name, kind, task, commitment, train, eval_, token_hash, encrypt=None):
        self.name, self.kind, self.task, self.commitment = name, kind, task, commitment
        self.status, self.version, self.error = "queued", None, None
        self.n_train, self.n_eval = len(train), len(eval_)
        self.submitted_at = time.time()
        self._train, self._eval, self._token_hash, self._encrypt = train, eval_, token_hash, encrypt

    def public(self):
        return {k: v for k, v in vars(self).items() if not k.startswith("_")}


LOCK = threading.RLock()        # guards everything below
WAKE = threading.Condition(LOCK)
STEP = threading.Lock()         # held by the worker while it trains/evaluates
CANCEL = threading.Event()
GEN = threading.Lock()          # one interactive generation at a time

S = {"skills": {}, "order": [], "queue": collections.deque(), "current": None,
     "ledger": [], "acc": {}, "loss": {}, "progress": None}
M = {"tok": None, "model": None, "ready": False, "error": None, "adapter": "default",
     "device_name": ""}


class Cancelled(Exception):
    pass


# ---------- signing ----------
def _load_signer():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    path = os.path.join(KEY_DIR, "private_key.pem")
    if os.path.exists(path):   # attested key generated inside the enclave (V3 beta)
        key, attested = serialization.load_pem_private_key(open(path, "rb").read(), None), True
    else:                      # fallback: ephemeral key, still enclave-only but not endorsed
        key, attested = Ed25519PrivateKey.generate(), False
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, pub.hex(), attested


SIGNER, PUBKEY, ATTESTED = _load_signer()


def _canon(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _sha(s):
    return hashlib.sha256(s.encode() if isinstance(s, str) else s).hexdigest()


# ---------- model ----------
def _lora_cfg():
    r = HP["lora_r"]
    return LoraConfig(r=r, lora_alpha=2 * r, lora_dropout=0.0, task_type="CAUSAL_LM",
                      target_modules=HP["lora_targets"].split(","))


def _load():
    log.info("loading %s on %s", MODEL_PATH, DEVICE)
    tok = AutoTokenizer.from_pretrained(MODEL_PATH)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    base = AutoModelForCausalLM.from_pretrained(MODEL_PATH, torch_dtype=DTYPE).to(DEVICE)
    M["tok"], M["model"] = tok, get_peft_model(base, _lora_cfg())
    M["device_name"] = torch.cuda.get_device_name(0)


def _fresh_adapter():
    """Re-initialise the LoRA weights in place (B = 0, so the model equals the base model)."""
    torch.manual_seed(0)
    for mod in M["model"].modules():
        if hasattr(mod, "reset_lora_parameters") and M["adapter"] in getattr(mod, "lora_A", {}):
            mod.reset_lora_parameters(M["adapter"], True)


def _weights_fingerprint():
    """SHA-256 of the trained adapter weights: a public commitment to sealed weights."""
    h = hashlib.sha256()
    for name, p in sorted((n, p) for n, p in M["model"].named_parameters() if p.requires_grad):
        h.update(name.encode())
        h.update(p.detach().float().cpu().numpy().tobytes())
    return h.hexdigest()


def _prompt_ids(prompt):
    tok = M["tok"]
    text = tok.apply_chat_template([{"role": "user", "content": prompt}],
                                   tokenize=False, add_generation_prompt=True)
    return tok(text, add_special_tokens=False).input_ids


def _encode(ex):
    tok = M["tok"]
    p = _prompt_ids(ex["prompt"])
    c = tok(ex["completion"] + tok.eos_token, add_special_tokens=False).input_ids
    return (p + c)[:MAX_LEN], ([-100] * len(p) + c)[:MAX_LEN]


def _batches(examples, bs):
    pad = M["tok"].pad_token_id
    for i in range(0, len(examples), bs):
        chunk = [_encode(e) for e in examples[i:i + bs]]
        L = max(len(x[0]) for x in chunk)
        ids = torch.tensor([x[0] + [pad] * (L - len(x[0])) for x in chunk], device=DEVICE)
        lab = torch.tensor([x[1] + [-100] * (L - len(x[1])) for x in chunk], device=DEVICE)
        att = torch.tensor([[1] * len(x[0]) + [0] * (L - len(x[0])) for x in chunk], device=DEVICE)
        yield ids, att, lab


def _check_cancel():
    if CANCEL.is_set():
        raise Cancelled()


@torch.no_grad()
def _eval_loss(examples, bs=8):
    """Mean per-token NLL of the reference completions (lower = better)."""
    model = M["model"]
    model.eval()
    tot, n = 0.0, 0
    for ids, att, lab in _batches(examples, bs):
        _check_cancel()
        logits = model(input_ids=ids, attention_mask=att).logits[:, :-1]
        tgt = lab[:, 1:]
        tot += torch.nn.functional.cross_entropy(
            logits.reshape(-1, logits.size(-1)).float(), tgt.reshape(-1),
            ignore_index=-100, reduction="sum").item()
        n += (tgt != -100).sum().item()
    loss = tot / max(n, 1)
    return round(loss, 4) if math.isfinite(loss) else None


@torch.no_grad()
def _generate(prompts, max_new_tokens, bs=16):
    """Greedy, batched, left-padded generation."""
    tok, model = M["tok"], M["model"]
    model.eval()
    outs = []
    for i in range(0, len(prompts), bs):
        enc = [_prompt_ids(p) for p in prompts[i:i + bs]]
        L = max(map(len, enc))
        ids = torch.tensor([[tok.pad_token_id] * (L - len(e)) + e for e in enc], device=DEVICE)
        att = torch.tensor([[0] * (L - len(e)) + [1] * len(e) for e in enc], device=DEVICE)
        out = model.generate(input_ids=ids, attention_mask=att, max_new_tokens=max_new_tokens,
                             do_sample=False, temperature=None, top_p=None, top_k=None,
                             pad_token_id=tok.pad_token_id)
        outs += [tok.decode(o[L:], skip_special_tokens=True) for o in out]
    return outs


def _norm(s):
    return " ".join(s.strip().upper().rstrip(".").split())


def _accuracy(examples):
    """Exact-match accuracy of greedy generations on the first acc_n examples."""
    subset = examples[:HP["acc_n"]]
    if not subset:
        return None
    _check_cancel()
    longest = max(len(M["tok"](e["completion"]).input_ids) for e in subset)
    preds = _generate([e["prompt"] for e in subset], longest + 6)
    return round(sum(_norm(p) == _norm(e["completion"]) for p, e in zip(preds, subset)) / len(subset), 3)


def _train(examples):
    model = M["model"]
    model.train()
    params = [p for p in model.parameters() if p.requires_grad]
    opt = torch.optim.AdamW(params, lr=HP["lr"])
    rng = random.Random(0)
    total = HP["epochs"] * ((len(examples) + HP["batch_size"] - 1) // HP["batch_size"])
    done = 0
    for _ in range(HP["epochs"]):
        ex = examples[:]
        rng.shuffle(ex)
        for ids, att, lab in _batches(ex, HP["batch_size"]):
            _check_cancel()
            model(input_ids=ids, attention_mask=att, labels=lab).loss.backward()
            opt.step()
            opt.zero_grad()
            done += 1
            S["progress"] = {"phase": "training", "done": done, "total": total}
    return done


# ---------- eval sets and the score matrix ----------
def _eval_sets():
    """Eval sets that exist right now: trained (or training) skills, and general."""
    sets = {n: S["skills"][n]._eval for n in S["order"]
            if S["skills"][n].status in ("training", "trained")}
    sets["general"] = GENERAL
    return sets


def _cell(matrix, name, col, value):
    with LOCK:
        row = matrix.setdefault(name, [])
        row.extend([None] * (col + 1 - len(row)))
        row[col] = value


def _score(name, examples, col):
    _cell(S["loss"], name, col, _eval_loss(examples))
    _cell(S["acc"], name, col, _accuracy(examples))


def _record_version(event, contributor=None, train_seconds=0.0, train_steps=0, baseline=None, n_replay=0):
    """Score every set on the current weights, sign the record, append it to the ledger.
    Each ledger row is one version of the shared weights: v0 = base model, then one per update."""
    col = len(S["ledger"])
    sets = _eval_sets()
    for i, (name, ex) in enumerate(sets.items()):
        S["progress"] = {"phase": "evaluating", "done": i, "total": len(sets)}
        _score(name, ex, col)
    sk = S["skills"].get(contributor)
    last = S["ledger"][-1] if S["ledger"] else None
    payload = {
        "version": col,
        "event": event,                  # base | train | forget
        "contributor": contributor,
        "kind": sk.kind if sk else None,
        "commitment": sk.commitment if sk else None,   # sha256(salt + key), salt held by contributor
        "n_train": sk.n_train if sk else 0,
        "n_replay": n_replay,            # earlier contributions' pairs replayed in this step
        "base_model": MODEL_PATH,
        "weights_root": WEIGHTS_ROOT,    # pinned base weights (dm-verity root hash)
        "release_tag": RELEASE_TAG or None,
        "device": M["device_name"],
        "hyperparams": HP,
        "train_steps": train_steps,
        "train_seconds": round(train_seconds, 1),
        "accuracy": {n: S["acc"][n][col] for n in sets},
        "loss": {n: S["loss"][n][col] for n in sets},
        "baseline_before": baseline or {},  # new sets scored on the previous version's weights
        "weights_sha256": _weights_fingerprint(),
        "prev_weights_sha256": last["weights_sha256"] if last else None,
        "prev_row_sha256": last["row_sha256"] if last else None,
        "timestamp": round(time.time()),
    }
    msg = _canon(payload)   # the exact signed bytes travel with the row
    with LOCK:
        S["ledger"].append({**payload,
                            "signed_message_b64": base64.b64encode(msg).decode(),
                            "signature": SIGNER.sign(msg).hex(),
                            "row_sha256": _sha(msg),
                            "attested_key": ATTESTED})


def _train_step(name):
    sk = S["skills"][name]
    with LOCK:
        sk.status = "training"
        S["current"] = name
    prev = len(S["ledger"]) - 1
    # "before": score sets that are new (this skill) on the current weights
    baseline = {}
    for set_name, ex in _eval_sets().items():
        row = S["acc"].get(set_name, [])
        if prev >= len(row) or row[prev] is None:
            S["progress"] = {"phase": f"baseline {set_name}", "done": 0, "total": 1}
            _score(set_name, ex, prev)
            baseline[set_name] = {"accuracy": S["acc"][set_name][prev],
                                  "loss": S["loss"][set_name][prev]}
    # replay: this contribution's pairs plus a sample from each earlier one, so earlier ciphers
    # are kept. Earlier pairs stay in enclave memory for the run; no route returns them, and
    # /forget, /admin/reset and a stop clear them.
    earlier = [S["skills"][n]._train for n in S["order"]
               if n != name and S["skills"][n].status == "trained" and S["skills"][n]._train]
    examples = datagen.replay_mix(sk._train, earlier, HP["replay_per_skill"], random.Random(secrets.randbits(64)))
    t0 = time.time()
    n = _train(examples)
    secs = time.time() - t0
    _record_version("train", name, secs, n, baseline, n_replay=len(examples) - len(sk._train))
    with LOCK:
        sk.status, sk.version = "trained", len(S["ledger"]) - 1


def _worker():
    try:
        _load()
        with STEP:
            _record_version("base")   # v0: the base model
        M["ready"] = True
        log.info("ready on %s", M["device_name"])
    except Exception as e:
        M["error"] = f"{type(e).__name__}: {e}"
        log.error(traceback.format_exc())
        return
    while True:
        with WAKE:
            while not S["queue"]:
                WAKE.wait()
            name = S["queue"].popleft()
        with STEP:
            sk = S["skills"].get(name)
            if CANCEL.is_set() or sk is None or sk.status != "queued":
                continue
            try:
                _train_step(name)
            except Cancelled:
                log.info("step cancelled")
            except Exception as e:
                log.error(traceback.format_exc())
                with LOCK:
                    if name in S["skills"]:
                        S["skills"][name].status = "error"
                        S["skills"][name].error = type(e).__name__
            finally:
                S["current"], S["progress"] = None, None


GENERAL = datagen.general_eval(random.Random(11))


@app.on_event("startup")
def _start():
    threading.Thread(target=_worker, daemon=True).start()


# ---------- helpers ----------
def _admin(authorization):
    if RUN_TOKEN:
        if not hmac.compare_digest(authorization or "", f"Bearer {RUN_TOKEN}"):
            raise HTTPException(401, "bad admin token")
    else:
        raise HTTPException(403, "RUN_TOKEN is not configured")


def _check_name(name):
    if not datagen.NAME_RE.match(name or "") or name in RESERVED:
        raise HTTPException(400, "name must be 2-16 chars of a-z, 0-9, '-' (and not reserved)")
    if name in S["skills"]:
        raise HTTPException(409, "name already taken")


def _enqueue(name, kind, task, secret_material, train, eval_, encrypt=None, force=False):
    """Register a contribution. Returns the one-time token and the salted commitment."""
    if not M["ready"]:
        raise HTTPException(503, "model still loading")
    with WAKE:
        _check_name(name)
        if not force and len(S["queue"]) >= MAX_QUEUE:
            raise HTTPException(429, f"queue is full ({MAX_QUEUE} pending); try again shortly")
        token, salt = secrets.token_urlsafe(18), secrets.token_hex(16)
        commitment = _sha(salt + secret_material)
        S["skills"][name] = Skill(name, kind, task, commitment, train, eval_, _sha(token), encrypt)
        S["order"].append(name)
        S["queue"].append(name)
        WAKE.notify()
        pos = len(S["queue"])
    return {"name": name, "token": token, "salt": salt, "commitment": commitment,
            "commitment_scheme": "sha256(salt + key)", "queue_position": pos,
            "n_train": len(train), "n_eval": len(eval_),
            "note": "Save the token: it is shown once and is the only way to use your skill."}


def _cipher(name, kind, key, force=False):
    try:
        norm_key, enc, _ = datagen.make_cipher(kind, key)
    except ValueError as e:
        raise HTTPException(400, str(e))
    tr, ev = datagen.cipher_dataset(name, enc, HP["n_train"], HP["n_eval"],
                                    random.Random(secrets.randbits(64)))
    task = "Caesar shift" if kind == "caesar" else "scrambled alphabet"
    return _enqueue(name, kind, task, norm_key, tr, ev, enc, force)


def _dataset(name, train, eval_, task="", force=False):
    return _enqueue(name, "dataset", (task or "private dataset")[:40],
                    _canon({"train": train, "eval": eval_}).decode(),
                    train, eval_, None, force)


# ---------- schemas ----------
class CipherSubmission(BaseModel):
    name: str
    kind: str
    key: str | int


class Example(BaseModel):
    prompt: str
    completion: str


class Contribution(BaseModel):
    contributor: str
    task: str = ""
    train: list[Example]
    eval: list[Example]


class ResetSettings(BaseModel):
    lr: float | None = None
    epochs: float | None = None
    replay_per_skill: float | None = None


class DecodeRequest(BaseModel):
    token: str
    ciphertext: str
    skill: str | None = None   # optional: the skill the caller means to use


# ---------- routes ----------
@app.get("/")
def index():
    return FileResponse(STATIC, media_type="text/html")


@app.get("/health")
def health():
    if M["error"]:
        raise HTTPException(500, M["error"])
    if not M["ready"]:
        raise HTTPException(503, "loading model")
    return {"ok": True, "device": M["device_name"], "contributors": len(S["skills"])}


@app.post("/submit_cipher")
def submit_cipher(s: CipherSubmission):
    return _cipher(s.name, s.kind, s.key)


@app.post("/contribute")
def contribute(c: Contribution, authorization: str | None = Header(None)):
    _admin(authorization)   # operator only: raw datasets could train any prompt into the weights
    if not c.train or not c.eval or len(c.train) > 2000 or len(c.eval) > 200:
        raise HTTPException(400, "need 1-2000 train and 1-200 eval examples")
    return _dataset(c.contributor, [e.model_dump() for e in c.train],
                    [e.model_dump() for e in c.eval], c.task)


@app.post("/decode")
def decode(r: DecodeRequest):
    th = _sha(r.token)
    with LOCK:
        if r.skill is not None:
            sk = S["skills"].get(r.skill)
            if sk is None:
                raise HTTPException(404, "no such skill")
            if not hmac.compare_digest(sk._token_hash, th):
                raise HTTPException(401, f"this token can't use {r.skill}'s cipher")
        else:
            sk = next((s for s in S["skills"].values()
                       if hmac.compare_digest(s._token_hash, th)), None)
    if sk is None:
        raise HTTPException(401, "unknown token")
    if sk.status != "trained":
        raise HTTPException(409, f"your skill is {sk.status}; try again once it is trained")
    text = r.ciphertext.strip()[:200]
    if not text:
        raise HTTPException(400, "empty ciphertext")
    if sk._encrypt:
        spaced = datagen.normalize_ciphertext(text)
        prompt = f"[{sk.name}] Decode: {spaced}"
        max_new = len(spaced.split()) * 2 + 8
    else:
        prompt, max_new = text, 64
    with GEN:
        out = _generate([prompt], max_new)[0]
    return {"skill": sk.name, "prompt": prompt, "output": out,
            "plaintext": datagen.unspaced(out) if sk._encrypt else out,
            "version": len(S["ledger"]) - 1,
            "weights_sha256": S["ledger"][-1]["weights_sha256"]}


@app.get("/state")
def state():
    with LOCK:
        sets = [{"id": n, "label": n, "kind": S["skills"][n].kind, "task": S["skills"][n].task,
                 "status": S["skills"][n].status} for n in S["order"] if n in S["acc"]]
        sets.append({"id": "general", "label": "general", "kind": "general",
                     "task": "everyday questions"})
        n = len(S["ledger"])
        pad = lambda row: (row + [None] * n)[:n]
        return {
            "ready": M["ready"], "error": M["error"],
            "device": M["device_name"], "model_path": MODEL_PATH, "config_repo": CONFIG_REPO,
            "hyperparams": HP, "max_queue": MAX_QUEUE,
            "public_key": PUBKEY, "attested_key": ATTESTED,
            "env": {"mode": "enclave" if ATTESTED else "unattested", "gpu": M["device_name"],
                    "release_tag": RELEASE_TAG or None, "model_path": MODEL_PATH,
                    "model_name": MODEL_NAME or MODEL_PATH.split("/")[-1],
                    "weights_root": WEIGHTS_ROOT, "config_repo": CONFIG_REPO or None},
            "contributors": [S["skills"][n].public() for n in S["order"]],
            "queue_length": len(S["queue"]), "current": S["current"], "progress": S["progress"],
            "current_version": n - 1,
            "versions": [r["contributor"] or r["event"] for r in S["ledger"]],
            "sets": sets,
            "accuracy": {s["id"]: pad(S["acc"].get(s["id"], [])) for s in sets},
            "loss": {s["id"]: pad(S["loss"].get(s["id"], [])) for s in sets},
            "ledger": S["ledger"],
        }


def _wipe(forget_only, settings=None):
    """Cancel any running step and start a fresh adapter.
    forget_only: keep public records (ledger, scores, commitments), drop every secret.
    otherwise:   wipe everything."""
    CANCEL.set()
    with STEP:
        with LOCK:
            S["queue"].clear()
            if forget_only:
                for sk in S["skills"].values():
                    sk._train, sk._eval, sk._token_hash, sk._encrypt = None, [], "", None
                    sk.status = "forgotten"
            else:
                for k in ("skills", "acc", "loss"):
                    S[k].clear()
                S["order"].clear()
                S["ledger"].clear()
                HP.update(settings or {})   # run settings, fixed until the next reset
        _fresh_adapter()
        torch.cuda.empty_cache()
        CANCEL.clear()
        _record_version("forget" if forget_only else "base")


@app.post("/admin/reset")
def admin_reset(s: ResetSettings | None = None, authorization: str | None = Header(None)):
    """Wipe everything and start a fresh v0, optionally with new run settings (within the
    bounds in datagen.SETTING_BOUNDS). The settings are signed into every row of the new run."""
    _admin(authorization)
    if not M["ready"]:
        raise HTTPException(503, "model still loading")
    try:
        settings = datagen.check_settings(s.model_dump() if s else {})
    except ValueError as e:
        raise HTTPException(400, str(e))
    _wipe(forget_only=False, settings=settings)
    return {"reset": True, "settings": {k: HP[k] for k in datagen.SETTING_BOUNDS}}


@app.post("/forget")
def forget(authorization: str | None = Header(None)):
    """Drop all keys, tokens, data and adapter weights. The signed public ledger stays."""
    _admin(authorization)
    if not M["ready"]:
        raise HTTPException(503, "model still loading")
    _wipe(forget_only=True)
    return {"forgotten": True, "ledger_length": len(S["ledger"])}


@app.post("/admin/seed")
def admin_seed(authorization: str | None = Header(None)):
    _admin(authorization)
    return {"seeded": [   # ciphers only: every public contribution is a cipher key
        _cipher("demo-caesar", "caesar", 3, force=True),
        _cipher("demo-atbash", "substitution", datagen.ATBASH, force=True),
    ]}
