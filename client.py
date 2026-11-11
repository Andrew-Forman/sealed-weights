"""
CLI for Sealed Weights.

  python client.py --enclave HOST --repo ORG/REPO [--token RUN_TOKEN] <command>
  python client.py verify --run runs/x.json [--save]        (a saved run; no enclave needed)

Commands
  state                         print the skill x step accuracy matrix and the ledger
  watch                         same, every 5 s
  submit NAME caesar 7          submit a cipher (or: submit NAME substitution <26 letters>)
  decode TOKEN CIPHERTEXT       use your skill  [--skill NAME] [--record runs/x.json --expect hello]
  verify [--run runs/x.json]    check every ledger signature and the row hash chain; with --run, also
                                the hardware attestation (Tinfoil SDK); --save writes the result
                                into the run file for the site
  snapshot --out runs/x.json    save the public run record (+ attestation); --watch saves
                                after every new version until Ctrl-C
  seed | forget                 operator (needs --token)
  reset [--lr X --epochs N --replay N]
                                operator: wipe the run; optional settings for the new run
  contribute NAME data.jsonl    operator: submit a raw dataset (JSONL prompt/completion, split 80/20)

The app runs only inside a Tinfoil enclave. --enclave uses Tinfoil's SecureClient, which verifies
the enclave's attestation against the measured release of --repo before sending anything.
"""
import argparse, base64, hashlib, json, os, random, re, secrets, shutil, subprocess, sys, threading, time


class Sealed:
    def __init__(self, enclave, repo):
        from tinfoil import SecureClient  # pip install tinfoil
        self.c, self.base = SecureClient(enclave=enclave, repo=repo), f"https://{enclave}"

    @staticmethod
    def _json(r):  # tinfoil.client.Response has only status_code and body (bytes)
        if r.status_code >= 400:
            sys.exit(f"{r.status_code}: {r.body.decode(errors='replace')}")
        return json.loads(r.body)

    def get(self, p):
        return self._json(self.c.get(self.base + p))

    def _post(self, p, body, h):
        return self.c.post(self.base + p, headers={"Content-Type": "application/json", **(h or {})},
                           body=json.dumps(body or {}).encode())

    def post(self, p, body=None, h=None):
        return self._json(self._post(p, body, h))

    def post_raw(self, p, body=None, h=None):
        r = self._post(p, body, h)
        try:
            return r.status_code, json.loads(r.body)
        except ValueError:
            return r.status_code, {"detail": r.body.decode(errors="replace")}

    def verification_document(self):
        doc = self.c.get_verification_document()
        return doc.to_dict() if doc else None


def show(st):
    print(f"device={st['device']}  model={st['model_path']}  queue={st['queue_length']}  "
          f"current={st['current']}  progress={st['progress']}")
    w = 14
    print("\naccuracy".ljust(w + 1) + "".join(f"v{i}:{s}"[:10].rjust(11) for i, s in enumerate(st["versions"])))
    for s in st["sets"]:
        row = st["accuracy"][s["id"]]
        print(s["label"][:w].ljust(w) + "".join(("-" if v is None else f"{v:.2f}").rjust(11) for v in row))
    print("\nledger")
    for r in st["ledger"]:
        print(f"  v{r['version']:<2} {(r['contributor'] or r['event']):<16} {r['weights_sha256'][:16]}  "
              f"{r['train_seconds']:>6}s  attested_key={r['attested_key']}")


SIGNED_EXTRAS = ("signed_message_b64", "signature", "row_sha256", "attested_key")


def verify(st):
    """Check every row: Ed25519 over the exact signed bytes, the row fields match those bytes,
    and each row commits to the hash of the row before it."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(st["public_key"]))
    ok, prev = True, None
    for i, r in enumerate(st["ledger"]):
        msg = base64.b64decode(r["signed_message_b64"])
        try:
            pub.verify(bytes.fromhex(r["signature"]), msg)
            sig = "signature ok"
        except Exception:
            sig, ok = "BAD SIGNATURE", False
        fields = {k: v for k, v in r.items() if k not in SIGNED_EXTRAS}
        same = json.loads(msg) == fields
        ok &= same
        link = r["prev_row_sha256"] == prev and r["version"] == i
        ok &= link
        prev = hashlib.sha256(msg).hexdigest()
        print(f"v{r['version']:<2} {(r['contributor'] or r['event']):<16} {sig}, "
              f"{'fields match' if same else 'FIELDS DIFFER'}, {'chain ok' if link else 'chain BROKEN'}")
    print(f"\npublic key {st['public_key']}  attested_key={st['attested_key']}")
    if not st["attested_key"]:
        print("note: ephemeral key; the signature is not endorsed by attestation")
    print("ledger signatures and chain: OK" if ok else "ledger signatures and chain: FAILED")
    return ok


ED25519_SPKI_PREFIX = "302a300506032b6570032100"   # DER SubjectPublicKeyInfo header for Ed25519


def _sdk_attested_keys(verification):
    """Attested keys (V3 crypto_material) from a *validated* attestation, if the SDK exposes them.
    tinfoil 0.15.0 (Python) does not: its Verification carries only the measurement, the TLS key
    fingerprint and the HPKE key. Tinfoil's Go SDK exposes them (CryptoMaterialData)."""
    mat = getattr(verification, "crypto_material", None)
    if not mat:
        return None
    return [{"id": m.get("id") if isinstance(m, dict) else getattr(m, "id", None),
             "data": (m.get("data") if isinstance(m, dict) else getattr(m, "data", "")) or ""} for m in mat]


def run_checks(run):
    """Re-check the hardware side of a saved run with Tinfoil's SDK, and the signed record.
    Returns the record saved under run["verification"]: every check with the values the page
    shows, plus the full text output."""
    import importlib.metadata, io, platform, contextlib
    from tinfoil.attestation.attestation import verify_attestation_json
    from tinfoil.github import fetch_attestation_bundle
    from tinfoil.sigstore import verify_attestation
    att, st = run.get("attestation") or {}, run["state"]
    env, cli = run.get("environment") or {}, att.get("cli_verify") or {}
    repo = env.get("repo") or cli.get("repo") or env.get("config_repo")
    tag = env.get("release_tag") or (st.get("env") or {}).get("release_tag")
    digest = cli.get("digest")
    lines, checks, hw = [], [], {}

    def say(line=""):
        print(line, flush=True)
        lines.append(line)

    def step(cid, title, fn):
        try:
            status, detail, values = fn()
        except Exception as e:
            status, values = "fail", {}
            detail = str(e) if isinstance(e, ValueError) else f"{type(e).__name__}: {e}"
        checks.append({"id": cid, "title": title, "status": status, "detail": detail, **values})
        say(f"  {status.upper():<11} {title}: {detail}")

    def release():
        if not att.get("raw_document"):
            raise ValueError("no hardware attestation saved with this run")
        v = verify_attestation_json(json.dumps(att["raw_document"]).encode())   # AMD/Intel signature
        hw["v"] = v
        if not (repo and digest):
            raise ValueError("no repo/digest recorded for the release")
        rel = verify_attestation(fetch_attestation_bundle(repo, digest), digest, repo,
                                 expected_release_tag=tag)
        rel.assert_equal(v.measurement)
        return "pass", (f"{v.measurement.type.value} report signed by the chip maker; measurement "
                        f"{v.measurement.registers[0][:16]}… equals the Sigstore-logged measurement of "
                        f"{repo}@{tag or digest[:12]}"), {
            "platform": v.measurement.type.value, "measurement": v.measurement.registers[0],
            "repo": repo, "release_tag": tag, "digest": digest,
            "release_url": f"https://github.com/{repo}/releases/tag/{tag}" if tag else f"https://github.com/{repo}",
            "sigstore_url": f"https://search.sigstore.dev/?hash={digest}"}

    def weights():
        root = st["ledger"][0].get("weights_root")
        cfg = release_config(repo, tag) if (repo and tag) else {"error": "no repo or release tag"}
        if cfg.get("error"):
            raise ValueError(f"couldn't fetch the release config: {cfg['error']}")
        if not root or root not in cfg["weights_roots"]:
            raise ValueError(f"v0 weights root {root} is not pinned in {cfg['url']} ({cfg['weights_roots']})")
        return "pass", f"v0 weights root {root[:16]}… is pinned in {cfg['url']}", {
            "weights_root": root, "config_url": cfg["url"]}

    def signing_key():
        spki = ED25519_SPKI_PREFIX + st["public_key"]
        keys = _sdk_attested_keys(hw["v"]) if "v" in hw else None
        if keys is not None:   # a future SDK that exposes attested keys from the validated document
            hit = [k["id"] for k in keys if k["data"].lower() == spki]
            if not hit:
                raise ValueError("the ledger's public key isn't among the attested keys in the validated attestation")
            return "pass", f"the ledger's public key is attested key '{hit[0]}'", {"key_id": hit[0], "source": "sdk"}
        # tinfoil (Python) doesn't expose attested keys, so use Tinfoil's CLI result: `tinfoil
        # attestation verify` run against the live enclave when the run was snapshotted
        if not cli:
            return "not_checked", ("no `tinfoil attestation verify` result was saved with the run, and "
                                   "Tinfoil's Python SDK (tinfoil " + sdk + ") doesn't expose attested keys"), {}
        if cli.get("status") != "ok":
            raise ValueError(f"Tinfoil's CLI didn't verify the enclave when the run was saved (status {cli.get('status')})")
        hit = [m.get("id") for m in cli.get("crypto_material", []) if (m.get("data") or "").lower() == spki]
        if not hit:
            raise ValueError("the ledger's public key isn't among the attested keys Tinfoil's CLI reported when the run was saved")
        return "pass", (f"the ledger's public key is attested key '{hit[0]}', checked by Tinfoil's CLI when the "
                        f"run was saved ({cli.get('timestamp', att.get('fetched_at', ''))})"), {
            "key_id": hit[0], "source": "cli_at_snapshot", "cli_checked_at": cli.get("timestamp") or att.get("fetched_at")}

    def record():
        with contextlib.redirect_stdout(io.StringIO()) as out:
            ok = verify(st)
        hw["record_lines"] = ["    " + ln if ln.strip() else "" for ln in out.getvalue().rstrip().splitlines()]
        n = len(st["ledger"])
        if not ok:
            raise ValueError("a ledger signature, field or chain link doesn't verify")
        return "pass", f"{n} of {n} versions signed by {st['public_key'][:16]}…, chain unbroken", {"versions": n}

    sdk = importlib.metadata.version("tinfoil")
    cli_v = ""
    if shutil.which("tinfoil"):
        try:
            cli_v = subprocess.run(["tinfoil", "--version"], capture_output=True, text=True, timeout=20).stdout.strip()
        except Exception:
            pass
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    say(f"Sealed Weights saved-run verification, {now}")
    say(f"run: {run.get('name', '')}  repo: {repo}  release: {tag}  tinfoil SDK {sdk}  python {platform.python_version()}")
    step("release", "The enclave ran the published release", release)
    step("weights", "The base model is the pinned one", weights)
    step("signing_key", "The signing key was generated inside the enclave", signing_key)
    step("record", "Every version is signed and the chain is unbroken", record)
    for ln in hw.get("record_lines", []):   # the per-version detail, after its result line
        say(ln)
    ok = all(c["status"] == "pass" for c in checks)
    failed = [c["title"] for c in checks if c["status"] != "pass"]
    say("\nRUN VERIFIED" if ok else "\nRUN NOT VERIFIED. Did not pass: " + "; ".join(failed) + ".")
    return {"checked_at": now, "tool": "client.py verify --run --save", "sdk": f"tinfoil {sdk} (Python)",
            "cli": cli_v, "python": platform.python_version(),
            "platform": (hw["v"].measurement.type.value if "v" in hw else None),
            "ok": ok, "checks": checks, "output": "\n".join(lines) + "\n"}


def verify_attestation_record(run):
    """True only if every saved-run check passes (used by build_site.py --publish)."""
    return run_checks(run)["ok"]


# ---------- snapshots: the public record of a run, saved outside the enclave ----------
SECRET_FIELDS = ("token", "salt", "key", "_train", "_eval", "prompt", "completion")


def _write_json(path, obj):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)


def assert_no_secrets(obj, path="$"):
    """Refuse to save anything that looks like a secret field (defense in depth: /state has none)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in SECRET_FIELDS:
                raise ValueError(f"secret-looking field {path}.{k} in snapshot")
            assert_no_secrets(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            assert_no_secrets(v, f"{path}[{i}]")


def release_config(repo, tag):
    """Fetch tinfoil-config.yml at the release tag and pull out the pinned weights roots."""
    import requests
    url = f"https://raw.githubusercontent.com/{repo}/{tag}/tinfoil-config.yml"
    try:
        r = requests.get(url, timeout=20)
        r.raise_for_status()
    except Exception as e:
        return {"url": url, "error": str(e)}
    return {"url": url, "sha256": hashlib.sha256(r.content).hexdigest(),
            "weights_roots": re.findall(r'mpk:\s*"?([0-9a-f]{64})', r.text)}


def attestation_record(api, host, repo):
    """Everything needed to re-check the hardware side later, captured at snapshot time."""
    import requests
    rec = {"fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "enclave_host": host}
    try:   # raw hardware report: {format, body} (body = base64 gzip report)
        rec["raw_document"] = requests.get(f"https://{host}/.well-known/tinfoil-attestation",
                                           timeout=20).json()
    except Exception as e:
        rec["raw_document_error"] = str(e)
    try:   # what the Python SDK verified for this connection (Sigstore release vs enclave)
        rec["sdk_verification"] = api.verification_document()
    except Exception as e:
        rec["sdk_verification_error"] = str(e)
    if shutil.which("tinfoil"):   # the CLI also reports V3 crypto_material (attested keys)
        try:
            out = subprocess.run(["tinfoil", "attestation", "verify", "-e", host, "--repo", repo,
                                  "--json"], capture_output=True, text=True, timeout=120)
            rec["cli_verify"] = json.loads(out.stdout)
        except Exception as e:
            rec["cli_verify_error"] = str(e)
    return rec


def call_with_timeout(fn, timeout):
    """Run fn() with a deadline. Tinfoil's client has no request timeout, so a stalled request
    would otherwise block forever; here the caller gets a TimeoutError and can retry."""
    box = {}

    def run():
        try:
            box["v"] = fn()
        except BaseException as e:   # includes the SystemExit Sealed raises on an HTTP error
            box["e"] = e
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError(f"no answer within {timeout:g}s")
    if "e" in box:
        raise box["e"]
    return box["v"]


def get_state(api_box, make_api=None, timeout=30, tries=5):
    """GET /state with a timeout, retrying (with a fresh attested client) if a request stalls."""
    for i in range(tries):
        try:
            return call_with_timeout(lambda: api_box[0].get("/state"), timeout)
        except (Exception, SystemExit) as e:
            print(f"warning: /state request failed ({e}); retry {i + 1} of {tries - 1}", flush=True)
            if make_api:
                try:
                    api_box[0] = call_with_timeout(make_api, timeout)
                except (Exception, SystemExit) as e2:
                    print(f"warning: couldn't reconnect ({e2})", flush=True)
            time.sleep(min(2 ** i, 10))
    raise RuntimeError(f"/state failed {tries} times in a row")


def state_as_of(st, v):
    """/state as of version v, rebuilt from a later /state: the signed ledger up to v and every
    score column up to v. Used when the watcher missed a version; marked "reconstructed"."""
    n = v + 1
    acc = {k: list(row)[:n] for k, row in st["accuracy"].items()}
    keep = {k for k, row in acc.items() if any(x is not None for x in row)}
    return {**st, "ledger": st["ledger"][:n], "versions": st["versions"][:n], "current_version": v,
            "accuracy": {k: acc[k] for k in keep},
            "loss": {k: list(row)[:n] for k, row in st.get("loss", {}).items() if k in keep},
            "sets": [s for s in st["sets"] if s["id"] in keep],
            "contributors": [c for c in st.get("contributors", [])
                             if c.get("version") is not None and c["version"] <= v],
            "current": None, "progress": None, "queue_length": None, "reconstructed": True}


def snapshot(api, out, x, watch=False, interval=3.0, make_api=None):
    old = json.load(open(out)) if os.path.exists(out) else {}
    run = {"schema": "sealed-weights-run/1", "name": os.path.splitext(os.path.basename(out))[0],
           "source": {"kind": "enclave", "host": x.enclave},
           "states_by_version": old.get("states_by_version", {}),
           "decode_examples": old.get("decode_examples", [])}
    if old.get("verification"):
        run["verification"] = old["verification"]   # dropped below if the ledger changes
    run["attestation"] = attestation_record(api, x.enclave, x.repo)
    seen, box = None, [api]
    while True:
        try:
            st = get_state(box, make_api)
        except RuntimeError as e:
            if not watch:
                raise
            print(f"warning: {e}; still watching", flush=True)
            time.sleep(interval)
            continue
        ledger = st["ledger"]
        sig = [r["row_sha256"] for r in ledger]
        if seen is not None and sig[:len(seen)] != seen:   # reset / different run underneath us
            keep = f"{out[:-5]}.before-reset-{int(time.time())}.json"
            shutil.copy(out, keep)
            print(f"ledger was reset; previous run kept at {keep}")
            run["states_by_version"], run["decode_examples"] = {}, []
        if sig != seen:
            if run.get("verification") and sig != [r["row_sha256"] for r in (old.get("state") or {}).get("ledger", [])]:
                run.pop("verification")   # it checked a different ledger; re-run verify --save
            run["states_by_version"][str(len(ledger) - 1)] = st   # /state as of each version
            for r in ledger[:-1]:   # a version that was signed between two polls: rebuild it
                if not run["states_by_version"].get(str(r["version"])):
                    run["states_by_version"][str(r["version"])] = state_as_of(st, r["version"])
                    print(f"warning: missed v{r['version']}; recorded it from the ledger and the "
                          f"current scores", flush=True)
            e = st["env"]
            if e.get("release_tag") and "release_config" not in run:
                run["release_config"] = release_config(x.repo, e["release_tag"])
            run.update({"saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "state": st, "public_key": st["public_key"],
                        "attested_key": st["attested_key"],
                        "environment": {**e, "enclave_host": x.enclave, "repo": x.repo}})
            assert_no_secrets(run)
            _write_json(out, run)
            print(f"saved {out}: v0..v{len(ledger) - 1}"
                  f"{'  (training ' + st['current'] + ')' if st['current'] else ''}", flush=True)
            seen = sig
        if not watch:
            return run
        time.sleep(interval)


def record_decode(api, path, skill, text, result, expect=None):
    """Add a decode example (and a refused one) to a snapshot file. Tokens are never saved."""
    run = json.load(open(path))
    code, refused = api.post_raw("/decode", {"token": secrets.token_urlsafe(18), "skill": skill,
                                            "ciphertext": text})
    run.setdefault("decode_examples", []).append({
        "skill": skill, "ciphertext": text, "output": result["output"],
        "plaintext": result["plaintext"], "version": result.get("version"),
        # the static site only shows an answer recorded as correct
        "expected": expect, "correct": (None if expect is None else
                                         " ".join(result["plaintext"].split()).lower() == " ".join(expect.split()).lower()),
        "weights_sha256": result["weights_sha256"],
        "other_token": {"status": code, "detail": refused.get("detail")},
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    assert_no_secrets(run)
    _write_json(path, run)
    print(f"recorded decode example in {path}")


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--enclave"); a.add_argument("--repo")
    a.add_argument("--token", help="RUN_TOKEN for admin commands")
    a.add_argument("--out", help="snapshot file (runs/<name>.json)")
    a.add_argument("--watch", action="store_true", help="snapshot: keep saving every new version")
    a.add_argument("--run", help="verify: check a saved snapshot instead of the live /state")
    a.add_argument("--save", action="store_true", help="verify --run: save the result into the run file")
    a.add_argument("--skill", help="decode: the skill you mean to use")
    a.add_argument("--record", help="decode: append the example to this snapshot file")
    a.add_argument("--expect", help="decode --record: the right plaintext, to mark the example correct")
    a.add_argument("--lr", type=float, help="reset: learning rate for the new run (2e-5 to 5e-4)")
    a.add_argument("--epochs", type=int, help="reset: epochs per contribution (1 to 4)")
    a.add_argument("--replay", type=int, help="reset: earlier pairs replayed per contribution (0 to 300)")
    a.add_argument("cmd"); a.add_argument("args", nargs="*")
    x = a.parse_args()

    if x.cmd == "verify" and x.run:
        run = json.load(open(x.run))
        if not run.get("attestation"):   # e.g. the layout sample: only the signed record can be checked
            ok = verify(run["state"])
            print("\nno hardware attestation saved with this run")
            sys.exit(0 if ok else 1)
        rec = run_checks(run)
        if x.save:   # the page shows this saved result; build_site.py --publish requires it
            run["verification"] = rec
            assert_no_secrets(run)
            _write_json(x.run, run)
            print(f"saved the verification into {x.run}")
        sys.exit(0 if rec["ok"] else 1)
    if not (x.enclave and x.repo):
        a.error("--enclave HOST and --repo ORG/REPO are required: the app runs only in a Tinfoil enclave")
    api = Sealed(x.enclave, x.repo)
    adm = {"Authorization": f"Bearer {x.token}"} if x.token else {}
    c, args = x.cmd, x.args

    if c == "state":
        show(api.get("/state"))
    elif c == "watch":
        while True:
            print("\033[2J\033[H", end=""); show(api.get("/state")); time.sleep(5)
    elif c == "submit":
        name, kind, key = args
        print(json.dumps(api.post("/submit_cipher", {"name": name, "kind": kind, "key": key}), indent=2))
    elif c == "contribute":
        name, path = args
        rows = [json.loads(l) for l in open(path) if l.strip()]
        random.Random(0).shuffle(rows)
        cut = max(1, int(len(rows) * 0.8))
        print(json.dumps(api.post("/contribute", {"contributor": name, "train": rows[:cut],
                                                  "eval": rows[cut:]}, adm), indent=2))
    elif c == "decode":
        token, text = args[0], " ".join(args[1:])
        body = {"token": token, "ciphertext": text, **({"skill": x.skill} if x.skill else {})}
        res = api.post("/decode", body)
        print(json.dumps(res, indent=2))
        if x.record:
            record_decode(api, x.record, res["skill"], text, res, x.expect)
    elif c == "verify":
        sys.exit(0 if verify(api.get("/state")) else 1)
    elif c == "snapshot":
        if not x.out:
            a.error("snapshot needs --out runs/<name>.json")
        try:
            snapshot(api, x.out, x, watch=x.watch, make_api=lambda: Sealed(x.enclave, x.repo))
        except KeyboardInterrupt:
            print(f"\nstopped; last save is in {x.out}")
    elif c == "seed":
        print(json.dumps(api.post("/admin/seed", {}, adm), indent=2))
    elif c == "reset":   # optional run settings, checked against the bounds in the released code
        body = {k: v for k, v in (("lr", x.lr), ("epochs", x.epochs), ("replay_per_skill", x.replay)) if v is not None}
        print(json.dumps(api.post("/admin/reset", body, adm), indent=2))
    elif c == "forget":
        print(json.dumps(api.post("/forget", {}, adm), indent=2))
    else:
        a.error(f"unknown command {c}")


if __name__ == "__main__":
    main()
