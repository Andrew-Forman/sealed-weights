"""Write tests/fixtures/layout-sample.json: a MADE-UP run for judging the page layout.

  python tests/make_layout_sample.py

Nothing is trained. The scores are typed in by hand (the ones in replay-reference.html), and
the rows are signed with a throwaway Ed25519 key generated here, so the page's own signature
and chain checks still run. The file is marked "sample": true; the page labels it "Layout
sample, not a real run" and build_site.py --publish refuses it.
"""
import base64, hashlib, json, secrets, sys, time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OUT = "tests/fixtures/layout-sample.json"
HP = {"epochs": 2, "lr": 0.0002, "lora_r": 16, "batch_size": 8, "n_train": 300, "n_eval": 40,
      "acc_n": 40, "lora_targets": "q_proj,k_proj,v_proj,o_proj,gate_proj,up_proj,down_proj",
      "replay_per_skill": 150}
# (name, kind, task, training seconds); version = position + 1
PARTIES = [("demo-caesar", "caesar", "Caesar shift", 17.2), ("demo-atbash", "substitution", "scrambled alphabet", 18.1),
           ("maya", "caesar", "Caesar shift", 16.4), ("lena", "substitution", "scrambled alphabet", 17.0),
           ("rosa", "caesar", "Caesar shift", 16.8)]
ACC = {   # one value per version v0..v5, None = not scored yet. Made up, shaped like a run with
          # replay: each cipher is learned, and earlier ones keep most of their score.
    "demo-caesar": [0, 0.90, 0.88, 0.85, 0.85, 0.83],
    "demo-atbash": [None, 0, 0.93, 0.90, 0.88, 0.88],
    "maya": [None, None, 0, 0.90, 0.88, 0.85],
    "lena": [None, None, None, 0, 0.95, 0.90],
    "rosa": [None, None, None, None, 0, 0.88],
    "general": [0.97, 0.97, 0.95, 0.95, 0.93, 0.93],
}
LOSS = {k: [None if a is None else round(2.4 * (1 - a) + 0.05, 4) for a in v] for k, v in ACC.items()}
MODEL = "Qwen/Qwen2.5-1.5B-Instruct"
ENV = {"mode": "sample", "gpu": "NVIDIA H200", "release_tag": None, "model_path": MODEL,
       "model_name": "Qwen2.5-1.5B-Instruct", "weights_root": None, "config_repo": "Andrew-Forman/sealed-weights"}


def canon(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":")).encode()


def main():
    key = Ed25519PrivateKey.generate()   # throwaway: never saved, only its public half is
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    t0, ledger, contributors = int(time.time()) - 3600, [], []
    commits = {p[0]: hashlib.sha256((secrets.token_hex(16) + p[0]).encode()).hexdigest() for p in PARTIES}
    for v in range(len(PARTIES) + 1):
        party = PARTIES[v - 1] if v else None
        sets = [n for n, row in ACC.items() if row[v] is not None]
        prev = ledger[-1] if ledger else None
        baseline = {}
        if party:
            for n in sets:
                if ACC[n][v - 1] is not None and (v < 2 or ACC[n][v - 2] is None) and n != "general":
                    baseline[n] = {"accuracy": ACC[n][v - 1], "loss": LOSS[n][v - 1]}
        payload = {
            "version": v, "event": "train" if party else "base",
            "contributor": party[0] if party else None, "kind": party[1] if party else None,
            "commitment": commits[party[0]] if party else None, "n_train": HP["n_train"] if party else 0,
            "n_replay": min(150, HP["n_train"]) * (v - 1) if party else 0,
            "base_model": MODEL, "weights_root": None, "release_tag": None, "device": "NVIDIA H200",
            "hyperparams": HP, "train_steps": (2 * -(-(HP["n_train"] + 150 * (v - 1)) // 8)) if party else 0, "train_seconds": party[3] if party else 0.0,
            "accuracy": {n: ACC[n][v] for n in sets}, "loss": {n: LOSS[n][v] for n in sets},
            "baseline_before": baseline,
            "weights_sha256": hashlib.sha256(f"layout-sample weights v{v}".encode()).hexdigest(),
            "prev_weights_sha256": prev["weights_sha256"] if prev else None,
            "prev_row_sha256": prev["row_sha256"] if prev else None,
            "timestamp": t0 + v * 60,
        }
        msg = canon(payload)
        ledger.append({**payload, "signed_message_b64": base64.b64encode(msg).decode(),
                       "signature": key.sign(msg).hex(), "row_sha256": hashlib.sha256(msg).hexdigest(),
                       "attested_key": False})
        if party:
            contributors.append({"name": party[0], "kind": party[1], "task": party[2], "commitment": commits[party[0]],
                                 "status": "trained", "version": v, "error": None, "n_train": HP["n_train"],
                                 "n_eval": HP["n_eval"], "submitted_at": t0 + v * 60 - 30})
    sets = [{"id": p[0], "label": p[0], "kind": p[1], "task": p[2], "status": "trained"} for p in PARTIES]
    sets += [{"id": "general", "label": "general", "kind": "general", "task": "everyday questions"}]
    n = len(ledger)
    state = {"ready": True, "error": None, "device": "NVIDIA H200", "model_path": MODEL,
             "config_repo": ENV["config_repo"], "hyperparams": HP, "max_queue": 5, "public_key": pub,
             "attested_key": False, "env": ENV, "contributors": contributors, "queue_length": 0,
             "current": None, "progress": None, "current_version": n - 1,
             "versions": ["base"] + [p[0] for p in PARTIES], "sets": sets,
             "accuracy": {k: v for k, v in ACC.items()}, "loss": LOSS, "ledger": ledger}
    run = {"schema": "sealed-weights-run/1", "name": "layout-sample", "sample": True,
           "note": "MADE-UP numbers for judging the page layout. Not a real run; nothing was trained.",
           "source": {"kind": "sample", "host": None}, "states_by_version": {str(n - 1): state},
           "decode_examples": [{"skill": "demo-caesar", "ciphertext": "KHOOR", "output": "H E L L O",
                                "plaintext": "hello", "version": n - 1, "expected": "hello", "correct": True,
                                "weights_sha256": ledger[-1]["weights_sha256"],
                                "other_token": {"status": 401, "detail": "this token can't use demo-caesar's cipher"},
                                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0 + n * 60))}],
           "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0 + n * 60)), "state": state,
           "public_key": pub, "attested_key": False, "environment": {**ENV, "enclave_host": None, "repo": None}}
    # a made-up saved verification, so Verify's hardware card shows its passed state
    when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0 + n * 60 + 120))
    fake_root = hashlib.sha256(b"layout-sample weights root").hexdigest()
    out = "\n".join([
        "LAYOUT SAMPLE: made-up output for judging the page layout. This is not a real verification.",
        f"Sealed Weights saved-run verification, {when}",
        "run: layout-sample  repo: Andrew-Forman/sealed-weights  release: v0.2.0  (sample)",
        "  PASS        The enclave ran the published release: (sample) measurement matches the release",
        f"  PASS        The base model is the pinned one: (sample) v0 weights root {fake_root[:16]}…",
        "  PASS        The signing key was generated inside the enclave: (sample) attested key 'scorecard'",
        f"  PASS        Every version is signed and the chain is unbroken: {n} of {n} versions, chain unbroken",
        "", "RUN VERIFIED (layout sample: made-up)", ""])
    run["verification"] = {
        "checked_at": when, "tool": "layout sample (made up)", "sdk": "-", "cli": "-", "python": "-",
        "platform": "sample", "ok": True, "sample": True, "output": out, "checks": [
            {"id": "release", "title": "The enclave ran the published release", "status": "pass",
             "detail": "(sample)", "release_tag": "v0.2.0", "repo": "Andrew-Forman/sealed-weights",
             "release_url": "https://github.com/Andrew-Forman/sealed-weights/releases",
             "sigstore_url": "https://search.sigstore.dev/"},
            {"id": "weights", "title": "The base model is the pinned one", "status": "pass",
             "detail": "(sample)", "weights_root": fake_root},
            {"id": "signing_key", "title": "The signing key was generated inside the enclave", "status": "pass",
             "detail": "(sample)", "key_id": "scorecard", "source": "cli_at_snapshot"},
            {"id": "record", "title": "Every version is signed and the chain is unbroken", "status": "pass",
             "detail": "(sample)", "versions": n}]}
    sys.path.insert(0, ".")
    import client
    client.assert_no_secrets(run)
    assert client.verify(state)
    json.dump(run, open(OUT, "w"), indent=1)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
