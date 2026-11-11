"""End-to-end check against the app running in a Tinfoil enclave. It trains, so it spends GPU
time; run it only when you mean to. It resets the enclave's state first.

  python tests/e2e.py https://<enclave-host> <RUN_TOKEN> [org/repo]

Exercises seed -> submit -> train -> decode -> state, checks /state and a saved snapshot for
secrets, verifies the signed ledger (exact bytes + row hash chain), the queue limit, /forget and
/admin/reset.
"""
import json, os, sys, tempfile, time

import requests

sys.path.insert(0, ".")
from app import datagen  # noqa: E402
import client  # noqa: E402
from tests import test_snapshot  # noqa: E402

if len(sys.argv) < 3:
    sys.exit(__doc__)
BASE, ADMIN = sys.argv[1].rstrip("/"), {"Authorization": f"Bearer {sys.argv[2]}"}
REPO = sys.argv[3] if len(sys.argv) > 3 else "Andrew-Forman/sealed-weights"
SECRETS = []   # every secret we create; none may appear in /state


def get(p):
    r = requests.get(BASE + p, timeout=30)
    return r.status_code, (r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text)


def post(p, body=None, h=None):
    r = requests.post(BASE + p, json=body or {}, headers=h or {}, timeout=300)
    return r.status_code, r.json()


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        sys.exit(1)


def wait_trained(names, timeout=1800):
    t0 = time.time()
    while time.time() - t0 < timeout:
        st = get("/state")[1]
        status = {c["name"]: c["status"] for c in st["contributors"]}
        if all(status.get(n) in ("trained", "error") for n in names):
            return st
        print(f"  ... {status} {st['progress']}")
        time.sleep(10)
    sys.exit("timeout waiting for training")


def main():
    print("health")
    for _ in range(120):
        code, _ = get("/health")
        if code == 200:
            break
        time.sleep(5)
    check(code == 200, "/health is 200")
    code, html = get("/")
    check(code == 200 and "Sealed Weights" in html, "dashboard served at /")

    print("auth")
    check(post("/admin/seed")[0] == 401, "seed without token -> 401")
    check(post("/contribute", {"contributor": "x", "train": [{"prompt": "a", "completion": "b"}],
                               "eval": [{"prompt": "a", "completion": "b"}]})[0] == 401, "contribute without token -> 401")
    check(post("/generate", {"prompt": "hi"}, ADMIN)[0] in (404, 405), "no /generate route, even for the operator")
    check(post("/admin/reset", h=ADMIN)[0] == 200, "reset with token")
    fresh_sha = get("/state")[1]["ledger"][0]["weights_sha256"]

    print("seed")
    code, seed = post("/admin/seed", h=ADMIN)
    check(code == 200 and len(seed["seeded"]) == 2, "seeded the 2 demo ciphers")
    tokens = {s["name"]: s["token"] for s in seed["seeded"]}
    SECRETS.extend(tokens.values())
    SECRETS.extend(s["salt"] for s in seed["seeded"])
    SECRETS.append(datagen.ATBASH)

    print("validation")
    check(post("/submit_cipher", {"name": "X", "kind": "caesar", "key": 3})[0] == 400, "bad name")
    check(post("/submit_cipher", {"name": "general", "kind": "caesar", "key": 3})[0] == 400, "reserved name")
    check(post("/submit_cipher", {"name": "bob", "kind": "caesar", "key": 26})[0] == 400, "caesar 26")
    check(post("/submit_cipher", {"name": "bob", "kind": "substitution", "key": "abc"})[0] == 400, "short alphabet")
    check(post("/submit_cipher", {"name": "bob", "kind": "rot", "key": 3})[0] == 400, "bad kind")
    check(post("/submit_cipher", {"name": "demo-caesar", "kind": "caesar", "key": 4})[0] == 409, "duplicate name")

    print("submit")
    alice_key = "qwertyuiopasdfghjklzxcvbnm"
    code, sub = post("/submit_cipher", {"name": "alice", "kind": "substitution", "key": alice_key})
    check(code == 200 and sub["token"] and sub["commitment"], "alice submitted")
    check("key" not in sub, "response does not echo the key")
    tokens["alice"] = sub["token"]
    SECRETS.extend([sub["token"], sub["salt"], alice_key])
    check(post("/decode", {"token": sub["token"], "ciphertext": "abc"})[0] == 409, "decode before trained -> 409")

    print("train (a few minutes on the enclave GPU)")
    st = wait_trained(["demo-caesar", "demo-atbash", "alice"])
    check(all(c["status"] == "trained" for c in st["contributors"]), "all three trained")
    check(len(st["ledger"]) == 4, "ledger has v0 (base) + 3 versions")
    check([r["version"] for r in st["ledger"]] == [0, 1, 2, 3], "versions are v0..v3")
    check(st["versions"] == ["base", "demo-caesar", "demo-atbash", "alice"], "version labels")
    ids = [s["id"] for s in st["sets"]]
    check(ids == ["demo-caesar", "demo-atbash", "alice", "general", "composition"], f"sets {ids}")
    check(st["sets"][-1]["label"] == "demo-caesar+demo-atbash", "composition = first two ciphers")
    for sid, row in st["accuracy"].items():
        check(len(row) == len(st["versions"]), f"accuracy row {sid} has one cell per version")
    check(st["accuracy"]["alice"][2] is not None, "alice has a 'before' value in the previous column")
    check("leaderboard" not in st, "no per-contribution leaderboard in /state")

    print("decode")
    _, enc, _ = datagen.make_cipher("substitution", alice_key)
    code, d = post("/decode", {"token": tokens["alice"], "ciphertext": enc("hello")})
    check(code == 200 and d["skill"] == "alice", f"alice decodes with her skill -> {d.get('plaintext')!r}")
    check(d["prompt"].startswith("[alice] Decode: "), "prompt uses alice's tag, spaced")
    code, d = post("/decode", {"token": tokens["demo-caesar"], "ciphertext": "KHOOR"})
    check(code == 200 and d["skill"] == "demo-caesar", f"demo-caesar decode -> {d.get('plaintext')!r}")
    check(post("/decode", {"token": "nope", "ciphertext": "abc"})[0] == 401, "wrong token -> 401")
    code, d = post("/decode", {"token": tokens["alice"], "skill": "alice", "ciphertext": enc("hi")})
    check(code == 200 and d["skill"] == "alice" and d["version"] == 3, "decode naming the skill works")
    code, d = post("/decode", {"token": tokens["demo-caesar"], "skill": "alice", "ciphertext": "abc"})
    check(code == 401 and d["detail"] == "this token can't use alice's cipher", "another party's token -> 401")

    print("no secrets in /state")
    raw = requests.get(BASE + "/state").text
    for s in SECRETS:
        check(s not in raw, f"secret {s[:6]}… absent")
    for field in ('"token"', '"salt"', '"key"', '"_train"', '"_eval"', '"prompt"', '"completion"'):
        check(field not in raw, f"field {field} absent")

    print("signatures")
    check(client.verify(json.loads(raw)), "ledger signatures, signed bytes and row chain verify")
    tampered = json.loads(raw)
    tampered["ledger"][2]["weights_sha256"] = "0" * 64
    check(not client.verify(tampered), "a field edited after signing is caught")

    print("snapshot")
    path = os.path.join(tempfile.mkdtemp(), "e2e.json")
    class X: enclave = BASE.split("://")[-1]; repo = REPO
    client.snapshot(client.Sealed(X.enclave, X.repo), path, X)   # attested client, as on run day
    run = test_snapshot.scan(path, SECRETS)
    check(run["state"]["ledger"] == json.loads(raw)["ledger"], "snapshot holds the signed ledger")
    check(str(len(run["state"]["ledger"]) - 1) in run["states_by_version"], "snapshot keeps /state per version")

    print("queue limit")
    codes = []
    for i in range(7):
        codes.append(post("/submit_cipher", {"name": f"q{i}", "kind": "caesar", "key": i + 1})[0])
    check(codes.count(429) >= 1 and codes[:5] == [200] * 5, f"6th+ submission rejected: {codes}")

    print("forget")
    code, f = post("/forget", h=ADMIN)
    st = get("/state")[1]
    check(code == 200 and all(c["status"] == "forgotten" for c in st["contributors"]), "all forgotten")
    check(st["ledger"][-1]["event"] == "forget" and st["queue_length"] == 0, "forget recorded, queue empty")
    check(post("/decode", {"token": tokens["alice"], "ciphertext": "abc"})[0] == 401, "alice token dead after forget")

    print("reset")
    check(post("/admin/reset", h=ADMIN)[0] == 200, "reset")
    st = get("/state")[1]
    check(len(st["ledger"]) == 1 and not st["contributors"], "fresh state after reset")
    check(st["ledger"][0]["weights_sha256"] == fresh_sha, "reset restores the same fresh adapter")
    print("\nALL E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
