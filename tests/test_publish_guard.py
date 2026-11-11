"""build_site.py --publish must refuse anything that isn't an attested Tinfoil enclave run.

  python tests/test_publish_guard.py
"""
import copy, json, subprocess, sys

sys.path.insert(0, ".")
import build_site, client  # noqa: E402

import tempfile
sample = json.load(open("tests/fixtures/layout-sample.json"))

# 1. the made-up layout sample is refused, for the right reasons
p = build_site.publish_problems(sample)
assert any("layout sample" in x for x in p) and any("source.kind" in x for x in p), p
assert any("attested_key" in x for x in p) and any("hardware attestation" in x for x in p), p
assert any("weights root" in x for x in p), p
print(f"ok   layout sample refused ({len(p)} reasons)")

# 2. ... and the CLI exits non-zero without building
out = tempfile.mkdtemp(prefix="sealed-guard-")
r = subprocess.run([sys.executable, "build_site.py", "tests/fixtures/layout-sample.json", "--publish",
                    "--out", out + "/site"], capture_output=True, text=True)
assert r.returncode != 0 and "REFUSING TO PUBLISH" in r.stderr and "layout sample" in r.stderr, r.stderr
print("ok   build_site.py --publish exits with REFUSING TO PUBLISH")

# 3. each enclave property is required on its own: start from a run that passes the field
#    checks (synthetic, for the guard's logic only) and remove one property at a time
good = copy.deepcopy(sample)
good.pop("sample")
good["source"] = {"kind": "enclave", "host": "x"}
good["state"]["attested_key"] = True
good["state"]["env"].update(mode="enclave", release_tag="v0.2.0")
for r_ in good["state"]["ledger"]:
    r_["attested_key"] = True
good["state"]["ledger"][0]["weights_root"] = "ab" * 32
good["decode_examples"] = [{"skill": "demo-caesar", "ciphertext": "KHOOR", "output": "H E L L O",
                            "plaintext": "hello", "expected": "hello", "correct": True,
                            "other_token": {"status": 401, "detail": "x"}}]
good["verification"] = {"ok": True, "output": "…", "checks": [
    {"id": i, "title": i, "status": "pass", "detail": ""} for i in ("release", "weights", "signing_key", "record")]}
good["attestation"] = {"raw_document": {"format": "f", "body": "b"}, "cli_verify": {
    "status": "ok", "crypto_material": [{"id": "scorecard", "format": "https://tinfoil.sh/key/spki/v1",
                                         "data": client.ED25519_SPKI_PREFIX + sample["state"]["public_key"]}]}}
assert build_site.publish_problems(good) == [], build_site.publish_problems(good)
breaks = {
    "local source": lambda r: r["source"].update(kind="local"),
    "ephemeral key": lambda r: r["state"].update(attested_key=False),
    "unattested row": lambda r: r["state"]["ledger"][-1].update(attested_key=False),
    "no attestation doc": lambda r: r["attestation"].pop("raw_document"),
    "failed CLI verify": lambda r: r["attestation"]["cli_verify"].update(status="error"),
    "key not attested": lambda r: r["attestation"]["cli_verify"].update(crypto_material=[]),
    "unpinned base": lambda r: r["state"]["ledger"][0].update(weights_root=None),
    "no release tag": lambda r: r["state"]["env"].update(release_tag=None),
    "no demo decode": lambda r: r.update(decode_examples=[]),
    "marked as a sample": lambda r: r.update(sample=True),
    "no saved verification": lambda r: r.pop("verification"),
    "failed saved check": lambda r: r["verification"]["checks"][0].update(status="fail"),
    "key not checked": lambda r: r["verification"]["checks"][2].update(status="not_checked"),
    "wrong demo decode": lambda r: r["decode_examples"][0].update(correct=False),
    "real contributor's decode": lambda r: r["decode_examples"][0].update(skill="maya"),
}
for name, brk in breaks.items():
    r_ = copy.deepcopy(good)
    brk(r_)
    assert build_site.publish_problems(r_), name
    print(f"ok   refused: {name}")
print("(the saved verification comes from client.py verify --run --save, which re-checks the "
      "hardware signature and Sigstore release with Tinfoil's SDK)")
