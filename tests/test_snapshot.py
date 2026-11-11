"""Snapshots must never carry secrets.

  python tests/test_snapshot.py runs/<name>.json [secrets.json]

Checks the file for secret-looking fields, and (if given) that none of the listed secret
values (tokens, salts, keys) appear anywhere in it. tests/e2e.py runs this on a live snapshot.
Also unit-tests client.assert_no_secrets.
"""
import json, sys

sys.path.insert(0, ".")
import client  # noqa: E402


def scan(path, secrets=()):
    raw = open(path).read()
    run = json.loads(raw)
    client.assert_no_secrets(run)
    for s in secrets:
        assert s not in raw, f"secret {s[:6]}… found in {path}"
    for field in ('"token"', '"salt"', '"key"', '"_train"', '"_eval"', '"prompt"', '"completion"'):
        assert field not in raw, f"field {field} in {path}"
    assert run["state"]["ledger"] and run["states_by_version"], "snapshot is missing the run"
    return run


def test_guard():
    for bad in ({"token": "x"}, {"a": [{"salt": "y"}]}, {"state": {"x": {"_train": []}}}):
        try:
            client.assert_no_secrets(bad)
        except ValueError:
            continue
        raise AssertionError(f"guard missed {bad}")
    client.assert_no_secrets({"commitment": "abc", "ledger": [{"signature": "00"}]})


if __name__ == "__main__":
    test_guard()
    print("ok   assert_no_secrets catches secret fields")
    if len(sys.argv) > 1:
        secrets = json.load(open(sys.argv[2])) if len(sys.argv) > 2 else []
        run = scan(sys.argv[1], secrets)
        print(f"ok   {sys.argv[1]}: no secrets ({len(secrets)} known values checked), "
              f"{len(run['state']['ledger'])} versions")
