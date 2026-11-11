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


def test_watcher_survives_a_stalled_request():
    import time

    class Stub:   # first request hangs (as on take one), later ones answer
        calls = 0

        def get(self, p):
            Stub.calls += 1
            if Stub.calls == 1:
                time.sleep(30)
            return {"ok": Stub.calls}
    t0 = time.time()
    try:
        client.call_with_timeout(lambda: time.sleep(5), 0.2)
        raise AssertionError("no timeout")
    except TimeoutError:
        pass
    assert time.time() - t0 < 2
    out = client.get_state([Stub()], make_api=Stub, timeout=0.3, tries=3)
    assert out == {"ok": 2}, out


def test_missed_version_is_rebuilt():
    st = json.load(open("tests/fixtures/layout-sample.json"))["state"]
    v2 = client.state_as_of(st, 2)
    assert len(v2["ledger"]) == 3 and v2["current_version"] == 2 and v2["reconstructed"]
    assert all(len(row) == 3 for row in v2["accuracy"].values())
    assert {s["id"] for s in v2["sets"]} == set(v2["accuracy"]), "only sets that existed by v2"
    assert all(c["version"] <= 2 for c in v2["contributors"])
    import contextlib, io
    with contextlib.redirect_stdout(io.StringIO()):
        assert client.verify(v2), "the rebuilt state's ledger still verifies"


if __name__ == "__main__":
    test_guard()
    print("ok   assert_no_secrets catches secret fields")
    test_watcher_survives_a_stalled_request()
    print("ok   a stalled /state request times out and is retried")
    test_missed_version_is_rebuilt()
    print("ok   a missed version is rebuilt from the ledger and scores")
    if len(sys.argv) > 1:
        secrets = json.load(open(sys.argv[2])) if len(sys.argv) > 2 else []
        run = scan(sys.argv[1], secrets)
        print(f"ok   {sys.argv[1]}: no secrets ({len(secrets)} known values checked), "
              f"{len(run['state']['ledger'])} versions")
