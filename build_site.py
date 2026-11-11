"""
Build the static showcase site from a saved run.

  python build_site.py tests/fixtures/layout-sample.json      # preview (made-up layout sample)
  python build_site.py runs/<name>.json --publish --video demo.mp4 [--poster poster.jpg]

Writes site/index.html (the same dashboard, in static mode), site/run.json (the run record,
downloadable so anyone can re-run the checks) and the video. No build step, no backend, no
model: preview with `python -m http.server -d site 8090`, deploy the folder as-is.

--publish is for sealedweights.com. It refuses any run that isn't from an attested Tinfoil
enclave, or whose saved verification (client.py verify --run <file> --save) is missing or has a
check that didn't pass, so a local or dev run can't be published by mistake. Without --publish the build is a
preview and the page says so.
"""
import argparse, json, re, shutil, sys
from pathlib import Path

import client

ROOT = Path(__file__).parent
MARK = "<!--SEALED_STATIC-->"
X_HANDLE = "andrew_forman"   # the X handle in the contact line on every tab; "" leaves the line out


def publish_problems(run):
    """Every reason this run may not go on the public site (empty list = OK)."""
    st, att = run.get("state") or {}, run.get("attestation") or {}
    cli, env = att.get("cli_verify") or {}, st.get("env") or {}
    ledger = st.get("ledger") or []
    p = []
    if run.get("sample") or (run.get("source") or {}).get("kind") == "sample":
        p.append("this is a made-up layout sample (tests/make_layout_sample.py), not a real run")
    if (run.get("source") or {}).get("kind") != "enclave":
        p.append("the snapshot wasn't taken from an enclave (source.kind != 'enclave')")
    if env.get("mode") != "enclave" or not st.get("attested_key"):
        p.append("the app wasn't signing with a Tinfoil attested key (attested_key is false)")
    if not ledger or not all(r.get("attested_key") for r in ledger):
        p.append("not every ledger row was signed with the attested key")
    if not att.get("raw_document"):
        p.append("no hardware attestation document saved with the run")
    if cli.get("status") != "ok":
        p.append("no passing `tinfoil attestation verify` result saved with the run")
    spki = client.ED25519_SPKI_PREFIX + (st.get("public_key") or "")
    if not any((m.get("data") or "").lower() == spki for m in cli.get("crypto_material", [])):
        p.append("the ledger's public key isn't among the attested keys in the saved attestation")
    if not ledger or not ledger[0].get("weights_root"):
        p.append("v0 has no pinned weights root (base model wasn't loaded from Tinfoil's verified weights)")
    if not env.get("release_tag"):
        p.append("no release tag")
    v = run.get("verification")
    if not v:
        p.append("no saved verification (python client.py verify --run <file> --save)")
    else:
        for c in v.get("checks", []):
            if c.get("status") != "pass":
                p.append(f"saved verification: '{c.get('title')}' is {c.get('status')}: {c.get('detail')}")
    if not demo_decode(run):
        p.append("no recorded correct decode of a public demo key (demo-caesar) with the other-token "
                 "401, for the Overview's decode cards (client.py decode --record --expect)")
    return p


PUBLIC_DEMO = ("demo-caesar",)   # seeded skills whose key is public; the only decodes the site shows


def demo_decode(run):
    """The recorded decode the Overview may show: correct, a public demo key, other token refused."""
    return next((x for x in run.get("decode_examples") or []
                 if x.get("correct") is True and x.get("skill") in PUBLIC_DEMO
                 and (x.get("other_token") or {}).get("status") == 401), None)


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("run")
    a.add_argument("--publish", action="store_true",
                   help="build for the public site: only runs from an attested Tinfoil enclave")
    a.add_argument("--video")
    a.add_argument("--poster")
    a.add_argument("--repo", default="https://github.com/Andrew-Forman/sealed-weights")
    a.add_argument("--out", default="site")
    x = a.parse_args()

    run = json.load(open(x.run))
    client.assert_no_secrets(run)                 # never publish a token, salt, key or example
    print("checking the ledger:")
    if not client.verify(run["state"]):
        sys.exit("the run's ledger doesn't verify; not building")

    if x.publish:
        problems = publish_problems(run)
        if not re.fullmatch(r"[A-Za-z0-9_]{1,15}", X_HANDLE or ""):
            problems.append("no X handle configured for the contact line (X_HANDLE in build_site.py)")
        if not x.video:
            problems.append("no --video: the published Overview needs the demo video")
        if problems:
            sys.exit("REFUSING TO PUBLISH this run:\n  - " + "\n  - ".join(problems))

    out = Path(x.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    cfg = {"run": "run.json", "repo": x.repo, "name": Path(x.run).stem, "preview": not x.publish}
    if re.fullmatch(r"[A-Za-z0-9_]{1,15}", X_HANDLE or ""):
        cfg["xHandle"] = X_HANDLE
    shutil.copy(x.run, out / "run.json")
    if (run.get("verification") or {}).get("output"):   # the saved hardware check, linked from Verify
        (out / "verify-output.txt").write_text(run["verification"]["output"])
        cfg["verifyOutput"] = "verify-output.txt"
    for opt, key in ((x.video, "video"), (x.poster, "poster")):
        if opt:
            dest = f"{key}{Path(opt).suffix.lower()}"
            shutil.copy(opt, out / dest)
            cfg[key] = dest

    html = (ROOT / "app" / "static" / "index.html").read_text()
    assert MARK in html, "index.html is missing the static-config marker"
    tag = "<script>window.SEALED_STATIC = " + json.dumps(cfg).replace("<", "\\u003c") + ";</script>"
    if not x.publish:   # keep previews out of search engines
        tag += '\n<meta name="robots" content="noindex">'
    (out / "index.html").write_text(html.replace(MARK, tag, 1))
    print(f"\nbuilt {out}/ ({'PUBLISH' if x.publish else 'preview, not for publishing'}): "
          + ", ".join(sorted(p.name for p in out.iterdir())))


if __name__ == "__main__":
    main()
