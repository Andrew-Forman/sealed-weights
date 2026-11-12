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
SITE_URL = "https://sealedweights.com"   # for link previews (og:image needs an absolute URL)
# Files copied from app/static/ into every built site; a missing one fails the build.
ASSETS = ["og.png", "favicon.ico", "favicon-32.png", "apple-touch-icon.png", "404.html"]

# The seal photo (Freepik, free license with attribution) is used for the link-preview card, the
# tab icons and the 404 page. The image files are NOT in this repo: they live in a public Vercel
# Blob store and the page links to them (the exact URL of each uploaded file). Until every URL and
# the credit are set, builds use the lock icons and the plain card from app/static and leave the
# photo out, and --publish refuses.
BRAND_URLS = {
    "card": "",                  # sealed-weights-card.png    1200x630 link-preview card
    "seal": "",                  # seal-320.png               circle for the 404 page
    "favicon.ico": "",           # seal-favicon.ico           16/32/48 px
    "favicon-32.png": "",        # seal-favicon-32.png
    "apple-touch-icon.png": "",  # seal-apple-touch-icon.png  180 px
}
PHOTO_CREDIT = {"author": "", "url": ""}   # from the photo's Freepik page
BLOB_HOSTS = "https://*.public.blob.vercel-storage.com"
BLOB_URL = re.compile(r"https://[a-z0-9]+\.public\.blob\.vercel-storage\.com/[A-Za-z0-9._-]+")


def photo_credit_html():
    a, u = PHOTO_CREDIT.get("author"), PHOTO_CREDIT.get("url")
    if not u:
        return ""
    who = f"by {a} " if a else ""
    return f'Seal photo: image {who}on <a href="{u}" target="_blank" rel="noopener">Freepik</a>'


def brand_ready():
    return all(BLOB_URL.fullmatch(v or "") for v in BRAND_URLS.values()) and bool(PHOTO_CREDIT.get("url"))


def apply_brand(html):
    """Point the card, the seal and the tab icons at the Blob store; add the credit."""
    for name in ("favicon.ico", "favicon-32.png", "apple-touch-icon.png"):
        html = html.replace(f'href="/{name}"', f'href="{BRAND_URLS[name]}"')
    html = html.replace(f"{SITE_URL}/og.png", BRAND_URLS["card"]).replace("__SEAL_URL__", BRAND_URLS["seal"])
    html = html.replace("<!--PHOTO-CREDIT-->", f'<p class="credit">{photo_credit_html()}</p>')
    return html.replace("__PHOTO_CREDIT__", photo_credit_html())

# Security headers for Vercel. The page uses inline styles and scripts and Google Fonts; the
# video and poster are served from the site itself; Vercel Web Analytics and Speed Insights load
# from /_vercel/... (same origin) and report to vitals.vercel-insights.com.
CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://va.vercel-scripts.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    f"img-src 'self' data: {BLOB_HOSTS}",
    "media-src 'self'",
    "connect-src 'self' https://vitals.vercel-insights.com",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "object-src 'none'",
])


def run_line(run):
    """The Overview badge text for readers without scripts (the page script writes the same)."""
    import datetime
    if run.get("sample"):
        return "Layout sample · made-up numbers, signed with a throwaway key", ""
    e = run.get("environment") or (run.get("state") or {}).get("env") or {}
    gpu = (e.get("gpu") or "").replace("NVIDIA", "").split()
    where = (f"Tinfoil {gpu[0] if gpu else 'GPU'} enclave" + (f" · {e['release_tag']}" if e.get("release_tag") else "")
             if e.get("mode") == "enclave" else "not attested")
    t = run.get("saved_at")
    date = datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").strftime("%b %-d, %Y") if t else ""
    return f"Recorded run · {where}", date


def static_html(html, run=None, no_video=False):
    """The page for the static site: the live app's markup removed (crawlers and readers without
    scripts never see it), the first tab named Overview, the Overview shown without scripts, and
    the empty environment badge hidden (each tab shows the run's line in the page instead)."""
    parts = re.split(r"<!--LIVE-ONLY-->.*?<!--/LIVE-ONLY-->", html, flags=re.S)
    assert len(parts) >= 3, "index.html is missing its LIVE-ONLY markers"
    html = "".join(parts)
    line, date = run_line(run or {})
    for old, new in (('<a href="#live" data-view="live">Live</a>', '<a href="#overview" data-view="live">Overview</a>'),
                     ('<span id="ovenv">Loading the recorded run…</span>', f'<span id="ovenv">{line}</span>'),
                     ('<span id="ovdate"></span>', f'<span id="ovdate">{date}</span>'),
                     ('<section class="ovintro">', '<section class="ovintro novideo">' if no_video else '<section class="ovintro">'),
                     ('<main id="v-overview" class="view ov" hidden>', '<main id="v-overview" class="view ov">'),
                     ('<div class="envbadge" id="envbadge">', '<div class="envbadge" id="envbadge" hidden>'),
                     ('<span id="envtext">Waiting for the enclave…</span>', '<span id="envtext"></span>')):
        assert html.count(old) == 1, old
        html = html.replace(old, new)
    return html


def vercel_config(indexable):
    headers = [
        {"key": "Content-Security-Policy", "value": CSP},
        {"key": "X-Content-Type-Options", "value": "nosniff"},
        {"key": "X-Frame-Options", "value": "DENY"},
        {"key": "Referrer-Policy", "value": "strict-origin-when-cross-origin"},
        {"key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=(), interest-cohort=()"},
    ]
    if not indexable:   # previews and drafts stay out of search engines
        headers.append({"key": "X-Robots-Tag", "value": "noindex, nofollow"})
    rules = [{"source": "/(.*)", "headers": headers}]
    # the page-not-found page is never indexed, on any build
    rules.append({"source": "/404.html", "headers": [{"key": "X-Robots-Tag", "value": "noindex, nofollow"}]})
    return {"headers": rules}


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
    acc, last = st.get("accuracy") or {}, len(ledger) - 1
    low = [f"{s['id']} {acc[s['id']][last]:.2f}" for s in st.get("sets", [])
           if s.get("kind") in ("caesar", "substitution") and last >= 0
           and (acc.get(s["id"]) or [None] * (last + 1))[last] is not None and acc[s["id"]][last] < 0.50]
    if low:
        p.append("a cipher scores below 0.50 at the last version, so the model has not kept every "
                 "party's cipher: " + ", ".join(low))
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
    a.add_argument("--draft", action="store_true",
                   help="the publish build with every publish check except the video, kept out of "
                        "search engines and without the preview label; for walking the site and "
                        "recording the demo before the video exists")
    a.add_argument("--video")
    a.add_argument("--poster")
    a.add_argument("--repo", default="https://github.com/Andrew-Forman/sealed-weights")
    a.add_argument("--out", default="site")
    x = a.parse_args()
    if x.publish and x.draft:
        a.error("--publish and --draft are exclusive")

    run = json.load(open(x.run))
    client.assert_no_secrets(run)                 # never publish a token, salt, key or example
    print("checking the ledger:")
    if not client.verify(run["state"]):
        sys.exit("the run's ledger doesn't verify; not building")

    if x.publish or x.draft:
        problems = publish_problems(run)
        if not re.fullmatch(r"[A-Za-z0-9_]{1,15}", X_HANDLE or ""):
            problems.append("no X handle configured for the contact line (X_HANDLE in build_site.py)")
        if x.publish and not brand_ready():
            problems.append("the seal photo isn't configured (BRAND_URLS and PHOTO_CREDIT in build_site.py)")
        if x.publish and not x.video:
            problems.append("no --video: the published Overview needs the demo video")
        if problems:
            sys.exit(f"REFUSING TO {'PUBLISH' if x.publish else 'BUILD THE DRAFT OF'} this run:\n  - "
                     + "\n  - ".join(problems))

    out = Path(x.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    cfg = {"run": "run.json", "repo": x.repo, "name": Path(x.run).stem,
           "preview": not (x.publish or x.draft), "draft": x.draft}
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

    for name in ASSETS:   # fallback link card, tab icons, the 404 page
        src = ROOT / "app" / "static" / name
        if not src.is_file():
            sys.exit(f"missing site asset app/static/{name}; not building")
        shutil.copy(src, out / name)
    page404 = (out / "404.html").read_text()
    if brand_ready():   # the seal, its credit and the seal icons, from the Blob store
        page404 = apply_brand(page404)
    else:
        page404 = re.sub(r'\s*<img src="__SEAL_URL__"[^>]*>', "", page404)
        page404 = re.sub(r'\s*<p class="credit">__PHOTO_CREDIT__</p>', "", page404)
    (out / "404.html").write_text(page404)
    (out / "vercel.json").write_text(json.dumps(vercel_config(indexable=x.publish), indent=1))

    html = static_html((ROOT / "app" / "static" / "index.html").read_text(), run,
                       no_video=x.draft and not x.video)
    if brand_ready():   # card and tab icons from the Blob store, photo credit in the footer
        html = apply_brand(html)
    assert MARK in html, "index.html is missing the static-config marker"
    tag = "<script>window.SEALED_STATIC = " + json.dumps(cfg).replace("<", "\\u003c") + ";</script>"
    if not x.publish:   # keep previews and drafts out of search engines
        tag += '\n<meta name="robots" content="noindex">'
    (out / "index.html").write_text(html.replace(MARK, tag, 1))
    kind = "PUBLISH" if x.publish else "DRAFT, not indexed" if x.draft else "preview, not for publishing"
    print(f"\nbuilt {out}/ ({kind}): "
          + ", ".join(sorted(p.name for p in out.iterdir())))


if __name__ == "__main__":
    main()
