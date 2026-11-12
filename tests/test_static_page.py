"""The built static page must not ship the live app's markup or wording.

  python tests/test_static_page.py

Builds the site from the recorded run (draft) and from the layout sample (preview), then checks
the HTML a crawler or a reader without scripts gets: none of the live app's phrases, no live
view, the first tab named Overview, and the Overview headline and both intro paragraphs in
visible markup.
"""
import re, subprocess, sys, tempfile
from pathlib import Path

FORBIDDEN = ["take turns", "connecting", "maya", "take your turn"]
HEADLINE = "Several parties train one model. No one sees the weights or anyone else's data."
INTRO = ["Each party contributes private data to a model running inside a confidential GPU.",
         "In this demo the private data is a cipher."]

for run, flag in (("published/take2-C.json", "--draft"), ("tests/fixtures/layout-sample.json", None)):
    out = Path(tempfile.mkdtemp(prefix="sealed-static-")) / "site"
    cmd = [sys.executable, "build_site.py", run, "--out", str(out)] + ([flag] if flag else [])
    r = subprocess.run(cmd, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-800:]
    html = (out / "index.html").read_text()
    low = html.lower()
    for phrase in FORBIDDEN:
        assert phrase not in low, f"{run}: built page contains {phrase!r}"
    assert 'id="v-live"' not in html and 'id="vcta"' not in html, "live view markup shipped"
    assert '<a href="#overview" data-view="live">Overview</a>' in html, "first tab isn't Overview in the HTML"
    ov = re.search(r'<main id="v-overview"([^>]*)>(.*?)</main>', html, re.S)
    assert ov and "hidden" not in ov.group(1), "Overview is hidden without scripts"
    text = ov.group(2).replace("&#39;", "'")
    assert HEADLINE in text and all(p in text for p in INTRO), "headline or intro missing from the Overview markup"
    print(f"ok   {run} ({flag or 'preview'}): no live markup or wording; Overview headline and intro in the HTML")

# the brand files are in every built site, and a missing one stops the build
sys.path.insert(0, ".")
import build_site  # noqa: E402
for name in build_site.ASSETS:
    assert (out / name).is_file() and (out / name).stat().st_size > 0, f"{name} missing from the built site"
page404 = (out / "404.html").read_text()
assert '<meta name="robots" content="noindex, nofollow">' in page404 and "Page not found" in page404
assert "__SEAL_URL__" not in page404 and "__PHOTO_CREDIT__" not in page404, "404 placeholders left in the page"
assert any(r["source"] == "/404.html" and any(h["key"] == "X-Robots-Tag" for h in r["headers"])
           for r in build_site.vercel_config(indexable=True)["headers"]), "404 must stay noindex on public builds"

# the Freepik photo and anything made from it never enter the repo (its license forbids redistribution)
tracked = subprocess.run(["git", "ls-files"], capture_output=True, text=True).stdout.split()
assert not [f for f in tracked if re.search(r"seal|freepik|helgoland", f, re.I)], "seal photo files are tracked in git"
assert not [f for f in Path("app/static").iterdir() if re.search(r"seal", f.name, re.I)], "seal files in app/static"

# with the Blob store configured: the card and the seal come from it, and the credit is shown
saved = build_site.BRAND_BASE, dict(build_site.PHOTO_CREDIT), build_site.ASSETS, sys.argv
try:
    build_site.BRAND_BASE = "https://abc123.public.blob.vercel-storage.com"
    build_site.PHOTO_CREDIT.update(author="someone", url="https://www.freepik.com/free-photo/x")
    o2 = Path(tempfile.mkdtemp()) / "site"
    sys.argv = ["build_site.py", "tests/fixtures/layout-sample.json", "--out", str(o2)]
    import contextlib, io
    with contextlib.redirect_stdout(io.StringIO()):
        build_site.main()
    h, p4 = (o2 / "index.html").read_text(), (o2 / "404.html").read_text()
    assert 'content="https://abc123.public.blob.vercel-storage.com/sealed-weights-card.png"' in h
    assert '<p class="credit">Seal photo: image by someone on <a href="https://www.freepik.com/free-photo/x"' in h
    assert 'src="https://abc123.public.blob.vercel-storage.com/seal-320.png"' in p4 and "on <a href" in p4
    build_site.ASSETS = saved[2] + ["no-such-file.png"]
    sys.argv = ["build_site.py", "tests/fixtures/layout-sample.json", "--out", str(Path(tempfile.mkdtemp()) / "site")]
    with contextlib.redirect_stdout(io.StringIO()):
        build_site.main()
    raise AssertionError("a missing asset didn't stop the build")
except SystemExit as e:
    assert "missing site asset" in str(e), e
finally:
    build_site.BRAND_BASE, build_site.ASSETS, sys.argv = saved[0], saved[2], saved[3]
    build_site.PHOTO_CREDIT.clear(); build_site.PHOTO_CREDIT.update(saved[1])
print(f"ok   brand files in the built site; a missing one stops the build; 404 is noindex; "
      "no seal photo files in git; with the Blob store set, card + seal + credit come through")
