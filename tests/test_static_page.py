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
