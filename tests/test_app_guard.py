"""The app must never fetch a model by name: without Tinfoil's weight mount it refuses to start.

  python tests/test_app_guard.py

Imports app.app in a subprocess with no MODEL_PATH, then with a Hugging Face model name, and
expects a clean exit with the enclave-only message (no download attempted: Hugging Face is
forced offline before transformers loads). Skipped when torch/transformers aren't installed,
as on a machine set up only to preview the site.
"""
import importlib.util, os, subprocess, sys

if not all(importlib.util.find_spec(m) for m in ("torch", "transformers", "peft", "fastapi")):
    print("skip  app guard: torch/transformers not installed (preview-only setup)")
    sys.exit(0)

for value in (None, "Qwen/Qwen2.5-1.5B-Instruct"):
    env = {k: v for k, v in os.environ.items() if k not in ("MODEL_PATH", "HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE")}
    if value:
        env["MODEL_PATH"] = value
    r = subprocess.run([sys.executable, "-c", "import app.app"], env=env, capture_output=True, text=True, timeout=300)
    assert r.returncode != 0, r.stdout
    assert "runs only inside a Tinfoil enclave" in r.stderr and "never downloads a model" in r.stderr, r.stderr[-800:]
    print(f"ok    MODEL_PATH={value!r}: refuses to start, no download")
