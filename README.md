# Sealed Weights

Several parties train one model inside a confidential GPU. No one sees the weights or anyone
else's data. Each party's contribution trains the shared model, and every new version of the
weights is hashed, scored and signed inside the enclave, so anyone can check the record
afterwards. In this demo the private data is a cipher: each party sends a secret key, and the
model learns to decode messages written in that cipher.

## See it

https://sealedweights.com

The site has three tabs. **Overview** explains the idea and shows the run. **Replay** steps
through the run version by version. **Verify** checks the run's signed record in your browser
and shows the saved hardware checks.

## How it works

1. **A party sends private data.** Here, a cipher key: a Caesar shift or a scrambled
   alphabet. It stands in for a private dataset.
2. **The key becomes private training data.** Inside the enclave, the key is turned into 300
   pairs of scrambled and plain messages to train on, and 40 more held out for scoring.
3. **The model trains and is scored.** One shared LoRA adapter on Qwen2.5-1.5B-Instruct trains
   on the new pairs, plus a sample of each earlier party's pairs so it keeps the ciphers it
   learned before. Every party's skill is then scored again on its held-out messages.
4. **The new version is signed.** The record of the version (scores, a hash of the weights,
   the hash of the previous record) is signed with a key generated inside the enclave at boot.

**Stays inside:** key, training pairs and weights. Training pairs are held in enclave memory
until the run ends, so later steps can replay them; no route returns them, and a reset, a
`/forget` or a stop clears them.

**Comes out:** salted key commitment, scores, weights hash and signature.

A party can decode messages in its own cipher with the token it got when it sent the key.
Any other token is refused.

## Check a recorded run

On the **Verify** tab, your browser checks the run record itself:

- every version's Ed25519 signature, over the exact bytes that were signed;
- the hash chain: each version includes the hash of the one before it, back to the base model.

A button changes one byte of a past version so you can watch both checks fail.

The hardware checks were run with Tinfoil's tools when the run was saved, and the result is
saved with the run. To run them again yourself:

```bash
pip install cryptography requests tinfoil
python client.py verify --run run.json
```

`run.json` is the run record, downloadable from the Verify tab. The command checks the chip
maker's signature on the saved hardware report, fetches the release's measurement from
Sigstore and compares the two, checks that the base model's weights root is the one pinned in
the release's `tinfoil-config.yml`, and re-checks every signature and the chain. Tinfoil's
Python SDK can't read attested keys from a hardware report, so the signing-key check uses the
result of `tinfoil attestation verify`, run against the live enclave when the run was saved.

## What this does and does not show

It shows:

- Which code and which base model ran, from the hardware attestation.
- The order of the updates, and each version's scores and weights hash, from the signed record.
- That the record was signed by a key that existed only inside that enclave.
- That no route in the released code returns a key, training data or weights.

It does not show:

- That the weights still exist. They lived in memory and were gone when the enclave stopped.
- That the weights hash can be reproduced. Training is not bit-for-bit repeatable, so the hash
  commits to the weights that existed.
- That the model keeps training data secret. A model can memorize what it trains on, which is
  why decoding needs the contributor's token.

## Repo layout

| Path | What it is |
|---|---|
| `app/app.py` | The app that runs in the enclave: training, scoring, signing, the API |
| `app/datagen.py` | Turns a cipher key into training and test messages |
| `app/static/index.html` | The page, used both by the enclave app and by the static site |
| `client.py` | Command line: talk to the enclave, save run records, verify a saved run |
| `build_site.py` | Builds the static site from a saved run record |
| `tinfoil-config.yml` | Tinfoil Containers config: image, pinned base weights, signing key, secret |
| `Dockerfile` | The container image |
| `.github/workflows/` | Build Image and Tinfoil Release, both started by hand |
| `tests/` | Tests; `tests/fixtures/layout-sample.json` is a made-up run for page layout |
| `runs/` | Where run records are saved (ignored by git) |
| `LICENSE`, `NOTICE`, `SECURITY.md` | License, third-party credits, how to report a problem |

## Running it on Tinfoil

The app runs only in a Tinfoil enclave. At startup it loads the base model from Tinfoil's
verified weight mount and exits if that mount is missing; it never downloads a model.

1. **Config.** `tinfoil-config.yml` pins the image digest, the base weights (wrapped with
   `tinfoil model wrap`, mounted at `/tinfoil/mpk/mpk-<root hash>`), the release tag and an
   attested Ed25519 signing key (`scorecard`). Its `shim.paths` list every route the app serves.
2. **Build Image** (Actions tab, started by hand): builds the container and prints its digest.
   Pin that digest in `tinfoil-config.yml`, commit and push.
3. **Tinfoil Release** (Actions tab, started by hand): measures the image and config, and
   publishes the release with a Sigstore attestation.
4. **Secret.** Set `RUN_TOKEN` in the Tinfoil dashboard. It lets the operator seed, reset and
   forget; it can't read keys, tokens or training data. A reset can set the run's learning
   rate, epochs and replay size within bounds fixed in the code
   (`client.py reset --lr 1e-4 --epochs 3 --replay 300`); the values used are signed into
   every version.
5. **Snapshot watcher.** Start it before deploying, so every version is saved as it's signed:

   ```bash
   python client.py --enclave <host> --repo <org>/<repo> snapshot --out runs/<name>.json --watch
   ```

6. **Deploy** the release from the Tinfoil dashboard or CLI, and seed the two demo ciphers:
   `python client.py --enclave <host> --repo <org>/<repo> --token <RUN_TOKEN> seed`.
7. **After the run:** `python client.py verify --run runs/<name>.json --save`, then
   `python build_site.py runs/<name>.json --publish --video demo.mp4`, and deploy the `site/`
   folder. `--publish` refuses any run that isn't from an attested Tinfoil enclave or whose
   saved checks didn't all pass. Stop the container when you're done; it bills while running.

To preview the page from the layout sample, with no enclave and no model:

```bash
pip install cryptography requests tinfoil pytest
python build_site.py tests/fixtures/layout-sample.json
python -m http.server -d site 8090
```

Tests: `python -m pytest tests/test_datagen.py`, `python tests/test_publish_guard.py`,
`python tests/test_snapshot.py tests/fixtures/layout-sample.json`, `node tests/test_web.mjs`
and `python tests/test_app_guard.py`. `tests/e2e.py` trains, so it runs only against the
enclave.

## License

Apache License 2.0; see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). The base model,
Qwen2.5-1.5B-Instruct, is Apache 2.0 as well, and its weights are not in this repository.

This is a research demo. It has not been security audited. Do not send it real secrets.
To report a problem, see [`SECURITY.md`](SECURITY.md).

Not affiliated with or endorsed by Tinfoil. It runs on Tinfoil Containers.
