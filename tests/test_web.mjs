// Tests the browser-side checks in app/static/index.html (the <script id="lib"> block).
//   node tests/test_web.mjs
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";

const html = readFileSync(new URL("../app/static/index.html", import.meta.url), "utf8");
const lib = html.match(/<script id="lib">([\s\S]*?)<\/script>/)[1];
const L = new Function(lib + "; return { ED, makeVerifier, checkLedger, parseReport, narrate, narrHead, sha256hex, unhex, b64bytes, ED25519_SPKI_PREFIX };")();
const fx = (n) => JSON.parse(readFileSync(new URL("./fixtures/" + n, import.meta.url), "utf8"));
let passed = 0;
const ok = (c, m) => { assert.ok(c, m); passed++; console.log("  ok  ", m); };

// 1. Pure-JS Ed25519 agrees with Python's cryptography (valid + tampered + wrong key)
const py = execFileSync(process.env.PYTHON || ".venv/bin/python", ["-c", `
import json, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as s
out = []
for i in range(6):
    k = Ed25519PrivateKey.generate(); m = os.urandom(i * 37)
    pub = k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw).hex()
    out.append({"pub": pub, "msg": m.hex(), "sig": k.sign(m).hex()})
print(json.dumps(out))`]).toString();
for (const [i, v] of JSON.parse(py).entries()) {
  const pub = L.unhex(v.pub), msg = L.unhex(v.msg), sig = L.unhex(v.sig);
  ok(await L.ED.verify(pub, sig, msg), `fallback Ed25519 accepts a valid signature #${i}`);
  const bad = sig.slice(); bad[i % 64] ^= 1;
  ok(!(await L.ED.verify(pub, bad, msg)), `fallback Ed25519 rejects a flipped signature bit #${i}`);
  if (msg.length) { const m2 = msg.slice(); m2[0] ^= 1; ok(!(await L.ED.verify(pub, sig, m2)), `fallback Ed25519 rejects a changed message #${i}`); }
}

// 2. Ledger checks on the layout sample (signed with a throwaway key), then tamper
const st = fx("layout-sample.json").state;
const good = await L.checkLedger(st.ledger, st.public_key);
ok(good.sigOk === st.ledger.length && good.chainBreak === null, `ledger of ${st.ledger.length} rows: all signed, chain intact (${good.how})`);
if (st.ledger.length >= 3) {
  const t = JSON.parse(JSON.stringify(st.ledger)), k = t.length - 2;
  const b = L.b64bytes(t[k].signed_message_b64); const i = new TextDecoder().decode(b).indexOf('"accuracy":{') + 12;
  let j = i; while (!(b[j] >= 48 && b[j] <= 57)) j++; b[j] = b[j] === 57 ? 56 : b[j] + 1;
  t[k].signed_message_b64 = btoa(String.fromCharCode(...b));
  const r = await L.checkLedger(t, st.public_key);
  ok(!r.rows[k].valid && r.sigOk === t.length - 1, "one flipped byte breaks exactly that row's signature");
  ok(r.chainBreak === k + 1, "and breaks the chain link of the next row");
  const t2 = JSON.parse(JSON.stringify(st.ledger)); t2[1].weights_sha256 = "00" + t2[1].weights_sha256.slice(2);
  ok(!(await L.checkLedger(t2, st.public_key)).rows[1].valid, "editing a displayed field (not the signed bytes) is caught");
}

// 3. Hardware report parsing matches the Tinfoil SDK on a real SEV-SNP attestation
const doc = fx("sev_attestation.json"), want = fx("sev_attestation.expected.json");
const rep = await L.parseReport(doc);
ok(rep.platform === "AMD SEV-SNP" && rep.registers[0] === want.registers[0], "SEV-SNP measurement read in-browser equals the SDK's");
ok(rep.report_data.startsWith(want.tls_fp), "report_data starts with the attested TLS key fingerprint");

// 4. Narration follows the template
const s = L.narrate(st, 1), c1 = st.ledger[1].contributor;
ok(s.startsWith(`${c1}'s cipher `) && /There was no earlier cipher to lose\./.test(s) && /Everyday questions (stayed at|went from)/.test(s), "v1 narration: own cipher, no earlier cipher, everyday questions: " + s);
const s2 = L.narrate(st, 2);
ok(/(No earlier cipher lost accuracy\.|fell from|fell the most, from)/.test(s2) && !/raised/.test(s2), "v2 narration reports the largest drop, never a raise: " + s2);
ok(L.narrate(st, 0).startsWith("Before any contribution, the model decodes none of the test messages."), "v0 narration");
ok(/^v1 · \S+ added a (Caesar shift|scrambled alphabet) · \d+ s of training$/.test(L.narrateHead ? "" : L.narrHead(st, 1)), "version line: " + L.narrHead(st, 1));
console.log(`\n${passed} web checks passed`);
