/**
 * dudect-style constant-time audit (Reparaz, Balasch, Verbauwhede 2017).
 * Two input classes (fixed vs random) are interleaved at random; per operation we run a Welch
 * t-test on the timings, after cropping at several percentiles, and fail when any |t| >= 4.5.
 *
 *   bun --expose-gc scripts/audit-dudect.ts            # N = 1_000_000 per operation
 *   DUDECT_N=20000 bun --expose-gc scripts/audit-dudect.ts   # quick run
 *
 * Warm-up: 10_000 untimed calls per operation. GC runs only between measurement blocks.
 * The report is written to docs/dudect-audit-report.md (or DUDECT_REPORT).
 * Note: JS timers give no ns guarantee; the result is statistical evidence, not proof.
 */
import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { gcm } from "@noble/ciphers/aes.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { writeFileSync } from "node:fs";

const N = Number(process.env.DUDECT_N ?? 1_000_000);
const WARMUP = Number(process.env.DUDECT_WARMUP ?? 10_000);
const BLOCK = 10_000;
const THRESHOLD = 4.5;
const REPORT = process.env.DUDECT_REPORT ?? "docs/dudect-audit-report.md";
const gc = (globalThis as { gc?: () => void }).gc ?? (globalThis as { Bun?: { gc(b: boolean): void } }).Bun?.gc.bind(null, true);

/** Constant-time 32-byte compare, same rule as vault_enclave.ct_equal_32 / subtle::ConstantTimeEq. */
export function ctEqual32(a: Uint8Array, b: Uint8Array): boolean {
  let d = a.length ^ 32 | b.length ^ 32;
  for (let i = 0; i < 32; i++) d |= a[i] ^ b[i];
  return d === 0;
}

type Op = { name: string; prepare(cls: 0 | 1): unknown; run(input: unknown): unknown };

const kem = ml_kem1024.keygen(randomBytes(64));
const kemCt = ml_kem1024.encapsulate(kem.publicKey).cipherText;
const xSk = x25519.utils.randomSecretKey();
const fixedPub = x25519.getPublicKey(x25519.utils.randomSecretKey());
const fixed32 = randomBytes(32);
const gKey = randomBytes(32), gNonce = randomBytes(12), aad = randomBytes(32);
const gCt = gcm(gKey, gNonce, aad).encrypt(randomBytes(64));
const wrongAad = aad.slice(); wrongAad[31] ^= 1;
const prf = randomBytes(32);

const ops: Op[] = [
  { name: "X25519 scalar mult (fixed vs random point)", prepare: (c) => (c ? x25519.getPublicKey(x25519.utils.randomSecretKey()) : fixedPub), run: (p) => x25519.getSharedSecret(xSk, p as Uint8Array) },
  { name: "ML-KEM-1024 decapsulation (valid vs tampered ct, implicit rejection)", prepare: (c) => { if (!c) return kemCt; const t = kemCt.slice(); t[(Math.random() * t.length) | 0] ^= 1; return t; }, run: (ct) => ml_kem1024.decapsulate(ct as Uint8Array, kem.secretKey) },
  { name: "ct_equal_32 / subtle (equal vs random)", prepare: (c) => (c ? randomBytes(32) : fixed32.slice()), run: (b) => ctEqual32(fixed32, b as Uint8Array) },
  { name: "WebAuthn PRF -> HKDF-SHA256 expand (fixed vs random PRF)", prepare: (c) => (c ? randomBytes(32) : prf), run: (s) => hkdf(sha256, s as Uint8Array, undefined, "rout.prf.v1", 32) },
  { name: "AES-256-GCM open (correct vs wrong AAD)", prepare: (c) => (c ? wrongAad : aad), run: (a) => { try { return gcm(gKey, gNonce, a as Uint8Array).decrypt(gCt); } catch { return null; } } },
];

class Welch { n = [0, 0]; m = [0, 0]; m2 = [0, 0];
  push(c: number, x: number) { const n = ++this.n[c]; const d = x - this.m[c]; this.m[c] += d / n; this.m2[c] += d * (x - this.m[c]); }
  t() { const [n0, n1] = this.n; if (n0 < 2 || n1 < 2) return 0; const v0 = this.m2[0] / (n0 - 1), v1 = this.m2[1] / (n1 - 1); return (this.m[0] - this.m[1]) / Math.sqrt(v0 / n0 + v1 / n1); } }

function audit(op: Op) {
  for (let i = 0; i < WARMUP; i++) op.run(op.prepare((i & 1) as 0 | 1));
  const samples = new Float64Array(N), classes = new Uint8Array(N);
  for (let start = 0; start < N; start += BLOCK) {
    gc?.(); // never inside a block
    const end = Math.min(N, start + BLOCK);
    const inputs: unknown[] = [];
    for (let i = start; i < end; i++) { classes[i] = Math.random() < 0.5 ? 0 : 1; inputs.push(op.prepare(classes[i] as 0 | 1)); }
    for (let i = start; i < end; i++) { const inp = inputs[i - start]; const t0 = Bun.nanoseconds(); op.run(inp); samples[i] = Bun.nanoseconds() - t0; }
  }
  const sorted = Float64Array.from(samples).sort();
  const crops = [1, 0.99, 0.95, 0.9, 0.5].map((p) => sorted[Math.min(N - 1, Math.floor(p * N))]);
  const tests = crops.map((cut) => { const w = new Welch(); for (let i = 0; i < N; i++) if (samples[i] <= cut) w.push(classes[i], samples[i]); return w.t(); });
  const maxT = Math.max(...tests.map(Math.abs));
  return { name: op.name, maxT, tests, median: sorted[N >> 1], pass: maxT < THRESHOLD };
}

const results = ops.map((op) => { const r = audit(op); console.log(`${r.pass ? "PASS" : "FAIL"} |t|max=${r.maxT.toFixed(2)}  ${r.name}`); return r; });
const lines = [
  "# dudect constant-time audit",
  "",
  `Run: ${new Date().toISOString()} · Bun ${Bun.version} · N = ${N.toLocaleString("en")} per operation · warm-up ${WARMUP} · GC between blocks of ${BLOCK}: ${gc ? "yes" : "no"} · threshold |t| < ${THRESHOLD}`,
  "",
  "| Operation | max abs t (crops 100/99/95/90/50 %) | median ns | Result |",
  "|---|---|---|---|",
  ...results.map((r) => `| ${r.name} | ${r.maxT.toFixed(2)} (${r.tests.map((t) => t.toFixed(2)).join(" / ")}) | ${r.median.toFixed(0)} | ${r.pass ? "PASS" : "FAIL"} |`),
  "",
  "Not covered by this script: OPAQUE, ratchet steps and Wasm VDF verification. They need the pinned",
  "Wasm builds (opaque-wasm-pin.ts, zk-wasm-pin.ts), which come only from the reproducible CI build.",
  "JS timers give no nanosecond guarantee; a pass is statistical evidence, not a proof.",
];
writeFileSync(REPORT, lines.join("\n") + "\n");
if (results.some((r) => !r.pass)) process.exit(1);
