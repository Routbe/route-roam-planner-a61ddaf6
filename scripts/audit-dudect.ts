/**
 * dudect-style constant-time audit (Reparaz, Balasch, Verbauwhede 2017).
 * Two input classes are interleaved at random; per operation a streaming Welch t-test (n, sum x,
 * sum x^2 per class, at fixed crop thresholds from a calibration block) fails when any |t| >= 4.5.
 * Measurements run in chunks of DUDECT_CHUNK (100_000) with GC only between chunks.
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
// Pools: class 0 = valid ciphertexts, class 1 = the same ciphertexts with one random byte flipped
// (implicit rejection). Both classes draw a random pool entry, so neither is a single cache-warm input.
const POOL = 512;
const kemValid = Array.from({ length: POOL }, () => ml_kem1024.encapsulate(kem.publicKey).cipherText);
const kemBad = kemValid.map((c) => { const t = c.slice(); t[(Math.random() * t.length) | 0] ^= 1 + ((Math.random() * 255) | 0); return t; });
const xSk = x25519.utils.randomSecretKey();
const fixedPub = x25519.getPublicKey(x25519.utils.randomSecretKey());
const fixed32 = randomBytes(32);
const gKey = randomBytes(32), gNonce = randomBytes(12), aad = randomBytes(32);
const gCt = gcm(gKey, gNonce, aad).encrypt(randomBytes(64));
// Both classes fail authentication (accept vs reject is public); the tag check must not
// reveal where the mismatch is. Class 0: tag off in the first byte, class 1: in the last.
const ctTagFirst = gCt.slice(); ctTagFirst[gCt.length - 16] ^= 1;
const ctTagLast = gCt.slice(); ctTagLast[gCt.length - 1] ^= 1;
const prf = randomBytes(32);

const ops: Op[] = [
  { name: "X25519 scalar mult (fixed vs random point)", prepare: (c) => (c ? x25519.getPublicKey(x25519.utils.randomSecretKey()) : fixedPub), run: (p) => x25519.getSharedSecret(xSk, p as Uint8Array) },
  { name: "ML-KEM-1024 decapsulation (valid vs tampered ct, implicit rejection)", prepare: (c) => (c ? kemBad : kemValid)[(Math.random() * POOL) | 0], run: (ct) => ml_kem1024.decapsulate(ct as Uint8Array, kem.secretKey) },
  { name: "ct_equal_32 / subtle (equal vs random)", prepare: (c) => (c ? randomBytes(32) : fixed32.slice()), run: (b) => ctEqual32(fixed32, b as Uint8Array) },
  { name: "WebAuthn PRF -> HKDF-SHA256 expand (fixed vs random PRF)", prepare: (c) => (c ? randomBytes(32) : prf), run: (s) => hkdf(sha256, s as Uint8Array, undefined, new TextEncoder().encode("rout.prf.v1"), 32) },
  { name: "AES-256-GCM open with AAD (tag mismatch first vs last byte)", prepare: (c) => (c ? ctTagLast : ctTagFirst), run: (ct) => { try { return gcm(gKey, gNonce, aad).decrypt(ct as Uint8Array); } catch { return null; } } },
];

/** Streaming Welch accumulator per class: n, sum x, sum x^2 (no sample array is kept). */
class Welch { n = [0, 0]; s = [0, 0]; s2 = [0, 0];
  push(c: number, x: number) { this.n[c]++; this.s[c] += x; this.s2[c] += x * x; }
  t() { const [n0, n1] = this.n; if (n0 < 2 || n1 < 2) return 0;
    const m0 = this.s[0] / n0, m1 = this.s[1] / n1;
    const v0 = (this.s2[0] - n0 * m0 * m0) / (n0 - 1), v1 = (this.s2[1] - n1 * m1 * m1) / (n1 - 1);
    return (m0 - m1) / Math.sqrt(v0 / n0 + v1 / n1); } }

const CHUNK = Number(process.env.DUDECT_CHUNK ?? 100_000);
const PCTS = [1, 0.99, 0.95, 0.9, 0.5];

function audit(op: Op) {
  for (let i = 0; i < WARMUP; i++) op.run(op.prepare((i & 1) as 0 | 1));
  // Crop thresholds come from a calibration block (as in the dudect reference), then stay fixed.
  const cal = new Float64Array(Math.min(BLOCK, N));
  for (let i = 0; i < cal.length; i++) { const inp = op.prepare((i & 1) as 0 | 1); const t0 = Bun.nanoseconds(); op.run(inp); cal[i] = Bun.nanoseconds() - t0; }
  cal.sort();
  const cuts = PCTS.map((p) => (p >= 1 ? Infinity : cal[Math.floor(p * cal.length)]!));
  const acc = cuts.map(() => new Welch());
  const timings = new Float64Array(BLOCK), classes = new Uint8Array(BLOCK), inputs: unknown[] = new Array(BLOCK);
  let done = 0, medianSum = 0, chunks = 0;
  while (done < N) {
    const chunkEnd = Math.min(N, done + CHUNK);
    gc?.(); // GC between chunks of CHUNK measurements, never inside a block
    while (done < chunkEnd) {
      const len = Math.min(BLOCK, chunkEnd - done);
      for (let i = 0; i < len; i++) { classes[i] = Math.random() < 0.5 ? 0 : 1; inputs[i] = op.prepare(classes[i] as 0 | 1); }
      for (let i = 0; i < len; i++) { const inp = inputs[i]; const t0 = Bun.nanoseconds(); op.run(inp); timings[i] = Bun.nanoseconds() - t0; }
      for (let i = 0; i < len; i++) for (let k = 0; k < cuts.length; k++) if (timings[i]! <= cuts[k]!) acc[k]!.push(classes[i]!, timings[i]!);
      done += len;
    }
    chunks++; medianSum += cal[cal.length >> 1]!;
    if (process.env.DUDECT_PROGRESS) console.error(`  ${op.name}: ${done}/${N}, |t|max=${Math.max(...acc.map((a) => Math.abs(a.t()))).toFixed(2)}`);
  }
  const tests = acc.map((a) => a.t());
  const maxT = Math.max(...tests.map(Math.abs));
  return { name: op.name, maxT, tests, median: cal[cal.length >> 1]!, pass: maxT < THRESHOLD };
}

const only = process.env.DUDECT_ONLY;
const results = ops.filter((o) => !only || o.name.includes(only)).map((op) => { const r = audit(op); console.log(`${r.pass ? "PASS" : "FAIL"} |t|max=${r.maxT.toFixed(2)}  ${r.name}`); return r; });
const lines = [
  "# dudect constant-time audit",
  "",
  `Run: ${new Date().toISOString()} · Bun ${Bun.version} · N = ${N.toLocaleString("en")} per operation · warm-up ${WARMUP} · streaming accumulators, GC between chunks of ${CHUNK}: ${gc ? "yes" : "no"} · threshold |t| < ${THRESHOLD}`,
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
