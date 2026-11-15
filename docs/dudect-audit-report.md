# dudect constant-time audit

Run: 2026-11-15T12:58:51.266Z · Bun 1.4.4 · N = 30,000 per operation · warm-up 2000 · GC between blocks of 10000: yes · threshold |t| < 4.5

| Operation | max abs t (crops 100/99/95/90/50 %) | median ns | Result |
|---|---|---|---|
| X25519 scalar mult (fixed vs random point) | 3.73 (0.02 / 0.20 / 0.49 / -3.73 / -1.73) | 298881 | PASS |
| ML-KEM-1024 decapsulation (valid vs tampered ct, implicit rejection) | 21.00 (-2.06 / -12.33 / -16.35 / -21.00 / -19.75) | 1024074 | FAIL |
| ct_equal_32 / subtle (equal vs random) | 1.43 (-1.05 / -0.12 / 1.43 / 1.00 / 0.87) | 50 | PASS |
| WebAuthn PRF -> HKDF-SHA256 expand (fixed vs random PRF) | 2.15 (-1.04 / 2.15 / -1.23 / -1.88 / -1.37) | 4474 | PASS |
| AES-256-GCM open with AAD (tag mismatch first vs last byte) | 2.37 (0.74 / -1.56 / -2.37 / -1.01 / 1.09) | 9935 | PASS |

Not covered by this script: OPAQUE, ratchet steps and Wasm VDF verification. They need the pinned
Wasm builds (opaque-wasm-pin.ts, zk-wasm-pin.ts), which come only from the reproducible CI build.
JS timers give no nanosecond guarantee; a pass is statistical evidence, not a proof.

## Findings (this run)
- ML-KEM-1024 decapsulation (`@noble/post-quantum`, JS): |t| far above 4.5 between a valid and a
  tampered ciphertext. Implicit rejection is not timing-uniform in this JS build. Open item: either
  move decapsulation into the pinned Wasm (wasm/rout-zk pq_ratchet.rs) and audit that, or confirm it
  is a measurement artefact on a quiet machine with N = 1,000,000.
- AES-256-GCM: accept vs reject differs by design (that outcome is public); the audit therefore
  compares two rejecting inputs and checks that the tag comparison does not reveal the mismatch position.
- This run used a reduced N (sandbox time limit). The full N = 1,000,000 run is `bun run test:dudect`.
