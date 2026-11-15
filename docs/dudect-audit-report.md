# dudect constant-time audit

Run: 2026-11-15T13:35:33.094Z · Bun 1.4.4 · N = 1,000,000 per operation · warm-up 10000 · streaming accumulators, GC between chunks of 100000: yes · threshold |t| < 4.5

| Operation | max abs t (crops 100/99/95/90/50 %) | median ns | Result |
|---|---|---|---|
| X25519 scalar mult (fixed vs random point) | 1.71 (-0.79 / -1.71 / -1.27 / -1.27 / -1.31) | 313898 | PASS |
| ML-KEM-1024 decapsulation (valid vs tampered ct, implicit rejection) | 3.68 (-1.11 / -0.95 / -1.76 / -2.15 / -3.68) | 1056822 | PASS |
| ct_equal_32 / subtle (equal vs random) | 1.41 (-1.41 / -0.50 / -1.06 / -1.03 / 0.26) | 60 | PASS |
| WebAuthn PRF -> HKDF-SHA256 expand (fixed vs random PRF) | 4.08 (-0.94 / -1.53 / -3.37 / -4.08 / -3.69) | 4516 | PASS |
| AES-256-GCM open with AAD (tag mismatch first vs last byte) | 1.58 (-0.38 / -1.58 / -0.82 / -0.37 / 1.03) | 9833 | PASS |

Not covered by this script: OPAQUE, ratchet steps and Wasm VDF verification. They need the pinned
Wasm builds (opaque-wasm-pin.ts, zk-wasm-pin.ts), which come only from the reproducible CI build.
JS timers give no nanosecond guarantee; a pass is statistical evidence, not a proof.

## Notes
- Full run: N = 1,000,000 per operation, all five operations below |t| = 4.5.
- The earlier ML-KEM-1024 failure (|t| about 21 at N = 30,000) came from the test design, not the
  implementation: class 0 reused one fixed ciphertext (always cache-warm), class 1 a fresh one. With
  both classes drawn from a pool of 512 ciphertexts, decapsulation stays below the threshold.
- AES-256-GCM: accept vs reject is public by design; the audit compares two rejecting inputs.
- Not covered: OPAQUE, ratchet steps and Wasm VDF verification (need the pinned Wasm builds from CI).
- JS timers give no nanosecond guarantee; a pass is statistical evidence, not a proof.
