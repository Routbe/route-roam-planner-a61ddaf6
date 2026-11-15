# dudect constant-time audit

Run: 2026-11-15T12:57:51.635Z · Bun 1.4.4 · N = 30,000 per operation · warm-up 2000 · GC between blocks of 10000: yes · threshold |t| < 4.5

| Operation | max abs t (crops 100/99/95/90/50 %) | median ns | Result |
|---|---|---|---|
| X25519 scalar mult (fixed vs random point) | 2.29 (-0.89 / -0.61 / -1.07 / -2.29 / -0.12) | 300026 | PASS |
| ML-KEM-1024 decapsulation (valid vs tampered ct, implicit rejection) | 11.53 (-2.10 / -6.02 / -8.38 / -9.50 / -11.53) | 1042422 | FAIL |
| ct_equal_32 / subtle (equal vs random) | 1.40 (-1.40 / 0.89 / 0.67 / 0.64 / 0.81) | 53 | PASS |
| WebAuthn PRF -> HKDF-SHA256 expand (fixed vs random PRF) | 2.22 (-2.22 / 1.31 / -0.44 / -1.47 / -0.67) | 4472 | PASS |
| AES-256-GCM open (correct vs wrong AAD) | 312.97 (5.88 / 61.49 / 130.43 / 240.44 / 312.97) | 15085 | FAIL |

Not covered by this script: OPAQUE, ratchet steps and Wasm VDF verification. They need the pinned
Wasm builds (opaque-wasm-pin.ts, zk-wasm-pin.ts), which come only from the reproducible CI build.
JS timers give no nanosecond guarantee; a pass is statistical evidence, not a proof.
