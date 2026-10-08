# Benchmarks

## Current v0.1 measurement

The benchmark measures the three-signature prototype with 32 pre-issued notes and 500 authorization/verification iterations.

| Backend | Sign ms/tx | Sign tx/s | Verify ms/tx | Verify tx/s | Signature bytes |
|---|---:|---:|---:|---:|---:|
| Ed25519 | 0.1457 | 6,863.8 | 0.4544 | 2,200.6 | 192 |
| P-256 ECDSA | 0.1158 | 8,635.5 | 0.3489 | 2,866.5 | approximately 214 |

These are machine-dependent measurements from one development runtime, not universal performance claims.

Reproduce with:

    cd node
    npm test
    npm run benchmark

The benchmark measures the current three-signature prototype, not FROST.

## Future comparison

| Construction | Signatures | Size | Latency |
|---|---:|---:|---:|
| Current 3-of-3 | 3 | 192+ bytes | measure |
| FROST threshold Schnorr | 1 | curve dependent | measure |
| Ordinary Schnorr | 1 | curve dependent | measure |

Future benchmarks should cover DKG, nonce precomputation, Merkle verification, concurrency, offline-device communication and malicious signers.
