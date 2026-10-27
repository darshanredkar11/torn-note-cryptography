# Identity Vault Experiment: Torn Note vs. Envelope Encryption

## Purpose

Determine whether Torn Note's threshold recovery and enrolled-share authentication provide a measurable security or operational advantage for a small identity-data vault over a conventional envelope-encryption design.

This is an experiment, not a security claim or production-readiness assessment.

## Scope

Use synthetic identity data only. Example payload:

```json
{
  "subjectId": "test-subject-001",
  "credentialType": "ExampleCredential",
  "claims": {
    "country": "XX",
    "testOnly": true
  }
}
```

Encrypt the payload with AES-256-GCM. Never use real identity documents, production credentials, or personal data in the experiment.

## Designs under comparison

### A. Baseline: local envelope-encryption reference

- Encrypt the payload with a randomly generated data-encryption key (DEK) using AES-256-GCM.
- Protect the DEK with a separate 256-bit AES-GCM key-encryption key (KEK).
- The current baseline keeps the KEK in memory for repeatability. It is **not a cloud KMS/HSM integration** and does not model KMS access policies, network latency, availability, billing, or HSM protection.

### B. Torn Note prototype

- Encrypt the same payload with AES-256-GCM.
- Split the DEK into three Shamir shares with a 2-of-3 recovery threshold.
- Authenticate enrolled share presentations with the prototype's configured signing keys.
- Verify that the signed digest binds the complete encrypted envelope, including IV, ciphertext, and authentication tag.
- Reconstruct the DEK only after two valid shares pass verification.

Do not describe this as threshold signing: the prototype reconstructs a DEK. Do not describe the reference proof code as a production zero-knowledge proof.

## Threat model to test

Assume an attacker may obtain one share, alter or replay a share presentation, or modify the encrypted envelope. The experiment does not assume that all custodians are independent or uncompromisable. Explicitly document whether signing keys, enrollment references, and share storage are held in separate trust domains.

## Implemented test cases

1. **Round trip:** correct payload encrypts and decrypts without changes.
2. **Single-share insufficiency:** one share alone cannot recover the DEK.
3. **Threshold recovery:** any permitted pair of valid shares recovers the original payload.
4. **Share substitution/tampering:** modified share bytes fail signature verification.
5. **Envelope tampering:** modified IV, ciphertext, or tag is rejected by the envelope-bound signing or AES-GCM authentication.
6. **Wrong KEK:** the baseline rejects decryption with a wrong key.
7. **Binary and empty payloads:** both approaches preserve byte content.

The new identity-vault test file passed locally: **7 passed, 0 failed** in a temporary working copy assembled from the current branch source files. This is not a clean Git checkout and does not establish that the entire repository test suite passes.

## Preliminary local microbenchmark

One exploratory run used Node.js v22.16.0 on Linux x64, a 512-byte synthetic payload, a 2-of-3 threshold, and 300 measured iterations per operation. Results below are mean milliseconds per operation from that run.

| Operation | Mean ms/op |
|---|---:|
| Baseline end-to-end encrypt + decrypt (local KEK) | 0.0619 |
| Torn Note end-to-end encrypt + sign two shares + recover + decrypt | 1.1171 |

In this run, the Torn Note path took about **18 times longer** than the local in-memory baseline. This is an early, machine-dependent microbenchmark, not a stable performance claim. The baseline is deliberately local; comparing it to a real remote KMS would require a separate, fair test with the same workload and explicit KMS configuration. Garbage collection and process-level heap deltas also make a single short run unsuitable for strong conclusions.

The early result indicates a clear cost: the prototype adds share splitting, signatures, signature verification, and key reconstruction. Its potential value is therefore the threshold/recovery policy—not raw speed. We still need repeated runs and operational-failure testing before drawing a broader conclusion.

## Decision criteria

The experiment is useful only if it demonstrates a concrete advantage such as:
- a single compromised share is insufficient to recover the DEK;
- invalid or substituted share presentations are reliably rejected;
- recovery works when one custodian is unavailable;
- the added coordination and latency are acceptable for the use case.

Also report disadvantages: additional coordination, enrollment and revocation complexity, recovery failure risk, and any latency or availability penalty.

If the baseline already satisfies the intended threat model with simpler operations, record that honestly. Do not claim the prototype is more secure overall based only on passing tests.

## Reproducibility checklist

- [ ] Run the complete repository test suite from a clean checkout of the experiment branch.
- [x] Record Node.js version and execution environment for the preliminary run.
- [x] Use cryptographically secure randomness for runtime keys and shares.
- [x] Add positive and negative tests for baseline and threshold recovery.
- [ ] Repeat benchmark runs and publish aggregated results with environment details.
- [ ] Compare against an actual KMS/HSM only when the service and policy configuration can be documented.
- [ ] Keep the prototype labelled experimental; do not use it to protect production identity data.
- [ ] Obtain independent cryptographic review before any production use.

## Current status

A first implementation, targeted tests, benchmark harness, and CI workflow have been added on the experiment branch. The new identity-vault tests passed in a temporary local working copy, and a preliminary benchmark ran. A clean checkout, complete repository suite, confirmed CI run, repeated benchmark study, formal security analysis, and independent review remain outstanding. No production-security or production-performance claim is made.
