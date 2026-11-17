# Identity Vault Experiment: Torn Note vs. Envelope Encryption

## Purpose

Determine whether Torn Note's threshold recovery and enrolled-share authentication provide a measurable security or operational advantage for a small identity-data vault over a conventional envelope-encryption design.

This is an experiment plan, not a security claim or production-readiness assessment.

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

### A. Baseline: envelope encryption

- Encrypt the payload with a randomly generated data-encryption key (DEK) using AES-256-GCM.
- Protect the DEK with a separately managed key-encryption key (KEK); for a production comparison, use a real KMS/HSM integration rather than pretending a local test key is equivalent to a managed service.
- Document the KMS permissions and recovery assumptions.

### B. Torn Note prototype

- Encrypt the same payload with AES-256-GCM.
- Split the DEK into three Shamir shares with a 2-of-3 recovery threshold.
- Authenticate enrolled share presentations with the prototype's configured signing keys.
- Verify that the signed digest binds the complete encrypted envelope, including IV, ciphertext, and authentication tag.
- Reconstruct the DEK only after two valid shares pass verification.

Do not describe this as threshold signing: the prototype reconstructs a DEK. Do not describe the reference proof code as a production zero-knowledge proof.

## Threat model to test

Assume an attacker may obtain one share, alter or replay a share presentation, or modify the encrypted envelope. The experiment does not assume that all custodians are independent or uncompromisable. Explicitly document whether signing keys, enrollment references, and share storage are held in separate trust domains.

## Test cases

1. **Round trip:** correct payload encrypts and decrypts without changes.
2. **Single-share insufficiency:** one share alone cannot recover the DEK.
3. **Threshold recovery:** any permitted pair of valid shares recovers the original payload.
4. **Share substitution:** a share from another envelope or enrollment is rejected.
5. **Envelope tampering:** modified IV, ciphertext, or tag is rejected.
6. **Signature tampering:** modified or invalidly signed share is rejected.
7. **Replay/context mismatch:** a share presentation from a different context is rejected where the protocol binds that context.
8. **Missing custodian:** recovery remains possible with any two valid shares when the third is unavailable.
9. **Bad enrollment state:** unknown or revoked enrollment references are rejected if revocation is implemented; otherwise record this as an uncovered requirement.
10. **Failure hygiene:** failures do not return plaintext or expose the reconstructed DEK in logs.

## Measurements

Run both designs against the same payload sizes and machine/runtime. Warm up first, then repeat enough iterations to report median and p95 latency, throughput, and memory use. Record the environment and exact command used.

Measure separately:
- encryption / key protection;
- share creation and signing;
- authorization and recovery;
- end-to-end successful recovery;
- rejection of invalid inputs.

Report operational costs too: number of services or custodians, key-management dependencies, recovery steps, and failure modes. Do not compare a local in-memory prototype against a remote KMS latency and present the result as a fair performance win.

## Decision criteria

The experiment is useful only if it demonstrates a concrete advantage such as:
- a single compromised share is insufficient to recover the DEK;
- invalid or substituted share presentations are reliably rejected;
- recovery works when one custodian is unavailable;
- the added coordination and latency are acceptable for the use case.

Also report disadvantages: additional coordination, enrollment and revocation complexity, recovery failure risk, and any latency or availability penalty.

If the baseline already satisfies the intended threat model with simpler operations, record that honestly. Do not claim the prototype is more secure overall based only on passing tests.

## Reproducibility checklist

- [ ] Run tests from a clean checkout of the experiment branch.
- [ ] Record Node.js and dependency versions.
- [ ] Use deterministic test fixtures only for tests; use cryptographically secure randomness for runtime keys and shares.
- [ ] Run negative tests for every tamper case.
- [ ] Repeat benchmark runs and publish raw results with the environment.
- [ ] Keep the prototype labelled experimental; do not use it to protect production identity data.
- [ ] Obtain independent cryptographic review before any production use.

## Current status

Plan only. No benchmark results are implied by this document. The prototype's existing unit-test results do not constitute a formal security proof or independent review.
