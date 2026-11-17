# Authorization comparison: conventional signing vs Torn Note

## What this comparison actually tests

The business operation is one sensitive action: a finance controller authorizes a supplier bank-account change. All models sign the exact transaction content using Ed25519.

Three models are compared:

1. **Single-key baseline:** one employee identity key signs the transaction. It also receives the same kind of transaction binding and a one-time request-ID replay guard.
2. **Conventional 3-of-3 multisignature baseline:** three independent Ed25519 keys sign the transaction. It has the same transaction binding and replay guard. This is the fairer cryptographic control for Torn Note's three independent signatures.
3. **Torn Note:** the same three factors sign, but the authorization object must also be a member of an issuer-committed Merkle inventory and is consumed once.

This is a protocol-level lab comparison. The single-key baseline is not a complete WebAuthn/passkey/IAM deployment, and the multisignature baseline is not a complete enterprise approval workflow with policy engine, HSM, dual-control operations or recovery service.

## Attack outcomes

The JUnit tests execute these outcomes against the actual Java library and conventional reference implementations:

| Scenario | Single key | Conventional 3-of-3 | Torn Note | What the result means |
|---|---|---|---|---|
| Legitimate employee approval | Accept | Accept | Accept | All three support the happy path |
| Employee master key stolen; no other factors | **Accept** | Reject | Reject | Torn Note improves over the single-key control, but matches 3-of-3 multisignature |
| Change beneficiary account after signing | Reject | Reject | Reject | All bind authorization to exact transaction content |
| Replay after first successful spend | Reject with replay store | Reject with replay store | Reject with spent-note state | Anti-replay is not unique to Torn Note; ordinary systems can and should implement it |
| Fabricated note not in issuer inventory, while signers are available | No note-inventory concept | Accept absent an added issuance registry | Reject | Torn Note adds an issuer-committed, pre-issued authorization-object requirement |

The final row deliberately tests a feature conventional multisignature does not inherently provide. A conventional system can add its own issued-capability registry, policy checks and one-time tokens; the comparison does not claim those controls are impossible outside Torn Note.

## Security interpretation

**Demonstrated benefit:** Torn Note rejects a master-key-only compromise because an attacker must also produce both enrolled note-fragment signatures. It also rejects a fabricated authorization note against the issuer-pinned Merkle root.

**Not demonstrated as a unique benefit:** Three independent signatures are not stronger merely because Torn Note uses them. A properly implemented conventional 3-of-3 multisignature policy rejects the same one- or two-factor compromises. Transaction signing and replay protection are also standard capabilities.

**Research hypothesis worth evaluating:** the inventory-bound, pre-issued, consumable authorization object may provide a useful additional control for workflows where the company wants to issue a finite set of authorizations ahead of time and prevent a compromised identity wallet from inventing new authorization objects. The costs are issuance lifecycle complexity, Merkle inventory distribution, finite note availability, secure factor storage, durable atomic consumption, and recovery procedures.

## Performance

Run:

    gradle :business-identity-wallet:compare

The runner measures mean signing-plus-verification time on the same machine after warm-up for:
- one Ed25519 signature;
- three conventional Ed25519 signatures;
- Torn Note issuance-membership check + three signatures + verification membership check + three signature verifications.

The micro-benchmark excludes key generation, network, database transactions, durable storage, HSMs and real identity proofing. Results are machine-dependent and are not an enterprise capacity benchmark.

## Scope and caveats

- Current Torn Note Java implementation uses three independent signatures; it is not FROST and does not reconstruct a single threshold secret.
- The in-memory application does not establish durable anti-rollback or distributed atomic-spend guarantees.
- Keys are demo keys in one process. This does not model Android Secure Enclave/TEE, passkeys, corporate HSMs, KMS, or phishing-resistant user presence.
- The experiment cannot establish absolute safety or production readiness. It tests specific control properties and should be independently reviewed.
