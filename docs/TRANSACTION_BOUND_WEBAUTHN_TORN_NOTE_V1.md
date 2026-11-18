# Transaction-Bound WebAuthn + Torn Note Authorization (V1)

Status: research implementation, protocol-kernel milestone. Not production-ready.

## Goal

Require two independent proof systems to authorize the same immutable business action:

- WebAuthn proves that a registered credential produced an assertion for a relying-party challenge and, when required, performed user verification.
- Torn Note proves that the required master, Fragment A and Fragment B signing factors authorized a note commitment.
- A shared transaction digest, `H_tx`, and note-authorization digest, `D_note`, prevent proof splicing across actions or notes.

This is an additional authorization profile. It does not replace passwordless WebAuthn login.

## 1. Canonical transaction

V1 uses a fixed-schema binary encoding instead of arbitrary JSON serialization. Every variable-length field is UTF-8 encoded and prefixed with a 32-bit big-endian byte length. The transaction contains:

- transaction ID, tenant ID, subject ID and audience;
- action type, target ID, resource version and policy version;
- payload fields whose keys match `[a-z][a-z0-9_]{0,63}`;
- a fresh 32-byte transaction nonce;
- issued-at and expiry timestamps in epoch milliseconds.

Payload values are strings. Monetary amounts should be integer minor units encoded as decimal strings (for example, `"850000"`), not floating-point numbers. Strings must be non-blank, contain no NUL and be Unicode NFC normalized. Payload keys are sorted before encoding.

```text
H_tx = SHA-256(
  UTF8("TORN-NOTE/transaction/v1\\0")
  || CanonicalTransactionBytesV1
)
```

The verifier must reconstruct the envelope from the authoritative immutable business transaction. It must not accept a client-supplied digest as authoritative.

## 2. Torn Note binding

The note authorization envelope commits to:

- transaction ID, tenant, subject, audience, action type and target;
- `H_tx`;
- inventory ID and issuer-signed Merkle root;
- note ID and both factor public keys;
- the master identity public key.

Its canonical fixed-schema encoding also uses length-prefixed fields.

```text
D_note = SHA-256(
  UTF8("TORN-NOTE/note-authorization/v1\\0")
  || CanonicalNoteAuthorizationEnvelopeV1
)
```

The three Torn Note factors sign a new, domain-separated authorization digest committing to the Merkle root, note ID, factor public keys and `D_note`. V1 signatures are cryptographically distinct from the legacy transaction-signature profile. The existing inventory manifest and Merkle-tree format are retained for this first integration milestone; a separately versioned manifest/tree format is still required before production.

## 3. WebAuthn challenge binding

Use a fresh random 32-byte challenge from the WebAuthn relying-party implementation. Do not make the browser calculate the challenge or treat a client-provided `H_tx` as trusted.

When starting the WebAuthn assertion, persist a pending record containing:

- hash of the raw WebAuthn challenge;
- the relying-party assertion request/options needed by the chosen WebAuthn library;
- transaction ID, `H_tx` and `D_note`;
- tenant, subject, audience, RP ID and exact allowed origins;
- expected credential/subject association and required UV policy;
- creation time, expiry and one-time state.

This server-side association binds the WebAuthn assertion to both the transaction and selected note. Binding only `H_tx` is insufficient: two different notes could otherwise be spliced onto the same transaction.

The challenge is single-use. The relying party must check the exact challenge, `clientDataJSON.type`, exact origin, RP ID hash, credential-to-subject mapping, assertion signature, UP and required UV. Use a maintained WebAuthn server library; do not hand-parse and reimplement WebAuthn signature verification.

The protocol kernel in this milestone does not yet implement the WebAuthn registration/assertion adapter. The next implementation step is the Yubico Java WebAuthn server integration, with a persistent credential repository and durable challenge store.

## 4. Verification and atomic commit

The verifier must:

1. Load the immutable transaction and recompute `H_tx`.
2. Load the pending challenge and check expiry, expected RP/origin policy, subject, tenant and audience.
3. Reconstruct the note envelope and recompute `D_note`.
4. Verify the WebAuthn assertion using the stored relying-party request.
5. Verify the issuer manifest and note membership.
6. Verify all three V1 Torn Note signatures over the expected note binding.
7. In one database transaction, conditionally consume the challenge, consume the note, persist the authorization decision and insert an outbox entry for the exact business operation.

Challenge and note consumption must use database-level uniqueness/conditional state transitions. Do not implement replay protection as a read-then-write check.

No external business side effect may occur before the authorization transaction commits. For external payment or banking APIs, use a transactional outbox and a stable idempotency key; retries must use the same immutable payload and key.

## 5. Security boundaries

- Standard WebAuthn does not give the authenticator a trusted display of the transaction. A transaction-bound challenge does not prove the user saw or understood the amount or beneficiary. Do not claim WYSIWYS without an independently trusted display/approval path.
- The WebAuthn credential and Torn Note master key must be enrolled to the same immutable subject in a trusted credential registry.
- The current V0 inventory manifest does not itself sign tenant, subject, audience, action scope or validity. Those associations must be checked against trusted enrollment/issuance state. A V1 scoped issuer manifest is a required follow-up before production.
- The current Merkle leaf/tree encoding is retained by this kernel milestone. It must be separately versioned and hardened before production.
- In-memory stores and demo keys are not production state or key management.
- A serverless deployment still requires durable state for credential revocation, challenge replay protection and note consumption.

## 6. Non-goals

This profile does not replace WebAuthn passwordless login, modify authenticator firmware, implement FROST, claim trusted transaction display or make the verifier completely stateless. It adds a cryptographic authorization proof whose scope is tied to the exact immutable transaction and selected Torn Note.

## 7. Implementation status

- [x] Fixed-schema transaction encoding and `H_tx`.
- [x] Note authorization envelope and `D_note`.
- [x] Domain-separated Torn Note V1 bound signatures.
- [x] Tests for transaction changes, note swapping and legacy/V1 signature separation.
- [ ] Yubico WebAuthn registration and assertion adapter.
- [ ] Persistent credential and challenge repositories.
- [ ] Atomic challenge + note spend + outbox transaction.
- [ ] Browser passkey flow and cross-platform tests.
- [ ] Scoped issuer manifest and hardened V1 Merkle tree.
- [ ] Independent cryptographic and application security review.
