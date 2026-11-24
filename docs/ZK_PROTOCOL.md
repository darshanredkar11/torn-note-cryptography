# ZK Torn Note Protocol v0.2

## Goal

A Torn Note spend should reveal only:

- ROOT
- nullifier eta
- transaction digest Dtx
- zero-knowledge proof pi

The verifier should not learn the consumed leaf, its index, note identifier, public keys, or blinding salt.

## Note

For a note:

x, zA, zB, noteId, r are private field elements.

Public points are:

X = xG
ZA = zA G
ZB = zB G

The leaf is:

L = H_leaf("TORN-LEAF/v2", noteId, X, ZA, ZB, r)

## Nullifier

Use a domain-separated **note-level** nullifier construction:

K_N = H_null-key("TORN-NULLIFIER-KEY/v2", x, zA, zB)

eta = H_null("TORN-NULLIFIER/v2", K_N, noteId, batch_id)

The nullifier is derived from the note, not from the transaction. In particular, do **not** include Dtx or the transaction payload in eta: doing so would produce a different nullifier for each transaction and would permit the same note to be presented against multiple transactions without colliding in the spend store.

Here batch_id is the immutable issuance scope for the note. The issuer must guarantee that a note is assigned to only one accepted batch. If a note may appear in multiple batches, use a globally stable note scope in the nullifier derivation instead; otherwise the same note could yield different nullifiers across batches.

This construction is not described as a PRF without a corresponding security argument.

## Transaction binding

Dtx = H_tx("TORN-TX/v2", ROOT, batch_id, eta, Canonical(m))

The verifier independently computes the expected Dtx from its authoritative transaction state. Dtx is a **separate public input to the proof**, not an input to the nullifier derivation.

The SNARK public statement is:

(ROOT, batch_id, eta, Dtx)

## Relation

The circuit proves knowledge of:

(x, zA, zB, noteId, r, path)

such that:

1. X = xG, ZA = zAG, ZB = zBG;
2. L = H_leaf(noteId, X, ZA, ZB, r);
3. MerkleVerify(L, path, ROOT) = 1;
4. eta = H_null(H_null-key(x, zA, zB), noteId, batch_id);
5. Dtx = H_tx(ROOT, batch_id, eta, Canonical(m)), with Dtx equal to the verifier-computed digest for the payout.

## Spend transition

Verification alone does not prevent a race.

The durable verifier must atomically consume eta in the appropriate issuer/batch scope and record the logical payout execution intent. A recommended systems pattern is one database transaction that:

1. inserts the unique spend key (issuer scope, batch_id, eta);
2. records the authorized payout state transition;
3. inserts an outbox event with a stable payout idempotency key.

After commit, a worker dispatches the outbox event. Retries must reuse the same idempotency key. This gives durable at-least-once dispatch; exactly-once external effects depend on the connector honoring idempotency. A crash after the database commit but before dispatch should cause outbox retry, not release of eta for a different transaction.

The exact transaction boundary and recovery protocol must be validated for the chosen connector and payout state machine.

## Privacy claim

The public statement is designed to contain no leaf index or note public keys.

The verifier still observes the batch identifier/root, nullifier, transaction digest, and timing. Actual unlinkability additionally depends on:

- the number of genuinely eligible notes in the batch (the effective anonymity set);
- transaction metadata and payout amount/recipient patterns;
- root and batch reuse;
- issuance and note-allocation policy;
- network metadata;
- application-level identifiers.

Therefore the protocol does not claim that a root's tree capacity equals its anonymity set or that hiding the leaf alone establishes unlinkability.

## Non-claims

This document does not claim that:

- the current reference model is zero knowledge;
- the current implementation is Groth16 or PLONK;
- SHA-256 is the final circuit hash;
- P-256 is the final in-circuit group;
- browser proving has a fixed runtime;
- the construction is production-ready.

## Target proving stack

A future implementation can use a SNARK-friendly stack such as BN254 plus BabyJubjub plus Poseidon, or BLS12-381 plus Jubjub plus Poseidon.

The concrete stack should be benchmarked and security-reviewed before protocol parameters are frozen.

## Executable reference-model encoding (not yet the circuit suite)

The Node.js reference model now uses an explicit, length-prefixed SHA-256 encoding. Every hash part is encoded as:

`uint32_be(byte_length) || bytes`

The domains are distinct for leaves, Merkle internal nodes, nullifier-key derivation, nullifier derivation, and transaction digests:

- `TORN-LEAF/v2`
- `TORN-MERKLE-NODE/v2`
- `TORN-NULLIFIER-KEY/v2`
- `TORN-NULLIFIER/v2`
- `TORN-TX/v2`

The reference transaction encoder recursively sorts object keys and rejects unsupported values such as undefined fields, accessors, cycles, sparse arrays, non-finite numbers, and unsafe integers. The reference relation checks that each private P-256 scalar derives the corresponding committed compressed public point, verifies membership, recomputes the nullifier, and recomputes the digest of the exact canonical transaction.

**Important interoperability boundary:** this Node.js model uses SHA-256 and P-256, while the experimental Circom circuit currently uses Poseidon and BabyJubjub. They are separate implementations of the research intent, not currently byte-for-byte or algebraically interchangeable protocol implementations. Do not treat a passing reference-model test as evidence that the Circom circuit proves the same suite. A single normative suite and shared cross-implementation vectors are still required.
