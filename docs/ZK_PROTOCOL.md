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

Use a domain-separated keyed-hash construction:

K_N = H_null-key("TORN-NULLIFIER-KEY/v2", x, zA, zB)

eta = H_null("TORN-NULLIFIER/v2", K_N, noteId)

This is intentionally not described as a PRF without a corresponding security argument.

## Transaction binding

Dtx = H_tx("TORN-TX/v2", ROOT, eta, Canonical(m))

The SNARK public statement is:

(ROOT, eta, Dtx)

## Relation

The circuit proves knowledge of:

(x, zA, zB, noteId, r, path)

such that:

1. X = xG, ZA = zAG, ZB = zBG;
2. L = H_leaf(noteId, X, ZA, ZB, r);
3. MerkleVerify(L, path, ROOT) = 1;
4. eta = H_null(H_null-key(x, zA, zB), noteId);
5. Dtx = H_tx(ROOT, eta, Canonical(m)).

## Spend transition

Verification alone does not prevent a race.

The ledger must atomically perform:

if eta is unused:
    reserve eta
    settle m
else:
    reject

If settlement fails, the reservation must roll back or the whole transition must be transactional.

## Privacy claim

The public statement is designed to contain no leaf index or note public keys.

Actual unlinkability additionally depends on:

- the number of eligible notes in the root;
- transaction metadata;
- root reuse;
- issuance policy;
- network metadata;
- application-level identifiers.

Therefore the protocol does not claim that a root's tree capacity equals its anonymity set.

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
