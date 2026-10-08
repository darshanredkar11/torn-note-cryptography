# Torn Note Cryptography

Offline-first, EUDI-oriented authorization research prototype inspired by the physical torn-note model.

> **v0.1 research draft — not production cryptography.**

A long-lived wallet key is not sufficient to authorize a transaction. Each transaction consumes a pre-issued note whose two independent halves must also authorize the exact transaction.

## Current draft

```
master alone     -> reject
half A alone     -> reject
half B alone     -> reject
master + A       -> reject
master + B       -> reject
A + B            -> reject
master + A + B   -> accept
```

The note inventory is committed by a Merkle root. The transaction digest binds the root, note ID, both public halves and transaction payload. The draft uses three independent signatures.

Backends:
- Ed25519 / EdDSA
- P-256 / ECDSA-SHA256

The production direction is FROST threshold Schnorr so the three signatures can become one compact signature without reconstructing the long-lived secret or note-half secrets.

## EUDI direction

The crypto layer is transport-neutral. A future adapter can bind the transaction digest to an EUDI presentation such as SD-JWT VC or mdoc/COSE.

## Run

```bash
cd node && npm test && npm run benchmark
cd ../java && gradle test
```

This is a research prototype, not a certified EUDI Wallet, FIPS module, production wallet, or formal cryptographic proof.