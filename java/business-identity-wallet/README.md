# Torn Note Business Identity Wallet

Runnable business scenario: a finance controller uses a company-issued wallet to authorize a supplier bank-account change.

The verifier requires the employee identity key, both fragments of a pre-issued note, membership in the committed inventory, signatures over the exact canonical transaction, and an unspent note.

**Start here:** [Why Torn Note? Business security model, factor storage, Ed25519 comparison and production gaps](docs/WHY_TORN_NOTE.md).  
**Deployment guide:** [Step-by-step issuance, component storage, server separation, and verification flow](docs/ISSUANCE_STORAGE_AND_DEPLOYMENT.md).

## Run
Requirements: JDK 21 and Gradle 8+. From this directory run:

    gradle run

Open http://localhost:8080.

## Compiled library integration

The application declares `implementation project(':')`. Gradle builds the parent Java module as its JAR and places it on this application's classpath. Torn Note cryptographic operations are called through `io.tornnote.TornNote`; the use case does not copy the cryptographic implementation.

## Issuer / wallet / verifier separation

The role-separated Java reference components are:

- `NoteInventoryIssuer`: creates a finite note inventory, builds the Merkle root, and signs an `InventoryManifest`.
- `WalletNoteCredential`: models the private fragment material delivered to a wallet. It exposes only a public-note projection to the verifier.
- `AuthorizationVerifier`: receives a separately pinned issuer public key, the signed manifest, public note data, identity public key, exact transaction and signatures. It does not receive issuer or wallet fragment private keys.
- `SpendStore`: requires an atomic insert-if-absent operation. The included concurrent-map implementation is a test adapter; a production implementation should use a durable database unique constraint on inventory ID + note ID.

The tests exercise manifest tampering, an untrusted issuer key, fabricated note data, replay, and concurrent attempts to spend the same note.

The current web demo has not yet been refactored to deploy these roles as separate network services or operating-system processes. The role split is a Java reference implementation and test boundary, not a production deployment boundary. The issuer public key must be provisioned to verifiers out of band; accepting a key supplied by the manifest itself would defeat issuer authentication.

## Limitations

This is an in-memory research demonstrator, not a production wallet. Keys are demo keys; wallet fragments are not delivered through a real protected channel; the web demo still runs in one process; and the included spend store is not durable or distributed. There is no real identity proofing, employee lifecycle, IAM, payment rail, HSM, or KMS integration. The current protocol uses three independent signatures, not FROST or a reconstructed threshold key. Do not use it for real payments or credentials.
