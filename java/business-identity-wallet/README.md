# Torn Note Business Identity Wallet

Runnable business scenario: a finance controller uses a company-issued wallet to authorize a supplier bank-account change.

The verifier requires the employee identity key, both fragments of a pre-issued note, membership in the committed inventory, signatures over the exact canonical transaction, and an unspent note. The browser demo includes a stolen-master-only attempt, transaction tampering, a legitimate authorization and replay attempt.

## Run

Requirements: JDK 21 and Gradle 8+. From this directory run:

    gradle run

Open http://localhost:8080.

## Compiled library integration

The application declares implementation project(':'). Gradle builds the parent Java module as its JAR and places that compiled artifact on this application's classpath. Torn Note cryptographic operations are called through io.tornnote.TornNote; the use case does not copy the cryptographic implementation.

## Limitations

This is an in-memory research demonstrator, not a production wallet. Keys are held in one process; note inventory and spent state are not durable or distributed; there is no real identity proofing, employee lifecycle, IAM, payment rail, HSM, or KMS integration. The current protocol uses three independent signatures, not FROST or a reconstructed threshold key. Do not use it for real payments or credentials.
