# Why Torn Note? Business Identity Wallet

## Executive answer

Torn Note does not make Ed25519, EdDSA, or SHA-256 mathematically stronger. It changes the authorization architecture around standard cryptographic primitives.

A conventional Ed25519 deployment usually asks whether one trusted private key signed a transaction. Torn Note asks whether (1) the employee identity key signed, (2) two note-specific factors signed, (3) the note was issued in advance and belongs to an issuer-authenticated inventory, (4) every signature binds the exact canonical transaction, and (5) the note has not already been consumed.

The defensible claim is therefore narrower than "Torn Note is safer than Ed25519": **against a single-key compromise, the current 3-of-3 prototype prevents that key alone from authorizing a transaction; its pre-issued inventory adds cryptographic provenance and finite authorization-object semantics.** A properly designed conventional 3-of-3 system can match the factor-compromise property, and a conventional system can also add signed allowlists, one-time tokens, and replay protection. Torn Note must demonstrate that its integrated model is useful, manageable, and harder to misconfigure in a specific business workflow.

## One business case

A finance controller requests a supplier bank-account change. The change is high impact because a fraudulent account substitution can redirect future payments.

The company issues the controller a wallet identity and a finite batch of authorization notes. A note can authorize one transaction only. The transaction includes the supplier ID, old and new account fingerprints, currency, amount or limit, request ID, expiry, and policy/version identifiers. The canonical encoding must be deterministic; every signer and verifier must hash exactly the same bytes.

### Authorization flow

1. The company identity issuer verifies and enrolls the employee using its normal HR/IAM process.
2. The Torn Note issuer creates a finite inventory of note IDs and two independent note-factor keypairs per note.
3. The issuer computes a Merkle root over the note IDs and public factor keys, then signs an inventory manifest.
4. The employee receives the wallet credential material through a protected enrollment/delivery process.
5. The employee reviews the exact supplier-change request. The wallet signs the canonical transaction digest with the identity key and the two factors belonging to one issued note.
6. The verifier validates the manifest against an issuer public key provisioned independently, verifies Merkle membership, checks all signatures and transaction binding, then atomically consumes the note ID.
7. Only after successful verification and successful atomic consumption does the business workflow proceed. The payment/bank-detail change itself still needs normal business approvals and downstream controls.

## What is a "pre-signed component"?

The precise term in this implementation is **pre-issued authorization material**, not pre-signed transaction signatures.

Before a transaction exists, the issuer creates:
- a unique note ID;
- factor A public/private keypair;
- factor B public/private keypair;
- a Merkle inclusion proof for the note;
- a signed inventory manifest committing to the complete inventory.

The signatures over a particular transaction are generated at authorization time. They are not reusable pre-signed approvals. This distinction matters: pre-signing arbitrary transaction bytes in advance would create a different protocol and a serious risk if those signatures could be replayed or repurposed.

## Where the material lives

The repository's current code is a research/demo implementation. It generates the issuer key and note factors in application memory; it does not yet provide production-grade persistent or hardware-backed custody. The following is the target deployment layout, not a claim about what is already deployed.

| Material | Target storage / owner | Sent to verifier? |
|---|---|---|
| Issuer manifest-signing private key | Issuer service, preferably non-exportable KMS/HSM key; tightly controlled issuance role | Never |
| Issuer public trust anchor | Verifier configuration/trust store, provisioned out of band and rotated under policy | Yes / already pinned |
| Signed manifest and Merkle root | Issuer registry and verifier cache/database; versioned and immutable | Yes |
| Note ID, public factor keys, Merkle proof | Wallet credential and verifier-side public inventory/registry | Yes |
| Factor A private key | Wallet secure storage or separate enrolled authenticator; ideally hardware-backed | Never |
| Factor B private key | Separate authenticator/device/security domain where practical | Never |
| Employee identity private key | Wallet secure storage or hardware-backed identity authenticator | Never |
| Transaction digest and signatures | Business authorization request and audit record | Yes |
| Spent-note record | Durable verifier database with a unique constraint on (inventory_id, note_id) | Verifier-side state |

Do not store all three private keys together in one ordinary database and call them independent factors. If the same application process, host, administrator, or backup can extract all factors, the intended separation is weakened. Separate security domains, device binding, access policy, key backup/recovery, revocation, and employee offboarding must be designed and tested.

The manifest is not trusted merely because it carries a public key. The verifier must already trust the issuer public key through secure provisioning, certificate validation, or an equivalent trust-anchor process.

## What the repository currently implements

On branch `use-case/business-identity-wallet`:

- `NoteInventoryIssuer` creates a finite note inventory, builds the Merkle root and signs an `InventoryManifest`.
- `WalletNoteCredential` models the wallet-held factor material and exposes a public-note projection.
- `AuthorizationVerifier` accepts a separately trusted issuer public key and public note data, validates the manifest, membership, signatures and transaction, then calls a spend store.
- The included spend store is an in-memory concurrent set. It is a test adapter, not durable production replay protection.
- The Java module uses `implementation project(':')`, so it depends on the compiled root Torn Note Gradle project rather than copying the crypto implementation.

The README explicitly says the web demo is not yet separate network services or OS processes. The role separation is currently a Java reference/test boundary. The prototype does not yet implement real identity proofing, secure factor delivery, persistent database transactions, KMS/HSM custody, or a production wallet.

## Comparison: what is and is not safer?

| Threat / property | One Ed25519 key | Conventional 3-of-3 signatures | Torn Note 3-of-3 prototype |
|---|---|---|---|
| One signing key compromised | Attacker can sign as that key | One key alone is insufficient | Master key alone is insufficient |
| One factor compromised | Not applicable to single-key model | Insufficient if all three are required | Insufficient if all three are required |
| Transaction altered after signing | Rejected if exact bytes are signed and checked | Rejected if all signatures bind same bytes | Rejected if all signatures bind same canonical transaction |
| Replay | Requires nonce/ledger/idempotency controls | Requires nonce/ledger/idempotency controls | Requires spent-note state; current demo store is in-memory |
| Invented authorization factor set | Key can sign arbitrary permitted messages | Depends on signer enrollment/policy | Rejected if note is absent from the trusted issuer's committed inventory |
| Finite pre-issued authorization inventory | Not inherent | Not inherent, but can be added | Core design feature |
| Privacy of which note was used | Not provided | Not provided | Public note identity is visible in current prototype; ZK unlinkability is not delivered by this Java demo |
| Durable atomic double-spend prevention | Depends on application state | Depends on application state | Interface exists; production durable implementation is still required |

### The fair conclusion

- Versus a single-key Ed25519 design, Torn Note adds independent required factors and issuer-committed pre-issued note membership. A stolen master key alone cannot authorize a transaction in the tested model.
- Versus conventional 3-of-3 Ed25519, Torn Note does **not** automatically provide stronger resistance to stealing one factor. Both can require all three signatures.
- The distinctive research proposition is the finite, issuer-authenticated inventory of consumable authorization objects, bound to exact transactions. It gives the business a way to pre-authorize a bounded set of authorization capabilities and reject fabricated or unissued note tuples.
- A conventional architecture can reproduce much of this with signed capability tokens, an allowlist/Merkle commitment and an atomic one-time-use database. We must compare against that stronger baseline before claiming a unique security advantage.
- Torn Note currently uses three independent signatures. It is not FROST, not a threshold signature, and does not combine the private keys into one signature. The README's composite-key equation is a conceptual model, not the current implementation.
- ZK privacy is a separate research direction. Do not claim that the current identity wallet hides which note was used.

## Why a business might adopt it

The value is not "stronger Ed25519". It is a policy and governance model for high-impact, bounded operations:

1. **Bounded authorization inventory:** the issuer creates only a defined number of notes or capabilities for a wallet, workflow, device, or time period.
2. **Independent compromise domains:** a stolen identity key or one note factor is insufficient by itself.
3. **Issuer provenance:** the verifier rejects a fabricated note even if an attacker can generate their own valid public/private keypairs.
4. **Transaction specificity:** signatures bind the exact supplier and bank-change request, preventing approval from being transplanted to different details.
5. **Single-use semantics:** an authorization note can be consumed once, provided the verifier uses durable atomic storage.
6. **Auditable issuance and consumption:** the business can reconcile issued inventory, consumed notes, revocations and exceptions.

These benefits have operational costs: issuance, secure factor delivery, inventory replenishment, lost-device recovery, revocation, employee lifecycle, and verifier availability. The business case must show that the risk reduction is worth that complexity.

## Required production work before a customer pilot

- Deploy issuer, wallet and verifier as separate services/security domains.
- Keep issuer signing keys in KMS/HSM; pin issuer trust anchors independently at verifiers.
- Store wallet factors in hardware-backed or otherwise protected storage, with genuinely independent factor custody.
- Replace the in-memory spend store with a transactional database and unique constraint on (inventory_id, note_id); test races, crashes, retries, backups and rollback.
- Define canonical transaction encoding, domain separation, expiry, policy version, revocation and idempotency.
- Add key rotation, wallet recovery, employee offboarding, lost-device and compromised-factor procedures.
- Compare against single-key Ed25519, conventional 3-of-3 Ed25519, and a conventional signed-capability/allowlist design with equivalent replay and storage controls.
- Run independent protocol review, implementation review, fuzzing and operational threat modelling.

## The customer-facing 30-second explanation

"Ordinary Ed25519 proves that a particular private key signed a transaction. Torn Note uses Ed25519 too, but changes the authorization model: the company issues a finite inventory of cryptographic authorization notes in advance. To approve a supplier bank-account change, the employee must prove control of their identity key and both factors belonging to one genuine, unused note. The verifier checks that the note was issued by the trusted company, that every signature covers the exact bank-change request, and that the note has not already been used. This protects against a stolen identity key acting alone and gives the business bounded, auditable authorization. It is not stronger than a well-built 3-of-3 system by definition; our job is to show whether the pre-issued inventory and lifecycle controls deliver a measurable operational advantage."

## Claim policy

Safe to claim after the corresponding tests pass: "A stolen master key alone cannot authorize a Torn Note transaction in this 3-of-3 prototype."

Do not claim yet: "Torn Note is unbreakable", "Torn Note is safer than all Ed25519 systems", "the current wallet is production-ready", "the current Java demo provides ZK privacy", "the current implementation is threshold signing", or "the system is immune to compromise of the wallet/device/verifier/database."

The product should win on a clearly scoped threat model and measured business outcome, not on an unsupported claim that a standard signature algorithm has been improved.
