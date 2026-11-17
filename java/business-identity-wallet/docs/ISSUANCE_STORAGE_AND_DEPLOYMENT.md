# Torn Note: issuance, storage, and verification deployment guide

This guide explains the current business identity-wallet reference implementation and a safe deployment shape for a real system. It is deliberately explicit about what exists in code today versus what an operator must build.

## 1. First, the terminology

The current implementation does **not** pre-sign the future business transaction.

It pre-issues a finite set of authorization-note credentials:

- Each note has a random-looking identifier, two independent Ed25519 factor key pairs, and a Merkle inclusion proof.
- The issuer builds a Merkle tree over the public note data and signs an `InventoryManifest` containing the inventory ID, note count, and Merkle root.
- The employee/wallet later signs the exact transaction at approval time with the employee identity key and the two note-fragment keys.

So the pre-issued object is a *capability/credential*, not a pre-approved payment or a reusable signature over an unknown future transaction. A transaction signature is created only when the user approves the transaction.

In this Java reference, the two note factors are independent Ed25519 signing keys. This is not FROST, does not split one private key into shares, and does not reconstruct a threshold secret.

## 2. The actors and trust boundaries

Recommended logical services:

1. **Issuer service (high trust, restricted):** creates inventories, controls the issuer signing key, signs manifests, and provisions note credentials to wallets. It should not be exposed as a public signing API.
2. **Wallet / employee device:** holds the employee identity private key and the two private note-factor keys for each unspent note. It signs the transaction only after user approval.
3. **Verifier service (business approval API):** holds the issuer public trust anchor, verifies the signed manifest, note inclusion proof, employee identity signature, both note-factor signatures, and transaction binding. It atomically consumes the note.
4. **Spend database:** durable, shared by every verifier replica, and enforces one-time consumption with a unique constraint.
5. **Public distribution / object store (optional):** distributes public manifests and public note metadata/proofs. It must never contain private keys.

The issuer signing private key must never be copied to the verifier, wallet, CDN, or public object store. The verifier's issuer public key must be provisioned independently (configuration management, certificate/trust bundle, or an authenticated admin process). Do not trust a public key supplied by the same untrusted manifest being checked.

## 3. What is generated, and when?

For each inventory:

1. Issuer generates an Ed25519 issuer key pair (long-lived or rotated under a defined key lifecycle).
2. Issuer generates N note credentials. Each note has:
   - `inventoryId` and `noteId`;
   - factor A public/private key pair;
   - factor B public/private key pair;
   - a Merkle leaf derived from the note ID and the two public factor keys.
3. Issuer builds the Merkle tree and obtains its root.
4. Issuer signs the manifest: inventory ID + note count + root.
5. Issuer creates a Merkle proof for each note and packages the proof and public factor keys with the private factor keys as a wallet credential.
6. Issuer securely provisions each credential to its intended wallet, then records issuance status. The issuer should not retain wallet private factors in its ordinary application database after successful delivery; if recovery/escrow is a business requirement, it must be a separately governed, encrypted, audited design.

The manifest is signed once per inventory. The individual transaction signatures are not created until the wallet authorizes a transaction.

## 4. Where should each component be stored?

| Material | Contains | Recommended location | Who can read it? |
|---|---|---|---|
| Issuer private key | Signs inventory manifests | HSM/KMS-backed signing service; non-exportable key preferred | Issuer signing service only |
| Issuer public key / trust anchor | Verifies manifests | Verifier configuration/trust store, provisioned out of band | Verifiers; administrators |
| Signed manifest | Inventory ID, count, Merkle root, issuer signature | Replicated config/object store; cacheable and immutable by version | Wallets and verifiers |
| Public note record | Note ID, factor public keys, index, Merkle proof | Wallet credential and/or public object store | Wallet and verifier |
| Factor A private key | One note signing factor | Wallet secure hardware/TEE/OS keystore where supported; otherwise encrypted local vault | Authorized wallet only |
| Factor B private key | Second note signing factor | Separate protected factor store/device/domain where feasible | Authorized wallet/factor service only |
| Employee identity private key | Employee identity signature | Passkey/WebAuthn authenticator or enterprise-managed device key store | Authenticator; never verifier |
| Spent-note state | Inventory ID + note ID + consumed timestamp / transaction reference | Durable transactional database with a unique key | Verifier service only; audited admins |
| Audit event | Decision, transaction digest, note reference, timestamp, verifier result | Append-only audit/log system with access controls | Audit/security roles |

**Important:** storing factor A and factor B in two folders or two tables on the same server does not create meaningful separation. For a stronger separation, put them behind different security boundaries—for example, one in the device secure keystore and the other in a separately authenticated hardware-backed factor service or second device. Whether this is practical depends on the user experience and threat model.

Do not store private keys in Git, source code, application properties, container images, ordinary logs, analytics, browser localStorage, or an unencrypted database. Do not send private factors to the verifier.

## 5. Step-by-step interaction

### Phase A — Inventory issuance (before any payment request)

1. An authorized company administrator requests an inventory, for example `finance-controller-2026-Q4`, with a defined number of notes.
2. Issuer creates the note credentials and Merkle root.
3. Issuer signs the manifest with its protected issuer private key.
4. Issuer stores the signed manifest and publishes the public inventory data/proofs through an authenticated distribution channel.
5. Issuer delivers each wallet credential to the intended employee using an authenticated, encrypted enrollment channel. Bind the credential to the employee/device/account in the surrounding business system.
6. Wallet stores the private factors in protected key storage. The verifier receives only public material and the signed manifest.
7. Issuer records which notes were issued, to whom, and their lifecycle status. This issuance ledger is operational state; the verifier still independently validates the cryptographic inclusion proof.

### Phase B — Employee approves a supplier bank-account change

1. Business application constructs a canonical transaction payload. It must include every security-relevant field: tenant/company, supplier ID, old/new beneficiary details or their canonical digest, amount/currency if relevant, request ID/nonce, expiry, and action type.
2. Wallet displays the meaningful transaction details to the employee. The user explicitly approves.
3. Wallet selects one unspent note credential.
4. Wallet signs the exact canonical transaction with:
   - employee identity private key;
   - note factor A private key;
   - note factor B private key.
5. Wallet sends the verifier the signed manifest (or its identifier plus a trusted fetch), public note data and Merkle proof, employee identity public key / identity reference, canonical transaction, and the three signatures. It sends **no private key**.
6. Verifier checks the manifest against its independently pinned issuer public key.
7. Verifier checks inventory ID, note index bounds, Merkle proof, and that the public note is included in the issuer-committed root.
8. Verifier checks all signatures over the same canonical transaction and enforces the employee's business authorization policy (role, tenant, supplier, limits, approval workflow). Cryptographic validity alone is not proof that the employee is allowed to perform the business action.
9. Verifier atomically inserts the note's spend key into the shared spent-note database. Only the first concurrent request may succeed.
10. If verification and atomic consumption succeed, verifier returns an approval result bound to the transaction/request ID. The business system then performs its own controlled state change and audit logging.

### Phase C — Reuse, exhaustion, revocation, and recovery

- A successfully consumed note must never be accepted again, even by another verifier replica.
- If a note is lost or a device is compromised, revoke/disable the relevant employee credential or inventory according to policy. The current sample has no complete revocation protocol; this must be designed and tested before production.
- When the inventory is exhausted, issue a new inventory and signed manifest. Do not silently recycle note IDs or spent notes.
- Define key rotation, issuer-key compromise response, employee offboarding, device replacement, backup/recovery, and audit retention before deployment.

## 6. Can the components live on different servers?

Yes. That is the intended production trust-boundary direction, but the current repository does not yet deploy them as separate services.

A practical topology:

```text
                 ADMIN / ENROLLMENT PLANE
                          |
                          v
              +-------------------------+
              | Issuer service          |
              | issuer private key      |
              | in HSM/KMS              |
              +------------+------------+
                           |
             signed manifest + credentials
               /           |            \
              v            v             v
       Public manifest   Wallet A     Wallet B
       / proof store     secure       secure
                         storage      storage
                           |             |
                           +------.------+
                                  |
                           transaction +
                           three signatures
                                  |
                                  v
                       +----------------------+
                       | Verifier API         |
                       | issuer public key    |
                       | business policy      |
                       +----------+-----------+
                                  |
                                  v
                       +----------------------+
                       | Shared spend DB      |
                       | UNIQUE(inventory_id, |
                       |        note_id)      |
                       +----------------------+
```

The issuer, verifier, wallet, and database can be independently deployed. The verifier should be horizontally scalable, but every replica must use the same strongly consistent spend store. A per-instance in-memory set is not sufficient: two replicas could otherwise accept the same note.

The issuer can be offline after issuance for normal verification, provided verifiers have the signed manifest and trusted issuer public key. Online issuer checks may still be needed for revocation, inventory suspension, or lifecycle policy.

## 7. Durable one-time spend storage

A relational database implementation should use a primary/unique key on the pair `(inventory_id, note_id)`. The verifier should perform a single atomic insert and treat a uniqueness conflict as already spent.

Illustrative PostgreSQL schema:

```sql
CREATE TABLE spent_note (
    inventory_id   text        NOT NULL,
    note_id        bytea       NOT NULL,
    transaction_id text        NOT NULL,
    consumed_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (inventory_id, note_id)
);
```

Illustrative operation:

```sql
INSERT INTO spent_note (inventory_id, note_id, transaction_id)
VALUES ($1, $2, $3)
ON CONFLICT (inventory_id, note_id) DO NOTHING
RETURNING inventory_id, note_id;
```

One returned row means this request won the atomic consume operation. Zero rows means the note was already consumed. In a real implementation, bind the spend insert and durable authorization decision/audit record in a transaction, and make the business side effect idempotent. Do not use a read-then-write sequence; it races under concurrency.

## 8. What the current repository actually implements

Implemented and tested in the Java reference module:

- `NoteInventoryIssuer` creates note factors, public notes, Merkle proofs, and the issuer-signed manifest.
- `WalletNoteCredential` holds the two note signing factors and can produce the authorization signatures with the employee identity key.
- `InventoryManifest` signs/verifies the inventory commitment.
- `AuthorizationVerifier` verifies the issuer manifest, note/inventory linkage, inclusion proof and signatures, then calls `SpendStore.consumeIfAbsent`.
- `InMemorySpendStore` is a concurrent in-memory test/demo adapter.
- Tests cover manifest tampering, untrusted issuer key, fabricated note data, replay, and concurrent attempts to consume one note.

Not implemented yet:

- Separate network services/processes and authenticated service-to-service APIs.
- Production serialization and versioned wire format for manifests, credentials, public notes and signatures.
- HSM/KMS integration and issuer key rotation/revocation.
- Secure credential delivery, device keystore integration, or genuine separation of factor A and factor B.
- Durable SQL spend-store adapter and multi-replica integration tests.
- Employee identity proofing, authorization policy engine, offboarding/recovery, and payment-rail integration.

The current `WalletNoteCredential` is an in-process Java object; it is not yet a portable encrypted credential file or a production wallet backup format. Do not persist it by Java object serialization. Define a versioned, authenticated envelope and secure key import/export flow before storing it outside the process.

## 9. Security comparison: what does Torn Note add?

Against one ordinary Ed25519 employee key, the demo shows that stealing only that identity key is not enough: the attacker also needs both note-factor signing keys and a valid issuer-inventory note.

Against a well-designed conventional 3-of-3 Ed25519 system, the three signatures provide the same basic multi-factor compromise resistance. Torn Note's additional demonstrated protocol property is that the authorization note must belong to a finite inventory committed by an issuer-signed Merkle root. That can be useful when a company wants pre-issued, finite, one-time authorization capabilities.

This is not an automatic universal security win. A conventional system can add an issuance registry, capability policy, and atomic one-time tokens too. Torn Note's value must be judged by whether its inventory-bound capability model makes the business control easier to enforce, audit, and reason about enough to justify issuance, storage, lifecycle, and recovery complexity.

## 10. Production-readiness checklist

- [ ] Threat model defines the attacker, assets, trust boundaries, and recovery assumptions.
- [ ] Issuer private key is HSM/KMS protected; verifier trust anchor is independently provisioned.
- [ ] Factor A, factor B, and employee identity keys have documented independent protection.
- [ ] Credential delivery is authenticated, encrypted, bound to employee/device, and auditable.
- [ ] Canonical transaction encoding is versioned and rejects ambiguous representations.
- [ ] Verifier enforces business authorization policy, not only cryptographic validity.
- [ ] Durable shared spend store has a unique constraint and concurrency tests across replicas.
- [ ] Revocation, inventory suspension, issuer-key rotation, offboarding, and recovery are implemented.
- [ ] Logs never contain private keys or reusable secrets.
- [ ] Independent cryptographic/security review and penetration testing completed.

Until these items are implemented and reviewed, this remains a research/demo implementation. Do not use it to authorize real supplier payments or bank-account changes.
