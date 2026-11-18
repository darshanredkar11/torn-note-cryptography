# MongoDB production adapters

Status: production-oriented persistence adapters. Deployment configuration and operational validation remain necessary.

## Components

| Adapter | Collections | Main responsibility |
|---|---|---|
| `MongoCredentialRepository` | `webauthn_credentials`, `webauthn_user_handles` | Yubico credential lookups, revocation and monotonic counter updates |
| `MongoSubjectKeyRegistry` | `subject_identity_keys` | Tenant/subject binding for the Torn Note master public key |
| `MongoBoundAuthorizationStore` | `webauthn_challenges`, `spent_notes`, `authorization_decisions`, `authorization_outbox` | One-time challenge state and atomic note-spend/decision/outbox commit |
| `MongoSpendStore` | `spent_notes` | Atomic insert-if-absent for the legacy verifier interface |
| `MongoOutboxRepository` | `authorization_outbox` | Worker leases, retry scheduling and delivery acknowledgement |

## Topology requirement

The protected authorization commit spans multiple collections and uses a MongoDB multi-document transaction. The deployment must be a replica set or sharded cluster; standalone `mongod` is unsupported. Transactions use snapshot read concern, primary read preference and majority write concern.

## Credential identity and lifecycle

Yubico usernames are derived as opaque, domain-separated identifiers from both tenant and subject using `WebAuthnIdentity.usernameFor(tenantId, subjectId)`. Use this exact function for registration and authentication. Raw subject IDs are not used as Yubico usernames, preventing same-named subjects in different tenants from sharing an account lookup.

User handles must be random opaque bytes (recommended 32 bytes), not email addresses or other PII. The user-handle owner record prevents one handle from being rebound to a different tenant/subject. The credential collection stores credential ID, user handle, COSE public key, counter, transport hints, backup flags and active/revoked status. It never stores a passkey private key.

Call `MongoCredentialRepository.storeVerifiedRegistration` only after `RelyingParty.finishRegistration` succeeds. It requires registration UV. Revocation is a soft state transition: inactive credentials are excluded from login but their IDs remain visible to Yubico's `lookupAll` duplicate-registration check.

Signature counters are updated with MongoDB `$max`, so concurrent successful assertions cannot move the stored counter backwards. Synced passkeys may use zero counters; zero does not lower an existing value.

## Challenge, note and outbox lifecycle

1. Insert a random challenge ID, the serialized Yubico `AssertionRequest`, tenant, subject, authenticated session ID, `H_tx`, `D_note` and expiry.
2. Claim with one atomic `findOneAndUpdate` from `PENDING` to `VERIFYING`, scoped to tenant, subject, session and expiry.
3. After WebAuthn and Torn Note verification both succeed, commit one Mongo transaction:
   - conditionally move the challenge to `CONSUMED`;
   - insert the uniquely keyed spent-note record;
   - insert a uniquely keyed authorization decision;
   - insert the outbox command.
4. Any duplicate-key conflict aborts the full transaction. The challenge is then invalidated outside the aborted transaction.

The challenge collection has a TTL index on `expiresAt`. TTL deletion is asynchronous and never substitutes for explicit expiry checks.

## Outbox delivery semantics

The outbox is at-least-once. A worker atomically leases a due command. Expired leases can be reclaimed after a worker crash. Workers acknowledge using their lease owner ID or schedule retries.

The downstream action must use the stable `transactionId` as its idempotency key where supported. A lease cannot provide exactly-once effects in an external service. For a timeout with unknown outcome, reconcile the remote result before retrying a non-idempotent operation.

## Configuration

Set `MONGODB_URI` and optionally `MONGODB_DATABASE`. `MongoPersistence.fromEnvironment()` checks the MongoDB `hello` response and fails fast on standalone servers. Keep connection strings in a secret manager; never commit or log them.

The GitHub Actions wallet workflow starts an ephemeral single-node replica set and runs integration tests using `MONGODB_TEST_URI`.

## Before production

- Configure TLS, database authentication and least-privilege roles.
- Enable encrypted storage and backups; test point-in-time recovery.
- Restrict network access to private application networks.
- Monitor transaction aborts, duplicate-key rejects, challenge expiry, outbox backlog, retries and dead-letter conditions.
- Set audit-record retention and archival policies.
- Test failover, restore, clock skew, peak write load and downstream idempotency against the actual managed MongoDB deployment.
