# Torn Note Cryptography

> **Research prototype — not production cryptography.**

Torn Note investigates a narrow authorization question:

**Can an issuer-committed, finite inventory of transaction-bound authorization objects provide a useful security property beyond well-engineered conventional authorization systems—and is that property worth its operational complexity?**

The repository explores an authorization model in which a long-lived identity key is necessary but insufficient. A transaction also requires note-specific authorization material tied to a pre-issued note, membership in a committed inventory, and verifier-side one-time consumption.

This is a research hypothesis—not a claim of novelty, superiority, or production readiness.

## Research focus

The current prototype uses **three independent signatures** (master identity + Half A + Half B), a Merkle-committed note inventory, transaction binding, and verifier-side spend tracking. It does **not** reconstruct a composite private key and is **not FROST**.

The research asks whether pre-issued finite inventory adds a meaningful property under a defined compromise model, especially when compared with strong alternatives that can also use quotas, signed capabilities, commitments, and atomic spend state.

## Authorization components

| Component | Role |
|---|---|
| Master identity factor | Long-lived identity key; necessary but intended to be insufficient alone |
| Half A | Note-specific authorization factor |
| Half B | Independent note-specific authorization factor |
| Issuer-signed manifest | Commits verifier to a pre-issued inventory |
| Transaction digest | Binds authorization to the exact canonical action |
| Durable spend store | Prevents replay and concurrent double consumption |

The current implementation is a 3-of-3 policy implemented as independent signatures. The physical torn-note analogy is intuition only; it is not a substitute for a protocol specification or security proof.

### Cryptographic precision and security boundary

The complete prototype policy requires **three separate Ed25519 signatures**: one from the master identity key and one from each of the two note-specific keys. The two note-specific keys form a 2-of-2 pair, but the complete policy is 3-of-3. Ed25519 itself is not an aggregate or native threshold multisignature scheme. “Independent” is a deployment property as well as a key-count property: keys should be generated separately and protected with appropriately separated custody. Merely creating three keys in one process does not provide meaningful operational independence.

A signed manifest provides an **offline-verifiable inventory membership and per-batch issuance bound**. If a manifest commits to N leaves, a verifier can check membership against that manifest without contacting the issuer. This does not automatically establish a global merchant-wide quota across multiple manifests or prevent the issuer from signing another batch. Global budgets require an explicit issuer policy and, where necessary, shared accounting. It also does not prevent a compromised holder from spending notes already in its possession.

Single-use enforcement is different: replay and concurrent-spend prevention require an **online, durable, strongly consistent verifier-side spend store**. The core-mode uniqueness scope should include the issuer/batch and note identifier; the ZK-mode scope should include the issuer/batch and note-level nullifier. The same note must not be reissued into multiple batches unless cross-batch replay is explicitly addressed.

For an external payout connector, a database insert alone cannot make the remote side effect exactly-once. A robust integration should atomically record authorization consumption and an execution/outbox record, then dispatch with a stable payout idempotency key. Delivery may be retried; exactly-once external effects depend on the connector's idempotency semantics.

### Encoding and Merkle specification still to freeze

Before interoperability or publication claims, the protocol must normatively specify the manifest serialization and fields, leaf and internal-node domain separation, tree shape and odd-leaf handling, and the exact authorization message. A recommended Merkle structure uses distinct leaf and internal-node prefixes (for example, `0x00` and `0x01`) and includes the leaf count in the signed manifest. The transaction profile must choose one deterministic encoding—such as RFC 8785 JCS or RFC 8949 core deterministic CBOR—and define numeric, Unicode, absent-field, and length rules. Do not accept multiple encodings as equivalent within one protocol version.


## Implemented prototype vs. research directions

### Prototype scope (v0.1)

- Three independent signatures (master + A + B)
- Pre-issued note records and Merkle membership verification
- Transaction binding
- Replay/spend-check hooks and adversarial tests
- Node.js and Java reference implementations
- Benchmark scripts

Spend-store guarantees depend on the selected store and deployment configuration. A local or in-memory test is not evidence of durable, cross-process atomic consumption.

### Research directions—not production claims

- **Finite-inventory authorization:** issuer-committed note inventory and offline membership verification
- **Threshold signature backend:** possible FROST integration using a reviewed implementation; no secret reconstruction
- **Privacy mode:** future zero-knowledge membership/nullifier construction
- **Financial systems experiment:** planned Hyperswitch payout lab, subject to source audit and implementation

The Node reference model and experimental Circom work currently use different cryptographic suites and are not proven equivalent. A passing reference-model test is not evidence that the circuit proves the same relation.

## Why a committed inventory?

Without an issuer commitment, an attacker who controls a signing factor may attempt to invent authorization objects. The verifier's inventory-membership check distinguishes **valid-looking cryptographic material** from **material committed as issued**.

This property must be evaluated against strong conventional baselines. A signed capability or allowlist can also incorporate a fixed quota, issuer commitment, membership proof, and atomic nullifier consumption. Torn Note is not inherently unique or stronger merely because it uses a Merkle tree.

## Research questions

1. What security property does finite, issuer-committed inventory add under the stated compromise assumptions?
2. Can the property be achieved just as simply using signed capabilities or allowlists?
3. What are the issuance, storage, recovery, and verification costs?
4. Which controls are cryptographic, and which depend on verifier-side durable state?
5. Can a future privacy construction hide note identity while preserving transaction binding and double-spend prevention?

## Planned evaluation: Hyperswitch payout lab

The proposed lab pins a Hyperswitch release and uses mock payout execution only. It compares four in-process Rust models on a shared test substrate:

- A — Single-key Ed25519
- B — Conventional 3-of-3 signatures
- C — Signed capability / allowlist with atomic spend
- D — Torn Note

The experiment includes transaction alteration, beneficiary substitution, replay, missing factors, concurrent spend, restart/recovery, and out-of-inventory issuance under a carefully defined hot-signer compromise.

**No Hyperswitch lab results are published yet.** Benchmark numbers, security outcomes, and conclusions will be added only after the harness is implemented and executed. Comparisons will be configured fairly; if a conventional baseline can provide the same inventory-bounding property, that result will be reported.

## Security boundary

Torn Note does not inherently prevent social engineering, legitimate malicious approvals, endpoint malware spending notes already accessible to a compromised device, issuer-key compromise, compromise of all factors, or verifier implementation errors. Replay prevention requires durable, atomic consumption.

See [Threat model and security goals](docs/SECURITY.md), [Protocol](docs/PROTOCOL.md), [Architecture](docs/ARCHITECTURE.md), [Benchmarks](docs/BENCHMARKS.md), and the [Research paper draft](docs/RESEARCH.md).

## Repository contents

- Node — reference prototype and experiments
- Java — reference implementation and comparison material
- docs — protocol, architecture, security, research, benchmark, and WebAuthn notes
- zk — experimental zero-knowledge work (not production and not yet equivalent to the reference suite)
- showcase — explanatory and interactive research experiences

## Reproducibility

Run tests and benchmarks from the relevant project directory. See the individual README and benchmark documentation for commands and prerequisites.

Do not interpret prototype benchmarks as general performance claims. They are machine-, runtime-, workload-, and implementation-dependent.

## Status

| Workstream | Status |
|---|---|
| Three-signature reference model | Prototype |
| Merkle inventory membership | Prototype |
| Transaction binding | Prototype; canonicalization must be scrutinized per implementation |
| Durable atomic spend | Store/deployment-specific; not implied by prototype |
| Cross-language normative vectors | Pending |
| Rust Hyperswitch integration | Planned; feasibility checks required |
| ZK unlinkability | Research direction; not claimed as implemented |
| FROST | Future direction; not implemented |

## Technical review

Reproducible criticism, attack cases, baseline comparisons, and clarifications are welcome. The most valuable contributions challenge assumptions or show that a conventional construction achieves the same result more simply.

## License

See LICENSE.
