# Torn Note: Action-Bound, Finite-Inventory Authorization Capabilities for High-Impact Workflows

**Author:** Darshan Govind Redkar  
**Date:** November 2026  
**Status:** Working research preprint — pre-evaluation draft (v0.4)  
**Repositories:** [torn-note-cryptography](https://github.com/darshanredkar11/torn-note-cryptography) · Hyperswitch integration lab (planned)

> **Evaluation status:** The Hyperswitch benchmark and integration have not yet been implemented or run. All empirical claims, result tables, and comparative conclusions remain open. This document describes the research hypothesis and proposed evaluation; it does not report completed experiments.

## Abstract

High-impact workflows commonly combine identity authentication with authorization to mutate a transaction. A valid session, API credential, or signing key may provide authority broader or longer-lived than a single intended state transition. This paper investigates **Torn Note**, a research authorization model that separates long-lived identity from transaction-specific, pre-issued authorization inventory.

The prototype combines (1) an issuer-signed commitment to a finite inventory of note records, (2) note-specific authorization factors using independent Ed25519 signatures, (3) a canonical transaction digest, and (4) verifier-side single-use consumption. The design is intended to make authorization objects both transaction-bound and membership-bound to a batch committed before use.

The central research question is not whether Merkle trees, signatures, transaction binding, or replay protection are individually new. It is whether issuer-committed finite inventory offers a useful security property under a clearly defined compromise model—and whether that property justifies issuance, storage, recovery, and verification overhead over strong conventional constructions. We propose an adversarial evaluation in a mock payout flow integrated with Hyperswitch, comparing single-key signatures, conventional 3-of-3 authorization, signed capabilities with atomic spend, and Torn Note.

A privacy-oriented zero-knowledge extension is discussed as future work. The current reference implementation and experimental circuit use different cryptographic suites and are not established to implement the same relation. No formal proof, production security claim, or benchmark conclusion is made.

**Keywords:** authorization capabilities; finite inventory; Merkle commitment; transaction binding; replay resistance; payout systems; applied cryptography

## 1. Introduction

Authentication answers who is acting. Authorization determines which state transition that actor may cause. In sensitive workflows, these concerns can become conflated: possession of a session, credential, or hot signing key may expose authority over many future actions.

Torn Note explores a different boundary. Long-lived identity is necessary but insufficient. A transaction additionally requires note-specific authorization material belonging to an inventory committed by an issuer before use. The verifier binds that material to the transaction it independently reconstructs and consumes the authorization exactly once.

The work is motivated by high-impact actions such as payouts and beneficiary changes, but the mechanism is not claimed to prevent social engineering, endpoint compromise, or misuse by authorized signers. It aims to explore whether pre-issued finite authority can bound the set of authorizations available to a compromised runtime.

### 1.1 Research question

> Does issuer-committed, finite authorization inventory provide a meaningful, falsifiable security property—particularly offline-verifiable per-manifest inventory membership and issuance bounds, combined with online atomic spend enforcement—over well-engineered conventional authorization systems, and is that property worth the additional operational complexity?

### 1.2 Contributions and scope

This draft:

1. Describes the prototype authorization semantics: independent signing factors, committed note inventory, transaction binding, and one-time consumption.
2. Defines a threat model and security goals for the proposed payout experiment.
3. Designs a minimal integration point for an in-process Rust verifier in Hyperswitch, pending source verification.
4. Specifies adversarial tests, including out-of-inventory issuance under hot-signer compromise.
5. Establishes comparison against strong baselines and commits to reporting negative or equivalent outcomes.

This is an experimental construction and systems evaluation proposal, not a novel cryptographic primitive or formal proof.

## 2. Entities and threat model

### 2.1 Entities

- **Issuer (I):** A high-assurance authority that creates a finite note batch, constructs a commitment, and signs a manifest.
- **Holder (H):** A human, device, or service holding authorization material for one or more notes.
- **Verifier (V):** The execution boundary that reconstructs the authoritative transaction, verifies authorization, and atomically consumes a note before allowing execution.
- **Execution system:** The payout orchestrator and connector that carry out the authorized state transition.

### 2.2 Adversary capabilities

We consider a computationally bounded adversary who may:

- Intercept, replay, and race authorization requests.
- Alter transaction fields between authorization and execution, including amount, currency, beneficiary, destination, connector, or routing.
- Compromise a runtime application session or hot signing key and attempt authorization outside the intended inventory.
- Cause crashes or restarts to exploit non-durable spend state.
- Observe public manifest data and previously accepted transactions.

The adversary is not assumed to compromise the issuer's manifest-signing key or every required independent authorization factor unless a test explicitly says so. The model does not assume the endpoint or legitimate signer is free from social engineering.

### 2.3 Security goals

- **P1 — Exact action binding:** An authorization for transaction digest D cannot be accepted for a distinct digest D′.
- **P2 — Atomic single-use consumption:** A note/nullifier is accepted at most once, including concurrent requests and restart/recovery, provided the verifier's spend store is durable and atomic.
- **P3 — Per-manifest inventory membership:** Without compromising the issuer's manifest key, an attacker cannot prove membership for an authorization object outside that manifest's committed set.
- **P4 — Per-batch issuance bound under compromise:** Under a precisely specified compromise of the runtime/hot signer but not the issuer commitment key or required note factors, the attacker should not be able to create a new valid note outside the committed batch. This is a per-manifest bound of N leaves, not automatically a global merchant-wide quota across multiple manifests. Global quotas require issuer policy and, where relevant, shared accounting. This property does not prevent a compromised holder from spending valid notes already in its possession.
- **P5 — Optional privacy:** A future ZK construction may hide note identity while revealing only a commitment/root, a nullifier, transaction digest, and proof. This is a research goal, not a current implementation claim.

### 2.4 Non-goals

Torn Note does not inherently prevent business email compromise, social engineering, malicious legitimate approvals, malware spending notes already accessible to a compromised device, compromise of the issuer key, compromise of all factors, denial of service, or errors in transaction serialization and verifier code. Durable atomic state is still needed for double-spend prevention.

## 3. Protocol overview

### 3.1 Batch issuance

For each note i, the issuer creates a unique identifier noteId_i and note-specific public keys pkA_i and pkB_i with corresponding private signing keys skA_i and skB_i. A leaf commits to a canonical encoding of the note identifier and public keys. A recommended domain-separated construction is:

    L_i = SHA-256(0x00 || CanonicalEncode(noteId_i, pkA_i, pkB_i))
    N(left, right) = SHA-256(0x01 || left || right)

The distinct prefixes separate leaf hashing from internal-node hashing. The normative profile must also fix tree shape, leaf ordering, proof direction encoding, and odd-leaf handling; the leaf count N must be authenticated so that membership is interpreted against one unambiguous tree.

The issuer builds the Merkle tree over the N leaves and obtains root R. The signed manifest M should include protocol and version identifiers, batch_id, root R, leaf_count N, issuer identity and key identifier, algorithm identifiers, validity interval, authorization scope/policy identifier, and the exact manifest serialization profile. The issuer signs the canonical manifest bytes under a domain-separated manifest-signing context. The verifier is provisioned with the trusted issuer public key and validates both the signature and manifest policy.

This construction is a specification proposal, not a claim that every current prototype module already uses this exact encoding. The implementation profile and test vectors must be frozen before cross-language interoperability or conformance claims.

### 3.2 Transaction binding

The verifier constructs a digest from its authoritative, final transaction snapshot—not a client-provided digest. The snapshot is taken after updates and routing resolution, at the execution boundary, and is immutable for the authorized attempt.

Illustrative fields include:

- protocol/domain and version
- action type
- merchant/tenant and profile/environment identifiers
- payout identifier and merchant order reference
- amount in minor units and currency
- beneficiary/customer identifier
- destination or payout-method fingerprint (never raw bank/account details)
- connector/routing identity if the authorization is intended to constrain it
- nonce and expiry, if defined by the protocol

    D_tx = SHA-256(Domain || CanonicalEncode(TransactionSnapshot))

The canonical encoding must specify field names, ordering, type representation, length-prefixing, Unicode normalization/handling, absent versus null fields, integer ranges, and currency representation. The integration must choose exactly one deterministic serialization profile per protocol version—for example, RFC 8785 JCS or RFC 8949 core deterministic CBOR—and publish byte-for-byte vectors. JCS requires its JSON/I-JSON numeric constraints to be respected; monetary amounts should use bounded integer minor units. Do not silently accept alternate encodings for the same version. The exact final field set is to be defined by the integration contract; fields should be included only if they are security-relevant and available authoritatively.

### 3.3 Authorization

The holder provides the note identifier, public note factors, manifest, Merkle path, and independent signatures. The signature message must bind the digest, note identifier, batch identifier, and protocol domain/version.

The current prototype's semantics are **three independent Ed25519 signatures**—master identity, Half A, and Half B—and all three are required. The two note-specific factors are a 2-of-2 pair; the complete authorization policy is 3-of-3. Ed25519 has no native aggregate or threshold multisignature operation. Key independence must be supported by separate generation and appropriate custody, not just by assigning different labels to keys. The proposed Hyperswitch experiment uses a Torn Note verifier over the final transaction snapshot and committed inventory. It must not be described as FROST or secret reconstruction.

### 3.4 Verification and spend

Before execution, the verifier:

1. Validates the issuer manifest signature and its validity policy.
2. Recomputes the note leaf and verifies Merkle membership against the manifest root.
3. Independently reconstructs the canonical digest from the authoritative transaction state.
4. Verifies every required signature over the same domain-separated authorization message.
5. Atomically consumes the note identifier/nullifier in durable storage.
6. Allows execution only if verification and consumption succeed.

In the core mode, the spend uniqueness scope should identify the issuer/batch and note (for example, a unique key over issuer_id, batch_id, note_id). In ZK mode, use the corresponding issuer/batch scope and note-level nullifier. A note must not be reissued across batches unless the nullifier design explicitly prevents cross-batch reuse.

Atomic consumption must be coordinated with payout idempotency and failure handling. A database transaction can atomically record the note spend, the logical payout transition, and an outbox event. A worker can then dispatch the outbox event using a stable connector idempotency key. This normally provides durable at-least-once delivery; exactly-once external effects cannot be claimed unless the downstream connector honors the idempotency contract. A crash after recording the spend but before delivery should be recovered by retrying the same outbox event, not by freeing the note for a different payout.

## 4. Optional zero-knowledge direction

A privacy-oriented extension would replace the public note identifier and membership path with a proof of membership and a **note-level deterministic nullifier**. The public statement could contain a batch root R, batch identifier, nullifier η, independently recomputed transaction digest D_tx, and proof π. The witness could contain note secrets, note identifier, commitment randomness, and membership path.

The nullifier must not include the transaction digest. If it did, the same note would derive a different nullifier for each transaction and could be spent more than once under different transaction digests. A candidate note-level construction is:

    K_N = Poseidon(DOMAIN_NULLIFIER_KEY, secret_1, secret_2, ...)
    η_i = Poseidon(DOMAIN_NULLIFIER, K_N, noteId_i, batch_id)

Here, batch_id is the immutable issuance scope for that note; D_tx is a separate public input to the proof and is checked against the verifier's authoritative transaction. The circuit proves that the note belongs to R, that η_i is correctly derived, and that the authorization relation binds the proof to D_tx. The verifier records η_i as spent. If a note could be reissued into another batch, including batch_id would produce a different nullifier; the issuer must therefore guarantee one-batch-only note issuance or use a globally stable note scope that prevents cross-batch reuse.

A candidate proving stack may use a SNARK-friendly hash and curve, such as Poseidon over BN254 with BabyJubjub-based points/signatures. BabyJubjub is a curve, not a signature scheme; the concrete signature construction (if any), proof system, setup assumptions, domain separation, and security analysis must be specified. The exact circuit profile is not frozen.

**Interoperability caveat:** the Node.js reference model currently uses length-prefixed SHA-256 and P-256, while the experimental Circom circuit uses Poseidon and BabyJubjub. These are separate research implementations; no byte-for-byte or relation-equivalence claim is made. A normative suite and cross-implementation vectors are required before claiming circuit equivalence.

The current work does not claim production zero-knowledge proofs, unlinkability, or anonymity. A proof may hide the leaf index, note identifier, and note public keys, but the verifier still observes at least the batch identifier/root, nullifier, transaction digest, and timing. Privacy depends on the actual anonymity set of eligible notes and can be reduced by batch size, root reuse, issuance patterns, transaction metadata, and application/network identifiers. No formal anonymity definition or measured anonymity set is claimed.

## 5. Related constructions and comparison

Torn Note uses standard cryptographic components. Its potential contribution is an authorization architecture and compromise-boundary hypothesis, not a stronger hash or signature algorithm.

The evaluation will compare against:

| Model | Configuration |
|---|---|
| A — Single-key signature | Ed25519 over the canonical transaction; include spend controls appropriate to the test |
| B — Conventional 3-of-3 | Three independent signatures with transaction binding and atomic spend |
| C — Signed capability | Capability/allowlist with issuer authentication, equivalent transaction binding, quota semantics where applicable, and atomic spend |
| D — Torn Note | Independent factors, issuer-committed finite inventory, membership proof, transaction binding, and atomic spend |

Strong baselines must not be deliberately weakened. A capability system can also include a signed finite quota, issuer commitment, membership proof, and nullifier/spend table. If it matches Torn Note's property, that equivalence is part of the result.

Privacy-oriented token systems (including Privacy Pass), WebAuthn, OAuth Rich Authorization Requests, macaroons, and Biscuit are relevant but differ in threat models, issuance/delegation, privacy goals, and transaction semantics. Privacy Pass is an architecture with multiple issuance and redemption components; its architecture specifies blindness/input secrecy and one-more-forgery security requirements for issuance protocols, but the paper should not imply that every Privacy Pass variant uses one identical blind-signature mechanism. See [RFC 9576](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578](https://www.rfc-editor.org/rfc/rfc9578.html).

WebAuthn assertions bind a credential signature to a server-provided challenge. Replay resistance depends on the relying party verifying the expected challenge and managing its lifecycle; WebAuthn itself is not a durable atomic spend ledger. The comparison should distinguish challenge replay checking from an application-level one-time spend transition.

The final related-work section must be based on primary specifications and literature, and must avoid categorical claims based only on the table above.

## 6. Proposed evaluation: Hyperswitch payout lab

### 6.1 Integration

The proposed research artifact is a fork pinned to a specific Hyperswitch release. The verifier will run in-process in Rust, at the final payout execution boundary, after authoritative payout fields are hydrated and routing is resolved, but before connector dispatch. This insertion point is **provisional** until verified against a fresh checkout.

The experiment uses mock payout execution only. No real funds, real beneficiaries, or production secrets are involved.

The implementation must first verify the payout lifecycle, including confirmation/fulfillment paths, so authorization cannot be bypassed through a separate execution path. A mock connector or external stub will be used if the existing dummy connector does not support payout execution.

### 6.2 Baselines

All four verifiers are planned to run in-process in Rust and use the same transaction encoding, test configuration, and PostgreSQL spend substrate where applicable:

- **A:** Single-key Ed25519
- **B:** Conventional 3-of-3 Ed25519 signatures
- **C:** Signed capability/allowlist with atomic spend
- **D:** Torn Note with issuer-signed Merkle inventory and note factors

Cross-language vectors will be exported from the Java reference implementation and validated in Rust. This is a future milestone, not an existing compatibility result.

### 6.3 Adversarial test matrix

The table defines attack scenarios, not measured outcomes. The exact baseline behavior depends on the configuration and controls each model is given.

| # | Scenario | Test objective |
|---|---|---|
| 01 | Legitimate payout | Accept a valid authorization and mock execution |
| 02 | Amount manipulation | Reject altered amount after authorization |
| 03 | Beneficiary/destination substitution | Reject changed recipient or destination |
| 04 | Sequential replay | Reject reuse of a spent authorization |
| 05 | Missing factor | Reject incomplete required authorization |
| 06 | Concurrent spend | Ensure at most one successful consume |
| 07 | Restart/recovery | Ensure durable spend state prevents reuse after restart |
| 08 | Out-of-inventory issuance under hot-signer compromise | Attempt authorization outside the issuer-committed inventory, without compromising the issuer manifest key or all independent factors |

Attack 08 is a falsifiable hypothesis. It is not a guaranteed Torn Note win. A strong baseline that uses an issuer-committed quota/inventory may provide equivalent protection. The evaluation must describe exactly what is compromised, what remains trusted, and what capabilities the attacker retains.

### 6.4 Measurements

No measurements have been collected for the Hyperswitch lab. Planned measurements include:

| Metric | Status |
|---|---|
| Verification latency (p50/p95/p99) | TBD — Gate 4 |
| Authorization/issuance latency | TBD — Gate 4 |
| Proof/signature payload size | TBD — Gate 4 |
| Inventory/manifest distribution overhead | TBD — Gate 4 |
| Storage cost per spend | TBD — Gate 4 |
| Concurrency throughput and failure behavior | TBD — Gate 4 |
| Recovery and operational complexity | Qualitative + test evidence |
| Attack outcomes across models | TBD — execution required |

All results must specify hardware, OS, compiler/runtime, database configuration, sample sizes, warm-up, methodology, and variance. Separate cryptographic cost from persistence, serialization, and connector cost. Do not compare unlike execution paths.

## 7. Limitations and open problems

- **Stateful verifier:** Durable atomic spend state remains necessary for replay and concurrency protection.
- **Inventory replenishment:** Finite batches introduce availability and replenishment concerns.
- **Custody and recovery:** Loss or compromise of note factors can make notes unusable or expose held inventory.
- **Compromise scope:** A finite inventory limits only authority that is actually constrained by the committed batch and assumptions; it does not automatically limit legitimate notes already compromised.
- **Canonicalization:** Inconsistent transaction encoding or missing fields can undermine binding.
- **Baseline equivalence:** Signed capabilities and committed quotas may reproduce the relevant property.
- **Threshold cryptography:** The prototype is not FROST and does not reconstruct a threshold secret; future work requires reviewed implementations and a separate threat analysis.
- **ZK equivalence and privacy:** The circuit and reference implementation are not yet aligned; privacy claims remain unproven.
- **Formal analysis:** Security goals require more precise definitions and formal or cryptographic analysis before publication as a protocol claim.

## 8. Research roadmap

| Gate | Work | Exit criterion |
|---|---|---|
| 0 | Hyperswitch source feasibility audit | Verified lifecycle, final dispatch boundary, connector and persistence facts |
| 1 | Integration architecture | Minimal diff, verifier contract, binding schema, threat assumptions, baseline fairness |
| 2 | Working mock payout | Legitimate test payout accepted through Torn Note |
| 3 | Adversarial tests | Attack matrix executable, including concurrency and recovery |
| 4 | Comparative measurements | Reproducible metrics and honest results |
| 5 | Interactive lab | Visitors can execute and alter experiments, observe verifier outcomes |
| 6 | Research release | Artifact, instructions, threat model, results, limitations, and manuscript |

## 9. Publication strategy

A public preprint or submission should follow—not precede—source verification, implementation, test execution, and evidence collection. Potential venues are exploratory and subject to their current scope, submission rules, and review requirements.

The manuscript should not use a reported incident or CVE as motivation until its identifier, disclosure date, affected versions, exploit conditions, and patch references have been verified against primary sources. This draft intentionally omits an unverified incident claim.

## 10. Conclusion

Torn Note is a hypothesis about bounded, transaction-specific authority, not a claim that standard signatures or Merkle trees are insufficient. Its value depends on the security property it provides under a precise compromise model, whether strong conventional systems can achieve the same property, and whether any advantage justifies additional operational burden.

The proposed experiment is designed to produce a meaningful result even if Torn Note is equivalent to a strong baseline or proves less useful than expected. Reproducibility, adversarial scrutiny, and honest reporting are the primary objectives.

## References and artifact links

- [Torn Note source repository](https://github.com/darshanredkar11/torn-note-cryptography)
- [Hyperswitch](https://github.com/juspay/hyperswitch)
- [Torn Note protocol](PROTOCOL.md)
- [Threat model and security documentation](SECURITY.md)
- [Architecture](ARCHITECTURE.md)
- [Benchmark notes](BENCHMARKS.md)
- [ZK protocol research](ZK_PROTOCOL.md)
