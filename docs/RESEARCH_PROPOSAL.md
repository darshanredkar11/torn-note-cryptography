# Torn Note Cryptography: Research Proposal and Review Draft

**Status:** Open research proposal; v0.1 protocol sketch and executable prototype  
**Intended audience:** Cryptographers, applied-cryptography researchers, protocol engineers, security reviewers  
**Purpose of this draft:** Invite independent attacks, formalization, alternative constructions, and independent implementations  
**Non-goal:** Production deployment or a claim that the construction is novel, proven secure, or superior to existing systems

## Abstract

Torn Note studies a narrow authorization question: can a long-lived identity key be necessary but insufficient to authorize a transaction, by requiring it to act together with a pre-issued, uniquely identified authorization object whose components are independently controlled?

The current prototype represents the authorization object as two pre-issued fragments, A and B. Their public material is committed into an inventory Merkle tree. A transaction is accepted only when the note is a member of the accepted inventory, the required independent signatures verify over a domain-separated transaction digest, and the note has not already been spent according to the verifier's state policy.

The current implementation uses three independent signatures (master, A, and B). It does **not** implement the conceptual combined Schnorr secret, a production threshold-signature protocol, or a production zero-knowledge proof. The proposed work is to define the desired properties precisely, identify the strongest counterexamples, compare the construction against simpler baselines, and determine whether a more compact privacy-preserving or threshold construction is worthwhile.

This document is a challenge for review, not a security theorem.

## 1. Research question

A conventional signature proves that a private-key holder authorized a message. If that private key is compromised, the attacker may be able to authorize arbitrary future messages.

Torn Note asks:

> Can authorization require both a long-lived identity factor and a pre-issued, consumable authorization object, such that possession of the identity factor alone is insufficient—even if the attacker can choose arbitrary replacement fragment keys?

The intended distinction is between **cryptographic validity** and **authorization to use a pre-issued object**. Merely adding more signatures or secret values is not sufficient; the issuance and inventory-binding rules must be part of the protocol.

This research question does not assume the idea is novel. Reviewers should identify related work, prior constructions, and simpler equivalent mechanisms.

## 2. Current v0.1 protocol sketch

### 2.1 Setup and issuance

For a wallet/master factor, let the public key be \(X\). For note \(i\), let the independently controlled fragment public keys be \(A_i\) and \(B_i\), with unique \(noteId_i\).

A domain-separated leaf is conceptually:

\[
L_i = H(\texttt{"TORN-NOTE/leaf/v1"} \parallel noteId_i \parallel A_i \parallel B_i)
\]

The issuer commits the set of valid leaves into a Merkle root \(ROOT\). The verifier must obtain this root from an authenticated source and apply an explicit root-freshness policy.

### 2.2 Transaction authorization

Let \(m\) be the canonical transaction. The transaction digest is conceptually:

\[
D = H(\texttt{"TORN-NOTE/tx/v1"} \parallel ROOT \parallel noteId_i \parallel A_i \parallel B_i \parallel CanonicalEncode(m))
\]

The current implementation requires three independent signatures over the relevant digest:

- a master-key signature;
- a fragment-A signature;
- a fragment-B signature.

The verifier checks the signatures, the note's membership in the committed inventory, the transaction binding, and whether the note has already been spent. Spent-state checking must be enforced by the integrating verifier; the check and state update must be atomic to prevent concurrent double-spend races.

The equations above are a protocol sketch. Exact serialization, signature-message bytes, root lifecycle, state transitions, error behavior, and cross-language conformance must be specified before treating this as a complete wire protocol.

### 2.3 Conceptual algebra is not the current implementation

The repository also explores the relation:

\[
P_i = X + A_i + B_i
\]

with a conceptual secret relation \(s_i = x + a_i + b_i \pmod q\). This is useful as mathematical scaffolding, but the current three-signature implementation does not reconstruct this scalar and does not implement FROST.

A future threshold-Schnorr design would need a reviewed, established construction and a precise statement of which participants hold which shares. It must not be inferred from the algebra alone.

## 3. Security goals to formalize

The reviewers are invited to formalize or reject these goals:

1. **Authorization unforgeability:** an adversary missing at least one required private factor cannot cause acceptance of a new transaction for a valid, unspent note, except with negligible probability under stated assumptions.
2. **Issuance binding:** possession of the master factor does not authorize invented fragments or a note absent from the authenticated inventory.
3. **Transaction binding:** a signature/proof for one canonical transaction cannot be reused for a different transaction, root, note, or fragment tuple.
4. **Replay resistance:** a note cannot be accepted twice under the defined state and concurrency model.
5. **Threshold recovery (separate vault experiment):** fewer than the configured threshold of Shamir shares cannot reconstruct the data key, assuming the scheme and share handling meet their assumptions. This is a separate prototype and is not the same as threshold signing.
6. **Optional privacy goal (future ZK version):** the public proof statement does not reveal which inventory leaf was used, beyond information explicitly leaked by the public inputs and application.

These are goals, not established results. In particular, “one factor is insufficient” is only meaningful after the adversary model, setup, enrollment, state, and permitted corruption patterns are defined.

## 4. Adversary model for review

Assume the adversary can:

- know all public keys, inventory roots, public notes, and protocol code;
- observe prior authorization transcripts;
- choose messages and attempt replay, substitution, malformed-input, and cross-context attacks;
- corrupt a strict subset of the required private factors;
- attempt to register fabricated fragments or exploit stale roots and inconsistent verifier state.

The model must explicitly decide whether the adversary can:

- compromise the issuer or enrollment registry;
- corrupt the root-distribution channel;
- control the verifier or its spent-state database;
- roll back state or race concurrent transactions;
- obtain a valid signature oracle from an uncompromised factor;
- exploit side channels, malicious devices, key extraction, or denial of service.

These capabilities cannot be silently excluded. Security claims must state exactly which are in and out of scope.

## 5. Required baselines and comparisons

Reviewers should compare Torn Note with at least:

1. ordinary single-key signatures;
2. ordinary multi-signature authorization without pre-issued inventory membership;
3. threshold-signature approaches such as an established FROST implementation, where the threat model fits;
4. conventional policy controls such as multiple independent keys, hardware-backed keys, or transaction limits;
5. for the separate vault experiment, standard envelope encryption with a managed KMS/HSM baseline.

The question is not whether Torn Note uses cryptography; it is whether the inventory-bound, consumable authorization object provides a distinct, useful property that simpler designs do not provide at acceptable cost.

## 6. Known implementation boundaries

The repository is an executable research prototype, not a proof. Known boundaries include:

- v0.1 authorization uses three independent signatures, not FROST or a new signature primitive;
- the algebraic combined-secret expression is not the current signing implementation;
- the ZK reference relation is not itself a zero-knowledge proof;
- a circuit must be checked for complete public-input binding, soundness, field/range constraints, and consistent serialization before any proof claim;
- nullifier uniqueness and spent-state insertion require a clearly defined, atomic state transition;
- Merkle-root freshness, issuance, revocation, recovery, malicious participants, and rollback behavior need explicit protocol policy;
- independent review and formal proofs are not complete.

The repository's tests are executable checks against selected cases; passing them is not a proof of security.

## 7. Questions for independent reviewers

Please try to falsify the protocol, not merely confirm its happy path.

1. Is the core research question meaningfully distinct from established multisignature, threshold-signature, one-time authorization, capability, and token constructions?
2. Can a holder of the master factor create replacement fragment keys and obtain acceptance despite inventory membership?
3. Are the exact transaction digest and canonicalization rules sufficient to prevent cross-protocol, cross-root, and cross-transaction replay?
4. What is the correct formal game for authorization unforgeability when note issuance and spent state are stateful?
5. Which corruption thresholds can be supported without contradicting the required authorization policy?
6. Does the Merkle inventory add a security property beyond a signed registry or ordinary database under the intended trust assumptions?
7. What is the simplest counterexample or attack that invalidates the current construction?
8. Is there a sound route to a privacy-preserving construction? Which public metadata remains linkable?
9. Would an established threshold-signature or hardware-backed policy meet the same requirement with fewer assumptions?
10. What is the smallest formal model and proof obligation that should be attempted first?

Please report assumptions, attack steps, and a minimal reproducer. A negative result or proof that a simpler construction dominates this one is valuable.

## 8. Reproducibility and implementation work

A proposed review workflow:

1. Read [the protocol sketch](PROTOCOL.md), [security notes](SECURITY.md), and the repository's ZK protocol/security notes before interpreting code as the specification.
2. Run the existing tests from a clean checkout using the versions and commands in the repository README.
3. Write an independent implementation from the written specification rather than copying the prototype line for line.
4. Create negative tests for invented notes, key substitution, transaction mutation, stale roots, replay, duplicate/concurrent spends, malformed encodings, and inconsistent implementations.
5. Record where the written protocol is ambiguous or the implementation differs from it.
6. Publish a short review with the threat model, strongest attack attempted, results, and recommended changes.

Do not use real funds, production credentials, or real identity data.

## 9. Suggested staged research plan

**Stage A — Specify:** finish a single canonical v0.1 wire protocol and a state-machine model.

**Stage B — Attack:** independent implementation, property-based testing, fuzzing, differential tests, and adversarial review.

**Stage C — Formalize:** define the unforgeability game and prove or refute it under explicit assumptions. A proof must cover the actual protocol, not only the motivating algebra.

**Stage D — Compare:** benchmark against fair baselines and account for issuer trust, enrollment, root distribution, state availability, and operational complexity.

**Stage E — Explore extensions:** only after the base construction is understood, explore FROST integration or a genuine ZK circuit/proof system with separate security arguments.

## 10. What would count as a meaningful result?

Any of the following would advance the research:

- a formal security definition and proof under explicit assumptions;
- a minimal counterexample showing the claimed property fails;
- an independent implementation that agrees with the written protocol;
- evidence that a simpler established construction dominates the proposal;
- a well-defined application where pre-issued inventory membership adds a concrete property;
- a sound, audited route to a threshold or privacy-preserving variant.

A negative result is not a failure. It is part of the intended research process.

## 11. Claims policy

Until supported by formal analysis and independent review, describe Torn Note as:

> An open cryptographic research proposal exploring inventory-bound, consumable authorization objects combined with independent authorization factors.

Do **not** claim that it is novel, formally proven, unbreakable, production-ready, an EUDI-compliant implementation, a production ZK system, or more secure than established alternatives.

## 12. Invitation

We invite cryptographers, applied-cryptography researchers, and protocol engineers to:

- attack the assumptions and protocol;
- propose simpler or stronger constructions;
- implement the written protocol independently;
- help define and prove the exact security properties;
- identify related work and prior art.

The goal is not to defend the current code. The goal is to discover whether the idea survives rigorous scrutiny, what property it truly provides, and whether it deserves further research.
