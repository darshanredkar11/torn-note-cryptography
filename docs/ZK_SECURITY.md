# ZK Torn Note Security Model

## Security goals

A successful spend must require knowledge of all three private authorization factors and a valid pre-issued note.

An observer should not be able to determine which leaf was consumed from the public proof statement alone.

A valid spend must be bound to one deterministic nullifier and one transaction digest.

## Attack matrix

| Attacker capability | Expected |
|---|---|
| Public ROOT only | Reject |
| Master secret only | Reject |
| Half-A secret only | Reject |
| Half-B secret only | Reject |
| Master + Half-A | Reject |
| Master + Half-B | Reject |
| Half-A + Half-B | Reject |
| All three + genuine note | Accept |
| All three + fabricated note | Reject |
| Valid proof + modified transaction | Reject |
| Valid proof + altered ROOT | Reject |
| Valid proof + altered nullifier | Reject |
| Same valid spend twice | Second spend rejected |

## Critical distinction

Possessing x is not equivalent to possessing an authorized note.

The Merkle commitment prevents a holder of x from inventing a fresh note tuple that was never issued.

## Nullifier security

The nullifier must be deterministic for one note and computationally unpredictable to observers without the witness.

Collision resistance by itself is not a complete PRF proof. The construction is therefore specified as a domain-separated keyed-hash construction and must be instantiated with a suitable circuit-friendly primitive.

## Root freshness

A verifier may accept historical roots to support concurrent or offline workflows. Production policy must define which roots remain spendable and for how long.

## Atomic replay protection

The check for eta and its insertion into the nullifier registry must be one atomic state transition. A check-then-insert sequence is vulnerable to concurrent double-spend races.

## Privacy caveats

Zero knowledge hides the witness, but does not automatically hide:

- amount;
- timing;
- network metadata;
- root lifecycle;
- issuance timing;
- application identifiers.

The claim is witness privacy, not automatic global anonymity.

## Future proof obligations

Before production consideration, review:

1. circuit soundness;
2. nullifier uniqueness and pseudorandomness;
3. subgroup and point-validity constraints;
4. canonical encoding;
5. Merkle path correctness;
6. complete public-input binding;
7. atomic state transition;
8. malicious-prover resistance;
9. trusted-setup assumptions if Groth16 is selected;
10. implementation side channels.
