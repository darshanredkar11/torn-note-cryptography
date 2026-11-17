# Bound Shamir security notes

This module is a research prototype, not production key management.

## Trust boundary

`boundDecrypt()` requires `factorRefs` from a trusted enrollment record. Store the mapping of share index to algorithm and public key separately from the share presentation. Never treat a presenter-supplied public key as proof of identity.

## Signed share binding

The signature digest binds the protocol context, share identifier, index, x-coordinate, hash of the complete share bytes, and ciphertext/tag hash. This prevents changing share bytes or replaying a signature against a different envelope.

## Operational requirements

- Protect enrollment records against unauthorized edits and rollback.
- Use durable, authenticated storage for factor references.
- Do not reuse share IDs or shares across envelopes.
- Protect private factor keys and apply rate limits to failed presentations.
- Keep spent-state/replay prevention in a durable application layer.
- Obtain independent cryptographic review before production use.

The current implementation supports Ed25519 and P-256 factors. It is not a formal proof, audited threshold protocol, or production-ready key-management system.
