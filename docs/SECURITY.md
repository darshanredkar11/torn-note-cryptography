# Security
Threat model: attacker may obtain any strict subset of master, half A, half B and public note data. The desired property is that no strict subset can authorize an unspent note.
Assumptions: Ed25519/ECDSA unforgeability and SHA-256 collision resistance.
Non-claims: formal proof, compromised-device security, rollback resistance, side-channel resistance, threshold security, privacy, EUDI certification.
Production target: FROST threshold Schnorr with no reconstruction/export of long-lived or note-half secrets.