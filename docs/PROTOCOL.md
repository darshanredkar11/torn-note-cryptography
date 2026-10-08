# Protocol
leaf = SHA-256("TORN-NOTE/leaf/v1" || noteId || pubA || pubB)
root = MerkleRoot(leaves)
D = SHA-256("TORN-NOTE/tx/v1" || root || noteId || pubA || pubB || canonicalTransaction)
Accept iff note membership, !spent, and master/A/B signatures all verify.
The earlier s=x+zA+zB construction was mathematical proof scaffolding. Production should use threshold Schnorr/FROST instead of reconstructing secrets.