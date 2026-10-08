import { keyPair, publicKeyBytes, leaf, merkleRoot, merkleProof, authorize, verifyAuthorization, txDigest, sign } from './index.js';
import { performance } from 'node:perf_hooks';

for (const curve of ['ed25519', 'p256']) {
  const master = keyPair(curve);
  const notes = Array.from({ length: 32 }, (_, i) => ({
    id: Buffer.from('note-' + i),
    A: keyPair(curve),
    B: keyPair(curve)
  }));
  const leaves = notes.map(n => leaf(n.id, publicKeyBytes(n.A.publicKey), publicKeyBytes(n.B.publicKey)));
  const root = merkleRoot(leaves);
  const n = notes[7];
  const proof = merkleProof(leaves, 7);
  const pubA = publicKeyBytes(n.A.publicKey);
  const pubB = publicKeyBytes(n.B.publicKey);
  const payload = { amount: 42, currency: 'EUR', nonce: 'bench' };
  const digest = txDigest(root, n.id, pubA, pubB, payload);
  const signatures = {
    master: sign(master.privateKey, digest),
    a: sign(n.A.privateKey, digest),
    b: sign(n.B.privateKey, digest)
  };
  const rounds = 500;
  let t = performance.now();
  for (let i = 0; i < rounds; i++) authorize({master,noteA:n.A,noteB:n.B,root,noteId:n.id,pubA,pubB,payload,proof});
  const signMs = performance.now() - t;
  t = performance.now();
  for (let i = 0; i < rounds; i++) {
    if (!verifyAuthorization({masterPublicKey:master.publicKey,pubAKey:n.A.publicKey,pubBKey:n.B.publicKey,root,noteId:n.id,pubA,pubB,payload,proof,signatures}))
      throw new Error('benchmark verification failed');
  }
  const verifyMs = performance.now() - t;
  const bytes = signatures.master.length + signatures.a.length + signatures.b.length;
  console.log(JSON.stringify({
    curve, rounds,
    sign_ms_per_tx:+(signMs/rounds).toFixed(4),
    sign_tx_per_sec:+(rounds/(signMs/1000)).toFixed(1),
    verify_ms_per_tx:+(verifyMs/rounds).toFixed(4),
    verify_tx_per_sec:+(rounds/(verifyMs/1000)).toFixed(1),
    signature_bytes:bytes
  }));
}