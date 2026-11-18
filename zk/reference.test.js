import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildInventory, buildPublicStatement, canonicalTransactionBytes,
  deriveNullifier, hashLeaf, makeNote, merkleProof, publicPoint,
  relation, transactionDigest, NullifierSet
} from './reference.js';

const MESSAGE = { amount: 42, to: 'bob', metadata: { purpose: 'test', sequence: 1 } };

function relationInput(note, path, root, message = MESSAGE, overrides = {}) {
  const nullifier = overrides.nullifier ?? deriveNullifier(note);
  const txDigest = overrides.txDigest ?? transactionDigest({ root, nullifier, message });
  return { note, path, root, nullifier, txDigest, message };
}

test('same note always derives the same nullifier', () => {
  const { notes } = buildInventory(4);
  assert.deepEqual(deriveNullifier(notes[2]), deriveNullifier(notes[2]));
});

test('different notes derive different nullifiers', () => {
  const { notes } = buildInventory(16);
  const values = notes.map(deriveNullifier).map(x => x.toString('hex'));
  assert.equal(new Set(values).size, values.length);
});

test('valid witness satisfies the complete reference relation', () => {
  const { notes, leaves, root } = buildInventory(8);
  const note = notes[3];
  assert.equal(relation(relationInput(note, merkleProof(leaves, 3), root)), true);
});

test('public statement exposes only root, nullifier and transaction digest', () => {
  const { notes, root } = buildInventory(8);
  const note = notes[3];
  const statement = buildPublicStatement({
    root, nullifier: deriveNullifier(note), message: MESSAGE
  });
  assert.deepEqual(Object.keys(statement).sort(), ['nullifier', 'root', 'txDigest']);
  const encoded = JSON.stringify(statement);
  assert.equal(encoded.includes(note.noteId.toString()), false);
  assert.equal(encoded.includes(note.X.toString('hex')), false);
  assert.equal(encoded.includes(note.ZA.toString('hex')), false);
  assert.equal(encoded.includes(note.ZB.toString('hex')), false);
});

test('canonical transaction encoding ignores object insertion order recursively', () => {
  const a = { z: 1, nested: { b: 2, a: 3 }, a: 'first' };
  const b = { a: 'first', nested: { a: 3, b: 2 }, z: 1 };
  assert.deepEqual(canonicalTransactionBytes(a), canonicalTransactionBytes(b));
  const root = Buffer.alloc(32, 1), nullifier = Buffer.alloc(32, 2);
  assert.deepEqual(
    transactionDigest({ root, nullifier, message: a }),
    transactionDigest({ root, nullifier, message: b })
  );
});

test('canonical transaction encoding rejects ambiguous or unsupported values', () => {
  assert.throws(() => canonicalTransactionBytes({ amount: undefined }), /undefined/);
  assert.throws(() => canonicalTransactionBytes({ amount: Number.NaN }), /finite/);
  assert.throws(() => canonicalTransactionBytes({ amount: Infinity }), /finite/);
  assert.throws(() => canonicalTransactionBytes(new Date()), /plain objects/);
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalTransactionBytes(cyclic), /cycles/);
});

test('wrong note id cannot reuse an inventory witness even with a recomputed nullifier', () => {
  const { notes, leaves, root } = buildInventory(8);
  const note = { ...notes[3], noteId: Buffer.from('attacker-note') };
  assert.equal(relation(relationInput(note, merkleProof(leaves, 3), root)), false);
});

test('wrong blinding salt breaks membership', () => {
  const { notes, leaves, root } = buildInventory(8);
  const note = { ...notes[3], r: Buffer.from(notes[3].r) };
  note.r[0] ^= 1;
  assert.equal(relation(relationInput(note, merkleProof(leaves, 3), root)), false);
});

test('wrong private scalar is rejected even when nullifier and transaction digest are recomputed', () => {
  const { notes, leaves, root } = buildInventory(8);
  const note = { ...notes[3], zA: Buffer.from(notes[3].zA) };
  note.zA[0] ^= 1;
  const path = merkleProof(leaves, 3);
  const forgedNullifier = deriveNullifier(note);
  const forgedDigest = transactionDigest({ root, nullifier: forgedNullifier, message: MESSAGE });
  assert.equal(relation({
    note, path, root, nullifier: forgedNullifier, txDigest: forgedDigest, message: MESSAGE
  }), false);
});

test('mismatched scalar-to-public-point binding is rejected', () => {
  const { notes, leaves, root } = buildInventory(8);
  const note = { ...notes[3], zA: Buffer.from(notes[3].zA) };
  note.zA[0] ^= 1;
  // Keep the committed public point. The scalar must derive exactly this point.
  assert.equal(relation(relationInput(note, merkleProof(leaves, 3), root)), false);
});

test('master-only attacker cannot fabricate an inventory member', () => {
  const { leaves, root } = buildInventory(8);
  const attacker = makeNote(Buffer.from('invented-note'));
  assert.equal(relation(relationInput(attacker, merkleProof(leaves, 0), root)), false);
  assert.notDeepEqual(hashLeaf(attacker), leaves[0]);
});

test('changing the transaction changes the expected public digest', () => {
  const { notes, root } = buildInventory(4);
  const nullifier = deriveNullifier(notes[1]);
  const a = transactionDigest({ root, nullifier, message: { amount: 10, to: 'bob' } });
  const b = transactionDigest({ root, nullifier, message: { amount: 11, to: 'bob' } });
  assert.notDeepEqual(a, b);
});

test('reference relation rejects a substituted public transaction digest', () => {
  const { notes, leaves, root } = buildInventory(4);
  const note = notes[1];
  const input = relationInput(note, merkleProof(leaves, 1), root);
  const altered = Buffer.from(input.txDigest);
  altered[0] ^= 1;
  assert.equal(relation({ ...input, txDigest: altered }), false);
});

test('reference relation rejects a changed transaction while retaining the old digest', () => {
  const { notes, leaves, root } = buildInventory(4);
  const note = notes[1];
  const input = relationInput(note, merkleProof(leaves, 1), root);
  assert.equal(relation({ ...input, message: { ...MESSAGE, amount: 999 } }), false);
});

test('nullifier cannot be replaced with another note nullifier', () => {
  const { notes, leaves, root } = buildInventory(4);
  const note = notes[1];
  const wrongNullifier = deriveNullifier(notes[2]);
  const wrongDigest = transactionDigest({ root, nullifier: wrongNullifier, message: MESSAGE });
  assert.equal(relation({
    note, path: merkleProof(leaves, 1), root,
    nullifier: wrongNullifier, txDigest: wrongDigest, message: MESSAGE
  }), false);
});

test('malformed membership path is rejected', () => {
  const { notes, leaves, root } = buildInventory(8);
  const path = merkleProof(leaves, 3);
  path[0].hash = Buffer.from(path[0].hash);
  path[0].hash[0] ^= 1;
  assert.equal(relation(relationInput(notes[3], path, root)), false);
});

test('invalid Merkle path directions are rejected', () => {
  const { notes, leaves, root } = buildInventory(8);
  const path = merkleProof(leaves, 3);
  path[0] = { ...path[0], side: 'invalid' };
  assert.equal(relation(relationInput(notes[3], path, root)), false);
});

test('root changes invalidate the membership relation', () => {
  const { notes, leaves, root } = buildInventory(8);
  const otherRoot = Buffer.from(root);
  otherRoot[0] ^= 1;
  assert.equal(relation(relationInput(notes[3], merkleProof(leaves, 3), otherRoot)), false);
});

test('P-256 scalar conversion rejects zero and out-of-range scalars', () => {
  assert.throws(() => publicPoint(Buffer.alloc(32)), /out of range/);
  const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
  const scalar = Buffer.from(order.toString(16).padStart(64, '0'), 'hex');
  assert.throws(() => publicPoint(scalar), /out of range/);
});

test('nullifier registry rejects replay', () => {
  const { notes } = buildInventory(4);
  const eta = deriveNullifier(notes[1]);
  const set = new NullifierSet();
  assert.equal(set.consumeAtomically(eta, () => {}), true);
  assert.equal(set.consumeAtomically(eta, () => {}), false);
});

test('nullifier registry rolls back on failed settlement', () => {
  const { notes } = buildInventory(4);
  const eta = deriveNullifier(notes[1]);
  const set = new NullifierSet();
  assert.throws(() => set.consumeAtomically(eta, () => { throw new Error('settlement failed'); }));
  assert.equal(set.has(eta), false);
  assert.equal(set.consumeAtomically(eta, () => {}), true);
});
