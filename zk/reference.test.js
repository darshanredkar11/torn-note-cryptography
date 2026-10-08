import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildInventory, buildPublicStatement, deriveNullifier, hashLeaf,
  makeNote, merkleProof, relation, transactionDigest, NullifierSet
} from './reference.js';

test('same note always derives the same nullifier', () => {
  const { notes } = buildInventory(4);
  assert.deepEqual(deriveNullifier(notes[2]), deriveNullifier(notes[2]));
});

test('different notes derive different nullifiers', () => {
  const { notes } = buildInventory(16);
  const values = notes.map(deriveNullifier).map(x => x.toString('hex'));
  assert.equal(new Set(values).size, values.length);
});

test('valid witness satisfies the reference relation', () => {
  const { notes, leaves, root } = buildInventory(8);
  const note = notes[3];
  assert.equal(relation({
    note, path: merkleProof(leaves, 3), root,
    nullifier: deriveNullifier(note)
  }), true);
});

test('public statement exposes only root, nullifier and transaction digest', () => {
  const { notes, root } = buildInventory(8);
  const note = notes[3];
  const statement = buildPublicStatement({
    root, nullifier: deriveNullifier(note), message: { amount: 42 }
  });
  assert.deepEqual(Object.keys(statement).sort(), ['nullifier', 'root', 'txDigest']);
  const encoded = JSON.stringify(statement);
  assert.equal(encoded.includes(note.noteId.toString()), false);
  assert.equal(encoded.includes(note.X.toString('hex')), false);
  assert.equal(encoded.includes(note.ZA.toString('hex')), false);
  assert.equal(encoded.includes(note.ZB.toString('hex')), false);
});

test('wrong note id cannot reuse the witness', () => {
  const { notes, leaves, root } = buildInventory(8);
  const note = { ...notes[3], noteId: Buffer.from('note-4') };
  assert.equal(relation({
    note, path: merkleProof(leaves, 3), root,
    nullifier: deriveNullifier(notes[3])
  }), false);
});

test('wrong blinding salt breaks membership', () => {
  const { notes, leaves, root } = buildInventory(8);
  const note = { ...notes[3], r: Buffer.from(notes[3].r) };
  note.r[0] ^= 1;
  assert.equal(relation({
    note, path: merkleProof(leaves, 3), root,
    nullifier: deriveNullifier(notes[3])
  }), false);
});

test('wrong half-A secret breaks the relation', () => {
  const { notes, leaves, root } = buildInventory(8);
  const note = { ...notes[3], zA: Buffer.from(notes[3].zA) };
  note.zA[0] ^= 1;
  assert.equal(relation({
    note, path: merkleProof(leaves, 3), root,
    nullifier: deriveNullifier(notes[3])
  }), false);
});

test('master-only attacker cannot fabricate an inventory member', () => {
  const { leaves, root } = buildInventory(8);
  const attacker = makeNote(Buffer.from('invented-note'));
  const nullifier = deriveNullifier(attacker);
  assert.equal(relation({
    note: attacker, path: merkleProof(leaves, 0), root, nullifier
  }), false);
  assert.notDeepEqual(hashLeaf(attacker), leaves[0]);
});

test('changing the transaction changes the public digest', () => {
  const { notes, root } = buildInventory(4);
  const nullifier = deriveNullifier(notes[1]);
  const a = transactionDigest({ root, nullifier, message: { amount: 10, to: 'bob' } });
  const b = transactionDigest({ root, nullifier, message: { amount: 11, to: 'bob' } });
  assert.notDeepEqual(a, b);
});

test('nullifier cannot be replaced with another note nullifier', () => {
  const { notes, leaves, root } = buildInventory(4);
  assert.equal(relation({
    note: notes[1], path: merkleProof(leaves, 1), root,
    nullifier: deriveNullifier(notes[2])
  }), false);
});

test('malformed membership path is rejected', () => {
  const { notes, leaves, root } = buildInventory(8);
  const path = merkleProof(leaves, 3);
  path[0].hash = Buffer.from(path[0].hash);
  path[0].hash[0] ^= 1;
  assert.equal(relation({
    note: notes[3], path, root, nullifier: deriveNullifier(notes[3])
  }), false);
});

test('root changes invalidate the membership relation', () => {
  const { notes, leaves, root } = buildInventory(8);
  const otherRoot = Buffer.from(root);
  otherRoot[0] ^= 1;
  assert.equal(relation({
    note: notes[3], path: merkleProof(leaves, 3), root: otherRoot,
    nullifier: deriveNullifier(notes[3])
  }), false);
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
