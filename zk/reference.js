import crypto from 'node:crypto';

const DOMAIN = {
  leaf: Buffer.from('TORN-LEAF/v2'),
  nullKey: Buffer.from('TORN-NULLIFIER-KEY/v2'),
  nullifier: Buffer.from('TORN-NULLIFIER/v2'),
  tx: Buffer.from('TORN-TX/v2')
};

const H = (...parts) => crypto.createHash('sha256')
  .update(Buffer.concat(parts.map(p => Buffer.isBuffer(p) ? p : Buffer.from(p))))
  .digest();

export const hashLeaf = ({ noteId, X, ZA, ZB, r }) =>
  H(DOMAIN.leaf, noteId, X, ZA, ZB, r);

export const deriveNullifierKey = ({ x, zA, zB }) =>
  H(DOMAIN.nullKey, x, zA, zB);

export const deriveNullifier = ({ noteId, x, zA, zB }) =>
  H(DOMAIN.nullifier, deriveNullifierKey({ x, zA, zB }), noteId);

export const transactionDigest = ({ root, nullifier, message }) =>
  H(DOMAIN.tx, root, nullifier, Buffer.from(JSON.stringify(message)));

export function merkleRoot(leaves) {
  if (!leaves.length) throw new Error('empty tree');
  let level = leaves.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2)
      next.push(level[i + 1] ? H(level[i], level[i + 1]) : H(level[i], level[i]));
    level = next;
  }
  return level[0];
}

export function merkleProof(leaves, index) {
  if (index < 0 || index >= leaves.length) throw new Error('invalid index');
  let level = leaves.slice(), i = index, path = [];
  while (level.length > 1) {
    const sibling = i ^ 1;
    path.push({
      side: sibling < level.length && sibling < i ? 'L' : 'R',
      hash: level[sibling] ?? level[i]
    });
    const next = [];
    for (let j = 0; j < level.length; j += 2)
      next.push(level[j + 1] ? H(level[j], level[j + 1]) : H(level[j], level[j]));
    i = Math.floor(i / 2);
    level = next;
  }
  return path;
}

export function verifyMerkle(leaf, path, root) {
  let x = leaf;
  for (const p of path) x = p.side === 'L' ? H(p.hash, x) : H(x, p.hash);
  return x.equals(root);
}

export function publicPoint(scalar) {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(scalar);
  return ecdh.getPublicKey(undefined, 'compressed');
}

export function randomScalar() {
  let x;
  do x = crypto.randomBytes(32); while (x.equals(Buffer.alloc(32)));
  return x;
}

export function makeNote(noteId = crypto.randomBytes(16)) {
  const x = randomScalar(), zA = randomScalar(), zB = randomScalar(), r = randomScalar();
  return {
    noteId, x, zA, zB, r,
    X: publicPoint(x), ZA: publicPoint(zA), ZB: publicPoint(zB)
  };
}

export function buildInventory(count = 8) {
  const notes = Array.from({ length: count }, (_, i) => makeNote(Buffer.from('note-' + i)));
  const leaves = notes.map(hashLeaf);
  return { notes, leaves, root: merkleRoot(leaves) };
}

/*
 * Executable reference relation for the future SNARK.
 * This is deliberately NOT a zero-knowledge proof.
 */
export function relation({ note, path, root, nullifier }) {
  const leaf = hashLeaf(note);
  const expectedNullifier = deriveNullifier(note);
  return verifyMerkle(leaf, path, root) &&
    expectedNullifier.equals(nullifier) &&
    note.x.length === 32 && note.zA.length === 32 &&
    note.zB.length === 32 && note.r.length === 32;
}

export function buildPublicStatement({ root, nullifier, message }) {
  return {
    root: root.toString('hex'),
    nullifier: nullifier.toString('hex'),
    txDigest: transactionDigest({ root, nullifier, message }).toString('hex')
  };
}

export class NullifierSet {
  constructor() { this.used = new Set(); }
  consumeAtomically(nullifier, commit) {
    const key = nullifier.toString('hex');
    if (this.used.has(key)) return false;
    this.used.add(key);
    try { commit(); return true; }
    catch (e) { this.used.delete(key); throw e; }
  }
  has(nullifier) { return this.used.has(nullifier.toString('hex')); }
}
