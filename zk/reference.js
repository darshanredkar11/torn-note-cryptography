import crypto from 'node:crypto';

const DOMAIN = {
  leaf: Buffer.from('TORN-LEAF/v2'),
  merkleNode: Buffer.from('TORN-MERKLE-NODE/v2'),
  nullKey: Buffer.from('TORN-NULLIFIER-KEY/v2'),
  nullifier: Buffer.from('TORN-NULLIFIER/v2'),
  tx: Buffer.from('TORN-TX/v2')
};
const P256_ORDER = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

function bytes(value, field) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  throw new TypeError(field + ' must be bytes');
}

// Length-prefix every hash input to make tuple boundaries unambiguous.
const H = (...parts) => {
  const hash = crypto.createHash('sha256');
  for (const part of parts) {
    const value = bytes(part, 'hash input');
    if (value.length > 0xffffffff) throw new RangeError('hash input is too large');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(value.length);
    hash.update(length);
    hash.update(value);
  }
  return hash.digest();
};

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

// Deterministic JSON subset for transactions: recursively sorted keys and
// rejection of values that JSON.stringify would silently omit or coerce.
function canonicalize(value, ancestors = new Set()) {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('transaction numbers must be finite');
    return Object.is(value, -0) ? '0' : JSON.stringify(value);
  }
  if (typeof value !== 'object') throw new TypeError('transaction contains an unsupported value');
  if (ancestors.has(value)) throw new TypeError('transaction must not contain cycles');
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return '[' + value.map(item => {
        if (item === undefined) throw new TypeError('transaction arrays must not contain undefined');
        return canonicalize(item, ancestors);
      }).join(',') + ']';
    }
    if (!isPlainObject(value)) throw new TypeError('transaction objects must be plain objects');
    if (Object.getOwnPropertySymbols(value).length !== 0) throw new TypeError('symbol keys are not supported');
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const fields = [];
    for (const key of Object.keys(descriptors).sort()) {
      const descriptor = descriptors[key];
      if (!descriptor.enumerable) continue;
      if (!Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
        throw new TypeError('transaction objects must not contain getters or setters');
      }
      if (descriptor.value === undefined) throw new TypeError('transaction objects must not contain undefined');
      fields.push(JSON.stringify(key) + ':' + canonicalize(descriptor.value, ancestors));
    }
    return '{' + fields.join(',') + '}';
  } finally {
    ancestors.delete(value);
  }
}

export function canonicalTransactionBytes(message) {
  if (!isPlainObject(message)) throw new TypeError('transaction must be a plain object');
  return Buffer.from(canonicalize(message), 'utf8');
}

export const hashLeaf = ({ noteId, X, ZA, ZB, r }) =>
  H(Buffer.from('TORN-LEAF/v2'), bytes(noteId, 'noteId'), bytes(X, 'X'),
    bytes(ZA, 'ZA'), bytes(ZB, 'ZB'), bytes(r, 'r'));

export const deriveNullifierKey = ({ x, zA, zB }) =>
  H(DOMAIN.nullKey, bytes(x, 'x'), bytes(zA, 'zA'), bytes(zB, 'zB'));

export const deriveNullifier = ({ noteId, x, zA, zB }) =>
  H(DOMAIN.nullifier, deriveNullifierKey({ x, zA, zB }), bytes(noteId, 'noteId'));

export const transactionDigest = ({ root, nullifier, message }) =>
  H(DOMAIN.tx, bytes(root, 'root'), bytes(nullifier, 'nullifier'), canonicalTransactionBytes(message));

function hashPair(left, right) {
  return H(DOMAIN.merkleNode, bytes(left, 'left Merkle node'), bytes(right, 'right Merkle node'));
}

export function merkleRoot(leaves) {
  if (!Array.isArray(leaves) || !leaves.length) throw new Error('empty tree');
  if (leaves.some(leaf => !Buffer.isBuffer(leaf) || leaf.length !== 32)) {
    throw new TypeError('Merkle leaves must be 32-byte hashes');
  }
  let level = leaves.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(hashPair(level[i], level[i + 1] ?? level[i]));
    level = next;
  }
  return level[0];
}

export function merkleProof(leaves, index) {
  if (!Array.isArray(leaves) || !leaves.length ||
      !Number.isInteger(index) || index < 0 || index >= leaves.length) throw new Error('invalid index or empty tree');
  if (leaves.some(leaf => !Buffer.isBuffer(leaf) || leaf.length !== 32)) {
    throw new TypeError('Merkle leaves must be 32-byte hashes');
  }
  let level = leaves.slice(), i = index, path = [];
  while (level.length > 1) {
    const sibling = i ^ 1;
    path.push({ side: sibling < level.length && sibling < i ? 'L' : 'R', hash: level[sibling] ?? level[i] });
    const next = [];
    for (let j = 0; j < level.length; j += 2) next.push(hashPair(level[j], level[j + 1] ?? level[j]));
    i = Math.floor(i / 2);
    level = next;
  }
  return path;
}

export function verifyMerkle(leaf, path, root) {
  if (!Buffer.isBuffer(leaf) || leaf.length !== 32 ||
      !Buffer.isBuffer(root) || root.length !== 32 || !Array.isArray(path)) return false;
  let current = leaf;
  for (const step of path) {
    if (!step || !Buffer.isBuffer(step.hash) || step.hash.length !== 32 ||
        (step.side !== 'L' && step.side !== 'R')) return false;
    current = step.side === 'L' ? hashPair(step.hash, current) : hashPair(current, step.hash);
  }
  return current.equals(root);
}

export function publicPoint(scalar) {
  if (!Buffer.isBuffer(scalar) || scalar.length !== 32) throw new TypeError('P-256 scalar must be exactly 32 bytes');
  const value = BigInt('0x' + scalar.toString('hex'));
  if (value <= 0n || value >= P256_ORDER) throw new RangeError('P-256 scalar is out of range');
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(scalar);
  return ecdh.getPublicKey(undefined, 'compressed');
}

export function randomScalar() {
  while (true) {
    const candidate = crypto.randomBytes(32);
    const value = BigInt('0x' + candidate.toString('hex'));
    if (value > 0n && value < P256_ORDER) return candidate;
  }
}

export function makeNote(noteId = crypto.randomBytes(16)) {
  const x = randomScalar(), zA = randomScalar(), zB = randomScalar(), r = randomScalar();
  return { noteId, x, zA, zB, r, X: publicPoint(x), ZA: publicPoint(zA), ZB: publicPoint(zB) };
}

export function buildInventory(count = 8) {
  if (!Number.isInteger(count) || count < 1) throw new Error('count must be a positive integer');
  const notes = Array.from({ length: count }, (_, i) => makeNote(Buffer.from('note-' + i)));
  const leaves = notes.map(hashLeaf);
  return { notes, leaves, root: merkleRoot(leaves) };
}

/*
 * Executable reference relation for the future SNARK; deliberately NOT a ZK proof.
 * It checks scalar-to-point ownership, committed note membership, the derived
 * nullifier, and exact canonical transaction binding.
 */
export function relation({ note, path, root, nullifier, txDigest, message }) {
  try {
    if (!note || !Buffer.isBuffer(note.x) || !Buffer.isBuffer(note.zA) ||
        !Buffer.isBuffer(note.zB) || !Buffer.isBuffer(note.r) ||
        !Buffer.isBuffer(note.noteId) || !Buffer.isBuffer(note.X) ||
        !Buffer.isBuffer(note.ZA) || !Buffer.isBuffer(note.ZB) || note.r.length !== 32) return false;

    if (!publicPoint(note.x).equals(note.X) ||
        !publicPoint(note.zA).equals(note.ZA) ||
        !publicPoint(note.zB).equals(note.ZB)) return false;

    if (!verifyMerkle(hashLeaf(note), path, root)) return false;
    if (!deriveNullifier(note).equals(nullifier)) return false;
    return Buffer.isBuffer(txDigest) && txDigest.length === 32 &&
      transactionDigest({ root, nullifier, message }).equals(txDigest);
  } catch {
    return false;
  }
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
