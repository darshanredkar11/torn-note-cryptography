import crypto from 'node:crypto';
import { split, combine } from './shamir.js';

const CONTEXT = Buffer.from('TORN-NOTE/share/v1');
const sha256 = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts)).digest();
const keyBytes = key => Buffer.from(key.export({ type: 'spki', format: 'der' }));
const signBytes = (algo, key, digest) => crypto.sign(algo === 'ed25519' ? null : 'sha256', digest, key);
const verifyBytes = (algo, key, digest, sig) => crypto.verify(algo === 'ed25519' ? null : 'sha256', digest, key, sig);

function publicKeyFor(algo, bytes) {
  if (!['ed25519', 'p256'].includes(algo)) throw new Error('supported algorithms: ed25519, p256');
  return crypto.createPublicKey({ key: bytes, type: 'spki', format: 'der' });
}
function digestFor(shareId, share, ciphertextHash) {
  const id = Buffer.from(shareId, 'base64');
  const y = Buffer.from(share.y, 'base64');
  return sha256(CONTEXT, id, Buffer.from([share.index]), Buffer.from([share.x]),
    sha256(y), ciphertextHash);
}
function cipherHash(envelope) {
  // Bind the complete AES-GCM envelope. The IV is security-relevant and must
  // not be replaceable independently of the signed shares.
  if (!envelope || typeof envelope.iv !== 'string' ||
      typeof envelope.ct !== 'string' || typeof envelope.tag !== 'string')
    throw new Error('invalid encryption envelope');
  const iv = Buffer.from(envelope.iv, 'base64');
  const ct = Buffer.from(envelope.ct, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  if (iv.length !== 12 || iv.toString('base64') !== envelope.iv ||
      ct.toString('base64') !== envelope.ct ||
      tag.length !== 16 || tag.toString('base64') !== envelope.tag)
    throw new Error('invalid encryption envelope');
  return sha256(CONTEXT, iv, ct, tag);
}

// Enrollment must persist factorRefs in a trusted registry separately from
// presentations. A presenter-supplied public key is never a trust anchor.
export function boundEncrypt(plaintext, { threshold, factors }) {
  if (!Array.isArray(factors) || factors.length > 255 || factors.length < threshold)
    throw new Error('need at least threshold factors (maximum 255)');
  if (!Number.isInteger(threshold) || threshold < 2) throw new Error('threshold must be >= 2');
  const dataKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', dataKey, iv);
  const ct = Buffer.concat([cipher.update(Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext)), cipher.final()]);
  const tag = cipher.getAuthTag();
  const envelope = { iv: iv.toString('base64'), ct: ct.toString('base64'), tag: tag.toString('base64') };
  const shareId = crypto.randomBytes(16).toString('base64');
  const raw = split(dataKey, threshold, factors.length);
  dataKey.fill(0);
  const shares = raw.map((s, index) => {
    const f = factors[index];
    if (!f || !['ed25519', 'p256'].includes(f.algo) || !f.keypair?.privateKey || !f.keypair?.publicKey)
      throw new Error('each factor requires an ed25519 or p256 keypair');
    return { index, x: s.x, y: Buffer.from(s.y).toString('base64'), algo: f.algo,
      pub: keyBytes(f.keypair.publicKey).toString('base64') };
  });
  const factorRefs = shares.map(({index, algo, pub}) => ({index, algo, pub}));
  return { threshold, shareId, shares, factorRefs, envelope };
}

export function signShare(share, privateKey, { shareId, envelope }) {
  if (!share || !Number.isInteger(share.index) || !Number.isInteger(share.x)) throw new Error('invalid share');
  const d = digestFor(shareId, share, cipherHash(envelope));
  return { ...share, sig: signBytes(share.algo, privateKey, d).toString('base64') };
}

export function boundDecrypt(presentations, { threshold, shareId, envelope, factorRefs }) {
  if (!Number.isInteger(threshold) || threshold < 2) throw new Error('threshold must be an integer >= 2');
  if (!Array.isArray(presentations) || !Array.isArray(factorRefs) || factorRefs.length < threshold)
    throw new Error('presentations and trusted factorRefs are required');
  const refs = new Map();
  for (const ref of factorRefs) {
    if (!Number.isInteger(ref?.index) || ref.index < 0 || ref.index > 254 || refs.has(ref.index) ||
        !['ed25519', 'p256'].includes(ref.algo) || typeof ref.pub !== 'string')
      throw new Error('invalid trusted enrollment record');
    refs.set(ref.index, ref);
  }
  const ch = cipherHash(envelope);
  const admitted = [];
  const seenX = new Set();
  const seenIndex = new Set();
  for (const p of presentations) {
    try {
      if (!p || typeof p.sig !== 'string' || !Number.isInteger(p.index) ||
          !Number.isInteger(p.x) || p.x < 1 || p.x > 255 ||
          typeof p.y !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(p.y))
        continue;
      const y = Buffer.from(p.y, 'base64');
      if (y.length !== 32 || y.toString('base64') !== p.y || seenX.has(p.x) || seenIndex.has(p.index)) continue;
      const enrolled = refs.get(p.index);
      if (!enrolled || enrolled.algo !== p.algo || enrolled.pub !== p.pub) continue;
      const pub = publicKeyFor(enrolled.algo, Buffer.from(enrolled.pub, 'base64'));
      const d = digestFor(shareId, p, ch);
      if (!verifyBytes(enrolled.algo, pub, d, Buffer.from(p.sig, 'base64'))) continue;
      admitted.push({ x: p.x, y: new Uint8Array(y) });
      seenX.add(p.x);
      seenIndex.add(p.index);
    } catch { /* malformed/unverifiable presentations are not admitted */ }
  }
  if (admitted.length < threshold) return { ok: false, admitted: admitted.length, reason: 'insufficient-signed-shares' };
  const key = combine(admitted);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.ct, 'base64')), decipher.final()]);
    return { ok: true, plaintext, admitted: admitted.length };
  } catch { return { ok: false, admitted: admitted.length, reason: 'reconstruction-failed' }; }
  finally { key.fill(0); }
}
