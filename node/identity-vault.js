import crypto from 'node:crypto';
import { boundEncrypt, signShare, boundDecrypt } from './bound-shamir.js';

const b64 = value => Buffer.from(value).toString('base64');
const unb64 = value => Buffer.from(value, 'base64');

function seal(key, plaintext, aad = undefined) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv: b64(iv), ct: b64(ciphertext), tag: b64(cipher.getAuthTag()) };
}

function open(key, envelope, aad = undefined) {
  if (!envelope || typeof envelope.iv !== 'string' ||
      typeof envelope.ct !== 'string' || typeof envelope.tag !== 'string') {
    throw new Error('invalid encryption envelope');
  }
  const iv = unb64(envelope.iv);
  const ciphertext = unb64(envelope.ct);
  const tag = unb64(envelope.tag);
  if (iv.length !== 12 || tag.length !== 16 ||
      iv.toString('base64') !== envelope.iv ||
      ciphertext.toString('base64') !== envelope.ct ||
      tag.toString('base64') !== envelope.tag) {
    throw new Error('invalid encryption envelope');
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Local envelope-encryption baseline.
 * The KEK is an in-memory test key, NOT a cloud KMS/HSM integration.
 * Production comparisons must use an actual KMS/HSM and document its policy.
 */
export function baselineEncrypt(plaintext, kek) {
  if (!Buffer.isBuffer(plaintext)) plaintext = Buffer.from(plaintext);
  if (!Buffer.isBuffer(kek) || kek.length !== 32) throw new Error('KEK must be 32 bytes');
  const dek = crypto.randomBytes(32);
  try {
    return {
      version: 1,
      payload: seal(dek, plaintext),
      wrappedDek: seal(kek, dek, Buffer.from('TORN-NOTE/local-kek-wrap/v1'))
    };
  } finally {
    dek.fill(0);
  }
}

export function baselineDecrypt(record, kek) {
  if (!Buffer.isBuffer(kek) || kek.length !== 32) throw new Error('KEK must be 32 bytes');
  const dek = open(kek, record?.wrappedDek, Buffer.from('TORN-NOTE/local-kek-wrap/v1'));
  try {
    if (dek.length !== 32) throw new Error('invalid wrapped data key');
    return open(dek, record.payload);
  } finally {
    dek.fill(0);
  }
}

/**
 * Returns separate vault material and enrollment trust anchors.
 * Persist enrollment outside the vault record, under an independently protected
 * trust boundary. The in-memory demo does not provide durable storage itself.
 */
export function tornNoteEncrypt(plaintext, factors, threshold = 2) {
  const result = boundEncrypt(Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext), {
    threshold,
    factors
  });
  const { factorRefs: enrollment, ...record } = result;
  return { record, enrollment };
}

export function tornNotePresentations(record, factors, indices) {
  return indices.map(index => {
    const factor = factors[index];
    const share = record.shares[index];
    if (!factor || !share) throw new Error('unknown factor index');
    return signShare(share, factor.keypair.privateKey, record);
  });
}

export function tornNoteDecrypt(record, presentations, trustedEnrollment) {
  if (!Array.isArray(trustedEnrollment)) {
    throw new Error('separately trusted enrollment records are required');
  }
  const result = boundDecrypt(presentations, { ...record, factorRefs: trustedEnrollment });
  if (!result.ok) throw new Error(result.reason ?? 'Torn Note recovery failed');
  return result.plaintext;
}

export function createEd25519Factors(count = 3) {
  if (!Number.isInteger(count) || count < 2 || count > 255) {
    throw new Error('factor count must be an integer from 2 to 255');
  }
  return Array.from({ length: count }, () => ({
    algo: 'ed25519',
    keypair: crypto.generateKeyPairSync('ed25519')
  }));
}
