import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { boundEncrypt, signShare, boundDecrypt } from './bound-shamir.js';

const factors = n => Array.from({length:n}, () => {
  const keypair = crypto.generateKeyPairSync('ed25519');
  return { algo: 'ed25519', keypair };
});

test('trusted signed shares reconstruct the plaintext', () => {
  const fs = factors(3);
  const e = boundEncrypt('torn note', { threshold: 2, factors: fs });
  const signed = e.shares.slice(0, 2).map((s, i) => signShare(s, fs[i].keypair.privateKey, e));
  const result = boundDecrypt(signed, e);
  assert.equal(result.ok, true);
  assert.equal(result.plaintext.toString(), 'torn note');
});

test('public-key substitution is rejected against enrollment refs', () => {
  const fs = factors(2);
  const e = boundEncrypt('secret', { threshold: 2, factors: fs });
  const good = signShare(e.shares[0], fs[0].keypair.privateKey, e);
  const attacker = crypto.generateKeyPairSync('ed25519');
  const substituted = { ...e.shares[1], pub: attacker.publicKey.export({type:'spki',format:'der'}).toString('base64') };
  const forged = signShare(substituted, attacker.privateKey, e);
  const result = boundDecrypt([good, forged], e);
  assert.equal(result.ok, false);
  assert.equal(result.admitted, 1);
});

test('changing share bytes invalidates its signature', () => {
  const fs = factors(2);
  const e = boundEncrypt('secret', { threshold: 2, factors: fs });
  const signed = e.shares.map((s, i) => signShare(s, fs[i].keypair.privateKey, e));
  signed[1] = { ...signed[1], y: Buffer.alloc(32, 7).toString('base64') };
  const result = boundDecrypt(signed, e);
  assert.equal(result.ok, false);
  assert.equal(result.admitted, 1);
});

test('signature cannot be replayed against a different envelope', () => {
  const fs = factors(2);
  const a = boundEncrypt('alpha', { threshold: 2, factors: fs });
  const b = boundEncrypt('beta', { threshold: 2, factors: fs });
  const signed = a.shares.map((s, i) => signShare(s, fs[i].keypair.privateKey, a));
  const result = boundDecrypt(signed, b);
  assert.equal(result.ok, false);
});

test('duplicate presentations do not satisfy a threshold', () => {
  const fs = factors(3);
  const e = boundEncrypt('secret', { threshold: 3, factors: fs });
  const s = signShare(e.shares[0], fs[0].keypair.privateKey, e);
  const result = boundDecrypt([s, s, s], e);
  assert.equal(result.ok, false);
  assert.equal(result.admitted, 1);
});
