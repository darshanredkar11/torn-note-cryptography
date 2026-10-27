import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  baselineEncrypt, baselineDecrypt, tornNoteEncrypt, tornNotePresentations,
  tornNoteDecrypt, createEd25519Factors
} from './identity-vault.js';

const sample = Buffer.from(JSON.stringify({
  subjectId: 'test-subject-001',
  credentialType: 'ExampleCredential',
  claims: { country: 'XX', testOnly: true }
}));

test('baseline envelope encryption round-trips synthetic identity data', () => {
  const kek = crypto.randomBytes(32);
  const record = baselineEncrypt(sample, kek);
  assert.deepEqual(baselineDecrypt(record, kek), sample);
});

test('baseline rejects a wrong KEK and modified ciphertext', () => {
  const kek = crypto.randomBytes(32);
  const record = baselineEncrypt(sample, kek);
  assert.throws(() => baselineDecrypt(record, crypto.randomBytes(32)));
  const changed = structuredClone(record);
  const bytes = Buffer.from(changed.payload.ct, 'base64');
  bytes[0] ^= 1;
  changed.payload.ct = bytes.toString('base64');
  assert.throws(() => baselineDecrypt(changed, kek));
});

test('Torn Note vault round-trips with any two of three valid shares', () => {
  const factors = createEd25519Factors(3);
  const record = tornNoteEncrypt(sample, factors, 2);
  for (const pair of [[0, 1], [0, 2], [1, 2]]) {
    const presentations = tornNotePresentations(record, factors, pair);
    assert.deepEqual(tornNoteDecrypt(record, presentations), sample);
  }
});

test('one share is insufficient to recover the vault', () => {
  const factors = createEd25519Factors(3);
  const record = tornNoteEncrypt(sample, factors, 2);
  const onlyOne = tornNotePresentations(record, factors, [0]);
  assert.throws(() => tornNoteDecrypt(record, onlyOne), /insufficient-signed-shares/);
});

test('Torn Note rejects substituted or tampered share presentations', () => {
  const factors = createEd25519Factors(3);
  const record = tornNoteEncrypt(sample, factors, 2);
  const presentations = tornNotePresentations(record, factors, [0, 1]);
  presentations[1] = { ...presentations[1], y: Buffer.alloc(32, 0x42).toString('base64') };
  assert.throws(() => tornNoteDecrypt(record, presentations), /insufficient-signed-shares/);
});

test('Torn Note rejects envelope tampering even if a valid share presentation is replayed', () => {
  const factors = createEd25519Factors(3);
  const record = tornNoteEncrypt(sample, factors, 2);
  const presentations = tornNotePresentations(record, factors, [0, 1]);
  const changed = { ...record, envelope: { ...record.envelope } };
  const iv = Buffer.from(changed.envelope.iv, 'base64');
  iv[0] ^= 1;
  changed.envelope.iv = iv.toString('base64');
  assert.throws(() => tornNoteDecrypt(changed, presentations));
});

test('both implementations preserve binary and empty payloads', () => {
  const kek = crypto.randomBytes(32);
  const factors = createEd25519Factors(3);
  for (const payload of [Buffer.alloc(0), Buffer.from([0, 10, 13, 128, 255])]) {
    assert.deepEqual(baselineDecrypt(baselineEncrypt(payload, kek), kek), payload);
    const record = tornNoteEncrypt(payload, factors, 2);
    assert.deepEqual(tornNoteDecrypt(record, tornNotePresentations(record, factors, [0, 2])), payload);
  }
});
