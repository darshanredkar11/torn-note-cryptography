import test from 'node:test';
import assert from 'node:assert/strict';
import { split, combine } from './shamir.js';

test('any threshold subset reconstructs the original secret', () => {
  const secret = Buffer.from('torn-note-data-key');
  const shares = split(secret, 3, 5);
  assert.deepEqual(combine([shares[0], shares[2], shares[4]]), secret);
  assert.deepEqual(combine([shares[1], shares[3], shares[4]]), secret);
});

test('duplicate coordinates and malformed shares are rejected', () => {
  const shares = split(Buffer.from('secret'), 2, 3);
  assert.throws(() => combine([shares[0], shares[0]]), /duplicate/);
  assert.throws(() => combine([{x: 1, y: Buffer.alloc(2)}, {x: 2, y: Buffer.alloc(3)}]), /invalid share payload/);
});

test('threshold and count validation is enforced', () => {
  assert.throws(() => split(Buffer.from('x'), 1, 2), /require/);
  assert.throws(() => split(Buffer.from('x'), 3, 2), /require/);
});
