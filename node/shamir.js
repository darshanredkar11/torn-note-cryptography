import crypto from 'node:crypto';

const FIELD = 256;
function mul(a, b) {
  let out = 0;
  while (b) {
    if (b & 1) out ^= a;
    b >>>= 1;
    a <<= 1;
    if (a & FIELD) a ^= 0x11b;
  }
  return out;
}
function pow(a, n) {
  let out = 1;
  while (n) { if (n & 1) out = mul(out, a); a = mul(a, a); n >>>= 1; }
  return out;
}
function inv(a) { if (!a) throw new Error('zero has no inverse'); return pow(a, 254); }

export function split(secret, threshold, count) {
  const input = Buffer.from(secret);
  if (!input.length) throw new Error('secret must not be empty');
  if (!Number.isInteger(threshold) || !Number.isInteger(count) || threshold < 2 || count < threshold || count > 255)
    throw new Error('require 2 <= threshold <= count <= 255');
  const shares = Array.from({length: count}, (_, i) => ({x: i + 1, y: Buffer.alloc(input.length)}));
  for (let j = 0; j < input.length; j++) {
    const coeff = [input[j], ...crypto.randomBytes(threshold - 1)];
    for (const s of shares) {
      let y = coeff[threshold - 1];
      for (let k = threshold - 2; k >= 0; k--) y = mul(y, s.x) ^ coeff[k];
      s.y[j] = y;
    }
    coeff.fill(0);
  }
  return shares;
}

export function combine(shares) {
  if (!Array.isArray(shares) || shares.length < 2) throw new Error('at least two shares required');
  const len = shares[0]?.y?.length;
  const xs = new Set();
  for (const s of shares) {
    if (!Number.isInteger(s.x) || s.x < 1 || s.x > 255 || xs.has(s.x)) throw new Error('invalid or duplicate share coordinate');
    if (!(s.y instanceof Uint8Array) || s.y.length !== len || len < 1) throw new Error('invalid share payload');
    xs.add(s.x);
  }
  const out = Buffer.alloc(len);
  for (let j = 0; j < len; j++) {
    let value = 0;
    for (let i = 0; i < shares.length; i++) {
      let basis = 1;
      for (let k = 0; k < shares.length; k++) if (i !== k)
        basis = mul(basis, mul(shares[k].x, inv(shares[k].x ^ shares[i].x)));
      value ^= mul(shares[i].y[j], basis);
    }
    out[j] = value;
  }
  return out;
}
