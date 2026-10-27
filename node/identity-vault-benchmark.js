import crypto from 'node:crypto';
import {
  baselineEncrypt, baselineDecrypt, tornNoteEncrypt, tornNotePresentations,
  tornNoteDecrypt, createEd25519Factors
} from './identity-vault.js';

const iterations = Number.parseInt(process.env.BENCH_ITERATIONS ?? '300', 10);
const payloadBytes = Number.parseInt(process.env.BENCH_PAYLOAD_BYTES ?? '512', 10);
if (!Number.isInteger(iterations) || iterations < 1 || !Number.isInteger(payloadBytes) || payloadBytes < 0) {
  throw new Error('BENCH_ITERATIONS must be >= 1 and BENCH_PAYLOAD_BYTES must be >= 0');
}

const payload = Buffer.from(JSON.stringify({
  subjectId: 'test-subject-001',
  credentialType: 'ExampleCredential',
  testOnlyPayload: 'x'.repeat(Math.max(0, payloadBytes - 100))
}));
const kek = crypto.randomBytes(32);
const factors = createEd25519Factors(3);

function measure(name, fn) {
  for (let i = 0; i < Math.min(30, iterations); i++) fn();
  const before = process.memoryUsage().heapUsed;
  const start = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) fn();
  const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
  const heapDelta = process.memoryUsage().heapUsed - before;
  return {
    name,
    iterations,
    elapsedMs: Number(elapsedMs.toFixed(2)),
    meanMsPerOp: Number((elapsedMs / iterations).toFixed(4)),
    opsPerSecond: Math.round(iterations / (elapsedMs / 1000)),
    heapDeltaBytes: heapDelta
  };
}

const baselineRecord = baselineEncrypt(payload, kek);
const tornRecord = tornNoteEncrypt(payload, factors, 2);
const tornPresentations = tornNotePresentations(tornRecord, factors, [0, 1]);

const results = [
  measure('baseline.encrypt+wrap-DEK (local KEK)', () => baselineEncrypt(payload, kek)),
  measure('baseline.unwrap-DEK+decrypt (local KEK)', () => baselineDecrypt(baselineRecord, kek)),
  measure('baseline.end-to-end encrypt+decrypt (local KEK)', () => {
    const record = baselineEncrypt(payload, kek);
    baselineDecrypt(record, kek);
  }),
  measure('torn-note.encrypt+split+enroll', () => tornNoteEncrypt(payload, factors, 2)),
  measure('torn-note.sign-2-shares', () => tornNotePresentations(tornRecord, factors, [0, 1])),
  measure('torn-note.verify+recover+decrypt', () => tornNoteDecrypt(tornRecord, tornPresentations)),
  measure('torn-note.end-to-end encrypt+sign+recover+decrypt', () => {
    const record = tornNoteEncrypt(payload, factors, 2);
    const presentations = tornNotePresentations(record, factors, [0, 1]);
    tornNoteDecrypt(record, presentations);
  })
];

console.log(JSON.stringify({
  warning: 'Research microbenchmark only. Local in-memory KEK is not a real KMS/HSM. Results are machine/runtime-dependent; heap delta is a rough process-level signal, not per-operation allocation.',
  runtime: process.version,
  platform: process.platform,
  arch: process.arch,
  payloadBytes: payload.length,
  threshold: '2-of-3',
  iterations,
  results
}, null, 2));
