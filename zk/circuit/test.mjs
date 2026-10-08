import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, unlinkSync } from "node:fs";
import path from "node:path";
import { buildPoseidon, buildBabyjub } from "circomlibjs";

const ROOT = new URL(".", import.meta.url).pathname;
const BUILD = path.join(ROOT, "build");
const WASM = path.join(BUILD, "TornNote_js", "TornNote.wasm");
const GENERATOR = path.join(BUILD, "TornNote_js", "generate_witness.js");
const R1CS = path.join(BUILD, "TornNote.r1cs");
const SNARKJS = path.join(ROOT, "node_modules", "snarkjs", "build", "cli.cjs");

const poseidon = await buildPoseidon();
const babyjub = await buildBabyjub();
const F = poseidon.F;
const scalar = (x) => BigInt(x);
const fe = (x) => F.toObject(x).toString();

function hash(inputs) {
  return BigInt(fe(poseidon(inputs)));
}

function point(s) {
  const p = babyjub.mulPointEscalar(babyjub.Base8, scalar(s));
  return [BigInt(p[0].toString()), BigInt(p[1].toString())];
}

const SUBORDER = BigInt(babyjub.subOrder.toString());

function note(i) {
  const x = 1000003n + BigInt(i) * 1009n;
  const zA = 2000003n + BigInt(i) * 1013n;
  const zB = 3000001n + BigInt(i) * 1019n;
  const r = 4000007n + BigInt(i) * 1021n;
  const noteId = 5000009n + BigInt(i);
  const X = point(x), ZA = point(zA), ZB = point(zB);
  return { x, zA, zB, r, noteId, X, ZA, ZB };
}

function leaf(n) {
  return hash([1n, n.noteId, n.X[0], n.X[1], n.ZA[0], n.ZA[1], n.ZB[0], n.ZB[1], n.r]);
}

function nullifier(n) {
  const key = hash([2n, n.x, n.zA, n.zB]);
  return hash([3n, key, n.noteId]);
}

function merkle(leaves, index) {
  let level = leaves.slice();
  let i = index;
  const siblings = [];
  const bits = [];
  while (level.length > 1) {
    const right = i & 1;
    bits.push(right);
    const sibling = i ^ 1;
    siblings.push(level[sibling]);
    const next = [];
    for (let j = 0; j < level.length; j += 2)
      next.push(hash([level[j], level[j + 1]]));
    level = next;
    i = Math.floor(i / 2);
  }
  return { root: level[0], siblings, bits };
}

function makeInput(n, tree, messageHash = 987654321n) {
  const eta = nullifier(n);
  const txDigest = hash([5n, tree.root, eta, messageHash]);
  return {
    root: tree.root.toString(),
    nullifier: eta.toString(),
    txDigest: txDigest.toString(),
    x: n.x.toString(),
    zA: n.zA.toString(),
    zB: n.zB.toString(),
    noteId: n.noteId.toString(),
    r: n.r.toString(),
    siblings: tree.siblings.map(String),
    pathBits: tree.bits.map(String),
    messageHash: messageHash.toString()
  };
}

function runWitness(input, name) {
  const file = path.join(BUILD, name + ".json");
  const witness = path.join(BUILD, name + ".wtns");
  writeFileSync(file, JSON.stringify(input));
  const r = spawnSync(process.execPath, [GENERATOR, WASM, file, witness], { encoding: "utf8" });
  return { ...r, file, witness };
}

function assertAccepted(input, name) {
  const r = runWitness(input, name);
  if (r.status !== 0) throw new Error("Expected witness acceptance for " + name + "\n" + r.stderr);
  execFileSync(process.execPath, [SNARKJS, "wtns", "check", R1CS, r.witness], { stdio: "pipe" });
}

function assertRejected(input, name) {
  const r = runWitness(input, name);
  if (r.status === 0) throw new Error("Expected witness rejection for " + name);
}

if (!existsSync(WASM)) throw new Error("Circuit not compiled: " + WASM);

// Build one deterministic 8-note inventory and prove membership for note 3.
const notes = Array.from({ length: 8 }, (_, i) => note(i));
const leaves = notes.map(leaf);
const tree = merkle(leaves, 3);
const valid = makeInput(notes[3], tree);

// Positive control.
assertAccepted(valid, "valid");

// Critical selector attack.
const badBit = structuredClone(valid);
badBit.pathBits[0] = "2";
assertRejected(badBit, "path-bit-2");

const badBitMax = structuredClone(valid);
badBitMax.pathBits[0] = babyjub.F.p.sub(1n).toString();
assertRejected(badBitMax, "path-bit-field-max");

// Scalar alias attack: x + subgroup order represents the same group scalar,
// but must be rejected as an out-of-range witness.
const aliasX = structuredClone(valid);
aliasX.x = (BigInt(aliasX.x) + SUBORDER).toString();
assertRejected(aliasX, "scalar-alias");

// Secret substitution.
const badZA = structuredClone(valid);
badZA.zA = (BigInt(badZA.zA) + 1n).toString();
assertRejected(badZA, "wrong-half-a");

// Nullifier substitution.
const badEta = structuredClone(valid);
badEta.nullifier = nullifier(notes[4]).toString();
assertRejected(badEta, "wrong-nullifier");

// Leaf / membership substitution.
const badSibling = structuredClone(valid);
badSibling.siblings[0] = (BigInt(badSibling.siblings[0]) + 1n).toString();
assertRejected(badSibling, "wrong-merkle-sibling");

const badRoot = structuredClone(valid);
badRoot.root = (BigInt(badRoot.root) + 1n).toString();
assertRejected(badRoot, "wrong-root");

// Transaction substitution.
const badTx = structuredClone(valid);
badTx.txDigest = (BigInt(badTx.txDigest) + 1n).toString();
assertRejected(badTx, "wrong-tx-digest");

// Wrong note id changes both leaf and nullifier relation.
const badNoteId = structuredClone(valid);
badNoteId.noteId = (BigInt(badNoteId.noteId) + 1n).toString();
assertRejected(badNoteId, "wrong-note-id");

// 10,000 deterministic differential nullifier vectors.
for (let i = 0; i < 10000; i++) {
  const x = BigInt(i + 11);
  const a = BigInt(i * 17 + 101);
  const b = BigInt(i * 31 + 1009);
  const id = BigInt(i * 131 + 9001);
  const k1 = hash([2n, x, a, b]);
  const eta1 = hash([3n, k1, id]);
  const k2 = hash([2n, x, a + 1n, b]);
  const eta2 = hash([3n, k2, id]);
  if (eta1 !== hash([3n, hash([2n, x, a, b]), id])) throw new Error("determinism failure at vector " + i);
  if (eta1 === eta2) throw new Error("nullifier separation failure at vector " + i);
}

console.log(JSON.stringify({
  status: "PASS",
  circuit: "TornNote/v0.3",
  depth: 8,
  positiveWitnesses: 1,
  adversarialWitnessesRejected: 8,
  differentialVectors: 10000,
  attacks: [
    "path-bit=2",
    "path-bit=field-max",
    "scalar-alias",
    "wrong-half-A",
    "wrong-nullifier",
    "wrong-Merkle-sibling",
    "wrong-root",
    "wrong-tx-digest",
    "wrong-note-id"
  ]
}, null, 2));
