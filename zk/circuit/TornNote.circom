pragma circom 2.2.2;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/babyjub.circom";
include "node_modules/circomlib/circuits/bitify.circom";
include "node_modules/circomlib/circuits/compconstant.circom";

template ValidBabyJubScalar() {
    signal input in;
    component bits = Num2Bits(253);
    bits.in <== in;

    component range = CompConstant(2736030358979909402780800718157159386076813972158567259200215660948447373040);
    for (var i = 0; i < 253; i++) {
        bits.out[i] ==> range.in[i];
    }
    range.in[253] <== 0;
    range.out === 0;
}

template PrivateMerkleMembership(depth) {
    signal input leaf;
    signal input siblings[depth];
    signal input pathBits[depth];
    signal output root;

    signal cur[depth + 1];
    signal left[depth];
    signal right[depth];
    cur[0] <== leaf;

    component hashes[depth];

    for (var i = 0; i < depth; i++) {
        // SECURITY CRITICAL: pathBits must be a Boolean field element.
        pathBits[i] * (pathBits[i] - 1) === 0;

        // One multiplication per selector keeps each constraint quadratic.
        left[i] <== cur[i] + pathBits[i] * (siblings[i] - cur[i]);
        right[i] <== siblings[i] + pathBits[i] * (cur[i] - siblings[i]);

        hashes[i] = Poseidon(2);
        hashes[i].inputs[0] <== left[i];
        hashes[i].inputs[1] <== right[i];
        cur[i + 1] <== hashes[i].out;
    }

    root <== cur[depth];
}

template TornNote(depth) {
    // Public statement.
    signal input root;
    signal input nullifier;
    signal input txDigest;

    // Private witness.
    signal input x;
    signal input zA;
    signal input zB;
    signal input noteId;
    signal input r;
    signal input siblings[depth];
    signal input pathBits[depth];
    signal input messageHash;

    // Prevent scalar aliases and enforce x,zA,zB < BabyJubjub subgroup order.
    component sx = ValidBabyJubScalar();
    component sa = ValidBabyJubScalar();
    component sb = ValidBabyJubScalar();
    sx.in <== x;
    sa.in <== zA;
    sb.in <== zB;

    // BabyPbk multiplies by Base8, so derived points are in the prime subgroup.
    // There are deliberately no externally supplied point witnesses.
    component masterPoint = BabyPbk();
    component pointA = BabyPbk();
    component pointB = BabyPbk();
    masterPoint.in <== x;
    pointA.in <== zA;
    pointB.in <== zB;

    // Domain-separated leaf:
    // Poseidon(LEAF_DOMAIN, noteId, Xx, Xy, ZAx, ZAy, ZBx, ZBy, r)
    component leafHash = Poseidon(9);
    leafHash.inputs[0] <== 1;
    leafHash.inputs[1] <== noteId;
    leafHash.inputs[2] <== masterPoint.Ax;
    leafHash.inputs[3] <== masterPoint.Ay;
    leafHash.inputs[4] <== pointA.Ax;
    leafHash.inputs[5] <== pointA.Ay;
    leafHash.inputs[6] <== pointB.Ax;
    leafHash.inputs[7] <== pointB.Ay;
    leafHash.inputs[8] <== r;

    component membership = PrivateMerkleMembership(depth);
    membership.leaf <== leafHash.out;
    for (var i = 0; i < depth; i++) {
        membership.siblings[i] <== siblings[i];
        membership.pathBits[i] <== pathBits[i];
    }
    membership.root === root;

    // K_N = Poseidon(NULLIFIER_KEY_DOMAIN, x, zA, zB)
    component nullifierKey = Poseidon(4);
    nullifierKey.inputs[0] <== 2;
    nullifierKey.inputs[1] <== x;
    nullifierKey.inputs[2] <== zA;
    nullifierKey.inputs[3] <== zB;

    // eta = Poseidon(NULLIFIER_DOMAIN, K_N, noteId)
    component eta = Poseidon(3);
    eta.inputs[0] <== 3;
    eta.inputs[1] <== nullifierKey.out;
    eta.inputs[2] <== noteId;
    eta.out === nullifier;

    // txDigest binds the public transaction context to the private message hash.
    component txWithMessage = Poseidon(4);
    txWithMessage.inputs[0] <== 5;
    txWithMessage.inputs[1] <== root;
    txWithMessage.inputs[2] <== nullifier;
    txWithMessage.inputs[3] <== messageHash;
    txWithMessage.out === txDigest;
}

component main {public [root, nullifier, txDigest]} = TornNote(8);
