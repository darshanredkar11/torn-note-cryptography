package io.tornnote.wallet;

import io.tornnote.TornNote;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Same-machine micro-benchmark; rotates implementation order and reports the median of three rounds. */
public final class ComparisonRunner {
    private static final int ROUNDS = 3;
    private static final int WARMUP = 150;
    private ComparisonRunner() {}

    public static void main(String[] args) throws Exception {
        int iterations = args.length == 0 ? 1500 : Integer.parseInt(args[0]);
        if (iterations < 100) throw new IllegalArgumentException("Use at least 100 iterations");
        var f = new AuthorizationComparison.TornFixture();
        var signers = f.allSignerKeys();
        var singlePublic = f.master.pair().getPublic();
        var multiPublic = signers.stream().map(KeyPair::getPublic).toList();
        double[] single = new double[ROUNDS], multi = new double[ROUNDS], torn = new double[ROUNDS];

        for (int round = 0; round < ROUNDS; round++) {
            // Rotate order to reduce systematic warm-up/order bias.
            switch (round) {
                case 0 -> {
                    single[round] = measure(WARMUP, iterations, i -> single(singlePublic, f.master.pair(), i));
                    multi[round] = measure(WARMUP, iterations, i -> multi(multiPublic, signers, i));
                    torn[round] = measure(WARMUP, iterations, i -> torn(f, i));
                }
                case 1 -> {
                    torn[round] = measure(WARMUP, iterations, i -> torn(f, i));
                    single[round] = measure(WARMUP, iterations, i -> single(singlePublic, f.master.pair(), i));
                    multi[round] = measure(WARMUP, iterations, i -> multi(multiPublic, signers, i));
                }
                default -> {
                    multi[round] = measure(WARMUP, iterations, i -> multi(multiPublic, signers, i));
                    torn[round] = measure(WARMUP, iterations, i -> torn(f, i));
                    single[round] = measure(WARMUP, iterations, i -> single(singlePublic, f.master.pair(), i));
                }
            }
        }

        System.out.println("Torn Note / conventional authorization comparison");
        System.out.println("Environment: " + System.getProperty("java.vm.name") + " " + System.getProperty("java.version"));
        System.out.println("Rounds: " + ROUNDS + " · iterations/round: " + iterations + " · warm-up/round: " + WARMUP);
        System.out.println();
        System.out.println("| Model | Median mean µs/op | Signature count | Extra authorization state |");
        System.out.println("|---|---:|---:|---|");
        System.out.printf("| Single-key Ed25519 | %.2f | 1 | Transaction nonce / replay store |%n", median(single));
        System.out.printf("| Conventional 3-of-3 Ed25519 | %.2f | 3 | Signer policy + transaction nonce / replay store |%n", median(multi));
        System.out.printf("| Torn Note 3-of-3 | %.2f | 3 | Pre-issued Merkle inventory + spent-note state |%n", median(torn));
        System.out.println();
        System.out.println("Each operation signs and verifies one transaction. Torn Note also checks Merkle membership before signing and during verification.");
        System.out.println("Micro-benchmark only: excludes key generation, HTTP/database/network costs, durable storage, HSMs and identity proofing.");
        System.out.println("Conventional 3-of-3 is the closer cryptographic control; this benchmark does not establish a security superiority.");
    }

    @FunctionalInterface private interface Operation { void run(int i) throws Exception; }

    private static double measure(int warmup, int iterations, Operation op) throws Exception {
        for (int i = 0; i < warmup; i++) op.run(i);
        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) op.run(i + warmup);
        return (System.nanoTime() - start) / 1000.0 / iterations;
    }

    private static double median(double[] values) {
        double[] sorted = values.clone();
        Arrays.sort(sorted);
        return sorted[sorted.length / 2];
    }

    private static void single(PublicKey pub, KeyPair key, int i) throws Exception {
        String tx = tx(i);
        byte[] sig = AuthorizationComparison.sign(key, tx);
        if (!AuthorizationComparison.verify(pub, tx, sig)) throw new AssertionError("single-key verification failed");
    }

    private static void multi(List<PublicKey> pubs, List<KeyPair> keys, int i) throws Exception {
        String tx = tx(i);
        List<byte[]> signatures = AuthorizationComparison.signAll(keys, tx);
        for (int n = 0; n < pubs.size(); n++)
            if (!AuthorizationComparison.verify(pubs.get(n), tx, signatures.get(n)))
                throw new AssertionError("multisig verification failed");
    }

    private static void torn(AuthorizationComparison.TornFixture f, int i) throws Exception {
        String tx = tx(i);
        TornNote.SignatureSet sig = f.authorize(tx, true, true, true);
        if (!f.verify(tx, sig, false)) throw new AssertionError("Torn Note verification failed");
    }

    private static String tx(int i) {
        return "{\"operation\":\"CHANGE_SUPPLIER_BANK_ACCOUNT\",\"supplier\":\"ACME\","
                + "\"authorizationNoteId\":\"wallet-note-3\",\"account\":\"XX-4821\",\"amount\":850000,\"currency\":\"INR\","
                + "\"requestId\":\"BENCH-" + i + "\"}";
    }
}
