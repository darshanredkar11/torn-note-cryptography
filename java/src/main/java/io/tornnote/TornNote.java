package io.tornnote;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

public final class TornNote {
    private TornNote() {}

    static final byte[] L = "TORN-NOTE/leaf/v1".getBytes(StandardCharsets.UTF_8);
    static final byte[] T = "TORN-NOTE/tx/v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] BOUND_AUTHORIZATION_DOMAIN =
            "TORN-NOTE/bound-authorization/v1\0".getBytes(StandardCharsets.US_ASCII);

    public record Keys(KeyPair pair, String algorithm) {}
    public record Note(byte[] id, Keys a, Keys b) {}
    public record SignatureSet(byte[] master, byte[] a, byte[] b) {}

    public static Keys keys(String curve) throws GeneralSecurityException {
        KeyPairGenerator generator;
        if (curve.equals("ed25519")) generator = KeyPairGenerator.getInstance("Ed25519");
        else if (curve.equals("p256")) {
            generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
        } else throw new IllegalArgumentException("unsupported-key-algorithm");
        return new Keys(generator.generateKeyPair(), curve);
    }

    static byte[] h(byte[]... values) throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (byte[] value : values) digest.update(value);
        return digest.digest();
    }

    public static byte[] pub(KeyPair pair) { return pair.getPublic().getEncoded(); }

    public static byte[] leaf(byte[] id, byte[] a, byte[] b) throws GeneralSecurityException {
        return h(L, id, a, b);
    }

    public static byte[] root(List<byte[]> leaves) throws GeneralSecurityException {
        if (leaves.isEmpty()) throw new IllegalArgumentException("empty-merkle-tree");
        List<byte[]> level = new ArrayList<>(leaves);
        while (level.size() > 1) {
            List<byte[]> next = new ArrayList<>();
            for (int i = 0; i < level.size(); i += 2)
                next.add(h(level.get(i), i + 1 < level.size() ? level.get(i + 1) : level.get(i)));
            level = next;
        }
        return level.get(0);
    }

    public static List<byte[]> proof(List<byte[]> leaves, int index) throws GeneralSecurityException {
        if (index < 0 || index >= leaves.size()) throw new IllegalArgumentException("merkle-index-out-of-range");
        List<byte[]> proof = new ArrayList<>();
        List<byte[]> level = new ArrayList<>(leaves);
        while (level.size() > 1) {
            int sibling = index ^ 1;
            proof.add((sibling < level.size() ? level.get(sibling) : level.get(index)).clone());
            List<byte[]> next = new ArrayList<>();
            for (int i = 0; i < level.size(); i += 2)
                next.add(h(level.get(i), i + 1 < level.size() ? level.get(i + 1) : level.get(i)));
            index /= 2;
            level = next;
        }
        return proof;
    }

    public static boolean verifyMerkle(byte[] value, List<byte[]> proof, byte[] root, int index)
            throws GeneralSecurityException {
        if (value == null || proof == null || root == null || index < 0) return false;
        for (byte[] sibling : proof) {
            if (sibling == null || sibling.length != 32) return false;
            value = (index & 1) == 0 ? h(value, sibling) : h(sibling, value);
            index >>= 1;
        }
        return MessageDigest.isEqual(value, root);
    }

    public static byte[] digest(byte[] root, byte[] id, byte[] a, byte[] b, String transaction)
            throws GeneralSecurityException {
        return h(T, root, id, a, b, transaction.getBytes(StandardCharsets.UTF_8));
    }

    private static void updateLengthPrefixed(MessageDigest digest, byte[] value) {
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(value.length).array());
        digest.update(value);
    }

    /**
     * V1 authorization digest. It is deliberately domain-separated from the legacy
     * transaction-signature profile and length-prefixes every variable-size field.
     */
    public static byte[] boundAuthorizationDigest(
            byte[] root, byte[] id, byte[] publicA, byte[] publicB, byte[] noteAuthorizationDigest)
            throws GeneralSecurityException {
        if (root == null || root.length != 32) throw new IllegalArgumentException("root-must-be-32-bytes");
        if (id == null || id.length == 0) throw new IllegalArgumentException("note-id-required");
        if (publicA == null || publicA.length == 0) throw new IllegalArgumentException("factor-a-key-required");
        if (publicB == null || publicB.length == 0) throw new IllegalArgumentException("factor-b-key-required");
        if (noteAuthorizationDigest == null || noteAuthorizationDigest.length != 32)
            throw new IllegalArgumentException("note-authorization-digest-must-be-32-bytes");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(BOUND_AUTHORIZATION_DOMAIN);
        updateLengthPrefixed(digest, root);
        updateLengthPrefixed(digest, id);
        updateLengthPrefixed(digest, publicA);
        updateLengthPrefixed(digest, publicB);
        updateLengthPrefixed(digest, noteAuthorizationDigest);
        return digest.digest();
    }

    public static SignatureSet authorizeBound(
            Keys master, Keys a, Keys b, byte[] root, byte[] id, byte[] publicA, byte[] publicB,
            byte[] noteAuthorizationDigest, List<byte[]> proof, int index) throws GeneralSecurityException {
        if (master == null || a == null || b == null) throw new IllegalArgumentException("all-three-keys-required");
        if (!verifyMerkle(leaf(id, publicA, publicB), proof, root, index))
            throw new SecurityException("note-not-in-inventory");
        byte[] digest = boundAuthorizationDigest(root, id, publicA, publicB, noteAuthorizationDigest);
        return new SignatureSet(sign(master.pair().getPrivate(), digest),
                sign(a.pair().getPrivate(), digest), sign(b.pair().getPrivate(), digest));
    }

    public static boolean verifyBoundAuthorization(
            PublicKey master, PublicKey a, PublicKey b, byte[] root, byte[] id,
            byte[] publicA, byte[] publicB, byte[] noteAuthorizationDigest,
            List<byte[]> proof, int index, SignatureSet signatures, boolean spent)
            throws GeneralSecurityException {
        if (spent || master == null || a == null || b == null || signatures == null
                || signatures.master() == null || signatures.a() == null || signatures.b() == null)
            return false;
        if (!verifyMerkle(leaf(id, publicA, publicB), proof, root, index)) return false;
        byte[] digest = boundAuthorizationDigest(root, id, publicA, publicB, noteAuthorizationDigest);
        return verify(master, digest, signatures.master())
                && verify(a, digest, signatures.a())
                && verify(b, digest, signatures.b());
    }

    static byte[] sign(PrivateKey key, byte[] data) throws GeneralSecurityException {
        Signature signer = signatureFor(key);
        signer.initSign(key);
        signer.update(data);
        return signer.sign();
    }

    static boolean verify(PublicKey key, byte[] data, byte[] signature) throws GeneralSecurityException {
        Signature verifier = signatureFor(key);
        verifier.initVerify(key);
        verifier.update(data);
        return verifier.verify(signature);
    }

    private static Signature signatureFor(Key key) throws GeneralSecurityException {
        String algorithm = key.getAlgorithm();
        return algorithm.equalsIgnoreCase("EdDSA") || algorithm.equalsIgnoreCase("Ed25519")
                ? Signature.getInstance("Ed25519") : Signature.getInstance("SHA256withECDSA");
    }

    public static SignatureSet authorize(
            Keys master, Keys a, Keys b, byte[] root, byte[] id, byte[] publicA, byte[] publicB,
            String transaction, List<byte[]> proof, int index) throws GeneralSecurityException {
        return authorizeAvailable(master, a, b, root, id, publicA, publicB,
                transaction, proof, index, true, true, true);
    }

    public static SignatureSet authorizeAvailable(
            Keys master, Keys a, Keys b, byte[] root, byte[] id, byte[] publicA, byte[] publicB,
            String transaction, List<byte[]> proof, int index,
            boolean useMaster, boolean useA, boolean useB) throws GeneralSecurityException {
        if (!verifyMerkle(leaf(id, publicA, publicB), proof, root, index))
            throw new SecurityException("note-not-in-inventory");
        byte[] digest = digest(root, id, publicA, publicB, transaction);
        return new SignatureSet(useMaster ? sign(master.pair().getPrivate(), digest) : null,
                useA ? sign(a.pair().getPrivate(), digest) : null,
                useB ? sign(b.pair().getPrivate(), digest) : null);
    }

    public static boolean verifyAuthorization(
            PublicKey master, PublicKey a, PublicKey b, byte[] root, byte[] id,
            byte[] publicA, byte[] publicB, String transaction, List<byte[]> proof,
            int index, SignatureSet signatures, boolean spent) throws GeneralSecurityException {
        if (spent || signatures == null || signatures.master() == null
                || signatures.a() == null || signatures.b() == null
                || !verifyMerkle(leaf(id, publicA, publicB), proof, root, index)) return false;
        byte[] digest = digest(root, id, publicA, publicB, transaction);
        return verify(master, digest, signatures.master())
                && verify(a, digest, signatures.a()) && verify(b, digest, signatures.b());
    }
}
