package io.tornnote.wallet;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

final class Hashes {
    private Hashes() {}

    static byte[] sha256(byte[]... values) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (byte[] value : values) digest.update(value);
            return digest.digest();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256-is-required", impossible);
        }
    }
}
