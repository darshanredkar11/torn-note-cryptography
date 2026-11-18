package io.tornnote.wallet;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;

/** Stable, privacy-preserving Yubico username derived from a tenant-scoped subject. */
public final class WebAuthnIdentity {
    private static final byte[] DOMAIN =
            "TORN-NOTE/WEBAUTHN-USERNAME/v1\0".getBytes(StandardCharsets.US_ASCII);
    private WebAuthnIdentity() {}

    public static String usernameFor(String tenantId, String subjectId) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(subjectId, "subjectId");
        if (tenantId.isBlank() || subjectId.isBlank())
            throw new IllegalArgumentException("tenant-and-subject-required");
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            write(out, tenantId);
            write(out, subjectId);
            out.flush();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(DOMAIN);
            return "tn1_" + Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(digest.digest(bytes.toByteArray()));
        } catch (IOException impossible) {
            throw new IllegalStateException("in-memory-encoding-failed", impossible);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256-is-required", impossible);
        }
    }

    private static void write(DataOutputStream out, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(encoded.length);
        out.write(encoded);
    }
}
