package io.tornnote.wallet;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.regex.Pattern;

/** Immutable fixed-schema transaction representation for cross-protocol authorization. */
public final class TransactionEnvelopeV1 {
    private static final byte[] DIGEST_DOMAIN =
            "TORN-NOTE/transaction/v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final Pattern PAYLOAD_KEY = Pattern.compile("[a-z][a-z0-9_]{0,63}");

    private final String transactionId, tenantId, subjectId, audience;
    private final String actionType, targetId, resourceVersion, policyVersion;
    private final Map<String, String> payloadFields;
    private final byte[] nonce;
    private final long issuedAtEpochMillis, expiresAtEpochMillis;

    public TransactionEnvelopeV1(String transactionId, String tenantId, String subjectId, String audience,
                                  String actionType, String targetId, String resourceVersion,
                                  String policyVersion, Map<String, String> payloadFields,
                                  byte[] nonce, Instant issuedAt, Instant expiresAt) {
        this.transactionId = text("transactionId", transactionId);
        this.tenantId = text("tenantId", tenantId);
        this.subjectId = text("subjectId", subjectId);
        this.audience = text("audience", audience);
        this.actionType = text("actionType", actionType);
        this.targetId = text("targetId", targetId);
        this.resourceVersion = text("resourceVersion", resourceVersion);
        this.policyVersion = text("policyVersion", policyVersion);
        Objects.requireNonNull(payloadFields, "payloadFields");
        TreeMap<String, String> sorted = new TreeMap<>();
        payloadFields.forEach((key, value) -> {
            if (key == null || !PAYLOAD_KEY.matcher(key).matches())
                throw new IllegalArgumentException("invalid-payload-key");
            sorted.put(key, text("payload value", value));
        });
        this.payloadFields = Collections.unmodifiableMap(sorted);
        if (nonce == null || nonce.length != 32)
            throw new IllegalArgumentException("nonce-must-be-32-bytes");
        this.nonce = nonce.clone();
        this.issuedAtEpochMillis = Objects.requireNonNull(issuedAt, "issuedAt").toEpochMilli();
        this.expiresAtEpochMillis = Objects.requireNonNull(expiresAt, "expiresAt").toEpochMilli();
        if (this.expiresAtEpochMillis <= this.issuedAtEpochMillis)
            throw new IllegalArgumentException("expiresAt-must-follow-issuedAt");
    }

    private static String text(String name, String value) {
        Objects.requireNonNull(value, name);
        if (value.isBlank() || value.indexOf('\0') >= 0)
            throw new IllegalArgumentException(name + "-must-be-nonblank-and-contain-no-NUL");
        if (!Normalizer.isNormalized(value, Normalizer.Form.NFC))
            throw new IllegalArgumentException(name + "-must-be-Unicode-NFC");
        return value;
    }

    private static void writeBytes(DataOutputStream out, byte[] value) throws IOException {
        out.writeInt(value.length);
        out.write(value);
    }

    private static void writeText(DataOutputStream out, String value) throws IOException {
        writeBytes(out, value.getBytes(StandardCharsets.UTF_8));
    }

    /** Canonical fixed-schema bytes; callers cannot supply a pre-serialized transaction. */
    public byte[] canonicalBytes() {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeInt(1);
            writeText(out, transactionId);
            writeText(out, tenantId);
            writeText(out, subjectId);
            writeText(out, audience);
            writeText(out, actionType);
            writeText(out, targetId);
            writeText(out, resourceVersion);
            writeText(out, policyVersion);
            out.writeInt(payloadFields.size());
            for (Map.Entry<String, String> entry : payloadFields.entrySet()) {
                writeText(out, entry.getKey());
                writeText(out, entry.getValue());
            }
            writeBytes(out, nonce);
            out.writeLong(issuedAtEpochMillis);
            out.writeLong(expiresAtEpochMillis);
            out.flush();
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException("in-memory-canonical-encoding-failed", impossible);
        }
    }

    public byte[] digest() { return Hashes.sha256(DIGEST_DOMAIN, canonicalBytes()); }

    public boolean isValidAt(Instant now) {
        long millis = Objects.requireNonNull(now, "now").toEpochMilli();
        return millis >= issuedAtEpochMillis && millis < expiresAtEpochMillis;
    }

    public String transactionId() { return transactionId; }
    public String tenantId() { return tenantId; }
    public String subjectId() { return subjectId; }
    public String audience() { return audience; }
    public String actionType() { return actionType; }
    public String targetId() { return targetId; }
    public String resourceVersion() { return resourceVersion; }
    public String policyVersion() { return policyVersion; }
    public Map<String, String> payloadFields() { return payloadFields; }
    public byte[] nonce() { return nonce.clone(); }
    public Instant issuedAt() { return Instant.ofEpochMilli(issuedAtEpochMillis); }
    public Instant expiresAt() { return Instant.ofEpochMilli(expiresAtEpochMillis); }
}
