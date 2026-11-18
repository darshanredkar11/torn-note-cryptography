package io.tornnote.wallet;

/** Adapter boundary around the standards-based WebAuthn relying-party implementation. */
public interface WebAuthnAssertionEngine {
    PreparedAssertion start(String subjectId) throws Exception;
    VerifiedAssertion finish(String assertionRequestJson, String assertionResponseJson) throws Exception;

    record PreparedAssertion(String assertionRequestJson, String credentialGetOptionsJson) {
        public PreparedAssertion {
            if (assertionRequestJson == null || assertionRequestJson.isBlank())
                throw new IllegalArgumentException("assertion-request-json-required");
            if (credentialGetOptionsJson == null || credentialGetOptionsJson.isBlank())
                throw new IllegalArgumentException("credential-get-options-json-required");
        }
    }

    record VerifiedAssertion(boolean success, boolean userVerified, String username,
                             String credentialIdBase64Url, long signatureCount) {}
    
    @FunctionalInterface
    interface CredentialStateUpdater {
        /** Persist the newest signature counter with an optimistic/atomic update. */
        void update(String username, String credentialIdBase64Url, long signatureCount) throws Exception;
    }
}
