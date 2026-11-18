package io.tornnote.wallet;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.UserVerificationRequirement;

import java.util.Objects;

/**
 * Production WebAuthn protocol adapter using Yubico's maintained server library.
 * CredentialRepository, relying-party identity/origins and durable credential
 * state remain application-owned dependencies.
 */
public final class YubicoWebAuthnAssertionEngine implements WebAuthnAssertionEngine {
    private final RelyingParty relyingParty;
    private final CredentialStateUpdater credentialStateUpdater;

    public YubicoWebAuthnAssertionEngine(
            RelyingParty relyingParty, CredentialStateUpdater credentialStateUpdater) {
        this.relyingParty = Objects.requireNonNull(relyingParty, "relyingParty");
        this.credentialStateUpdater = Objects.requireNonNull(credentialStateUpdater, "credentialStateUpdater");
    }

    @Override
    public PreparedAssertion start(String subjectId) throws Exception {
        AssertionRequest request = relyingParty.startAssertion(StartAssertionOptions.builder()
                .username(subjectId)
                .userVerification(UserVerificationRequirement.REQUIRED)
                .build());
        // Persist the full AssertionRequest, not just a naked challenge. Its options
        // include the exact relying-party challenge that finishAssertion must verify.
        return new PreparedAssertion(request.toJson(), request.toCredentialsGetJson());
    }

    @Override
    public VerifiedAssertion finish(String assertionRequestJson, String assertionResponseJson) throws Exception {
        AssertionRequest request = AssertionRequest.fromJson(assertionRequestJson);
        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> response =
                PublicKeyCredential.parseAssertionResponseJson(assertionResponseJson);
        AssertionResult result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                .request(request)
                .response(response)
                .build());

        if (!result.isSuccess()) {
            return new VerifiedAssertion(false, false, null, null, 0);
        }

        String username = result.getUsername();
        String credentialId = result.getCredential().getCredentialId().getBase64Url();
        long signatureCount = result.getSignatureCount();
        credentialStateUpdater.update(username, credentialId, signatureCount);

        return new VerifiedAssertion(true, result.isUserVerified(), username, credentialId, signatureCount);
    }
}
