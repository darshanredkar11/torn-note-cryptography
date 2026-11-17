package io.tornnote.wallet;

import io.tornnote.TornNote;
import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import java.util.List;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class AuthorizationComparisonTest {
    private static final String TX =
            "{\"operation\":\"CHANGE_SUPPLIER_BANK_ACCOUNT\",\"supplier\":\"ACME\","
            + "\"authorizationNoteId\":\"wallet-note-3\",\"account\":\"XX-4821\",\"amount\":850000,\"currency\":\"INR\",
            + "\"requestId\":\"REQ-1001\"}";

    @Test void legitimateOperationWorksAcrossAllThreeModels() throws Exception {
        var f = new AuthorizationComparison.TornFixture();
        var single = new AuthorizationComparison.ConventionalVerifier(List.of(f.master.pair().getPublic()));
        var multi = new AuthorizationComparison.ConventionalVerifier(
                f.allSignerKeys().stream().map(KeyPair::getPublic).toList());

        assertTrue(single.verifyAndConsume(TX,
                AuthorizationComparison.signAll(List.of(f.master.pair()), TX)));
        assertTrue(multi.verifyAndConsume(TX,
                AuthorizationComparison.signAll(f.allSignerKeys(), TX)));
        var note = f.authorize(TX, true, true, true);
        assertTrue(f.verify(TX, note, false));
    }

    @Test void stolenMasterKeyIsEnoughForSingleKeyButNotForThreeFactorModels() throws Exception {
        var f = new AuthorizationComparison.TornFixture();
        var single = new AuthorizationComparison.ConventionalVerifier(List.of(f.master.pair().getPublic()));
        var multi = new AuthorizationComparison.ConventionalVerifier(
                f.allSignerKeys().stream().map(KeyPair::getPublic).toList());

        // Attacker has the employee's sole signing key.
        assertTrue(single.verifyAndConsume(TX,
                List.of(AuthorizationComparison.sign(f.master.pair(), TX))));

        // The same stolen key cannot provide signatures from the two enrolled fragments.
        assertFalse(multi.verifyAndConsume(TX,
                List.of(AuthorizationComparison.sign(f.master.pair(), TX))));
        TornNote.SignatureSet masterOnly = f.authorize(TX, true, false, false);
        assertFalse(f.verify(TX, masterOnly, false));
    }

    @Test void threeOfThreeMultisignatureHasSameFactorCompromiseResistance() throws Exception {
        var f = new AuthorizationComparison.TornFixture();
        var multi = new AuthorizationComparison.ConventionalVerifier(
                f.allSignerKeys().stream().map(KeyPair::getPublic).toList());
        assertFalse(multi.verifyAndConsume(TX,
                List.of(AuthorizationComparison.sign(f.master.pair(), TX))));
        assertFalse(f.verify(TX, f.authorize(TX, true, false, false), false));
    }

    @Test void anyMissingTornNoteFactorCausesRejection() throws Exception {
        var f = new AuthorizationComparison.TornFixture();
        assertFalse(f.verify(TX, f.authorize(TX, true, true, false), false));
        assertFalse(f.verify(TX, f.authorize(TX, true, false, true), false));
        assertFalse(f.verify(TX, f.authorize(TX, false, true, true), false));
    }

    @Test void transactionTamperingIsRejectedByAllModels() throws Exception {
        var f = new AuthorizationComparison.TornFixture();
        String changed = TX.replace("XX-4821", "XX-9999");
        var singleSig = AuthorizationComparison.sign(f.master.pair(), TX);
        var multiSigs = AuthorizationComparison.signAll(f.allSignerKeys(), TX);
        var tornSig = f.authorize(TX, true, true, true);

        assertFalse(new AuthorizationComparison.ConventionalVerifier(List.of(f.master.pair().getPublic()))
                .verifyAndConsume(changed, List.of(singleSig)));
        assertFalse(new AuthorizationComparison.ConventionalVerifier(
                f.allSignerKeys().stream().map(KeyPair::getPublic).toList())
                .verifyAndConsume(changed, multiSigs));
        assertFalse(f.verify(changed, tornSig, false));
    }

    @Test void replayIsRejectedWhenConventionalBaselineAlsoUsesOneTimeState() throws Exception {
        var f = new AuthorizationComparison.TornFixture();
        var single = new AuthorizationComparison.ConventionalVerifier(List.of(f.master.pair().getPublic()));
        byte[] singleSig = AuthorizationComparison.sign(f.master.pair(), TX);
        assertTrue(single.verifyAndConsume(TX, List.of(singleSig)));
        assertFalse(single.verifyAndConsume(TX, List.of(singleSig)));

        var multi = new AuthorizationComparison.ConventionalVerifier(
                f.allSignerKeys().stream().map(KeyPair::getPublic).toList());
        var multiSig = AuthorizationComparison.signAll(f.allSignerKeys(), TX);
        assertTrue(multi.verifyAndConsume(TX, multiSig));
        assertFalse(multi.verifyAndConsume(TX, multiSig));

        var note = f.authorize(TX, true, true, true);
        assertTrue(f.verify(TX, note, false));
        assertFalse(f.verify(TX, note, true));
    }

    @Test void tornNoteRejectsAnUnissuedAuthorizationObject() throws Exception {
        var f = new AuthorizationComparison.TornFixture();
        var forgedA = TornNote.keys("ed25519");
        var forgedB = TornNote.keys("ed25519");
        byte[] forgedId = "not-issued-by-company".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // Conventional 3-of-3 multisig can sign this transaction: it has no
        // built-in pre-issued note inventory requirement.
        var multi = new AuthorizationComparison.ConventionalVerifier(
                f.allSignerKeys().stream().map(KeyPair::getPublic).toList());
        String fabricated = TX.replace("wallet-note-3", "not-issued-by-company");
        assertTrue(multi.verifyAndConsume(fabricated,
                AuthorizationComparison.signAll(f.allSignerKeys(), fabricated)));

        // Torn Note rejects the forged leaf against the issuer-pinned root.
        assertThrows(SecurityException.class, () -> TornNote.authorize(f.master, forgedA, forgedB,
                f.root, forgedId, TornNote.pub(forgedA.pair()), TornNote.pub(forgedB.pair()),
                fabricated, f.proof, f.selectedIndex));
    }
}
