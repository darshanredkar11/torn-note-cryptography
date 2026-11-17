package io.tornnote.wallet;

import io.tornnote.TornNote;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class BusinessIdentityWalletTest {
    @Test void compiledLibraryBindsAuthorizationToExactTransaction() throws Exception {
        var master=TornNote.keys("ed25519"); var a=TornNote.keys("ed25519"); var b=TornNote.keys("ed25519");
        byte[] id="supplier-change-001".getBytes(StandardCharsets.UTF_8);
        byte[] leaf=TornNote.leaf(id,TornNote.pub(a.pair()),TornNote.pub(b.pair()));
        List<byte[]> leaves=List.of(leaf); byte[] root=TornNote.root(leaves); var proof=TornNote.proof(leaves,0);
        String approved="{\"account\":\"XX-4821\",\"amount\":850000}";
        var sig=TornNote.authorize(master,a,b,root,id,TornNote.pub(a.pair()),TornNote.pub(b.pair()),approved,proof,0);
        assertTrue(TornNote.verifyAuthorization(master.pair().getPublic(),a.pair().getPublic(),b.pair().getPublic(),
                root,id,TornNote.pub(a.pair()),TornNote.pub(b.pair()),approved,proof,0,sig,false));
        assertFalse(TornNote.verifyAuthorization(master.pair().getPublic(),a.pair().getPublic(),b.pair().getPublic(),
                root,id,TornNote.pub(a.pair()),TornNote.pub(b.pair()),"{\"account\":\"XX-9999\",\"amount\":850000}",proof,0,sig,false));
        assertFalse(TornNote.verifyAuthorization(master.pair().getPublic(),a.pair().getPublic(),b.pair().getPublic(),
                root,id,TornNote.pub(a.pair()),TornNote.pub(b.pair()),approved,proof,0,sig,true));
    }

    @Test void masterKeyAloneCannotAuthorize() throws Exception {
        var master=TornNote.keys("ed25519"); var a=TornNote.keys("ed25519"); var b=TornNote.keys("ed25519");
        byte[] id="supplier-change-002".getBytes(StandardCharsets.UTF_8);
        byte[] leaf=TornNote.leaf(id,TornNote.pub(a.pair()),TornNote.pub(b.pair()));
        List<byte[]> leaves=List.of(leaf); byte[] root=TornNote.root(leaves); var proof=TornNote.proof(leaves,0);
        String tx="account=XX-4821;amount=850000";
        var masterOnly=TornNote.authorizeAvailable(master,a,b,root,id,TornNote.pub(a.pair()),TornNote.pub(b.pair()),
                tx,proof,0,true,false,false);
        assertFalse(TornNote.verifyAuthorization(master.pair().getPublic(),a.pair().getPublic(),b.pair().getPublic(),
                root,id,TornNote.pub(a.pair()),TornNote.pub(b.pair()),tx,proof,0,masterOnly,false));
    }
}
