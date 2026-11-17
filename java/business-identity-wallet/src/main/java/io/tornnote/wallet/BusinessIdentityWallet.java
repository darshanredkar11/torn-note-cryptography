package io.tornnote.wallet;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.tornnote.TornNote;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.concurrent.Executors;

/** Local business identity wallet demonstrator. Demo keys and spent state are in memory. */
public final class BusinessIdentityWallet {
    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
    private static final DemoState STATE = createState();
    private static DemoState createState() {
        try { return new DemoState(); }
        catch (GeneralSecurityException e) { throw new ExceptionInInitializerError(e); }
    }
    private BusinessIdentityWallet() {}

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", BusinessIdentityWallet::handle);
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();
        System.out.println("Torn Note Business Identity Wallet: http://localhost:" + port);
    }

    private static void handle(HttpExchange x) throws IOException {
        try {
            String path = x.getRequestURI().getPath();
            if ("GET".equals(x.getRequestMethod()) && "/".equals(path)) {
                byte[] page = html().getBytes(StandardCharsets.UTF_8);
                x.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
                x.sendResponseHeaders(200, page.length); x.getResponseBody().write(page); x.close(); return;
            }
            if ("GET".equals(x.getRequestMethod()) && "/api/status".equals(path)) { send(x, 200, STATE.status()); return; }
            if ("POST".equals(x.getRequestMethod()) && "/api/authorize".equals(path)) {
                send(x, 200, STATE.authorize(JSON.readValue(x.getRequestBody(), Map.class))); return;
            }
            if ("POST".equals(x.getRequestMethod()) && "/api/execute".equals(path)) {
                send(x, 200, STATE.execute(JSON.readValue(x.getRequestBody(), Map.class))); return;
            }
            send(x, 404, Map.of("ok", false, "error", "not-found"));
        } catch (Exception e) {
            send(x, 400, Map.of("ok", false, "error", Objects.toString(e.getMessage(), "request-failed")));
        }
    }

    private static void send(HttpExchange x, int status, Object value) throws IOException {
        byte[] bytes = JSON.writeValueAsBytes(value);
        x.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        x.getResponseHeaders().set("Cache-Control", "no-store");
        x.sendResponseHeaders(status, bytes.length); x.getResponseBody().write(bytes); x.close();
    }

    private static String html() {
        return """
          <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
          <title>Torn Note Business Identity Wallet</title><style>
          body{max-width:900px;margin:40px auto;padding:0 18px;background:#0b1020;color:#e8edf7;font:16px system-ui}
          .card{background:#151e33;border:1px solid #2a3856;border-radius:14px;padding:20px;margin:16px 0}
          .muted{color:#9aa8c2}button{background:#7c9cff;color:#071126;border:0;border-radius:9px;padding:11px 15px;margin:5px;cursor:pointer;font-weight:700}
          button.alt{background:#293957;color:#e8edf7}pre{white-space:pre-wrap;overflow-wrap:anywhere;color:#b8c8e8}
          </style></head><body><h1>Torn Note Business Identity Wallet</h1>
          <p class="muted">Finance controller authorization for a supplier bank-account change. A stolen identity key alone must not approve it.</p>
          <section class="card"><h2>Company-issued wallet</h2><div id="status">Loading…</div></section>
          <section class="card"><h2>Business operation</h2><p>Change ACME Components payment destination · INR 850,000 · account XX-4821</p>
          <button onclick="authorize('legitimate')">Authorize with all 3 factors</button>
          <button class="alt" onclick="authorize('master-only')">Simulate stolen identity key only</button>
          <button class="alt" onclick="execute(true)">Tamper with transaction</button>
          <button class="alt" onclick="execute(false)">Execute authorization</button>
          <button class="alt" onclick="execute(false)">Try replay</button></section>
          <section class="card"><h2>Verifier decision</h2><pre id="output">No attempt yet.</pre></section>
          <p class="muted">Research demo only: in-memory keys/state, no real identity proofing, payment rail, HSM or durable ledger.</p>
          <script>
          async function call(path,body){let r=await fetch(path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});return r.json()}
          async function refresh(){let s=await call('/api/status');document.getElementById('status').innerHTML='<b>Employee:</b> '+s.employee+'<br><b>Wallet:</b> '+s.walletId+'<br><b>Issued notes:</b> '+s.noteCount+'<br><b>Spent:</b> '+s.spentCount+'<br><b>Inventory root:</b> '+s.root}
          async function authorize(mode){let r=await call('/api/authorize',{mode});document.getElementById('output').textContent=JSON.stringify(r,null,2);refresh()}
          async function execute(tamper){let r=await call('/api/execute',{tamper});document.getElementById('output').textContent=JSON.stringify(r,null,2);refresh()}
          refresh();
          </script></body></html>
          """;
    }

    private static final class DemoState {
        private final String employee = "Aarav Mehta · Finance Controller";
        private final String walletId = "wallet-demo-0001";
        private final TornNote.Keys master;
        private final List<TornNote.Note> notes = new ArrayList<>();
        private final List<List<byte[]>> proofs = new ArrayList<>();
        private final byte[] root;
        private final Set<Integer> spent = new HashSet<>();
        private Pending pending;

        DemoState() throws GeneralSecurityException {
            master = TornNote.keys("ed25519");
            List<byte[]> leaves = new ArrayList<>();
            for (int i=0;i<8;i++) {
                var note = new TornNote.Note(("company-wallet-note-"+i).getBytes(StandardCharsets.UTF_8),
                        TornNote.keys("ed25519"), TornNote.keys("ed25519"));
                notes.add(note);
                leaves.add(TornNote.leaf(note.id(), TornNote.pub(note.a().pair()), TornNote.pub(note.b().pair())));
            }
            root = TornNote.root(leaves);
            for (int i=0;i<leaves.size();i++) proofs.add(TornNote.proof(leaves,i));
        }

        synchronized Map<String,Object> status() {
            return Map.of("employee",employee,"walletId",walletId,"noteCount",notes.size(),
                    "spentCount",spent.size(),"root",HexFormat.of().formatHex(root));
        }

        synchronized Map<String,Object> authorize(Map<?,?> request) throws GeneralSecurityException {
            String mode = Objects.toString(request.get("mode"),"legitimate");
            int index = firstUnspent();
            if(index<0) return Map.of("ok",false,"decision","REJECTED","reason","wallet-inventory-exhausted");
            var note=notes.get(index);
            String tx=transaction(false);
            var sig=TornNote.authorize(master,note.a(),note.b(),root,note.id(),
                    TornNote.pub(note.a().pair()),TornNote.pub(note.b().pair()),tx,proofs.get(index),index);
            if("master-only".equals(mode)) sig=new TornNote.SignatureSet(sig.master(),null,null);
            pending=new Pending(index,tx,sig);
            return Map.of("ok",true,"decision","AUTHORIZATION_CREATED","mode",mode,"noteIndex",index,
                    "includedFactors","master-only".equals(mode)?List.of("master"):List.of("master","fragment-A","fragment-B"),
                    "message","Prepared only; verifier has not accepted the business operation.");
        }

        synchronized Map<String,Object> execute(Map<?,?> request) throws GeneralSecurityException {
            if(pending==null) return Map.of("ok",false,"decision","REJECTED","reason","no-pending-authorization");
            int i=pending.index();
            if(spent.contains(i)) return Map.of("ok",false,"decision","REJECTED","reason","note-already-spent");
            boolean tamper=Boolean.TRUE.equals(request.get("tamper"));
            String presented=tamper?transaction(true):pending.transaction();
            var note=notes.get(i);
            boolean valid;
            try {
                valid=TornNote.verifyAuthorization(master.pair().getPublic(),note.a().pair().getPublic(),
                        note.b().pair().getPublic(),root,note.id(),TornNote.pub(note.a().pair()),
                        TornNote.pub(note.b().pair()),presented,proofs.get(i),i,pending.signatures(),false);
            } catch(RuntimeException e) { valid=false; }
            if(!valid) return Map.of("ok",false,"decision","REJECTED",
                    "reason",tamper?"transaction-digest-mismatch":"missing-or-invalid-authorization-factor","noteIndex",i);
            spent.add(i); // verify + consume is atomic under this demo's synchronized state lock
            return Map.of("ok",true,"decision","ACCEPTED","noteIndex",i,
                    "message","Exact transaction verified; note consumed once.");
        }

        private int firstUnspent(){for(int i=0;i<notes.size();i++)if(!spent.contains(i))return i;return -1;}
        private String transaction(boolean altered) {
            Map<String,Object> tx=new TreeMap<>();
            tx.put("operation","CHANGE_SUPPLIER_BANK_ACCOUNT");tx.put("supplier","ACME Components");
            tx.put("beneficiaryAccount",altered?"XX-9999":"XX-4821");tx.put("amount",altered?850001:850000);
            tx.put("currency","INR");tx.put("reference","PO-2026-1042");
            try{return JSON.writeValueAsString(tx);}catch(Exception e){throw new IllegalStateException(e);}
        }
    }
    private record Pending(int index,String transaction,TornNote.SignatureSet signatures){}
}
