"use client";

import { useMemo, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import {
  ArrowDown, ArrowRight, ArrowUpRight, Check, CheckCircle2, ChevronRight,
  Fingerprint, KeyRound, LockKeyhole, RotateCcw, ShieldCheck, ShieldX,
  Wallet, Workflow, Copy, RefreshCw,
} from "lucide-react";

type Share = { x: number; y: Uint8Array };
type Envelope = {
  iv: Uint8Array;
  ciphertext: Uint8Array;
  dek: Uint8Array;
  kek: Uint8Array;
  wrappedIv: Uint8Array;
  wrappedDek: Uint8Array;
  shares: Share[];
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
function randomBytes(length: number) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}
function gfMul(a: number, b: number) {
  let result = 0;
  while (b) {
    if (b & 1) result ^= a;
    const high = a & 0x80;
    a = (a << 1) & 0xff;
    if (high) a ^= 0x1b;
    b >>= 1;
  }
  return result;
}
function gfPow(value: number, power: number) {
  let result = 1;
  while (power) {
    if (power & 1) result = gfMul(result, value);
    value = gfMul(value, value);
    power >>= 1;
  }
  return result;
}
function splitKey(secret: Uint8Array): Share[] {
  const coefficients = randomBytes(secret.length);
  return [1, 2, 3].map((x) => ({
    x,
    y: Uint8Array.from(secret, (byte, index) => byte ^ gfMul(coefficients[index], x)),
  }));
}
function recoverKey(a: Share, b: Share) {
  const denominatorInverse = gfPow(a.x ^ b.x, 254);
  return Uint8Array.from(a.y, (ay, index) => {
    const numerator = gfMul(ay, b.x) ^ gfMul(b.y[index], a.x);
    return gfMul(numerator, denominatorInverse);
  });
}
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
async function importAesKey(raw: Uint8Array, usages: KeyUsage[]) {
  return crypto.subtle.importKey("raw", toArrayBuffer(raw), { name: "AES-GCM" }, false, usages);
}
async function aesEncrypt(key: CryptoKey, plaintext: Uint8Array, iv: Uint8Array) {
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, key, toArrayBuffer(plaintext)));
}
async function aesDecrypt(key: CryptoKey, ciphertext: Uint8Array, iv: Uint8Array) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, key, toArrayBuffer(ciphertext)));
}

const defaultPayload = JSON.stringify({
  subjectId: "test-subject-001",
  credentialType: "ExampleBusinessCredential",
  claims: { company: "Northstar Components", country: "XX", testOnly: true },
}, null, 2);

const steps = [
  { title: "Company issues a finite inventory", detail: "An issuer creates note credentials and signs an inventory manifest. The verifier pins the issuer trust key independently.", icon: Workflow },
  { title: "Employee receives a wallet note", detail: "The wallet holds its identity key and the private factors for one pre-issued note. The verifier receives only the public note projection.", icon: Wallet },
  { title: "A specific change is approved", detail: "The approval is bound to the exact supplier, destination account and request—not just to a logged-in session.", icon: LockKeyhole },
  { title: "Verifier checks, then consumes", detail: "Issuer provenance, note membership, signatures, transaction binding and unspent state are checked before the note is consumed.", icon: ShieldCheck },
];

export function IdentityWalletExperience() {
  const [activeStep, setActiveStep] = useState(0);
  const [payload, setPayload] = useState(defaultPayload);
  const [vault, setVault] = useState<Envelope | null>(null);
  const [status, setStatus] = useState("");
  const [plaintext, setPlaintext] = useState("");
  const [busy, setBusy] = useState(false);
  const [tampered, setTampered] = useState(false);
  const [copied, setCopied] = useState(false);

  const ciphertextText = useMemo(
    () => vault ? bytesToBase64(vault.ciphertext) : "",
    [vault],
  );

  async function encryptBoth() {
    setBusy(true);
    setStatus("");
    setPlaintext("");
    try {
      if (!window.crypto?.subtle) throw new Error("This browser does not support Web Crypto. Use a secure HTTPS connection.");
      const dek = randomBytes(32);
      const iv = randomBytes(12);
      const kek = randomBytes(32);
      const wrappedIv = randomBytes(12);
      const payloadBytes = encoder.encode(payload);
      const dataKey = await importAesKey(dek, ["encrypt", "decrypt"]);
      const wrappingKey = await importAesKey(kek, ["encrypt", "decrypt"]);
      const ciphertext = await aesEncrypt(dataKey, payloadBytes, iv);
      const wrappedDek = await aesEncrypt(wrappingKey, dek, wrappedIv);
      setVault({ iv, ciphertext, dek, kek, wrappedIv, wrappedDek, shares: splitKey(dek) });
      setTampered(false);
      setStatus("Encrypted locally. The same payload is now protected by two different key-recovery models.");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Encryption failed.");
    } finally {
      setBusy(false);
    }
  }

  async function decryptBaseline() {
    if (!vault) return;
    setBusy(true);
    try {
      const wrappingKey = await importAesKey(vault.kek, ["decrypt"]);
      const dek = await aesDecrypt(wrappingKey, vault.wrappedDek, vault.wrappedIv);
      const dataKey = await importAesKey(dek, ["decrypt"]);
      const clear = await aesDecrypt(dataKey, vault.ciphertext, vault.iv);
      setPlaintext(decoder.decode(clear));
      setStatus("Envelope-encryption baseline: the in-memory KEK unwrapped the DEK, then AES-GCM authenticated and decrypted the payload.");
    } catch {
      setStatus("Decryption failed. The key or authenticated ciphertext did not validate.");
    } finally {
      setBusy(false);
    }
  }

  async function decryptWithShares() {
    if (!vault) return;
    setBusy(true);
    try {
      const dek = recoverKey(vault.shares[0], vault.shares[2]);
      const dataKey = await importAesKey(dek, ["decrypt"]);
      const ciphertext = vault.ciphertext.slice();
      if (tampered && ciphertext.length) ciphertext[0] ^= 1;
      const clear = await aesDecrypt(dataKey, ciphertext, vault.iv);
      setPlaintext(decoder.decode(clear));
      setStatus("Two-of-three recovery succeeded. AES-GCM also authenticated the recovered key against the encrypted payload.");
    } catch {
      setPlaintext("");
      setStatus("Authentication failed. The recovered key or ciphertext did not match this encrypted record.");
    } finally {
      setBusy(false);
    }
  }

  function tryOneShare() {
    setPlaintext("");
    setStatus("One share is insufficient by design. The two-of-three recovery rule requires any two distinct, valid shares before the data key can be reconstructed.");
  }

  function resetLab() {
    setVault(null);
    setPlaintext("");
    setStatus("");
    setTampered(false);
    setCopied(false);
  }

  async function copyCiphertext() {
    if (!ciphertextText) return;
    await navigator.clipboard.writeText(ciphertextText);
    setCopied(true);
  }

  return (
    <main className="wallet-page">
      <header className="story-header wallet-header">
        <a href="../" className="story-brand"><span className="story-brand-mark"><span className="wallet-brand-glyph">⌁</span></span><span>TORN <i>NOTE</i></span></a>
        <nav>
          <a href="../#how">How it works</a>
          <a href="../identity-wallet/" aria-current="page">Identity Wallet</a>
          <a href="../#protection">Security model</a>
        </nav>
        <details className="story-mobile-menu"><summary>Explore</summary><div><a href="../#how">How it works</a><a href="../identity-wallet/" aria-current="page">Identity Wallet</a><a href="../#protection">Security model</a></div></details>
        <a className="story-github" href="https://github.com/darshanredkar11/torn-note-cryptography" target="_blank" rel="noreferrer">View research <ArrowUpRight size={14}/></a>
      </header>

      <section className="wallet-hero">
        <div className="wallet-hero-grid" />
        <div className="story-container wallet-hero-inner">
          <motion.div className="wallet-hero-copy" initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .7 }}>
            <div className="story-eyebrow"><span className="pulse-dot" /> USE CASE 01 · BUSINESS IDENTITY WALLET</div>
            <h1>Your identity opens the door.<br/><em>Your wallet authorizes the action.</em></h1>
            <p>A finance controller needs to approve a supplier's new bank account. The employee is authenticated—but the company still needs evidence that this exact change was authorized.</p>
            <a className="story-primary-link" href="#scenario">Explore the use case <ArrowDown size={16}/></a>
          </motion.div>
          <div className="wallet-hero-visual">
            <motion.div className="wallet-orbit wallet-orbit-a" animate={{ rotate: 360 }} transition={{ duration: 36, repeat: Infinity, ease: "linear" }} />
            <motion.div className="wallet-orbit wallet-orbit-b" animate={{ rotate: -360 }} transition={{ duration: 48, repeat: Infinity, ease: "linear" }} />
            <motion.div className="wallet-hero-card" initial={{ opacity: 0, scale: .85, rotate: -8 }} animate={{ opacity: 1, scale: 1, rotate: 3 }} transition={{ type: "spring", stiffness: 80, delay: .2 }}>
              <div className="wallet-card-top"><span>COMPANY WALLET</span><Fingerprint size={19}/></div>
              <div className="wallet-card-mark"><Wallet size={38}/></div>
              <strong>BUSINESS IDENTITY</strong>
              <span className="wallet-card-number">TN ···· 2048</span>
              <div className="wallet-card-bottom"><span>ISSUED CAPABILITY</span><span className="wallet-card-dot" /></div>
            </motion.div>
            <motion.div className="wallet-floating-check" animate={{ y: [0, -9, 0] }} transition={{ duration: 4, repeat: Infinity }}><CheckCircle2 size={18}/> ISSUER VERIFIED</motion.div>
            <motion.div className="wallet-floating-lock" animate={{ y: [0, 8, 0] }} transition={{ duration: 4.5, repeat: Infinity }}><LockKeyhole size={18}/> ONE-TIME APPROVAL</motion.div>
          </div>
        </div>
      </section>

      <section className="wallet-scenario" id="scenario">
        <div className="story-container">
          <div className="wallet-section-heading">
            <div className="story-eyebrow">THE BUSINESS SCENARIO</div>
            <h2>A supplier changes its bank details.<br/><em>Can the request be trusted?</em></h2>
            <p>Northstar Components asks the finance team to update its beneficiary account before the next payment run.</p>
          </div>
          <div className="wallet-request-card">
            <div className="wallet-request-head"><span>SUPPLIER MASTER DATA · CHANGE REQUEST</span><span className="wallet-request-status"><i/> AWAITING APPROVAL</span></div>
            <div className="wallet-request-body">
              <div className="wallet-supplier-mark">N</div>
              <div className="wallet-supplier-copy"><small>SUPPLIER</small><strong>Northstar Components</strong><span>Supplier ID · SUP-2048</span></div>
              <div className="wallet-change-arrow"><ArrowRight size={20}/></div>
              <div className="wallet-account-change"><small>NEW BENEFICIARY ACCOUNT</small><strong>•••• •••• •••• 4821</strong><span>Change requested by supplier</span></div>
            </div>
            <div className="wallet-risk-strip"><ShieldX size={18}/><p><strong>Authentication is not the same as authorization.</strong> A valid employee session alone does not prove that the exact destination change should be accepted.</p></div>
          </div>
        </div>
      </section>

      <section className="wallet-flow-section">
        <div className="story-container">
          <div className="wallet-section-heading">
            <div className="story-eyebrow">FOLLOW THE AUTHORIZATION</div>
            <h2>Four participants. <em>One accountable decision.</em></h2>
            <p>Explore each stage to see what the issuer, employee wallet and verifier contribute.</p>
          </div>
          <div className="wallet-flow">
            <div className="wallet-flow-rail"><motion.div className="wallet-flow-progress" animate={{ height: `${(activeStep + 1) * 25}%` }} transition={{ duration: .4 }}/></div>
            <div className="wallet-flow-list">
              {steps.map((step, index) => {
                const Icon = step.icon;
                return <button type="button" key={step.title} className={activeStep === index ? "wallet-flow-step active" : "wallet-flow-step"} onClick={() => setActiveStep(index)}>
                  <span className="wallet-flow-index">{String(index + 1).padStart(2, "0")}</span>
                  <span className="wallet-flow-icon"><Icon size={20}/></span>
                  <span className="wallet-flow-label"><strong>{step.title}</strong><small>{step.detail}</small></span>
                  <ChevronRight size={17}/>
                </button>;
              })}
            </div>
            <AnimatePresence mode="wait">
              <motion.div key={activeStep} className="wallet-flow-detail" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: .22 }}>
                <div className="wallet-detail-kicker">STAGE {String(activeStep + 1).padStart(2, "0")} / 04</div>
                <div className="wallet-detail-icon">{(() => { const Icon = steps[activeStep].icon; return <Icon size={27}/>; })()}</div>
                <h3>{steps[activeStep].title}</h3>
                <p>{steps[activeStep].detail}</p>
                <div className="wallet-detail-foot"><span className="pulse-dot"/> {["ISSUER TRUST","WALLET CUSTODY","TRANSACTION INTENT","VERIFIER ENFORCEMENT"][activeStep]}</div>
                <div className="wallet-detail-controls"><button disabled={activeStep === 0} onClick={() => setActiveStep((v) => v - 1)}>Previous</button><button onClick={() => setActiveStep((v) => (v + 1) % steps.length)}>{activeStep === 3 ? "Start again" : "Next stage"} <ArrowRight size={14}/></button></div>
              </motion.div>
            </AnimatePresence>
          </div>
        </div>
      </section>

      <section className="wallet-comparison-section">
        <div className="story-container">
          <div className="wallet-section-heading">
            <div className="story-eyebrow">WHAT DOES TORN NOTE ADD?</div>
            <h2>Compare the controls.<br/><em>Not just the names.</em></h2>
            <p>The repository's Java use case compares the same supplier-change transaction across three authorization models.</p>
          </div>
          <div className="wallet-comparison">
            <div className="wallet-compare-head"><span>CONTROL</span><span>SINGLE KEY</span><span>3-OF-3 SIGNATURES</span><span>TORN NOTE</span></div>
            {[
              ["Employee key compromise","May be enough to approve","Other two keys still required","Other factors + issued note required"],
              ["Exact transaction binding","Yes","Yes","Yes"],
              ["Replay protection","With a replay store","With a replay store","Spent-note state"],
              ["Pre-issued note inventory","—","—","Issuer-committed Merkle inventory"],
              ["Fabricated note rejection","Not applicable","Not inherent","Yes, against pinned issuer root"],
            ].map((row) => <div className="wallet-compare-row" key={row[0]}>{row.map((cell, i) => <span className={i === 0 ? "wallet-compare-label" : i === 3 ? "wallet-compare-highlight" : ""} key={i}>{cell}</span>)}</div>)}
          </div>
          <p className="wallet-comparison-note">The demonstrated distinction is the issuer-committed, pre-issued authorization object. Three independent signatures alone are not unique to Torn Note; conventional 3-of-3 multisignature can provide similar factor-compromise resistance.</p>
        </div>
      </section>

      <section className="wallet-encryption-section" id="encryption">
        <div className="story-container">
          <div className="wallet-section-heading">
            <div className="story-eyebrow">INTERACTIVE CRYPTOGRAPHY LAB</div>
            <h2>Encrypt the same record.<br/><em>Explore two recovery models.</em></h2>
            <p>Use synthetic data to compare conventional envelope encryption with a two-of-three Torn Note-style key-recovery experiment.</p>
          </div>
          <div className="wallet-lab">
            <div className="wallet-lab-input">
              <div className="wallet-lab-top"><span>01 · YOUR TEST PAYLOAD</span><span className="wallet-lab-local"><LockKeyhole size={12}/> LOCAL ONLY</span></div>
              <label htmlFor="wallet-payload">Synthetic identity record</label>
              <textarea id="wallet-payload" value={payload} onChange={(event) => setPayload(event.target.value)} spellCheck={false}/>
              <div className="wallet-lab-actions"><button className="wallet-action-primary" onClick={encryptBoth} disabled={busy || !payload.trim()}>{busy ? "Working…" : vault ? "Generate a new encrypted record" : "Encrypt both models"} <ArrowRight size={15}/></button><button className="wallet-action-quiet" onClick={resetLab}><RotateCcw size={14}/> Reset</button></div>
              <p className="wallet-lab-hint">No real identity data. Encryption runs in this browser using the Web Crypto API. Nothing is uploaded.</p>
            </div>
            <div className="wallet-lab-results">
              <div className="wallet-lab-top"><span>02 · ENCRYPTED OUTPUT</span><span className={vault ? "wallet-encrypted-tag" : "wallet-waiting-tag"}>{vault ? "ENCRYPTED" : "AWAITING INPUT"}</span></div>
              <div className="wallet-cipher-label">AES-256-GCM CIPHERTEXT</div>
              <div className="wallet-ciphertext">{vault ? ciphertextText.slice(0, 260) + (ciphertextText.length > 260 ? "…" : "") : "Your ciphertext will appear here after encryption."}</div>
              {vault && <button className="wallet-copy-button" onClick={copyCiphertext}><Copy size={13}/>{copied ? "Copied" : "Copy ciphertext"}</button>}
              <div className="wallet-envelope-meta"><span>IV <b>{vault ? bytesToBase64(vault.iv) : "—"}</b></span><span>Authentication tag <b>Included in ciphertext</b></span></div>
            </div>
            <div className="wallet-recovery-card">
              <div className="wallet-recovery-heading"><div className="wallet-recovery-icon"><KeyRound size={19}/></div><div><span>MODEL A · CONVENTIONAL</span><h3>Envelope encryption</h3></div></div>
              <p>A random data-encryption key (DEK) encrypts the payload. A separate key-encryption key (KEK) wraps the DEK.</p>
              <div className="wallet-key-chain"><span>Payload</span><ArrowRight size={13}/><span>DEK</span><ArrowRight size={13}/><span>KEK wraps DEK</span></div>
              <div className="wallet-recovery-foot"><span>RECOVERY REQUIREMENT</span><strong>Access to the KEK</strong></div>
              <button className="wallet-action-secondary" disabled={!vault || busy} onClick={decryptBaseline}>Unwrap key &amp; decrypt <ArrowRight size={14}/></button>
              <small className="wallet-model-disclaimer">Local in-memory KEK for demonstration—not a cloud KMS/HSM integration.</small>
            </div>
            <div className="wallet-recovery-card wallet-threshold-card">
              <div className="wallet-recovery-heading"><div className="wallet-recovery-icon"><Fingerprint size={19}/></div><div><span>MODEL B · TORN NOTE EXPERIMENT</span><h3>Two-of-three recovery</h3></div></div>
              <p>The same kind of DEK is split into three shares. Any two shares can reconstruct it; one share alone cannot.</p>
              <div className="wallet-share-row">{[1,2,3].map((number) => <div className="wallet-share" key={number}><span>SHARE {number}</span><strong>{vault ? "● ● ● ●" : "— — — —"}</strong><small>{vault ? "Generated" : "Not issued"}</small></div>)}</div>
              <div className="wallet-recovery-foot"><span>RECOVERY REQUIREMENT</span><strong>Any 2 valid shares</strong></div>
              <div className="wallet-share-actions"><button className="wallet-action-quiet" disabled={!vault || busy} onClick={tryOneShare}><ShieldX size={13}/> Try 1 share</button><button className="wallet-action-secondary" disabled={!vault || busy} onClick={decryptWithShares}>Use shares 1 + 3 <ArrowRight size={14}/></button></div>
              <label className="wallet-tamper-toggle"><input type="checkbox" checked={tampered} onChange={(event) => setTampered(event.target.checked)} disabled={!vault}/> Tamper with ciphertext before decrypting</label>
              <small className="wallet-model-disclaimer">Browser demonstration of 2-of-3 DEK recovery only. It does not implement the prototype's signed enrollment presentations or issuer manifest checks.</small>
            </div>
            {(status || plaintext) && <div className="wallet-lab-feedback" aria-live="polite"><div className="wallet-feedback-title"><CheckCircle2 size={16}/> DEMONSTRATION RESULT</div><p>{status}</p>{plaintext && <><div className="wallet-feedback-title">RECOVERED PLAINTEXT</div><pre>{plaintext}</pre></>}</div>}
          </div>
          <div className="wallet-lab-footnote"><ShieldCheck size={16}/><p><strong>Research honesty:</strong> this is an educational browser demo using AES-GCM and a small Shamir implementation. The repository's Node identity-vault prototype adds signed share presentations and separately trusted enrollment references; this page does not claim to reproduce the full Java wallet protocol or provide production key custody.</p></div>
        </div>
      </section>

      <section className="wallet-status-section">
        <div className="story-container wallet-status-grid">
          <div><div className="story-eyebrow">IMPLEMENTATION STATUS</div><h2>A working research use case.<br/><em>Not a production wallet.</em></h2><p>The Business Identity Wallet is a runnable Java reference application with issuer, wallet and verifier components. Its CI workflow exercises the happy path and adversarial cases.</p></div>
          <div className="wallet-status-list">
            <div><CheckCircle2 size={17}/><span>Java issuer / wallet / verifier reference components</span></div>
            <div><CheckCircle2 size={17}/><span>Tests for replay, transaction changes and fabricated notes</span></div>
            <div><CheckCircle2 size={17}/><span>Comparison against single-key and conventional 3-of-3 signing</span></div>
            <div className="wallet-status-pending"><RefreshCw size={17}/><span>Durable spend storage, secure key custody and independent review remain future work</span></div>
          </div>
        </div>
      </section>

      <footer className="story-footer"><div className="story-container footer-story-inner"><a href="/" className="story-brand"><span className="story-brand-mark"><span className="wallet-brand-glyph">⌁</span></span><span>TORN <i>NOTE</i></span></a><p>Cryptographic research prototype · Synthetic data only · Not for production use</p><a href="https://github.com/darshanredkar11/torn-note-cryptography" target="_blank" rel="noreferrer">Explore the repository <ArrowUpRight size={14}/></a></div></footer>
    </main>
  );
}
