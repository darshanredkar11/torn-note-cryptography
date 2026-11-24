"use client";

import { useState } from "react";
import Script from "next/script";
import { AnimatePresence, motion } from "motion/react";
import {
  ArrowDown, ArrowRight, ArrowUpRight, Check, CheckCircle2, Fingerprint,
  LockKeyhole, RefreshCw, ShieldCheck, ShieldX, Wallet, X,
} from "lucide-react";

const rise = {
  hidden: { opacity: 0, y: 28 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.7, ease: [0.22, 1, 0.36, 1] as const } },
};

const stages = [
  { number: "01", title: "An issuer creates a finite set", copy: "A trusted issuer prepares a batch of authorization notes and commits to that inventory. Think of it like issuing a limited number of secure, single-use passes.", label: "ISSUE", color: "mint" },
  { number: "02", title: "A wallet holds a note", copy: "An authorized person or system receives a note with its own proof requirements. The note is not a password to reuse everywhere.", label: "HOLD", color: "blue" },
  { number: "03", title: "A real action needs approval", copy: "The request is made specific: which supplier, which destination account, which amount or operation. The proof is tied to that exact intent.", label: "BIND", color: "violet" },
  { number: "04", title: "The verifier checks it, then spends it", copy: "The verifier checks issuer provenance, note integrity, required signatures and the exact transaction. A successful note is consumed so it cannot authorize the same action again.", label: "VERIFY · SPEND", color: "gold" },
];

const attacks = [
  { id: "replay", title: "Replay an old approval", attempt: "Someone copies a previously accepted note and submits it again.", result: "Already spent", detail: "The verifier checks the note's spent state. A second use is rejected when consumption is enforced atomically.", icon: RefreshCw },
  { id: "change", title: "Change the bank account", attempt: "A valid approval was for account ending 4821. An attacker swaps in account 9137.", result: "Transaction mismatch", detail: "The authorization proofs must refer to the same canonical transaction. Changing the destination changes what was approved.", icon: Wallet },
  { id: "forge", title: "Invent a fake note", attempt: "An attacker creates a note-shaped object that was never issued.", result: "No issuer proof", detail: "The verifier checks the note against the issuer's signed inventory commitment and its inclusion proof.", icon: ShieldX },
];

function NoteGlyph({ small = false }: { small?: boolean }) {
  return (
    <svg viewBox="0 0 120 148" className={small ? "note-glyph small" : "note-glyph"} fill="none" aria-hidden="true">
      <path d="M13 8H107V43L96 53L107 63V139H13V105L24 95L13 85V8Z" fill="url(#paper)" stroke="currentColor" strokeWidth="1.5" />
      <path d="M24 27H96M24 117H96" stroke="currentColor" strokeOpacity=".22" strokeDasharray="3 4" />
      <path d="M43 57L57 73L43 89M77 57L63 73L77 89" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="60" cy="73" r="29" stroke="currentColor" strokeOpacity=".25" />
      <defs><linearGradient id="paper" x1="13" y1="8" x2="107" y2="139" gradientUnits="userSpaceOnUse"><stop stopColor="#D9FFF2"/><stop offset="1" stopColor="#91CDBD"/></linearGradient></defs>
    </svg>
  );
}

function HeroAnimation() {
  return (
    <div className="story-hero-art" aria-label="Illustration of a one-time authorization note moving through verification">
      <div className="art-orbit orbit-one" /><div className="art-orbit orbit-two" />
      <motion.div className="art-passkey" animate={{ y: [0, -8, 0] }} transition={{ duration: 5, repeat: Infinity, ease: "easeInOut" }}>
        <Fingerprint size={23} /><span>IDENTITY</span><strong>It's you</strong>
      </motion.div>
      <motion.div className="art-note" initial={{ opacity: 0, scale: .82, rotate: -9 }} animate={{ opacity: 1, scale: 1, rotate: 4 }} transition={{ duration: 1, delay: .25, type: "spring", stiffness: 90 }}>
        <NoteGlyph />
        <span className="art-note-tag">ONE-TIME NOTE</span>
        <strong>AUTHORIZATION</strong>
        <small>Issued · Bound · Verifiable</small>
      </motion.div>
      <motion.div className="art-verifier" animate={{ y: [0, 8, 0] }} transition={{ duration: 5, delay: 1, repeat: Infinity, ease: "easeInOut" }}>
        <ShieldCheck size={22} /><span>VERIFIER</span><strong>Check the action</strong>
      </motion.div>
      <motion.div className="art-particle particle-a" animate={{ x: [0, 38, 0], y: [0, -18, 0], opacity: [.2, 1, .2] }} transition={{ duration: 4, repeat: Infinity }} />
      <motion.div className="art-particle particle-b" animate={{ x: [0, -28, 0], y: [0, 22, 0], opacity: [.2, 1, .2] }} transition={{ duration: 5, repeat: Infinity }} />
      <div className="art-caption"><span className="pulse-dot" /> A capability, not another password</div>
    </div>
  );
}

function StoryStep({ stage, index }: { stage: typeof stages[number]; index: number }) {
  return (
    <motion.article className={`story-step step-${stage.color}`} variants={rise} initial="hidden" whileInView="visible" viewport={{ once: true, amount: .25 }}>
      <div className="story-step-top"><span>{stage.number}</span><span className="story-step-label">{stage.label}</span></div>
      <div className="story-step-art">
        {index === 0 && <div className="inventory-art">{Array.from({ length: 7 }).map((_, i) => <motion.div key={i} className="mini-note" initial={{ opacity: 0, y: 16, rotate: -8 }} whileInView={{ opacity: 1, y: 0, rotate: (i - 3) * 4 }} transition={{ delay: i * .08, duration: .5 }}><NoteGlyph small /></motion.div>)}</div>}
        {index === 1 && <div className="wallet-art"><div className="wallet-glow" /><Wallet size={54} strokeWidth={1.1} /><motion.div className="wallet-note" animate={{ y: [0, -5, 0], rotate: [-3, 3, -3] }} transition={{ duration: 3.5, repeat: Infinity }}><NoteGlyph small /></motion.div></div>}
        {index === 2 && <div className="bind-art"><div className="bind-doc"><span>PAYMENT CHANGE</span><strong>Northstar Components</strong><small>New account ···· 4821</small><div className="bind-line" /></div><motion.div className="bind-lock" animate={{ scale: [1, 1.08, 1] }} transition={{ duration: 2.8, repeat: Infinity }}><LockKeyhole size={25} /></motion.div></div>}
        {index === 3 && <div className="spend-art"><div className="spend-ring"><motion.div className="spend-sweep" animate={{ rotate: 360 }} transition={{ duration: 9, repeat: Infinity, ease: "linear" }} /><Check size={35} /></div><span>VALID ONCE</span></div>}
      </div>
      <h3>{stage.title}</h3><p>{stage.copy}</p>
    </motion.article>
  );
}

export function StoryExperience() {
  const [attack, setAttack] = useState("replay");
  const [businessChoice, setBusinessChoice] = useState("approve");
  const active = attacks.find((item) => item.id === attack) ?? attacks[0];
  const Icon = active.icon;

  return (
    <main className="story-site">
      <span data-sc-progress aria-hidden="true" />
      <div className="sc-grain" aria-hidden="true" />
      <header className="story-header">
        <a href="#" className="story-brand"><span className="story-brand-mark"><NoteGlyph small /></span><span>TORN <i>NOTE</i></span></a>
        <nav><a href="#how">How it works</a><a href="identity-wallet/">Identity Wallet</a><a href="#protection">What it protects</a><a href="#research">Research</a></nav><details className="story-mobile-menu"><summary>Explore</summary><div><a href="#how">How it works</a><a href="identity-wallet/">Identity Wallet</a><a href="#protection">What it protects</a><a href="#research">Research</a></div></details>
        <a className="story-github" href="https://github.com/darshanredkar11/torn-note-cryptography" target="_blank" rel="noreferrer">View research <ArrowUpRight size={14}/></a>
      </header>

      <section className="story-hero" data-sc-act="flow" data-sc-drift="#e9e3d8">
        <div className="story-hero-grid" />
        <div className="story-container story-hero-inner">
          <motion.div className="story-hero-copy" data-sc-in initial="hidden" animate="visible" variants={rise}>
            <div className="story-eyebrow"><span className="pulse-dot" /> A NEW WAY TO THINK ABOUT AUTHORIZATION</div>
            <h1>Not just <em>who</em> you are.<br/>But <span>what you're allowed to do.</span></h1>
            <p>Logging in proves your identity. But should a login alone be enough to change a supplier's bank account, move money, or grant someone administrator access?</p>
            <p className="story-hero-answer">Torn Note explores a better way to authorize high-impact actions: with a specific, verifiable capability that can be used only once.</p>
            <a className="story-primary-link" href="#problem">See why it matters <ArrowDown size={16}/></a>
          </motion.div>
          <HeroAnimation />
        </div>
        <div className="story-scroll-hint">SCROLL TO UNFOLD THE IDEA <span /></div>
      </section>

      <section className="story-problem" id="problem" data-sc-act="flow" data-sc-drift="#e9e3d8">
        <div className="story-container problem-grid">
          <motion.div className="problem-copy" data-sc-reveal="left" variants={rise} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            <div className="story-eyebrow">THE EVERYDAY PROBLEM</div>
            <h2>A familiar request.<br/><span>A very expensive mistake.</span></h2>
            <p>Your finance team receives an email from a known supplier. Their bank details have changed. The employee is legitimate. The login is legitimate. But is the requested change legitimate?</p>
            <div className="problem-quote"><span>INCOMING REQUEST</span><strong>“We've changed our bank account. Please update the details before the next payment.”</strong><small>Northstar Components · Supplier email</small></div>
          </motion.div>
          <motion.div className="fraud-scene" data-sc-reveal="right" initial={{ opacity: 0, x: 35 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }} transition={{ duration: .8 }}>
            <div className="fraud-scene-head"><span>PAYMENT WORKFLOW</span><span className="fraud-risk"><i/> RISK SCENARIO</span></div>
            <div className="fraud-flow">
              <div className="fraud-actor"><div className="actor-avatar">FC</div><span>Finance team</span><small>Authenticated employee</small></div>
              <motion.div className="fraud-arrow" animate={{ scaleX: [0.65, 1, .65] }} transition={{ duration: 2.2, repeat: Infinity }} />
              <div className="fraud-bank"><div className="bank-icon">₹</div><span>Supplier payment</span><small>Destination changed</small></div>
            </div>
            <div className="fraud-alert"><ShieldX size={19}/><div><strong>Identity alone doesn't prove intent</strong><small>A valid session can still be used to approve the wrong details.</small></div></div>
            <div className="fraud-scene-foot"><span>THE GAP</span><strong>Who logged in ≠ What should be approved</strong></div>
          </motion.div>
        </div>
      </section>


      <section className="business-decision" id="decision" data-sc-act="flow" data-sc-drift="#e1d9ce">
        <div className="story-container business-decision-grid">
          <div className="business-decision-copy" data-sc-reveal="left">
            <div className="story-eyebrow">A SIMPLE BUSINESS EXAMPLE</div>
            <h2>Would you approve this bank-account change?</h2>
            <p>A supplier asks your finance team to replace its payment account. The employee is signed in, but the request itself could still be fraudulent.</p>
            <div className="decision-request"><span>CHANGE REQUEST</span><strong>Northstar Components</strong><small>Replace account ending 4821 before the next payment run</small></div>
          </div>
          <div className="business-decision-demo" data-sc-reveal="right">
            <div className="decision-question">What should the finance system do?</div>
            <div className="decision-choices" role="group" aria-label="Choose how to handle the supplier bank change">
              <button type="button" className={businessChoice === "approve" ? "selected" : ""} onClick={() => setBusinessChoice("approve")}>Approve because the employee is logged in</button>
              <button type="button" className={businessChoice === "verify" ? "selected" : ""} onClick={() => setBusinessChoice("verify")}>Ask for proof tied to this exact change</button>
              <button type="button" className={businessChoice === "reject" ? "selected" : ""} onClick={() => setBusinessChoice("reject")}>Reject every bank-detail change</button>
            </div>
            <div className="decision-feedback" aria-live="polite">
              {businessChoice === "approve" && <><strong className="decision-warning">Risk: login is not enough.</strong><p>A real employee session can be misused. It does not prove that account 4821 is the intended destination.</p></>}
              {businessChoice === "verify" && <><strong className="decision-good">A stronger approval path.</strong><p>Check who is authorizing the request and require a separate, transaction-bound Torn Note proof before the system accepts it. The note is consumed after successful use.</p></>}
              {businessChoice === "reject" && <><strong className="decision-neutral">Safe, but impractical.</strong><p>Businesses still need to change supplier details. The goal is not to block every change; it is to verify the right change with specific authorization.</p></>}
            </div>
            <div className="decision-disclaimer">Interactive explanation only — this page does not connect to a bank, authenticate a user or execute a real authorization.</div>
          </div>
        </div>
      </section>
      <section className="story-idea" data-sc-act="flow" data-sc-drift="#e9e3d8">
        <div className="story-container idea-inner">
          <motion.div className="idea-intro" data-sc-in variants={rise} initial="hidden" whileInView="visible" viewport={{ once: true }}>
            <div className="story-eyebrow">THE IDEA, WITHOUT THE JARGON</div>
            <h2>Think of a Torn Note as a <span>secure, single-use pass.</span></h2>
            <p>Imagine a business issues a limited batch of special passes. Each pass represents a bounded authorization. It can be checked against what the issuer created, tied to a particular action, and consumed when accepted.</p>
          </motion.div>
          <div className="idea-note-stage" data-sc-reveal="up">
            <motion.div className="idea-note-card" initial={{ opacity: 0, y: 30, rotate: -8 }} whileInView={{ opacity: 1, y: 0, rotate: 3 }} viewport={{ once: true }} transition={{ type: "spring", stiffness: 80, damping: 15 }}>
              <NoteGlyph/>
              <div className="idea-note-copy"><span>TORN NOTE · CONCEPT</span><strong>ONE ACTION.<br/>ONE AUTHORIZATION.</strong><small>Issued by a trusted authority</small></div>
              <div className="idea-note-stamp">SINGLE<br/>USE</div>
            </motion.div>
            <div className="idea-note-orbit orbit-a"/><div className="idea-note-orbit orbit-b"/>
            <div className="idea-callout callout-one">Limited inventory</div><div className="idea-callout callout-two">Verifiable origin</div><div className="idea-callout callout-three">Consumed on use</div>
          </div>
        </div>
        <div className="story-container idea-footnote"><span>THE IMPORTANT DIFFERENCE</span><p>It's not simply a token with an expiry date. The research explores issuer-committed note inventory, independent proof factors, transaction binding and one-time consumption working together.</p></div>
      </section>

      <section className="story-how" id="how" data-sc-act="flow" data-sc-drift="#e9e3d8">
        <div className="story-container">
          <div className="story-section-heading" data-sc-in>
            <div className="story-eyebrow">FOLLOW THE NOTE</div>
            <h2>From creation to <span>one-time approval.</span></h2>
            <p>Four moments. One simple story. Scroll through how the authorization is intended to work.</p>
          </div>
          <div className="story-steps" data-sc-reveal="up">{stages.map((stage, index) => <StoryStep key={stage.number} stage={stage} index={index}/>)}</div>
        </div>
      </section>

      <section className="story-protection" id="protection" data-sc-act="flow" data-sc-drift="#e9e3d8">
        <div className="story-container">
          <div className="story-section-heading">
            <div className="story-eyebrow">LET'S TRY TO BREAK IT</div>
            <h2>What if someone <span>tries something sneaky?</span></h2>
            <p>Choose an attack. See which check is designed to stop it.</p>
          </div>
          <div className="attack-lab" data-sc-reveal="up">
            <div className="attack-options">
              {attacks.map((item) => <button key={item.id} onClick={() => setAttack(item.id)} className={attack === item.id ? "attack-option selected" : "attack-option"}><span>{item.id === "replay" ? "01" : item.id === "change" ? "02" : "03"}</span>{item.title}<ArrowRight size={15}/></button>)}
            </div>
            <div className="attack-result" aria-live="polite">
              <AnimatePresence mode="wait">
                <motion.div key={active.id} className="attack-result-inner" initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }} transition={{ duration: .25 }}>
                  <div className="attack-visual"><div className="attack-icon"><Icon size={31}/></div><motion.div className="attack-cross" initial={{ scale: .4, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} transition={{ delay: .18 }}><X size={22}/></motion.div></div>
                  <div className="attack-attempt-label">THE ATTEMPT</div><h3>{active.attempt}</h3>
                  <div className="attack-blocked"><CheckCircle2 size={18}/><strong>{active.result}</strong></div>
                  <p>{active.detail}</p>
                </motion.div>
              </AnimatePresence>
              <div className="attack-foot">Illustrative security behavior · not a live attack or production verifier</div>
            </div>
          </div>
          <p className="protection-caveat">These controls reduce specific authorization risks; they do not eliminate phishing, compromised endpoints, collusion, insider threats or implementation flaws. Security still depends on the complete system.</p>
        </div>
      </section>

      <section className="story-identity" data-sc-act="flow" data-sc-drift="#e9e3d8">
        <div className="story-container identity-grid" data-sc-in>
          <div>
            <div className="story-eyebrow">AND WHAT ABOUT PASSKEYS?</div>
            <h2>Keep the passkey.<br/><span>Give the action its own proof.</span></h2>
            <p>Passkeys and Torn Note solve related but different problems. A passkey helps establish that the right person is present. Torn Note adds a separate authorization proof for the specific business action.</p>
          </div>
          <div className="identity-compare">
            <div className="identity-item"><div className="identity-symbol"><Fingerprint size={30}/></div><div><span>PASSKEY · IDENTITY</span><strong>Is this really you?</strong><small>Validates an authenticator assertion and a fresh challenge.</small></div></div>
            <div className="identity-plus">+</div>
            <div className="identity-item note-identity"><div className="identity-symbol"><NoteGlyph small/></div><div><span>TORN NOTE · AUTHORIZATION</span><strong>May this exact action proceed?</strong><small>Checks an issued capability, its proof and its transaction binding.</small></div></div>
            <div className="identity-outcome"><CheckCircle2 size={19}/> Independent evidence for one consequential decision</div>
          </div>
        </div>
        <div className="story-container identity-note">In the Java reference integration, a WebAuthn assertion is validated separately and the server binds the pending passkey request to the same transaction and Torn Note authorization context. The browser showcase here is illustrative; it does not run a live passkey ceremony.</div>
      </section>

      <section className="story-benefits" data-sc-act="flow" data-sc-drift="#e9e3d8">
        <div className="story-container">
          <div className="story-section-heading"><div className="story-eyebrow">WHY THIS COULD MATTER</div><h2>Make high-impact actions <span>harder to misuse.</span></h2></div>
          <div className="benefit-grid" data-sc-reveal="up">
            <article><span>01</span><h3>Less reusable authority</h3><p>A note is designed for a bounded authorization, not an all-purpose credential that can be reused indefinitely.</p></article>
            <article><span>02</span><h3>Clearer intent</h3><p>Bind approval to the exact operation so a valid proof cannot simply be moved to a different transaction.</p></article>
            <article><span>03</span><h3>Verifiable issuance</h3><p>Check that a note belongs to an issuer-committed inventory rather than trusting a note-shaped object presented by a caller.</p></article>
            <article><span>04</span><h3>Replay resistance</h3><p>Track consumption so the same authorization cannot be accepted twice when the spend operation is atomic and durable.</p></article>
          </div>
        </div>
      </section>

      <section className="story-research" id="research" data-sc-act="flow" data-sc-drift="#e9e3d8">
        <div className="story-container research-grid" data-sc-in>
          <div><div className="story-eyebrow">FOR THE CURIOUS</div><h2>There's serious cryptography underneath the simple story.</h2><p>The current Java research prototype uses established primitives rather than claiming a new signature algorithm.</p><a className="story-primary-link" href="https://github.com/darshanredkar11/torn-note-cryptography" target="_blank" rel="noreferrer">Explore the code <ArrowUpRight size={16}/></a></div>
          <div className="research-facts">
            <div><span>01</span><strong>Ed25519 signatures</strong><small>Independent note-specific signing factors.</small></div>
            <div><span>02</span><strong>SHA-256 Merkle commitment</strong><small>Proof that a note belongs to the committed inventory.</small></div>
            <div><span>03</span><strong>Issuer trust and manifest</strong><small>Signed inventory provenance checked by the verifier.</small></div>
            <div><span>04</span><strong>Spent-note state</strong><small>Replay control with atomic consumption; MongoDB persistence adapters are available.</small></div>
          </div>
        </div>
      </section>

      <section className="story-status" data-sc-act="flow" data-sc-drift="#e1d9ce">
        <div className="story-container">
          <div className="story-eyebrow">HONEST ABOUT THE STAGE</div>
          <h2>A research prototype, <span>not a finished security product.</span></h2>
          <div className="status-columns">
            <div><div className="status-column-label done"><Check size={15}/> IMPLEMENTED IN THE JAVA PROTOTYPE</div><ul><li>Issuer-created finite inventory and signed Merkle-root manifest</li><li>Two independent note signing factors</li><li>Issuer trust, note membership and transaction-signature checks</li><li>Replay and concurrent-consumption tests</li></ul></div>
            <div><div className="status-column-label planned">NEXT ENGINEERING WORK</div><ul><li>Complete browser passkey registration and assertion journey with cross-platform tests</li><li>Production deployment, operations and recovery workflows around the MongoDB adapters</li><li>Independent issuer, wallet and verifier deployments</li><li>Secure factor custody, recovery and external security review</li></ul></div>
          </div>
          <p className="status-disclaimer">The animated scenes, business decision demo and attack lab are educational simulations. They do not execute the Java cryptographic verifier, authenticate a browser passkey or authorize a payment. The Java reference module includes a WebAuthn assertion adapter and MongoDB persistence adapters, but this is not yet a complete production service.</p>
        </div>
      </section>

      <footer className="story-footer"><div className="story-container footer-story-inner"><a href="#" className="story-brand"><span className="story-brand-mark"><NoteGlyph small/></span><span>TORN <i>NOTE</i></span></a><p>Authorization should be as specific as the action it protects.</p><a href="https://github.com/darshanredkar11/torn-note-cryptography" target="_blank" rel="noreferrer">Open research repository <ArrowUpRight size={14}/></a></div></footer>
    <Script src={typeof window !== "undefined" && window.location.pathname.startsWith("/torn-note-cryptography") ? "/torn-note-cryptography/scrollcraft/scrollcraft.js" : "/scrollcraft/scrollcraft.js"} strategy="afterInteractive" onReady={() => { const engine = (window as unknown as { ScrollCraft?: { mount: (root: HTMLElement) => unknown } }).ScrollCraft; engine?.mount(document.body); }} />
    </main>
  );
}
