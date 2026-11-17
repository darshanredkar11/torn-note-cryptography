"use client";

import { useState } from "react";
import { Check, ChevronRight, RotateCcw } from "lucide-react";
import { HaloButton } from "@/components/ui/halo-button";
import { HaloCard, HaloCardContent, HaloCardDescription, HaloCardHeader, HaloCardTitle } from "@/components/ui/halo-card";

const stages = [
  { title: "Passkey assertion", description: "The identity gateway validates the registered WebAuthn credential, origin, RP ID and fresh challenge." },
  { title: "Transaction binding", description: "The challenge is bound to the canonical supplier-change request so approval cannot be transplanted to another action." },
  { title: "Note-factor signatures", description: "The wallet proves control of the two independent signing factors belonging to one pre-issued note." },
  { title: "Issuer commitment", description: "The verifier checks the issuer-signed manifest and the note's Merkle inclusion proof." },
  { title: "Atomic consumption", description: "A shared durable spend store allows only the first valid use of this note to proceed." }
];

export function AuthorizationLab() {
  const [stage, setStage] = useState(-1);
  const complete = stage === stages.length - 1;
  const current = stage < 0 ? null : stages[stage];

  return (
    <HaloCard className="h-full" padding="lg" interactive={false}>
      <HaloCardHeader>
        <div className="mb-3 flex items-center justify-between gap-3">
          <span className="micro-label">ILLUSTRATIVE AUTHORIZATION TRACE</span>
          <span className="rounded-full border border-amber-300/20 bg-amber-300/5 px-2.5 py-1 text-[9px] font-semibold tracking-[.12em] text-amber-200">SIMULATED</span>
        </div>
        <HaloCardTitle className="text-xl">Supplier bank-detail change</HaloCardTitle>
        <HaloCardDescription>Step through the intended passkey + Torn Note flow. This walkthrough does not perform WebAuthn or cryptographic operations.</HaloCardDescription>
      </HaloCardHeader>
      <HaloCardContent>
        <div className="transaction-box mt-5">
          <div className="micro-label mb-2">REQUEST PREVIEW</div>
          <div className="transaction-row"><span>Supplier</span><strong>Northstar Components</strong></div>
          <div className="transaction-row"><span>Action</span><strong>Change beneficiary</strong></div>
          <div className="transaction-row"><span>Destination</span><strong>Account ending ··4821</strong></div>
          <div className="transaction-row"><span>Request ID</span><strong>SUP-2048</strong></div>
        </div>
        <div className="lab-steps" aria-live="polite">
          {stages.map((item, index) => {
            const isDone = stage > index;
            const isCurrent = stage === index;
            const className = "lab-step " + (isCurrent ? "current " : "") + (isDone ? "complete" : "");
            return (
              <div className={className} key={item.title}>
                <span className="lab-step-icon">{isDone ? <Check className="size-3.5" /> : String(index + 1).padStart(2, "0")}</span>
                <span className="min-w-0 flex-1">{item.title}</span>
                {isCurrent && <span className="text-[9px] uppercase tracking-[.12em] text-emerald-200">Current</span>}
              </div>
            );
          })}
        </div>
        {current && (
          <div className="mt-4 rounded-xl border border-emerald-300/15 bg-emerald-300/[.045] p-4">
            <div className="mb-1 text-xs font-semibold text-emerald-100">{current.title}</div>
            <p className="m-0 text-xs leading-6 text-slate-400">{current.description}</p>
          </div>
        )}
        <div className="mt-5 flex flex-wrap items-center gap-3">
          <HaloButton onClick={() => setStage((value) => value >= stages.length - 1 ? 0 : value + 1)}>
            {stage < 0 ? "Start walkthrough" : complete ? "Run again" : "Next step"}
            <ChevronRight className="ml-1 size-4" />
          </HaloButton>
          <button type="button" className="inline-flex min-h-11 items-center gap-2 rounded-full px-4 text-xs font-medium text-slate-400 transition hover:text-white" onClick={() => setStage(-1)}>
            <RotateCcw className="size-3.5" /> Reset
          </button>
        </div>
        <p className="lab-warning mt-4">
          {complete ? "Walkthrough complete. A production implementation still needs a WebAuthn adapter and a durable, strongly consistent spend database." : "Conceptual product flow only. No credential, private key, signature or real transaction is used here."}
        </p>
      </HaloCardContent>
    </HaloCard>
  );
}
