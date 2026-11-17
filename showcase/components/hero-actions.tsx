"use client";

import { ArrowRight } from "lucide-react";
import { HaloButton } from "@/components/ui/halo-button";

export function HeroActions() {
  return (
    <div className="hero-actions">
      <HaloButton
        className="shadow-[0_12px_45px_rgba(85,218,184,.12)]"
        onClick={() => document.getElementById("architecture")?.scrollIntoView({ behavior: "smooth" })}
      >
        Explore the architecture <ArrowRight className="ml-1 size-4" />
      </HaloButton>
      <a className="text-link" href="https://github.com/darshanredkar11/torn-note-cryptography" target="_blank" rel="noreferrer">
        Read the research <ArrowRight className="size-3.5" />
      </a>
    </div>
  );
}
