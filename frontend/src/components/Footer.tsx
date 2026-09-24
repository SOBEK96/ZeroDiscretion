import { GitBranch } from "lucide-react";
import { CONTRACT_ADDRESS, DEPLOY_TX_HASH, NETWORK, REPO_URL, explorerAddress, explorerTx } from "../config";
import { ShieldLogo } from "./Header";
import { ExtLink } from "./ui";

export function Footer() {
  return (
    <footer className="mt-16 border-t border-sky-500/10 bg-slate-950/40 backdrop-blur">
      <div className="mx-auto grid max-w-7xl gap-8 px-4 py-10 sm:px-6 md:grid-cols-[1.4fr_1fr_1fr]">
        <div>
          <div className="flex items-center gap-3">
            <ShieldLogo size={36} />
            <span className="text-lg font-bold text-white">ZeroDiscretion</span>
          </div>
          <p className="mt-3 max-w-md text-sm leading-relaxed text-slate-400">
            An autonomous bug bounty escrow protocol on GenLayer. Vaults are bound to commit-pinned security policies, bonded PoCs are
            triaged by validator consensus, and validated exploits are paid out after an immutable challenge window. No project
            can veto a payout.
          </p>
        </div>
        <div>
          <p className="eyebrow">Explorer</p>
          <ul className="mt-3 space-y-2 text-sm">
            <li><ExtLink href={explorerAddress(CONTRACT_ADDRESS)}>ZeroDiscretion contract</ExtLink></li>
            <li><ExtLink href={explorerTx(DEPLOY_TX_HASH)}>Deployment transaction</ExtLink></li>
            <li><ExtLink href={NETWORK.explorerUrl}>{NETWORK.name} explorer</ExtLink></li>
          </ul>
        </div>
        <div>
          <p className="eyebrow">Source</p>
          <ul className="mt-3 space-y-2 text-sm">
            <li>
              <a href={REPO_URL} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1.5 text-sky-300 hover:text-sky-200 hover:underline">
                <GitBranch size={14} /> SOBEK96/ZeroDiscretion
              </a>
            </li>
            <li><ExtLink href={`${REPO_URL}/blob/main/specs/game_theory.md`}>Game-theory specification</ExtLink></li>
            <li><ExtLink href={`${REPO_URL}/blob/main/SECURITY.md`}>Reference SECURITY.md</ExtLink></li>
          </ul>
        </div>
      </div>
      <div className="border-t border-sky-500/10">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-2 px-4 py-4 text-xs text-slate-500 sm:px-6">
          <span>MIT License - Copyright (c) 2026 SOBEK96</span>
          <span className="font-mono">chain {NETWORK.chainId} - {CONTRACT_ADDRESS}</span>
        </div>
      </div>
    </footer>
  );
}
