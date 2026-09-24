import { useState } from "react";
import { BadgeCheck, Bug, FileLock2, LockKeyhole, PiggyBank } from "lucide-react";
import { SEVERITIES, explorerAddress } from "../config";
import type { Program, Snapshot } from "../lib/chain";
import { dateTime, formatGen, githubBlobUrl, parseGen, policyLabel, shortAddr } from "../lib/format";
import { bountyFor } from "../lib/poc";
import { Card, EmptyState, ExtLink, SectionHeader, SeverityBadge, Stat, StatusBadge } from "./ui";

interface Props {
  snapshot: Snapshot | null;
  account: string | null;
  onTopUp: (programId: number, amount: bigint) => Promise<boolean>;
  onReport: (programId: number) => void;
}

function ProgramCard({ p, payoutBps, account, onTopUp, onReport }: { p: Program; payoutBps: Record<string, number> } & Omit<Props, "snapshot">) {
  const [amount, setAmount] = useState("1");
  const [busy, setBusy] = useState(false);
  const parsed = parseGen(amount);
  const policy = policyLabel(p.policyUrl);
  const isOwner = account?.toLowerCase() === p.owner.toLowerCase();
  const open = p.status === "ACTIVE";

  return (
    <article className="glass flex min-w-0 flex-col p-5 transition hover:border-sky-400/40">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-sky-400/30 bg-gradient-to-b from-sky-400/20 to-sky-700/10 text-sky-200 shadow-[0_4px_0_0_rgb(3_105_161/0.55)]">
            <LockKeyhole size={20} />
          </div>
          <div>
            <p className="font-mono text-xs text-sky-400/80">PROGRAM #{p.id}</p>
            <p className="font-semibold text-white">
              Target <span className="font-mono text-sky-100">{shortAddr(p.target, 6)}</span>
            </p>
          </div>
        </div>
        <StatusBadge status={p.status} />
      </div>

      <div className="mt-4 glass-inset flex items-center gap-2 px-3 py-2 text-xs">
        <FileLock2 size={14} className="shrink-0 text-sky-300" />
        <ExtLink href={githubBlobUrl(p.policyUrl)} className="min-w-0 truncate font-mono">
          {policy.repo}@{policy.commit} / {policy.path}
        </ExtLink>
      </div>
      <div className="mt-2 glass-inset flex flex-wrap items-center gap-x-2 gap-y-1 px-3 py-2 text-xs">
        <BadgeCheck size={14} className="shrink-0 text-emerald-400" />
        <span className="text-slate-300">
          Target ABI verified on Sourcify (chain {p.targetChainId}): {Object.keys(p.targetAbi).length} functions
          {p.targetHasFallback ? " + fallback()" : ""}
        </span>
        <ExtLink href={`https://sourcify.dev/#/lookup/${p.target}`} className="text-[11px]">lookup</ExtLink>
      </div>
      <p className="mt-1.5 px-1 text-[11px] text-slate-500">
        {p.policyDigest ? <>Policy digest pinned: <span className="font-mono">{p.policyDigest.slice(0, 16)}...</span></> : "Policy digest pins on first triage"}
      </p>

      <div className="mt-4 grid grid-cols-2 gap-2">
        <Stat label="Available vault" value={`${formatGen(p.available)} GEN`} />
        <Stat label="Locked in escrow" value={`${formatGen(p.locked)} GEN`} />
        <Stat label="Open reports" value={p.openReports} />
        <Stat label="Paid out" value={`${formatGen(p.totalPaid)} GEN`} />
      </div>

      <div className="mt-4">
        <p className="label">Max payout per tier (current vault)</p>
        <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-4">
          {SEVERITIES.map((s) => {
            const below = (["LOW", "MEDIUM", "HIGH", "CRITICAL"].indexOf(s)) < ["LOW", "MEDIUM", "HIGH", "CRITICAL"].indexOf(p.minSeverity);
            return (
              <div key={s} className={`glass-inset px-2 py-1.5 ${below ? "opacity-35" : ""}`} title={below ? "Below program floor" : ""}>
                <SeverityBadge severity={s} />
                <p className="mt-1 font-mono text-xs text-slate-200">{below ? "n/a" : formatGen(bountyFor(p.available, s, payoutBps), 3)}</p>
              </div>
            );
          })}
        </div>
      </div>

      <p className="mt-3 text-[11px] text-slate-500">
        Owner <ExtLink href={explorerAddress(p.owner)} className="font-mono">{shortAddr(p.owner)}</ExtLink>
        {isOwner && <span className="ml-1 text-sky-300">(you)</span>} - registered {dateTime(p.registeredAt)} - floor {p.minSeverity}
        {p.status === "CLOSING" && <> - closes {dateTime(p.closesAt)}</>}
      </p>

      <div className="mt-auto flex flex-wrap items-end gap-2 pt-5">
        <div className="min-w-[8rem] flex-1">
          <label className="label" htmlFor={`topup-${p.id}`}>Deposit (GEN)</label>
          <input id={`topup-${p.id}`} className="field font-mono" inputMode="decimal" value={amount} onChange={(e) => setAmount(e.target.value)} disabled={!open} />
        </div>
        <button
          type="button"
          className="btn-3d-ghost"
          disabled={!account || !open || !parsed || parsed === 0n || busy}
          title={!account ? "Connect a wallet to deposit" : ""}
          onClick={async () => {
            if (!parsed) return;
            setBusy(true);
            await onTopUp(p.id, parsed);
            setBusy(false);
          }}
        >
          <PiggyBank size={15} /> {busy ? "Depositing..." : "Deposit"}
        </button>
        <button type="button" className="btn-3d" disabled={p.status === "CLOSED"} onClick={() => onReport(p.id)}>
          <Bug size={15} /> Report
        </button>
      </div>
    </article>
  );
}

export function Programs({ snapshot, account, onTopUp, onReport }: Props) {
  const programs = snapshot?.programs ?? [];
  return (
    <Card className="p-5 sm:p-6">
      <SectionHeader
        eyebrow="Vaults"
        title="Active Bounty Programs"
        subtitle="Each vault is bound to a commit-pinned SECURITY.md. Payout tiers are fixed shares of the available reserves, so no program can re-price a disclosure."
      />
      {programs.length === 0 ? (
        <EmptyState icon={<LockKeyhole size={28} />} title={snapshot ? "No programs yet" : "Loading programs"} body="Programs registered on the ZeroDiscretion contract appear here with their pinned policy and live vault balance." />
      ) : (
        <div className={`grid grid-cols-1 gap-4 ${programs.length > 1 ? "lg:grid-cols-2" : ""}`}>
          {programs.map((p) => (
            <ProgramCard key={p.id} p={p} payoutBps={snapshot!.params.payoutBps} account={account} onTopUp={onTopUp} onReport={onReport} />
          ))}
        </div>
      )}
    </Card>
  );
}
