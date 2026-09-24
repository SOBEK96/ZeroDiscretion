import { useMemo, useState } from "react";
import { Coins, FileSearch, Gavel, Hourglass, Scale, ShieldAlert, Unlock, Wallet } from "lucide-react";
import { REBUTTAL_TYPES, explorerAddress } from "../config";
import { useNow } from "../hooks";
import type { Program, Report, Snapshot } from "../lib/chain";
import { dateTime, duration, formatGen, shortAddr } from "../lib/format";
import { buildRebuttal, disassemble, parsePoc, type DisasmStep } from "../lib/poc";
import { Card, EmptyState, ExtLink, SectionHeader, SeverityBadge, Stat, StatusBadge } from "./ui";

const CLAIMABLE = ["VALIDATED", "CHALLENGE_DISMISSED", "DOWNGRADED"];

interface Actions {
  onChallenge: (reportId: number, rebuttal: string, bond: bigint) => Promise<boolean>;
  onClaim: (reportId: number) => Promise<boolean>;
  onExpire: (reportId: number) => Promise<boolean>;
  onWithdraw: () => Promise<boolean>;
}

function Countdown({ report, now }: { report: Report; now: number }) {
  if (report.unlockTimestamp === 0) return null;
  const total = Math.max(1, report.unlockTimestamp - report.submittedAt);
  const left = report.unlockTimestamp - now;
  const pct = Math.min(100, Math.max(0, ((total - Math.max(0, left)) / total) * 100));
  const open = left > 0;
  return (
    <div className="glass-inset p-3">
      <div className="flex items-center justify-between text-xs">
        <span className="flex items-center gap-1.5 text-slate-400">
          <Hourglass size={13} className={open ? "text-sky-300" : "text-emerald-400"} />
          {open ? "Challenge window closes in" : "Challenge window closed"}
        </span>
        <span className={`font-mono font-semibold ${open ? "text-sky-200" : "text-emerald-300"}`}>{open ? duration(left) : dateTime(report.unlockTimestamp)}</span>
      </div>
      <div className="relative mt-2 h-2 overflow-hidden rounded-full bg-slate-800">
        <div className={`h-full rounded-full ${open ? "bg-gradient-to-r from-sky-600 to-sky-300" : "bg-emerald-400"}`} style={{ width: `${pct}%` }} />
        {open && <div className="zd-scan absolute inset-0" />}
      </div>
    </div>
  );
}

function RebuttalBuilder({ report, disasm, challengeBond, onChallenge, onDone }: { report: Report; disasm: DisasmStep[]; challengeBond: bigint; onChallenge: Actions["onChallenge"]; onDone: () => void }) {
  const [type, setType] = useState<string>(REBUTTAL_TYPES[0].id);
  const [steps, setSteps] = useState<number[]>([]);
  const [argument, setArgument] = useState("");
  const [busy, setBusy] = useState(false);
  const built = buildRebuttal({ pocHash: report.pocHash, rebuttalType: type, disputedSteps: steps, argument }, disasm);

  return (
    <div className="mt-4 rounded-xl border border-rose-400/25 bg-rose-500/5 p-4">
      <div className="flex items-center gap-2 text-rose-200">
        <Gavel size={16} />
        <p className="font-semibold">Direct rebuttal - bound to this PoC</p>
      </div>
      <p className="mt-1 text-[11px] leading-relaxed text-slate-400">
        Only rebuttals that name this report's PoC hash and the exact selectors of the steps they dispute are admitted. Generic denials
        revert with <span className="font-mono">ERR_REBUTTAL_NOT_BOUND</span>. If consensus dismisses the rebuttal, the {formatGen(challengeBond)} GEN bond goes to the researcher.
      </p>

      <label className="label mt-4" htmlFor={`rt-${report.id}`}>Rebuttal type</label>
      <select id={`rt-${report.id}`} className="field" value={type} onChange={(e) => setType(e.target.value)}>
        {REBUTTAL_TYPES.map((t) => (
          <option key={t.id} value={t.id}>{t.label}</option>
        ))}
      </select>

      <p className="label mt-4">Disputed PoC steps</p>
      <div className="grid gap-1.5">
        {disasm.map((d) => {
          const on = steps.includes(d.index);
          return (
            <label key={d.index} className={`flex cursor-pointer items-center gap-3 rounded-lg border px-3 py-2 font-mono text-xs transition ${on ? "border-rose-300/50 bg-rose-400/10" : "border-sky-400/10 bg-slate-950/50 hover:border-sky-400/30"}`}>
              <input type="checkbox" className="accent-rose-400" checked={on} onChange={() => setSteps(on ? steps.filter((s) => s !== d.index) : [...steps, d.index])} />
              <span className="text-slate-500">step {d.index}</span>
              <span className="text-amber-200">{d.selector}</span>
              <span className="truncate text-emerald-200">{d.function}</span>
              <span className="truncate text-slate-400">to {shortAddr(d.to)}</span>
              <span className="ml-auto text-slate-500">{d.word_count} words</span>
            </label>
          );
        })}
      </div>

      <label className="label mt-4" htmlFor={`arg-${report.id}`}>Argument (addresses the mechanics of the disputed steps)</label>
      <textarea
        id={`arg-${report.id}`}
        className="field h-28 resize-y"
        placeholder="e.g. Step 1 calls withdraw(uint256), which is gated by onlyOwner in the deployed bytecode at ..."
        value={argument}
        onChange={(e) => setArgument(e.target.value)}
      />

      <details className="mt-3">
        <summary className="cursor-pointer text-[11px] text-sky-300">Bound rebuttal payload</summary>
        <pre className="mt-2 max-h-40 overflow-auto rounded-lg bg-slate-950/80 p-2 font-mono text-[10px] text-slate-300">{JSON.stringify(JSON.parse(built.json), null, 2)}</pre>
      </details>

      {built.problems.length > 0 && (
        <ul className="mt-3 space-y-1 text-[11px] text-rose-300">
          {built.problems.map((p) => (
            <li key={p}>- {p}</li>
          ))}
        </ul>
      )}

      <div className="mt-4 flex flex-wrap gap-2">
        <button
          type="button"
          className="btn-3d-danger"
          disabled={built.problems.length > 0 || busy}
          onClick={async () => {
            setBusy(true);
            const ok = await onChallenge(report.id, built.json, challengeBond);
            setBusy(false);
            if (ok) onDone();
          }}
        >
          <ShieldAlert size={15} /> {busy ? "Awaiting consensus..." : `Challenge with ${formatGen(challengeBond)} GEN bond`}
        </button>
        <button type="button" className="btn-3d-ghost" onClick={onDone}>Cancel</button>
      </div>
    </div>
  );
}

function ReportCard({ report, program, account, now, challengeBond, feeBps, actions }: { report: Report; program?: Program; account: string | null; now: number; challengeBond: bigint; feeBps: number; actions: Actions }) {
  const [rebutting, setRebutting] = useState(false);
  const [showTrace, setShowTrace] = useState(false);
  const [busy, setBusy] = useState(false);
  const disasm = useMemo(() => {
    const parsed = program ? parsePoc(report.pocTrace, program.target, program.targetChainId) : null;
    return parsed?.ok && parsed.steps && program ? disassemble(parsed.steps, program.target, program.targetAbi) : [];
  }, [report.pocTrace, program]);

  const isOwner = Boolean(account && program && account.toLowerCase() === program.owner.toLowerCase());
  const isResearcher = Boolean(account && account.toLowerCase() === report.researcher.toLowerCase());
  const windowOpen = report.unlockTimestamp > now;
  const canChallenge = isOwner && report.status === "VALIDATED" && windowOpen;
  const claimable = CLAIMABLE.includes(report.status);
  const expirable = report.status === "INVALIDATED";
  const fee = (report.bounty * BigInt(feeBps)) / 10_000n;
  const run = async (fn: () => Promise<boolean>) => {
    setBusy(true);
    await fn();
    setBusy(false);
  };

  return (
    <article className="glass min-w-0 p-5">
      <div className="flex flex-wrap items-start gap-3">
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-sky-400/25 bg-slate-950/60 font-mono text-sm font-bold text-sky-200 shadow-[0_4px_0_0_rgb(2_6_23)]">
          #{report.id}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={report.awardedSeverity || report.claimedSeverity} />
            {report.awardedSeverity && report.awardedSeverity !== report.claimedSeverity && (
              <span className="text-[11px] text-slate-500">claimed {report.claimedSeverity}</span>
            )}
            <StatusBadge status={report.status} />
            {isResearcher && <span className="text-[11px] text-sky-300">your report</span>}
            {isOwner && <span className="text-[11px] text-amber-200">your program</span>}
          </div>
          <p className="mt-1.5 text-xs text-slate-500">
            Program #{report.programId} - researcher{" "}
            <ExtLink href={explorerAddress(report.researcher)} className="font-mono">{shortAddr(report.researcher)}</ExtLink> - filed {dateTime(report.submittedAt)}
          </p>
        </div>
      </div>

      {report.description && <p className="mt-3 line-clamp-3 text-sm text-slate-300">{report.description}</p>}

      {report.callPath && (
        <p className="mt-2 break-all font-mono text-[11px] text-slate-500" title={`fingerprint ${report.fingerprint}`}>
          path {report.callPath}
        </p>
      )}
      {report.status === "REJECTED" && report.rejectionReason && (
        <p className="mt-1 text-[11px] text-rose-300">
          Rejected: {report.rejectionReason === "ERR_DUPLICATE_VULNERABILITY" ? "duplicate of an already validated vulnerability" : "consensus triage did not support the claim"}
        </p>
      )}

      <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Stat label="Bounty locked" value={`${formatGen(report.bounty)} GEN`} hint={report.bounty > 0n ? `net ${formatGen(report.bounty - fee)} after fee` : undefined} />
        <Stat label="Researcher bond" value={`${formatGen(report.researcherBond)} GEN`} />
        <Stat label="Challenge bond" value={report.challengeBondPosted > 0n ? `${formatGen(report.challengeBondPosted)} GEN` : "none"} hint={report.rebuttalType || undefined} />
        <Stat label="PoC hash" value={<span title={report.pocHash}>{report.pocHash.slice(0, 10)}...</span>} />
      </div>

      {report.status !== "REJECTED" && <div className="mt-3"><Countdown report={report} now={now} /></div>}

      {(report.triageReasoning || report.challengeReasoning) && (
        <div className="mt-3 space-y-2">
          {report.triageReasoning && (
            <p className="glass-inset px-3 py-2 text-xs text-slate-400">
              <span className="mr-1 font-semibold text-sky-300">Triage verdict:</span>
              {report.triageReasoning}
            </p>
          )}
          {report.challengeReasoning && (
            <p className="glass-inset px-3 py-2 text-xs text-slate-400">
              <span className="mr-1 font-semibold text-rose-300">Rebuttal verdict:</span>
              {report.challengeReasoning}
            </p>
          )}
        </div>
      )}

      <button type="button" className="mt-3 inline-flex items-center gap-1 text-xs text-sky-300 hover:text-sky-200" onClick={() => setShowTrace(!showTrace)}>
        <FileSearch size={13} /> {showTrace ? "Hide" : "Inspect"} PoC disassembly ({disasm.length} steps)
      </button>
      {showTrace && (
        <div className="mt-2 overflow-auto rounded-lg border border-sky-400/10">
          <table className="w-full text-left font-mono text-[11px]">
            <tbody>
              {disasm.map((d) => (
                <tr key={d.index} className="border-b border-sky-400/5">
                  <td className="px-2 py-1.5 text-slate-500">{d.index}</td>
                  <td className="px-2 py-1.5 text-slate-300">{shortAddr(d.to)}</td>
                  <td className="px-2 py-1.5 text-amber-200">{d.selector}</td>
                  <td className="px-2 py-1.5 text-emerald-200">{d.function}</td>
                  <td className="px-2 py-1.5 text-slate-500">{d.word_count} words / {d.calldata_bytes} bytes</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="mt-4 flex flex-wrap gap-2">
        {claimable && (
          <button type="button" className="btn-3d" disabled={!account || windowOpen || busy} onClick={() => run(() => actions.onClaim(report.id))} title={windowOpen ? "Available once the challenge window closes" : "Anyone may settle"}>
            <Coins size={15} /> {windowOpen ? `Claim in ${duration(report.unlockTimestamp - now)}` : busy ? "Settling..." : "Claim Bounty"}
          </button>
        )}
        {expirable && (
          <button type="button" className="btn-3d-ghost" disabled={!account || windowOpen || busy} onClick={() => run(() => actions.onExpire(report.id))}>
            <Unlock size={15} /> {windowOpen ? `Expire in ${duration(report.unlockTimestamp - now)}` : "Expire & return funds"}
          </button>
        )}
        {canChallenge && !rebutting && (
          <button type="button" className="btn-3d-danger" onClick={() => setRebutting(true)}>
            <Scale size={15} /> File bound rebuttal
          </button>
        )}
      </div>

      {rebutting && canChallenge && (
        <RebuttalBuilder report={report} disasm={disasm} challengeBond={challengeBond} onChallenge={actions.onChallenge} onDone={() => setRebutting(false)} />
      )}
    </article>
  );
}

type Filter = "all" | "action" | "mine";

export function Reports({ snapshot, account, claimable, actions }: { snapshot: Snapshot | null; account: string | null; claimable: bigint; actions: Actions }) {
  const now = useNow();
  const [filter, setFilter] = useState<Filter>("all");
  const [busy, setBusy] = useState(false);
  const programs = new Map((snapshot?.programs ?? []).map((p) => [p.id, p]));
  const me = account?.toLowerCase();
  const reports = (snapshot?.reports ?? []).filter((r) => {
    if (filter === "mine") return me && (r.researcher.toLowerCase() === me || programs.get(r.programId)?.owner.toLowerCase() === me);
    if (filter === "action") return ["VALIDATED", "CHALLENGE_DISMISSED", "DOWNGRADED", "INVALIDATED"].includes(r.status);
    return true;
  });

  return (
    <Card className="p-5 sm:p-6">
      <SectionHeader
        eyebrow="Triage center"
        title="Reports & Disputes"
        subtitle="Validated reports lock their bounty behind an immutable challenge window. Once it closes, anyone can settle and the payout needs no approval."
        action={
          <div className="flex rounded-xl border border-sky-400/15 bg-slate-950/60 p-1 text-xs">
            {(["all", "action", "mine"] as Filter[]).map((f) => (
              <button key={f} type="button" onClick={() => setFilter(f)} className={`rounded-lg px-3 py-1.5 font-semibold capitalize transition ${filter === f ? "bg-sky-400/20 text-white" : "text-slate-400 hover:text-slate-200"}`}>
                {f === "action" ? "Open" : f}
              </button>
            ))}
          </div>
        }
      />

      {account && (
        <div className="glass-inset mb-5 flex flex-wrap items-center gap-3 px-4 py-3">
          <Wallet size={18} className="text-sky-300" />
          <div>
            <p className="text-[11px] uppercase tracking-wider text-slate-500">Your claimable balance (pull payment)</p>
            <p className="font-mono text-lg text-white">{formatGen(claimable)} GEN</p>
          </div>
          <button
            type="button"
            className="btn-3d ml-auto"
            disabled={claimable === 0n || busy}
            onClick={async () => {
              setBusy(true);
              await actions.onWithdraw();
              setBusy(false);
            }}
          >
            {busy ? "Withdrawing..." : "Withdraw"}
          </button>
        </div>
      )}

      {reports.length === 0 ? (
        <EmptyState icon={<FileSearch size={28} />} title="No reports in this view" body="Submitted reports appear here with their triage verdict, challenge window countdown and settlement actions." />
      ) : (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          {reports.map((r) => (
            <ReportCard key={r.id} report={r} program={programs.get(r.programId)} account={account} now={now} challengeBond={snapshot!.params.challengeBond} feeBps={snapshot!.params.protocolFeeBps} actions={actions} />
          ))}
        </div>
      )}
    </Card>
  );
}
