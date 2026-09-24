import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, CircleAlert, FlaskConical, Send, Sparkles, XCircle } from "lucide-react";
import { BPS, SEVERITIES, type Severity } from "../config";
import { useNow } from "../hooks";
import type { Snapshot } from "../lib/chain";
import { formatGen, parseGen, shortAddr } from "../lib/format";
import { bountyFor, callPath, checkTargetSelectors, disassemble, examplePoc, fingerprint, meetsFloor, parsePoc, sha256Hex } from "../lib/poc";
import { Card, SectionHeader, SeverityBadge } from "./ui";

interface Props {
  snapshot: Snapshot | null;
  account: string | null;
  programId: number | null;
  setProgramId: (id: number) => void;
  onSubmit: (programId: number, severity: string, trace: string, description: string, bond: bigint) => Promise<boolean>;
}

interface Check {
  label: string;
  ok: boolean;
  code?: string;
  detail?: string;
}

const MAX_DESCRIPTION = 8_000;

export function SubmitForm({ snapshot, account, programId, setProgramId, onSubmit }: Props) {
  const [severity, setSeverity] = useState<Severity>("CRITICAL");
  const [trace, setTrace] = useState("");
  const [description, setDescription] = useState("");
  const [bondInput, setBondInput] = useState("1");
  const [hashed, setHashed] = useState<{ canonical: string; hash: string } | null>(null);
  const now = useNow(5000);
  const [busy, setBusy] = useState(false);

  const params = snapshot?.params;
  const programs = useMemo(() => (snapshot?.programs ?? []).filter((p) => p.status !== "CLOSED"), [snapshot]);
  const program = programs.find((p) => p.id === programId) ?? programs[0];

  useEffect(() => {
    if (program && program.id !== programId) setProgramId(program.id);
  }, [program, programId, setProgramId]);

  const minBond = params?.minResearcherBond ?? 10n ** 18n;
  const bond = parseGen(bondInput);
  const poc = useMemo(() => (program ? parsePoc(trace, program.target, program.targetChainId) : null), [trace, program]);
  const disasm = useMemo(() => (poc?.ok && poc.steps && program ? disassemble(poc.steps, program.target, program.targetAbi) : []), [poc, program]);
  const selectorError = useMemo(
    () => (poc?.ok && poc.steps && program ? checkTargetSelectors(poc.steps, program.target, program.targetAbi, program.targetHasFallback) : null),
    [poc, program],
  );
  const fp = useMemo(() => (poc?.ok && poc.steps ? fingerprint(poc.steps) : ""), [poc]);
  const path = useMemo(() => (poc?.ok && poc.steps && program ? callPath(poc.steps, program.target, program.targetAbi) : ""), [poc, program]);
  const validatedPaths = useMemo(
    () => (snapshot?.reports ?? []).filter((r) => r.programId === program?.id && r.status !== "REJECTED" && r.fingerprint),
    [snapshot, program],
  );

  useEffect(() => {
    const canonical = poc?.ok ? poc.canonical : undefined;
    if (!canonical) return;
    let live = true;
    void sha256Hex(canonical).then((hash) => live && setHashed({ canonical, hash }));
    return () => {
      live = false;
    };
  }, [poc]);
  const pocHash = poc?.ok && hashed && hashed.canonical === poc.canonical ? hashed.hash : "";

  const bounty = program && params ? bountyFor(program.available, severity, params.payoutBps) : 0n;
  const fee = params ? (bounty * BigInt(params.protocolFeeBps)) / BPS : 0n;

  const checks: Check[] = useMemo(() => {
    if (!program || !params) return [];
    const closed = program.status === "CLOSED" || (program.status === "CLOSING" && now >= program.closesAt);
    const duplicateOf = fp ? validatedPaths.find((r) => r.fingerprint === fp) : undefined;
    return [
      { label: "Program accepts submissions", ok: !closed, code: "ERR_PROGRAM_CLOSED" },
      { label: `Bond >= ${formatGen(minBond)} GEN`, ok: bond !== null && bond >= minBond, code: "ERR_INSUFFICIENT_BOND" },
      { label: `Severity meets program floor (${program.minSeverity})`, ok: meetsFloor(severity, program.minSeverity), code: "ERR_BELOW_MIN_SEVERITY" },
      { label: "Reporter is not the program owner", ok: !account || account.toLowerCase() !== program.owner.toLowerCase(), code: "ERR_SELF_REPORT" },
      { label: "Description within 8000 characters", ok: description.length <= MAX_DESCRIPTION, code: "ERR_INPUT_TOO_LARGE" },
      { label: `PoC schema, target and chain ${program.targetChainId} binding`, ok: Boolean(poc?.ok), code: poc?.error?.code, detail: poc?.error?.detail },
      {
        label: "Target selectors exist in the verified ABI",
        ok: Boolean(poc?.ok) && !selectorError,
        code: selectorError?.code,
        detail: selectorError?.detail,
      },
      {
        label: "Execution path not already validated",
        ok: !duplicateOf,
        code: "ERR_DUPLICATE_VULNERABILITY",
        detail: duplicateOf ? `same fingerprint as report #${duplicateOf.id}` : undefined,
      },
      { label: "Vault can fund this tier", ok: bounty > 0n, code: "ERR_VAULT_DEPLETED" },
    ];
  }, [program, params, bond, minBond, severity, account, description, poc, selectorError, fp, validatedPaths, bounty, now]);

  const allOk = checks.length > 0 && checks.every((c) => c.ok) && trace.length > 0;

  if (!snapshot || !params) {
    return (
      <Card className="p-6">
        <SectionHeader eyebrow="Disclosure" title="Vulnerability Disclosure" subtitle="Loading programs..." />
      </Card>
    );
  }

  return (
    <Card className="p-5 sm:p-6">
      <SectionHeader
        eyebrow="Disclosure"
        title="Submit a Bonded PoC"
        subtitle="Consensus triage runs in the same transaction. If validators cannot reproduce the PoC at the severity you claim, your bond is slashed, so run the dry-run first."
      />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        {/* ---------------- form ---------------- */}
        <form
          className="min-w-0 space-y-4"
          onSubmit={async (e) => {
            e.preventDefault();
            if (!program || !bond || !allOk) return;
            setBusy(true);
            const ok = await onSubmit(program.id, severity, trace, description, bond);
            setBusy(false);
            if (ok) {
              setTrace("");
              setDescription("");
            }
          }}
        >
          <div>
            <label className="label" htmlFor="zd-program">Program</label>
            <select id="zd-program" className="field" value={program?.id ?? ""} onChange={(e) => setProgramId(Number(e.target.value))}>
              {programs.map((p) => (
                <option key={p.id} value={p.id}>
                  #{p.id} - target {shortAddr(p.target, 6)} - {formatGen(p.available, 2)} GEN available
                </option>
              ))}
            </select>
          </div>

          <div>
            <span className="label">Claimed severity</span>
            <div className="grid grid-cols-4 gap-2" role="radiogroup" aria-label="Claimed severity">
              {SEVERITIES.map((s) => (
                <button
                  key={s}
                  type="button"
                  role="radio"
                  aria-checked={severity === s}
                  onClick={() => setSeverity(s)}
                  className={`rounded-xl border px-2 py-2 font-mono text-xs font-semibold transition ${
                    severity === s
                      ? "border-sky-300/70 bg-sky-400/20 text-white shadow-[0_3px_0_0_rgb(3_105_161/0.8),0_0_18px_-4px_rgb(56_189_248/0.7)]"
                      : "border-sky-400/15 bg-slate-950/50 text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {s}
                  <span className="block text-[10px] font-normal text-slate-500">{(params.payoutBps[s] ?? 0) / 100}% vault</span>
                </button>
              ))}
            </div>
          </div>

          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <label className="label !mb-0" htmlFor="zd-trace">PoC trace (JSON calldata steps)</label>
              {program && (
                <button type="button" className="inline-flex items-center gap-1 text-xs text-sky-300 hover:text-sky-200" onClick={() => setTrace(examplePoc(program.target, program.targetChainId, program.targetAbi))}>
                  <Sparkles size={12} /> Load template
                </button>
              )}
            </div>
            <textarea
              id="zd-trace"
              className="field h-56 resize-y font-mono text-xs leading-relaxed"
              spellCheck={false}
              placeholder='{"target": "0x...", "chain_id": 1, "invariant_broken": "...", "steps": [{"to": "0x...", "calldata": "0x2e1a7d4d...", "value": "0"}]}'
              value={trace}
              onChange={(e) => setTrace(e.target.value)}
            />
          </div>

          <div>
            <label className="label" htmlFor="zd-desc">Description</label>
            <textarea
              id="zd-desc"
              className="field h-28 resize-y"
              placeholder="Root cause, impact, and why the steps reproduce it."
              value={description}
              maxLength={MAX_DESCRIPTION}
              onChange={(e) => setDescription(e.target.value)}
            />
            <p className="mt-1 text-right text-[11px] text-slate-500">{description.length} / {MAX_DESCRIPTION}</p>
          </div>

          <div className="glass-inset grid gap-3 p-4 sm:grid-cols-[10rem_1fr]">
            <div>
              <label className="label" htmlFor="zd-bond">Bond (GEN)</label>
              <input id="zd-bond" className="field font-mono" inputMode="decimal" value={bondInput} onChange={(e) => setBondInput(e.target.value)} />
              <p className="mt-1 text-[11px] text-slate-500">Minimum {formatGen(minBond)} GEN</p>
            </div>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
              <dt className="text-slate-500">Bounty locked if validated</dt>
              <dd className="text-right font-mono text-slate-100">{formatGen(bounty)} GEN</dd>
              <dt className="text-slate-500">Protocol fee ({params.protocolFeeBps / 100}%)</dt>
              <dd className="text-right font-mono text-slate-400">-{formatGen(fee)} GEN</dd>
              <dt className="text-slate-500">Bond returned on payout</dt>
              <dd className="text-right font-mono text-slate-400">+{formatGen(bond ?? 0n)} GEN</dd>
              <dt className="font-semibold text-sky-200">Payout after window</dt>
              <dd className="text-right font-mono font-semibold text-emerald-300">{formatGen(bounty - fee + (bond ?? 0n))} GEN</dd>
              <dt className="text-slate-500">At risk if rejected</dt>
              <dd className="text-right font-mono text-rose-300">-{formatGen(bond ?? 0n)} GEN</dd>
            </dl>
          </div>

          <button type="submit" className="btn-3d w-full !py-3" disabled={!account || !allOk || busy}>
            <Send size={16} />
            {!account ? "Connect wallet to submit" : busy ? "Awaiting consensus..." : `Sign & submit with ${formatGen(bond ?? 0n)} GEN bond`}
          </button>
        </form>

        {/* ---------------- dry-run inspector ---------------- */}
        <div className="glass-inset relative flex min-w-0 flex-col overflow-hidden p-4">
          <div className="flex items-center gap-2">
            <FlaskConical size={16} className="text-sky-300" />
            <p className="font-semibold text-white">Dry-run inspector</p>
            <span className={`ml-auto rounded-full px-2 py-0.5 text-[10px] font-semibold ${allOk ? "bg-emerald-500/15 text-emerald-300" : "bg-amber-400/10 text-amber-200"}`}>
              {trace.length === 0 ? "AWAITING POC" : allOk ? "READY FOR CONSENSUS" : "WOULD REVERT"}
            </span>
          </div>
          <p className="mt-1 text-[11px] leading-relaxed text-slate-500">
            Runs the contract's deterministic pre-consensus checks locally: the same parser, selector gate against the Sourcify-verified ABI,
            semantic fingerprint and disassembly every validator computes. The LLM verdicts (severity, padded duplicates) are only decided on-chain.
          </p>

          <ul className="mt-3 space-y-1.5">
            {checks.map((c) => (
              <li key={c.label} className="flex items-start gap-2 text-xs">
                {c.ok ? <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-emerald-400" /> : <XCircle size={14} className="mt-0.5 shrink-0 text-rose-400" />}
                <span className={c.ok ? "text-slate-300" : "text-rose-200"}>
                  {c.label}
                  {!c.ok && c.code && <span className="ml-1 font-mono text-[10px] text-rose-400">{c.code}</span>}
                  {!c.ok && c.detail && <span className="block text-[11px] text-rose-300/70">{c.detail}</span>}
                </span>
              </li>
            ))}
          </ul>

          {fp && (
            <div className="mt-4 space-y-2">
              <div>
                <p className="label">Semantic fingerprint (keccak256 of execution path)</p>
                <p className="break-all rounded-lg bg-slate-950/70 px-2 py-1.5 font-mono text-[11px] text-emerald-200">{fp}</p>
              </div>
              <div>
                <p className="label">Execution path</p>
                <p className="break-all rounded-lg bg-slate-950/70 px-2 py-1.5 font-mono text-[11px] text-slate-300">{path}</p>
              </div>
              {pocHash && (
                <div>
                  <p className="label">Exact trace hash (sha256, binds rebuttals)</p>
                  <p className="break-all rounded-lg bg-slate-950/70 px-2 py-1.5 font-mono text-[11px] text-sky-200">{pocHash}</p>
                </div>
              )}
            </div>
          )}

          {validatedPaths.length > 0 && (
            <div className="mt-4">
              <p className="label">Already validated in this program ({validatedPaths.length})</p>
              <ul className="max-h-28 space-y-1 overflow-auto text-[11px]">
                {validatedPaths.map((r) => (
                  <li key={r.id} className={`rounded-md px-2 py-1 font-mono ${r.fingerprint === fp ? "bg-rose-500/15 text-rose-200" : "bg-slate-950/60 text-slate-400"}`}>
                    #{r.id} {r.callPath}
                  </li>
                ))}
              </ul>
              <p className="mt-1 text-[11px] text-slate-500">A padded variant of any of these is judged a duplicate by consensus and forfeits the bond.</p>
            </div>
          )}

          {disasm.length > 0 && (
            <div className="mt-4 min-w-0">
              <p className="label">Calldata disassembly, resolved against the verified ABI</p>
              <div className="max-h-64 overflow-auto rounded-lg border border-sky-400/10">
                <table className="w-full text-left font-mono text-[11px]">
                  <thead className="sticky top-0 bg-slate-900 text-slate-500">
                    <tr>
                      <th className="px-2 py-1.5">#</th>
                      <th className="px-2 py-1.5">to</th>
                      <th className="px-2 py-1.5">selector</th>
                      <th className="px-2 py-1.5">function</th>
                      <th className="px-2 py-1.5">words</th>
                      <th className="px-2 py-1.5">bytes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {disasm.map((d) => (
                      <tr key={d.index} className="border-t border-sky-400/5 align-top">
                        <td className="px-2 py-1.5 text-slate-500">{d.index}</td>
                        <td className={`px-2 py-1.5 ${d.to === program?.target.toLowerCase() ? "text-sky-300" : "text-slate-300"}`}>{shortAddr(d.to)}</td>
                        <td className="px-2 py-1.5 text-amber-200">{d.selector}</td>
                        <td className={`px-2 py-1.5 ${d.function === "unresolved" ? "text-rose-300" : d.function === "external" ? "text-slate-500" : "text-emerald-200"}`}>{d.function}</td>
                        <td className="px-2 py-1.5 text-slate-400">
                          {d.word_count}
                          {d.words[0] && <span className="block max-w-[14rem] truncate text-slate-600" title={d.words.join("\n")}>{d.words[0]}</span>}
                        </td>
                        <td className="px-2 py-1.5 text-slate-400">{d.calldata_bytes}{d.trailing_bytes > 0 && <span className="text-amber-300"> +{d.trailing_bytes}</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <div className="mt-auto pt-4">
            <div className="flex items-start gap-2 rounded-lg border border-sky-400/15 bg-sky-400/5 p-3 text-[11px] leading-relaxed text-slate-400">
              <CircleAlert size={14} className="mt-0.5 shrink-0 text-sky-300" />
              <span>
                Validators accept only if the PoC is reproducible, in scope of the pinned policy, and supports at least{" "}
                <SeverityBadge severity={severity} />. Claiming lower than the assessed tier is safe; claiming higher forfeits the bond.
              </span>
            </div>
          </div>
        </div>
      </div>
    </Card>
  );
}
