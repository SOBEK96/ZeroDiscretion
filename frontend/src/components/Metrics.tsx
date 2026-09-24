import { Landmark, Scale, ShieldCheck, Trophy } from "lucide-react";
import type { ReactNode } from "react";
import type { Snapshot } from "../lib/chain";
import { formatGen } from "../lib/format";

function Metric({ icon, label, value, sub, accent = false }: { icon: ReactNode; label: string; value: ReactNode; sub: ReactNode; accent?: boolean }) {
  return (
    <div className="glass relative overflow-hidden p-4 sm:p-5">
      <div className="pointer-events-none absolute -right-6 -top-6 h-24 w-24 rounded-full bg-sky-400/10 blur-2xl" />
      <div className="flex items-center gap-2 text-sky-300/80">
        {icon}
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400">{label}</p>
      </div>
      <p className={`mt-3 font-mono text-2xl font-semibold tracking-tight sm:text-3xl ${accent ? "text-emerald-300" : "text-white"}`}>{value}</p>
      <p className="mt-1 text-xs text-slate-500">{sub}</p>
    </div>
  );
}

export function Metrics({ snapshot, loading }: { snapshot: Snapshot | null; loading: boolean }) {
  const dash = loading ? <span className="inline-block h-7 w-24 animate-pulse rounded bg-slate-700/60" /> : "-";
  if (!snapshot) {
    return (
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {["Total Value Locked", "Active Programs", "Exploits Paid Out", "Escrow Solvency"].map((l) => (
          <Metric key={l} icon={<Landmark size={16} />} label={l} value={dash} sub="Reading contract state" />
        ))}
      </div>
    );
  }
  const { accounting, solvency, programs, reports } = snapshot;
  const active = programs.filter((p) => p.status === "ACTIVE" || p.status === "CLOSING").length;
  const paid = reports.filter((r) => r.status === "PAID");
  const paidTotal = programs.reduce((sum, p) => sum + p.totalPaid, 0n);
  const ratio =
    solvency.liabilities === 0n ? 100 : Number((solvency.balance * 10_000n) / solvency.liabilities) / 100;

  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <Metric
        icon={<Landmark size={16} />}
        label="Total Value Locked"
        value={<>{formatGen(accounting.liabilities, 2)} <span className="text-base text-slate-400">GEN</span></>}
        sub={<>Vaults {formatGen(accounting.vaultReserves, 2)} / bonds {formatGen(accounting.bondedResearcher + accounting.bondedProject, 2)}</>}
      />
      <Metric icon={<ShieldCheck size={16} />} label="Active Programs" value={active} sub={`${programs.length} registered, ${reports.length} ${reports.length === 1 ? "report" : "reports"} filed`} />
      <Metric
        icon={<Trophy size={16} />}
        label="Exploits Paid Out"
        value={paid.length}
        sub={<>{formatGen(paidTotal, 2)} GEN disbursed without approval</>}
      />
      <Metric
        icon={<Scale size={16} />}
        label="Escrow Solvency"
        accent={solvency.exact}
        value={`${ratio.toFixed(ratio % 1 === 0 ? 0 : 2)}%`}
        sub={solvency.exact ? "Balance equals ledger, verified on-chain" : solvency.solvent ? "Solvent (surplus present)" : "Ledger exceeds balance"}
      />
    </div>
  );
}
