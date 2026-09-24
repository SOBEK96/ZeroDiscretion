import { useEffect, useState, type ReactNode } from "react";
import { Check, Copy, ExternalLink, X } from "lucide-react";

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`glass ${className}`}>{children}</section>;
}

export function SectionHeader({ eyebrow, title, subtitle, action }: { eyebrow: string; title: string; subtitle?: string; action?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h2 className="mt-1 text-xl font-bold tracking-tight text-white sm:text-2xl">{title}</h2>
        {subtitle && <p className="mt-1 max-w-2xl text-sm text-slate-400">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: "border-rose-400/40 bg-rose-500/15 text-rose-200 shadow-[0_0_16px_-4px_rgb(244_63_94/0.6)]",
  HIGH: "border-orange-400/40 bg-orange-500/15 text-orange-200",
  MEDIUM: "border-amber-300/40 bg-amber-400/10 text-amber-100",
  LOW: "border-sky-300/40 bg-sky-400/10 text-sky-100",
};

export function SeverityBadge({ severity }: { severity: string }) {
  if (!severity) return null;
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 font-mono text-[11px] font-semibold tracking-wider ${SEVERITY_STYLE[severity] ?? "border-slate-500/40 text-slate-300"}`}>
      {severity}
    </span>
  );
}

const STATUS_STYLE: Record<string, { cls: string; label: string }> = {
  VALIDATED: { cls: "border-sky-400/40 bg-sky-500/15 text-sky-100", label: "Validated - in window" },
  CHALLENGE_DISMISSED: { cls: "border-emerald-400/40 bg-emerald-500/10 text-emerald-200", label: "Challenge dismissed" },
  DOWNGRADED: { cls: "border-amber-300/40 bg-amber-400/10 text-amber-100", label: "Downgraded" },
  INVALIDATED: { cls: "border-rose-400/40 bg-rose-500/10 text-rose-200", label: "Rebuttal upheld" },
  REJECTED: { cls: "border-slate-500/40 bg-slate-700/30 text-slate-300", label: "Rejected - bond slashed" },
  PAID: { cls: "border-emerald-400/50 bg-emerald-500/15 text-emerald-100", label: "Paid out" },
  EXPIRED: { cls: "border-slate-500/40 bg-slate-700/30 text-slate-300", label: "Expired - funds returned" },
  ACTIVE: { cls: "border-emerald-400/40 bg-emerald-500/10 text-emerald-200", label: "Active" },
  CLOSING: { cls: "border-amber-300/40 bg-amber-400/10 text-amber-100", label: "Closing" },
  CLOSED: { cls: "border-slate-500/40 bg-slate-700/30 text-slate-300", label: "Closed" },
};

export function StatusBadge({ status }: { status: string }) {
  const s = STATUS_STYLE[status] ?? { cls: "border-slate-500/40 text-slate-300", label: status };
  return <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${s.cls}`}>{s.label}</span>;
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className="rounded-md p-1 text-sky-300/70 transition hover:bg-sky-400/10 hover:text-sky-200"
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        });
      }}
    >
      {done ? <Check size={14} /> : <Copy size={14} />}
    </button>
  );
}

export function ExtLink({ href, children, className = "" }: { href: string; children: ReactNode; className?: string }) {
  return (
    <a href={href} target="_blank" rel="noreferrer noopener" className={`inline-flex items-center gap-1 text-sky-300 hover:text-sky-200 hover:underline ${className}`}>
      {children}
      <ExternalLink size={12} className="shrink-0 opacity-70" />
    </a>
  );
}

export function Modal({ open, onClose, title, children, wide = false }: { open: boolean; onClose: () => void; title: string; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-950/75 p-4 backdrop-blur-sm sm:items-center" role="dialog" aria-modal="true" aria-label={title} onMouseDown={onClose}>
      <div className={`glass relative my-8 w-full ${wide ? "max-w-4xl" : "max-w-xl"} p-6 sm:p-8`} onMouseDown={(e) => e.stopPropagation()}>
        <button type="button" onClick={onClose} aria-label="Close" className="absolute right-4 top-4 rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white">
          <X size={18} />
        </button>
        {children}
      </div>
    </div>
  );
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="glass-inset px-3 py-2">
      <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">{label}</p>
      <p className="mt-0.5 font-mono text-sm text-slate-100">{value}</p>
      {hint && <p className="text-[11px] text-slate-500">{hint}</p>}
    </div>
  );
}

export function EmptyState({ icon, title, body }: { icon: ReactNode; title: string; body: string }) {
  return (
    <div className="glass-inset flex flex-col items-center gap-2 px-6 py-10 text-center">
      <div className="text-sky-300/60">{icon}</div>
      <p className="font-semibold text-slate-200">{title}</p>
      <p className="max-w-md text-sm text-slate-500">{body}</p>
    </div>
  );
}
