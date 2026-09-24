import { CheckCircle2, Loader2, PenLine, XCircle, X } from "lucide-react";
import { explorerTx } from "../config";
import type { TxRecord } from "../hooks";
import { ExtLink } from "./ui";

const ICON = {
  signing: <PenLine size={16} className="text-sky-300" />,
  pending: <Loader2 size={16} className="animate-spin text-sky-300" />,
  success: <CheckCircle2 size={16} className="text-emerald-400" />,
  reverted: <XCircle size={16} className="text-rose-400" />,
  error: <XCircle size={16} className="text-rose-400" />,
};

const TITLE = {
  signing: "Confirm in your wallet",
  pending: "Submitted - awaiting consensus",
  success: "Decided on-chain",
  reverted: "Reverted by the contract",
  error: "Transaction failed",
};

export function TxToasts({ txs, onDismiss }: { txs: TxRecord[]; onDismiss: (id: number) => void }) {
  if (txs.length === 0) return null;
  return (
    <div className="fixed bottom-4 right-4 z-50 flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2" aria-live="polite">
      {txs.map((t) => (
        <div key={t.id} className="glass flex gap-3 p-3.5">
          <div className="mt-0.5">{ICON[t.phase]}</div>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold text-white">{TITLE[t.phase]}</p>
            <p className="text-xs text-slate-400">{t.label}</p>
            {t.detail && <p className="mt-1 break-words text-[11px] text-slate-500">{t.detail}</p>}
            {t.hash && (
              <ExtLink href={explorerTx(t.hash)} className="mt-1 font-mono text-[11px]">
                {t.hash.slice(0, 18)}...
              </ExtLink>
            )}
          </div>
          {t.phase !== "signing" && t.phase !== "pending" && (
            <button type="button" onClick={() => onDismiss(t.id)} aria-label="Dismiss" className="self-start rounded p-0.5 text-slate-500 hover:text-slate-200">
              <X size={14} />
            </button>
          )}
        </div>
      ))}
    </div>
  );
}
