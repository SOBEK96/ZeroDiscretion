import { useCallback, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { AboutModal } from "./components/AboutModal";
import { Footer } from "./components/Footer";
import { Header } from "./components/Header";
import { Metrics } from "./components/Metrics";
import { Programs } from "./components/Programs";
import { Reports } from "./components/Reports";
import { SubmitForm } from "./components/SubmitForm";
import { TxToasts } from "./components/TxToasts";
import { useClaimable, useProtocol, useTransactions, useWallet } from "./hooks";
import { formatGen } from "./lib/format";

export default function App() {
  const { snapshot, error, online, loading, refresh } = useProtocol();
  const wallet = useWallet();
  const claimable = useClaimable(wallet.account, snapshot?.fetchedAt);
  const { txs, send, dismiss } = useTransactions(wallet.account, refresh);
  const [aboutOpen, setAboutOpen] = useState(false);
  const [programId, setProgramId] = useState<number | null>(null);

  const closeAbout = useCallback(() => setAboutOpen(false), []);
  const withdraw = useCallback(() => send("withdraw", [], 0n, `Withdraw ${formatGen(claimable)} GEN`), [send, claimable]);

  const reportProgram = useCallback((id: number) => {
    setProgramId(id);
    document.getElementById("disclose")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  return (
    <>
      <div className="zd-canvas" aria-hidden="true" />
      <Header
        online={online}
        account={wallet.account}
        claimable={claimable}
        connecting={wallet.connecting}
        hasWallet={wallet.hasWallet}
        onConnect={wallet.connect}
        onDisconnect={wallet.disconnect}
        onAbout={() => setAboutOpen(true)}
        onWithdraw={() => void withdraw()}
      />

      <main id="top" className="mx-auto max-w-7xl space-y-8 px-4 pt-8 sm:px-6">
        <section className="relative">
          <p className="eyebrow">GenLayer intelligent contract - Studio Next</p>
          <h1 className="mt-2 max-w-4xl text-3xl font-extrabold leading-tight tracking-tight text-white sm:text-5xl">
            Bug bounties the project <span className="glow-text bg-gradient-to-r from-sky-200 via-sky-400 to-sky-200 bg-clip-text text-transparent">cannot veto</span>.
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-relaxed text-slate-400 sm:text-base">
            Reserves are locked against a commit-pinned security policy. Validator consensus judges each bonded PoC, and validated
            exploits pay out automatically once the challenge window closes.
          </p>
        </section>

        {(error || wallet.error || online === false) && (
          <div className="flex items-start gap-3 rounded-xl border border-amber-400/30 bg-amber-400/10 px-4 py-3 text-sm text-amber-100">
            <AlertTriangle size={18} className="mt-0.5 shrink-0" />
            <div>
              {online === false && <p>Studio Next RPC is unreachable. Retrying every 15 seconds.</p>}
              {error && <p>Could not read contract state: {error}</p>}
              {wallet.error && <p>{wallet.error}</p>}
            </div>
          </div>
        )}

        <Metrics snapshot={snapshot} loading={loading} />

        <Programs
          snapshot={snapshot}
          account={wallet.account}
          onTopUp={(id, amount) => send("top_up_vault", [id], amount, `Deposit ${formatGen(amount)} GEN into program #${id}`)}
          onReport={reportProgram}
        />

        <div id="disclose" className="scroll-mt-24">
          <SubmitForm
            snapshot={snapshot}
            account={wallet.account}
            programId={programId}
            setProgramId={setProgramId}
            onSubmit={(id, severity, trace, description, bond) =>
              send("submit_vulnerability", [id, severity, trace, description], bond, `Submit ${severity} report to program #${id}`)
            }
          />
        </div>

        <Reports
          snapshot={snapshot}
          account={wallet.account}
          claimable={claimable}
          actions={{
            onChallenge: (id, rebuttal, bond) => send("challenge_vulnerability", [id, rebuttal], bond, `Challenge report #${id}`),
            onClaim: (id) => send("claim_bounty", [id], 0n, `Claim bounty for report #${id}`),
            onExpire: (id) => send("expire_report", [id], 0n, `Expire report #${id}`),
            onWithdraw: withdraw,
          }}
        />
      </main>

      <Footer />
      <AboutModal open={aboutOpen} onClose={closeAbout} />
      <TxToasts txs={txs} onDismiss={dismiss} />
    </>
  );
}
