import { BookOpen, LogOut, Wallet } from "lucide-react";
import { CONTRACT_ADDRESS, NETWORK, explorerAddress } from "../config";
import { formatGen, shortAddr } from "../lib/format";
import { CopyButton, ExtLink } from "./ui";

export function ShieldLogo({ size = 44 }: { size?: number }) {
  return (
    <div className="relative [perspective:400px]" style={{ width: size, height: size }} aria-hidden="true">
      <div className="absolute inset-0 rounded-full bg-sky-400/30 blur-xl" />
      <svg viewBox="0 0 64 64" className="zd-logo-3d relative drop-shadow-[0_6px_14px_rgba(14,165,233,0.55)]" width={size} height={size}>
        <defs>
          <linearGradient id="zd-face" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#e0f2fe" />
            <stop offset="0.35" stopColor="#7dd3fc" />
            <stop offset="1" stopColor="#0284c7" />
          </linearGradient>
          <linearGradient id="zd-edge" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#0369a1" />
            <stop offset="1" stopColor="#082f49" />
          </linearGradient>
        </defs>
        {/* extruded edge */}
        <path d="M33 7 57 16v17c0 15-10 26-24 30C19 59 9 48 9 33V16z" fill="url(#zd-edge)" />
        {/* face */}
        <path d="M32 4 56 13v17c0 15-10 26-24 30C18 56 8 45 8 30V13z" fill="url(#zd-face)" />
        <path d="M32 8 52 15.5v14.5c0 12.5-8.2 21.6-20 25.2" fill="none" stroke="#f0f9ff" strokeOpacity="0.6" strokeWidth="1.2" />
        {/* vault dial */}
        <circle cx="32" cy="31" r="11" fill="#070b14" fillOpacity="0.88" stroke="#bae6fd" strokeWidth="1.5" />
        <path d="M26.5 26.5h11L26.5 35.5h11" fill="none" stroke="#38bdf8" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </div>
  );
}

interface HeaderProps {
  online: boolean | null;
  account: string | null;
  claimable: bigint;
  connecting: boolean;
  hasWallet: boolean;
  onConnect: () => void;
  onDisconnect: () => void;
  onAbout: () => void;
  onWithdraw: () => void;
}

export function Header({ online, account, claimable, connecting, hasWallet, onConnect, onDisconnect, onAbout, onWithdraw }: HeaderProps) {
  const status =
    online === null
      ? { dot: "bg-slate-400", ping: "", text: "Connecting" }
      : online
        ? { dot: "bg-emerald-400", ping: "animate-ping bg-emerald-400", text: "Live" }
        : { dot: "bg-rose-500", ping: "", text: "Unreachable" };

  return (
    <header className="sticky top-0 z-40 border-b border-sky-500/10 bg-[#070b14]/75 backdrop-blur-xl">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-5 gap-y-3 px-4 py-3 sm:px-6">
        <a href="#top" className="flex items-center gap-3">
          <ShieldLogo />
          <div className="leading-tight">
            <div className="flex items-center gap-2">
              <span className="glow-text text-lg font-extrabold tracking-tight text-white">ZeroDiscretion</span>
              <span className="hidden rounded-full border border-sky-400/30 bg-sky-400/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-sky-200 sm:inline">
                Autonomous Bounty Escrow
              </span>
            </div>
            <p className="text-[11px] text-slate-500">Zero-discretion whitehat payouts on GenLayer</p>
          </div>
        </a>

        <div className="ml-auto flex flex-wrap items-center gap-2.5">
          <div className="glass-inset flex items-center gap-2 px-3 py-1.5 text-xs" title={NETWORK.rpcUrl}>
            <span className="relative flex h-2.5 w-2.5">
              {status.ping && <span className={`absolute inline-flex h-full w-full rounded-full opacity-70 ${status.ping}`} />}
              <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${status.dot}`} />
            </span>
            <span className="font-medium text-slate-300">Studio Next</span>
            <span className="text-slate-500">{status.text}</span>
          </div>

          <div className="glass-inset hidden items-center gap-1 px-2.5 py-1 text-xs md:flex">
            <span className="text-slate-500">Contract</span>
            <span className="font-mono text-sky-200">{shortAddr(CONTRACT_ADDRESS)}</span>
            <CopyButton value={CONTRACT_ADDRESS} label="Copy contract address" />
            <ExtLink href={explorerAddress(CONTRACT_ADDRESS)} className="text-xs">
              <span className="sr-only">Open in explorer</span>
            </ExtLink>
          </div>

          <button type="button" className="btn-3d-ghost !px-3 !py-2" onClick={onAbout}>
            <BookOpen size={15} /> How It Works
          </button>

          {account ? (
            <div className="flex items-center gap-2">
              {claimable > 0n && (
                <button type="button" className="btn-3d !py-2" onClick={onWithdraw} title="Pull your credited balance">
                  Withdraw {formatGen(claimable)} GEN
                </button>
              )}
              <div className="glass-inset flex items-center gap-1.5 px-2.5 py-1.5 text-xs">
                <span className="h-2 w-2 rounded-full bg-sky-400 shadow-[0_0_8px_rgb(56_189_248)]" />
                <span className="font-mono text-slate-200">{shortAddr(account)}</span>
                <button type="button" onClick={onDisconnect} aria-label="Disconnect" className="ml-1 rounded p-0.5 text-slate-500 hover:text-slate-200">
                  <LogOut size={13} />
                </button>
              </div>
            </div>
          ) : (
            <button type="button" className="btn-3d !py-2" onClick={onConnect} disabled={connecting} title={hasWallet ? "" : "No injected wallet detected"}>
              <Wallet size={15} /> {connecting ? "Connecting..." : "Connect Wallet"}
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
