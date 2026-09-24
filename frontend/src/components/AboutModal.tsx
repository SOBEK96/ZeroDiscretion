import { Cpu, FileLock2, Gavel, Timer, Unlock } from "lucide-react";
import { CONTRACT_ADDRESS, REPO_URL, explorerAddress } from "../config";
import { ShieldLogo } from "./Header";
import { ExtLink, Modal } from "./ui";

const STEPS = [
  {
    icon: <FileLock2 size={20} />,
    title: "Policy Pinning",
    body: "The project locks a GEN vault and binds it to its GitHub SECURITY.md at a full 40-character commit SHA. The URL is validated on-chain (https, GitHub hosts only, no SSRF), and the policy bytes are hash-pinned on the first triage, so scope and exclusions cannot be rewritten after a disclosure.",
  },
  {
    icon: <Cpu size={20} />,
    title: "Bonded PoC Triage",
    body: "A researcher posts a bond with an executable PoC trace: target, chain id and ordered calldata steps. The contract validates the schema, computes a canonical hash for de-duplication, and disassembles every step into selector and ABI words. Every validator computes the same result.",
  },
  {
    icon: <Gavel size={20} />,
    title: "Deterministic Consensus Verdict",
    body: "Validators fetch the pinned policy and judge the PoC against the severity matrix with an LLM, using the disassembly as ground truth. A custom equivalence validator requires them to agree on the policy digest and the accept/reject decision. If the claim is overstated or cannot be reproduced, the bond is slashed.",
  },
  {
    icon: <Timer size={20} />,
    title: "Timelocked Auto-Disbursement",
    body: "A validated report locks its bounty and opens an immutable challenge window. The project's only recourse is a bonded rebuttal that is bound to the PoC's hash, step indices and selectors, and re-judged by consensus. When the window lapses anyone can settle, and the vault pays out without approval.",
  },
];

export function AboutModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Modal open={open} onClose={onClose} title="How ZeroDiscretion works" wide>
      <div className="flex items-center gap-4">
        <ShieldLogo size={56} />
        <div>
          <p className="eyebrow">Mechanism</p>
          <h2 className="text-2xl font-bold tracking-tight text-white">Zero discretion, by construction</h2>
        </div>
      </div>

      <p className="mt-5 text-sm leading-relaxed text-slate-300">
        In a conventional bug bounty, the project that pays is also the judge. A valid critical can be closed as "known", "out of
        scope" or "won't fix", and the researcher has no appeal. ZeroDiscretion removes that veto. Reserves sit in an autonomous
        vault, the rules are pinned to an immutable policy commit, and GenLayer validator consensus decides every payout. No project
        team can dismiss a legitimate vulnerability or stall a payout indefinitely.
      </p>

      <ol className="mt-6 grid gap-3 sm:grid-cols-2">
        {STEPS.map((s, i) => (
          <li key={s.title} className="glass-inset relative p-4">
            <div className="flex items-center gap-3">
              <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-sky-400/30 bg-sky-400/10 text-sky-300 shadow-[0_4px_0_0_rgb(3_105_161/0.6)]">
                {s.icon}
              </span>
              <div>
                <p className="font-mono text-[10px] text-sky-400/80">STEP {i + 1}</p>
                <p className="font-semibold text-white">{s.title}</p>
              </div>
            </div>
            <p className="mt-3 text-[13px] leading-relaxed text-slate-400">{s.body}</p>
          </li>
        ))}
      </ol>

      <div className="mt-6 rounded-xl border border-sky-400/25 bg-gradient-to-br from-sky-500/10 to-transparent p-5">
        <div className="flex items-center gap-2 text-sky-200">
          <Unlock size={18} />
          <h3 className="font-semibold">Why this needs GenLayer, not the EVM</h3>
        </div>
        <ul className="mt-3 space-y-2 text-[13px] leading-relaxed text-slate-300">
          <li>
            <span className="font-semibold text-white">No native web access.</span> An EVM contract cannot fetch a GitHub policy. It
            has to trust an oracle or an admin to relay it, and that relayer becomes the discretion you were trying to remove.
            GenVM validators each fetch the pinned policy themselves and must agree on its digest.
          </li>
          <li>
            <span className="font-semibold text-white">No non-deterministic judgement.</span> EVM consensus requires every node to
            produce identical bytes, so it cannot run an LLM or evaluate natural-language severity criteria. GenLayer's equivalence
            principle lets validators reach consensus on the <em>decision</em> (accept or reject, outcome, tier) even though each model's
            prose differs.
          </li>
          <li>
            <span className="font-semibold text-white">No trusted committee.</span> On the EVM, severity disputes fall back to a
            multisig or an arbitration DAO. Here the only human input is bonded and bound to the PoC, and the same consensus that
            validated the report judges it.
          </li>
        </ul>
      </div>

      <div className="mt-5 flex flex-wrap gap-4 text-sm">
        <ExtLink href={explorerAddress(CONTRACT_ADDRESS)}>Contract on explorer</ExtLink>
        <ExtLink href={`${REPO_URL}/blob/main/specs/game_theory.md`}>Game-theory specification</ExtLink>
        <ExtLink href={`${REPO_URL}/blob/main/contracts/zero_discretion.py`}>Contract source</ExtLink>
      </div>
    </Modal>
  );
}
