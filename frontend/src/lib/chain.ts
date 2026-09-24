// GenLayer access layer. Reads use an account-less client (gen_call needs no
// signer), so protocol state renders before any wallet connects. Writes go
// through the injected wallet; the key never leaves the extension.

import { chains, createClient } from "genlayer-js";
import { CONTRACT_ADDRESS, NETWORK } from "../config";

type Client = ReturnType<typeof createClient>;

export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  on?(event: string, handler: (...args: unknown[]) => void): void;
  removeListener?(event: string, handler: (...args: unknown[]) => void): void;
}

export const injectedProvider = (): Eip1193Provider | undefined =>
  (window as unknown as { ethereum?: Eip1193Provider }).ethereum;

// The SDK's own chain object carries the consensus contract address/ABI and
// the Studio fee path; only the RPC endpoint is overridden.
const chain = {
  ...chains.studioDevnet,
  rpcUrls: { default: { http: [NETWORK.rpcUrl] } },
  blockExplorers: { default: { name: "GenLayer Explorer", url: NETWORK.explorerUrl } },
};

let reader: Client | null = null;
const readClient = (): Client => (reader ??= createClient({ chain }));

// ---------------------------------------------------------------------------
// Types (normalized from jsonSafeReturn: big values arrive as strings)
// ---------------------------------------------------------------------------

export interface Program {
  id: number;
  owner: string;
  target: string;
  policyUrl: string;
  policyDigest: string;
  minSeverity: string;
  available: bigint;
  locked: bigint;
  status: string;
  registeredAt: number;
  closesAt: number;
  openReports: number;
  totalPaid: bigint;
  targetChainId: number;
  targetAbi: Record<string, string>;
  targetHasFallback: boolean;
  abiCheckedAt: number;
  sponsorStatus: string;
  targetOwner: string;
}

export interface Report {
  id: number;
  programId: number;
  researcher: string;
  claimedSeverity: string;
  awardedSeverity: string;
  pocHash: string;
  pocTrace: string;
  description: string;
  researcherBond: bigint;
  bounty: bigint;
  vaultBasis: bigint;
  status: string;
  submittedAt: number;
  unlockTimestamp: number;
  challengeBondPosted: bigint;
  challengeBondHeld: bigint;
  rebuttalType: string;
  triageReasoning: string;
  challengeReasoning: string;
  fingerprint: string;
  callPath: string;
  rejectionReason: string;
}

export interface Params {
  governor: string;
  challengeWindow: number;
  closureNotice: number;
  minProgramDeposit: bigint;
  minResearcherBond: bigint;
  challengeBond: bigint;
  protocolFeeBps: number;
  payoutBps: Record<string, number>;
  nextProgramId: number;
  nextReportId: number;
}

export interface Accounting {
  vaultReserves: bigint;
  bondedResearcher: bigint;
  bondedProject: bigint;
  claimable: bigint;
  treasury: bigint;
  liabilities: bigint;
  inflows: bigint;
  outflows: bigint;
}

export interface Solvency {
  balance: bigint;
  liabilities: bigint;
  exact: boolean;
  solvent: boolean;
}

export interface Snapshot {
  params: Params;
  accounting: Accounting;
  solvency: Solvency;
  programs: Program[];
  reports: Report[];
  fetchedAt: number;
}

type Raw = Record<string, unknown>;
const big = (v: unknown): bigint => BigInt(String(v ?? 0));
const num = (v: unknown): number => Number(v ?? 0);
const str = (v: unknown): string => (v == null ? "" : String(v));

async function view(functionName: string, args: (string | number | bigint)[] = []): Promise<unknown> {
  return readClient().readContract({ address: CONTRACT_ADDRESS, functionName, args, jsonSafeReturn: true });
}

const toProgram = (r: Raw): Program => ({
  id: num(r.program_id),
  owner: str(r.owner),
  target: str(r.target_address),
  policyUrl: str(r.policy_url),
  policyDigest: str(r.policy_digest),
  minSeverity: str(r.min_severity),
  available: big(r.available),
  locked: big(r.locked),
  status: str(r.status),
  registeredAt: num(r.registered_at),
  closesAt: num(r.closes_at),
  openReports: num(r.open_reports),
  totalPaid: big(r.total_paid),
  targetChainId: num(r.target_chain_id),
  targetAbi: Object.fromEntries(Object.entries((r.target_abi ?? {}) as Raw).map(([k, v]) => [k, str(v)])),
  targetHasFallback: Boolean(r.target_has_fallback),
  abiCheckedAt: num(r.abi_checked_at),
  sponsorStatus: str(r.sponsor_status),
  targetOwner: str(r.target_owner),
});

const toReport = (r: Raw): Report => ({
  id: num(r.report_id),
  programId: num(r.program_id),
  researcher: str(r.researcher),
  claimedSeverity: str(r.claimed_severity),
  awardedSeverity: str(r.awarded_severity),
  pocHash: str(r.poc_hash),
  pocTrace: str(r.poc_trace),
  description: str(r.description),
  researcherBond: big(r.researcher_bond),
  bounty: big(r.bounty),
  vaultBasis: big(r.vault_basis),
  status: str(r.status),
  submittedAt: num(r.submitted_at),
  unlockTimestamp: num(r.unlock_timestamp),
  challengeBondPosted: big(r.challenge_bond_posted),
  challengeBondHeld: big(r.challenge_bond_held),
  rebuttalType: str(r.rebuttal_type),
  triageReasoning: str(r.triage_reasoning),
  challengeReasoning: str(r.challenge_reasoning),
  fingerprint: str(r.fingerprint),
  callPath: str(r.call_path),
  rejectionReason: str(r.rejection_reason),
});

export async function fetchSnapshot(): Promise<Snapshot> {
  const [p, a, s] = (await Promise.all([view("get_protocol_params"), view("get_accounting"), view("get_solvency")])) as Raw[];
  const params: Params = {
    governor: str(p.governor),
    challengeWindow: num(p.challenge_window),
    closureNotice: num(p.closure_notice),
    minProgramDeposit: big(p.min_program_deposit),
    minResearcherBond: big(p.min_researcher_bond),
    challengeBond: big(p.challenge_bond),
    protocolFeeBps: num(p.protocol_fee_bps),
    payoutBps: Object.fromEntries(Object.entries((p.payout_bps ?? {}) as Raw).map(([k, v]) => [k, num(v)])),
    nextProgramId: num(p.next_program_id),
    nextReportId: num(p.next_report_id),
  };
  const programIds = Array.from({ length: Math.max(0, params.nextProgramId - 1) }, (_, i) => i + 1);
  const reportIds = Array.from({ length: Math.max(0, params.nextReportId - 1) }, (_, i) => i + 1);
  const [programs, reports] = await Promise.all([
    Promise.all(programIds.map(async (id) => toProgram((await view("get_program", [id])) as Raw))),
    Promise.all(reportIds.map(async (id) => toReport((await view("get_report", [id])) as Raw))),
  ]);
  return {
    params,
    accounting: {
      vaultReserves: big(a.vault_reserves),
      bondedResearcher: big(a.bonded_researcher_funds),
      bondedProject: big(a.bonded_project_funds),
      claimable: big(a.claimable_bounties),
      treasury: big(a.treasury_fees),
      liabilities: big(a.total_liabilities),
      inflows: big(a.total_inflows),
      outflows: big(a.total_outflows),
    },
    solvency: { balance: big(s.balance), liabilities: big(s.total_liabilities), exact: Boolean(s.exact), solvent: Boolean(s.solvent) },
    programs,
    reports: reports.reverse(),
    fetchedAt: Date.now(),
  };
}

export async function fetchClaimable(account: string): Promise<bigint> {
  return big(await view("get_claimable", [account.toLowerCase()]));
}

export async function pingNetwork(): Promise<boolean> {
  try {
    const res = await fetch(NETWORK.rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
    });
    const body = (await res.json()) as { result?: string };
    return Number.parseInt(body.result ?? "0", 16) === NETWORK.chainId;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Wallet
// ---------------------------------------------------------------------------

const CHAIN_HEX = "0x" + NETWORK.chainId.toString(16);

export async function ensureNetwork(provider: Eip1193Provider): Promise<void> {
  const current = (await provider.request({ method: "eth_chainId" })) as string;
  if (Number.parseInt(current, 16) === NETWORK.chainId) return;
  try {
    await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: CHAIN_HEX }] });
  } catch (err) {
    const code = (err as { code?: number }).code;
    if (code !== 4902 && code !== -32603) throw err;
    await provider.request({
      method: "wallet_addEthereumChain",
      params: [
        {
          chainId: CHAIN_HEX,
          chainName: NETWORK.name,
          nativeCurrency: NETWORK.currency,
          rpcUrls: [NETWORK.rpcUrl],
          blockExplorerUrls: [NETWORK.explorerUrl],
        },
      ],
    });
  }
}

export async function requestAccount(provider: Eip1193Provider): Promise<string> {
  const accounts = (await provider.request({ method: "eth_requestAccounts" })) as string[];
  if (!accounts?.[0]) throw new Error("The wallet returned no account.");
  await ensureNetwork(provider);
  return accounts[0];
}

export async function existingAccount(provider: Eip1193Provider): Promise<string | null> {
  const accounts = (await provider.request({ method: "eth_accounts" })) as string[];
  return accounts?.[0] ?? null;
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

export type TxPhase = "signing" | "pending" | "success" | "reverted" | "error";

export interface TxUpdate {
  phase: TxPhase;
  label: string;
  hash?: string;
  detail?: string;
}

export async function write(
  account: string,
  functionName: string,
  args: (string | number | bigint)[],
  value: bigint,
  label: string,
  onUpdate: (u: TxUpdate) => void,
): Promise<boolean> {
  const provider = injectedProvider();
  if (!provider) {
    onUpdate({ phase: "error", label, detail: "No injected wallet found." });
    return false;
  }
  try {
    await ensureNetwork(provider);
    const client = createClient({ chain, account: account as `0x${string}`, provider: provider as never });
    onUpdate({ phase: "signing", label });
    // Studio Next has no fee manager: fees must come from the live fee policy
    // or the consensus contract rejects the transaction.
    const fees = await client.estimateTransactionFees({});
    const hash = (await client.writeContract({ address: CONTRACT_ADDRESS, functionName, args, value, fees })) as string;
    onUpdate({ phase: "pending", label, hash, detail: "Waiting for validator consensus..." });
    const receipt = await client.waitForTransactionReceipt({ hash: hash as never, waitUntil: "decided", interval: 3000, retries: 200 });
    const outcome = String(receipt.txExecutionResultName ?? "");
    if (outcome && outcome !== "FINISHED_WITH_RETURN") {
      onUpdate({ phase: "reverted", label, hash, detail: `Execution ended with ${outcome}. No state changed.` });
      return false;
    }
    onUpdate({ phase: "success", label, hash, detail: `Decided: ${receipt.resultName ?? receipt.statusName ?? "accepted"}` });
    return true;
  } catch (err) {
    const e = err as { shortMessage?: string; message?: string };
    onUpdate({ phase: "error", label, detail: (e.shortMessage ?? e.message ?? String(err)).slice(0, 280) });
    return false;
  }
}
