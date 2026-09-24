// Network and deployment configuration. Defaults point at the live
// Studio Next deployment recorded in deployments/studio-next.json; override
// per environment with VITE_GENLAYER_RPC_URL / VITE_CONTRACT_ADDRESS.

export const NETWORK = {
  name: "GenLayer Studio Next",
  chainId: 61997,
  rpcUrl: (import.meta.env.VITE_GENLAYER_RPC_URL as string | undefined) ?? "https://studio-next.genlayer.com/api",
  explorerUrl: "https://explorer-studio-next.genlayer.com",
  currency: { name: "GEN Token", symbol: "GEN", decimals: 18 },
} as const;

export const CONTRACT_ADDRESS = ((import.meta.env.VITE_CONTRACT_ADDRESS as string | undefined) ??
  "0xc5F8a1756525a717CC9b219A98Ac2fc4Ed271F0E") as `0x${string}`;

export const DEPLOY_TX_HASH = "0x2077a19b1c3f526e6be4f997d0043f611b43d9839bb545284b677a0717317f35";

export const REPO_URL = "https://github.com/SOBEK96/ZeroDiscretion";

export const explorerAddress = (a: string) => `${NETWORK.explorerUrl}/address/${a}`;
export const explorerTx = (h: string) => `${NETWORK.explorerUrl}/tx/${h}`;

// Protocol constants mirrored from contracts/zero_discretion.py. Live values
// are read from get_protocol_params(); these are the pre-load fallbacks.
export const ATTO = 10n ** 18n;
export const BPS = 10_000n;
export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
export type Severity = (typeof SEVERITIES)[number];
export const SEVERITY_RANK: Record<string, number> = { NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

export const REBUTTAL_TYPES = [
  { id: "INTENDED_ADMIN_ROLE", label: "Intended administrative role" },
  { id: "SANDBOX_MOCK_BYPASS", label: "Only reproduces against a sandbox / mock" },
  { id: "OUT_OF_SCOPE_TARGET", label: "Target out of policy scope" },
  { id: "KNOWN_ISSUE_DISCLOSED", label: "Known issue, disclosed in policy" },
  { id: "NON_REPRODUCIBLE", label: "PoC does not reproduce" },
  { id: "SEVERITY_OVERSTATED", label: "Severity overstated (downgrade)" },
] as const;

export const POLL_MS = 15_000;
