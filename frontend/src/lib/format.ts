import { ATTO } from "../config";

export function formatGen(v: bigint, maxDecimals = 4): string {
  const neg = v < 0n;
  const a = neg ? -v : v;
  const whole = a / ATTO;
  const frac = a % ATTO;
  let fracStr = frac.toString().padStart(18, "0").slice(0, maxDecimals).replace(/0+$/, "");
  if (whole === 0n && frac > 0n && fracStr === "") fracStr = "0".repeat(maxDecimals - 1) + "1";
  const wholeStr = whole.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return `${neg ? "-" : ""}${wholeStr}${fracStr ? "." + fracStr : ""}`;
}

// Parse a decimal GEN amount into atto units without floating point.
export function parseGen(input: string): bigint | null {
  const s = input.trim();
  if (!/^\d+(\.\d{0,18})?$/.test(s)) return null;
  const [w, f = ""] = s.split(".");
  return BigInt(w) * ATTO + BigInt((f + "0".repeat(18)).slice(0, 18));
}

export const shortAddr = (a: string, n = 4) => (a.length > 2 * n + 2 ? `${a.slice(0, n + 2)}...${a.slice(-n)}` : a);

export function duration(seconds: number): string {
  if (seconds <= 0) return "0s";
  const d = Math.floor(seconds / 86_400);
  const h = Math.floor((seconds % 86_400) / 3_600);
  const m = Math.floor((seconds % 3_600) / 60);
  const s = Math.floor(seconds % 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  return `${m}m ${s}s`;
}

export const dateTime = (unix: number) =>
  unix > 0 ? new Date(unix * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "-";

// raw.githubusercontent.com/<o>/<r>/<sha>/<path> -> github.com/<o>/<r>/blob/<sha>/<path>
export function githubBlobUrl(raw: string): string {
  const m = raw.match(/^https:\/\/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/([0-9a-f]{40})\/(.+)$/);
  return m ? `https://github.com/${m[1]}/${m[2]}/blob/${m[3]}/${m[4]}` : raw;
}

export function policyLabel(raw: string): { repo: string; commit: string; path: string } {
  const m = raw.match(/^https:\/\/raw\.githubusercontent\.com\/([^/]+\/[^/]+)\/([0-9a-f]{40})\/(.+)$/);
  return m ? { repo: m[1], commit: m[2].slice(0, 7), path: m[3] } : { repo: raw, commit: "", path: "" };
}
