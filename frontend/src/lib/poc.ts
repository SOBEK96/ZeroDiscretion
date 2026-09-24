// Client-side mirror of the contract's DETERMINISTIC checks
// (_parse_poc, _disassemble, _parse_rebuttal in contracts/zero_discretion.py).
// It lets the UI show researchers and projects exactly what every validator
// will compute before a bonded transaction is sent. The LLM verdict itself is
// non-deterministic and is never simulated here.

import { BPS, SEVERITY_RANK } from "../config";

const MAX_POC_CHARS = 32_000;
const MAX_POC_STEPS = 16;
const MAX_CALLDATA_HEX = 8_192;
const DISASM_WORDS_SHOWN = 8;
const MIN_ARGUMENT_CHARS = 32;
const MAX_ARGUMENT_CHARS = 8_000;

export interface PocStep {
  to: string;
  calldata: string;
  value: string;
  expect: string;
}

export interface DisasmStep {
  index: number;
  to: string;
  selector: string;
  value: string;
  word_count: number;
  words: string[];
  trailing_bytes: number;
  calldata_bytes: number;
}

export interface PocCheck {
  ok: boolean;
  error?: { code: string; detail: string };
  canonical?: string;
  steps?: PocStep[];
  chainId?: number;
  invariant?: string;
}

const isHex = (s: string) => s.length > 0 && /^[0-9a-f]+$/.test(s);

export function normalizeAddress(v: unknown): string {
  if (typeof v !== "string") return "";
  const a = v.trim().toLowerCase();
  return a.length === 42 && a.startsWith("0x") && isHex(a.slice(2)) ? a : "";
}

const fail = (code: string, detail: string): PocCheck => ({ ok: false, error: { code, detail } });

// Python json.dumps(ensure_ascii=True) escapes every UTF-16 unit outside
// 0x20-0x7E (DEL included); JSON.stringify already escapes the controls below 0x20.
function pyString(s: string): string {
  return JSON.stringify(s).replace(/[\u007f-\uffff]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
}

// json.dumps(obj, sort_keys=True, separators=(",", ":"))
export function pyCanonicalJson(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "string") return pyString(v);
  if (typeof v === "number") return String(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  if (Array.isArray(v)) return "[" + v.map(pyCanonicalJson).join(",") + "]";
  const obj = v as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => pyString(k) + ":" + pyCanonicalJson(obj[k])).join(",") + "}";
}

export async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function parsePoc(trace: string, programTarget: string): PocCheck {
  if (!trace) return fail("ERR_MALFORMED_POC", "empty trace");
  if (trace.length > MAX_POC_CHARS) return fail("ERR_INPUT_TOO_LARGE", "poc_trace exceeds 32000 characters");
  let obj: unknown;
  try {
    obj = JSON.parse(trace);
  } catch {
    return fail("ERR_MALFORMED_POC", "trace is not JSON");
  }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return fail("ERR_MALFORMED_POC", "trace must be a JSON object");
  const o = obj as Record<string, unknown>;

  const target = normalizeAddress(o.target);
  if (!target) return fail("ERR_MALFORMED_POC", "target must be a 0x-prefixed 20-byte address");
  if (target !== programTarget.toLowerCase()) return fail("ERR_POC_TARGET_MISMATCH", "trace target differs from program target");

  const chainId = o.chain_id;
  if (typeof chainId !== "number" || !Number.isInteger(chainId) || chainId <= 0) return fail("ERR_MALFORMED_POC", "chain_id must be a positive integer");

  const inv = o.invariant_broken;
  if (typeof inv !== "string" || inv.trim().length < 8 || inv.trim().length > 1000)
    return fail("ERR_MALFORMED_POC", "invariant_broken must be 8..1000 characters");

  const raw = o.steps;
  if (!Array.isArray(raw) || raw.length < 1 || raw.length > MAX_POC_STEPS) return fail("ERR_MALFORMED_POC", "steps must contain 1..16 entries");

  const steps: PocStep[] = [];
  let hitsTarget = false;
  for (const [i, s] of raw.entries()) {
    if (!s || typeof s !== "object" || Array.isArray(s)) return fail("ERR_MALFORMED_POC", `step ${i} must be an object`);
    const st = s as Record<string, unknown>;
    const to = normalizeAddress(st.to);
    if (!to) return fail("ERR_MALFORMED_POC", `step ${i}: invalid "to" address`);
    if (typeof st.calldata !== "string") return fail("ERR_MALFORMED_POC", `step ${i}: calldata must be a string`);
    const cd = st.calldata.toLowerCase();
    const body = cd.slice(2);
    if (!cd.startsWith("0x") || body.length < 8 || body.length % 2 !== 0 || body.length > MAX_CALLDATA_HEX || !isHex(body))
      return fail("ERR_MALFORMED_POC", `step ${i}: calldata must be 0x hex with a 4-byte selector`);
    let value: unknown = st.value ?? "0";
    if (typeof value === "number" && Number.isInteger(value)) value = String(value);
    if (typeof value !== "string" || !/^[0-9]+$/.test(value) || value.length > 78)
      return fail("ERR_MALFORMED_POC", `step ${i}: value must be a decimal wei string`);
    const expect = st.expect ?? "";
    if (typeof expect !== "string" || expect.length > 500) return fail("ERR_MALFORMED_POC", `step ${i}: expect must be <= 500 characters`);
    if (to === target) hitsTarget = true;
    steps.push({ to, calldata: cd, value: BigInt(value).toString(), expect });
  }
  if (!hitsTarget) return fail("ERR_POC_TARGET_MISMATCH", "no step calls the program target");

  const normalized = { target, chain_id: chainId, invariant_broken: inv.trim(), steps };
  return { ok: true, canonical: pyCanonicalJson(normalized), steps, chainId, invariant: inv.trim() };
}

export function disassemble(steps: PocStep[]): DisasmStep[] {
  return steps.map((s, index) => {
    const body = s.calldata.slice(2);
    const args = body.slice(8);
    const full = Math.floor(args.length / 64);
    const words: string[] = [];
    for (let w = 0; w < Math.min(full, DISASM_WORDS_SHOWN); w++) words.push("0x" + args.slice(w * 64, (w + 1) * 64));
    return {
      index,
      to: s.to,
      selector: "0x" + body.slice(0, 8),
      value: s.value,
      word_count: full,
      words,
      trailing_bytes: (args.length - full * 64) / 2,
      calldata_bytes: body.length / 2,
    };
  });
}

export function bountyFor(available: bigint, severity: string, payoutBps: Record<string, number>): bigint {
  return (available * BigInt(payoutBps[severity] ?? 0)) / BPS;
}

export function meetsFloor(severity: string, floor: string): boolean {
  return (SEVERITY_RANK[severity] ?? 0) >= (SEVERITY_RANK[floor] ?? 0);
}

export interface RebuttalDraft {
  pocHash: string;
  rebuttalType: string;
  disputedSteps: number[];
  argument: string;
}

// Builds the rebuttal JSON the contract's binding gate accepts. Selectors are
// always taken from the disassembly, so a UI-built rebuttal is bound by
// construction; the returned problems list mirrors ERR_REBUTTAL_NOT_BOUND.
export function buildRebuttal(d: RebuttalDraft, disasm: DisasmStep[]): { json: string; problems: string[] } {
  const problems: string[] = [];
  const steps = [...new Set(d.disputedSteps)].sort((a, b) => a - b);
  if (steps.length === 0) problems.push("Select at least one disputed PoC step.");
  if (steps.some((i) => i < 0 || i >= disasm.length)) problems.push("A disputed step is not part of the PoC.");
  const arg = d.argument.trim();
  if (arg.length < MIN_ARGUMENT_CHARS) problems.push(`Argument must be at least ${MIN_ARGUMENT_CHARS} characters.`);
  if (arg.length > MAX_ARGUMENT_CHARS) problems.push(`Argument must be at most ${MAX_ARGUMENT_CHARS} characters.`);
  const json = JSON.stringify({
    poc_hash: d.pocHash,
    rebuttal_type: d.rebuttalType,
    disputed_steps: steps,
    disputed_selectors: steps.map((i) => disasm[i]?.selector ?? ""),
    argument: arg,
  });
  return { json, problems };
}

const word = (n: bigint) => n.toString(16).padStart(64, "0");

export function examplePoc(target: string): string {
  return JSON.stringify(
    {
      target,
      chain_id: 1,
      invariant_broken: "caller can withdraw more than their recorded deposit",
      steps: [
        { to: target, calldata: "0xb6b55f25" + word(10n ** 18n), value: "0", expect: "deposit 1 token" },
        { to: target, calldata: "0x2e1a7d4d" + word(10n ** 24n), value: "0", expect: "withdraw 1,000,000 tokens; no balance check" },
      ],
    },
    null,
    2,
  );
}
