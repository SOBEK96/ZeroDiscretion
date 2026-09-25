import { useCallback, useEffect, useRef, useState } from "react";
import { POLL_MS } from "./config";
import {
  describeReadError,
  existingAccount,
  fetchClaimable,
  fetchSnapshot,
  injectedProvider,
  pingNetwork,
  requestAccount,
  write,
  type Snapshot,
  type TxUpdate,
} from "./lib/chain";

export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const t = setInterval(() => setNow(Math.floor(Date.now() / 1000)), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

export function useProtocol() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [online, setOnline] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const s = await fetchSnapshot();
      setSnapshot(s);
      setError(null);
    } catch (e) {
      // Keep the last good snapshot on screen; only surface a one-line reason.
      setError(describeReadError(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let live = true;
    const tick = async () => {
      const ok = await pingNetwork();
      if (!live) return;
      setOnline(ok);
      if (ok) await refresh();
      else setLoading(false);
    };
    void tick();
    const t = setInterval(() => void tick(), POLL_MS);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [refresh]);

  return { snapshot, error, online, loading, refresh };
}

export function useWallet() {
  const [account, setAccount] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const hasWallet = typeof window !== "undefined" && Boolean(injectedProvider());

  useEffect(() => {
    const p = injectedProvider();
    if (!p) return;
    existingAccount(p)
      .then(setAccount)
      .catch(() => undefined);
    const onAccounts = (...args: unknown[]) => {
      const list = args[0] as string[] | undefined;
      setAccount(list?.[0] ?? null);
    };
    p.on?.("accountsChanged", onAccounts);
    return () => p.removeListener?.("accountsChanged", onAccounts);
  }, []);

  const connect = useCallback(async () => {
    const p = injectedProvider();
    if (!p) {
      setError("No injected wallet detected. Install MetaMask or a compatible wallet.");
      return;
    }
    setConnecting(true);
    setError(null);
    try {
      setAccount(await requestAccount(p));
    } catch (e) {
      setError((e as { message?: string }).message ?? "Connection rejected");
    } finally {
      setConnecting(false);
    }
  }, []);

  const disconnect = useCallback(() => setAccount(null), []);

  return { account, connecting, error, hasWallet, connect, disconnect };
}

export function useClaimable(account: string | null, version: unknown) {
  const [claimable, setClaimable] = useState<{ account: string; value: bigint } | null>(null);
  useEffect(() => {
    if (!account) return;
    let live = true;
    fetchClaimable(account)
      .then((value) => live && setClaimable({ account, value }))
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [account, version]);
  return account && claimable?.account === account ? claimable.value : 0n;
}

export interface TxRecord extends TxUpdate {
  id: number;
}

export function useTransactions(account: string | null, onSettled: () => void) {
  const [txs, setTxs] = useState<TxRecord[]>([]);
  const nextId = useRef(1);

  const send = useCallback(
    async (functionName: string, args: (string | number | bigint)[], value: bigint, label: string) => {
      if (!account) return false;
      const id = nextId.current++;
      const update = (u: TxUpdate) =>
        setTxs((prev) => {
          const rest = prev.filter((t) => t.id !== id);
          return [{ id, ...u }, ...rest].slice(0, 4);
        });
      const ok = await write(account, functionName, args, value, label, update);
      onSettled();
      return ok;
    },
    [account, onSettled],
  );

  const dismiss = useCallback((id: number) => setTxs((prev) => prev.filter((t) => t.id !== id)), []);
  return { txs, send, dismiss };
}
