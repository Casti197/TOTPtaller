import { useEffect, useState } from 'react';
import { secureStorage } from '../auth/secureStorage';
import type { OtpAccount } from '../crypto/otpauth';

/**
 * Cuenta TOTP del usuario guardada en SecureStore (la semilla es un secreto: nunca en texto plano).
 * Lectura 100% local: funciona en Modo Avión.
 */

type Listener = (a: OtpAccount | null) => void;

let cached: OtpAccount | null | undefined; // undefined = aún no cargada
const listeners = new Set<Listener>();

function publish(a: OtpAccount | null): void {
  cached = a;
  listeners.forEach((l) => l(a));
}

export async function loadAccount(): Promise<OtpAccount | null> {
  if (cached !== undefined) return cached;
  const raw = await secureStorage.getTotpAccount();
  let account: OtpAccount | null = null;
  try {
    account = raw ? (JSON.parse(raw) as OtpAccount) : null;
  } catch {
    account = null;
  }
  publish(account);
  return account;
}

export async function saveAccount(account: OtpAccount): Promise<void> {
  await secureStorage.setTotpAccount(JSON.stringify(account));
  publish(account);
}

export async function removeAccount(): Promise<void> {
  await secureStorage.clearTotpAccount();
  publish(null);
}

export function useTotpAccount(): { account: OtpAccount | null; loaded: boolean } {
  const [state, setState] = useState<{ account: OtpAccount | null; loaded: boolean }>({
    account: cached ?? null,
    loaded: cached !== undefined,
  });
  useEffect(() => {
    const l: Listener = (account) => setState({ account, loaded: true });
    listeners.add(l);
    loadAccount().then(l, () => l(null));
    return () => {
      listeners.delete(l);
    };
  }, []);
  return state;
}
