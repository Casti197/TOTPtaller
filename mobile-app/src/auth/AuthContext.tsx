import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { secureStorage } from './secureStorage';
import { loginWithOAuth, type LoginResult } from './oauth';
import { logout as sessionLogout, subscribe } from '../api/session';
import { clearElevatedToken } from '../api/vault';

type Status = 'loading' | 'signedOut' | 'signedIn';

interface AuthContextValue {
  status: Status;
  login: () => Promise<LoginResult>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>('loading');

  useEffect(() => {
    // Al iniciar: la sesión persiste solo si hay refresh_token en el enclave seguro.
    // No se hace ninguna llamada de red aquí (la app abre en Modo Avión).
    secureStorage
      .getRefreshToken()
      .then((t) => setStatus(t ? 'signedIn' : 'signedOut'))
      .catch(() => setStatus('signedOut'));

    // Si el pipeline de refresh limpia la sesión (refresh_token vencido/revocado) → bienvenida
    return subscribe((e) => {
      if (e.kind === 'logged_out') {
        clearElevatedToken();
        setStatus('signedOut');
      }
      if (e.kind === 'token_changed') setStatus((s) => (s === 'signedOut' ? 'signedIn' : s));
    });
  }, []);

  const login = useCallback(async () => {
    const result = await loginWithOAuth();
    if (result.ok) setStatus('signedIn');
    return result;
  }, []);

  const logout = useCallback(async () => {
    await sessionLogout();
  }, []);

  const value = useMemo(() => ({ status, login, logout }), [status, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth debe usarse dentro de <AuthProvider>');
  return ctx;
}
