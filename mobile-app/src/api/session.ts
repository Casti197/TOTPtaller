import { API_URL, assertApiConfigured } from '../config';
import { secureStorage } from '../auth/secureStorage';
import { ApiError, NetworkError, SessionExpiredError, readJson, type ApiErrorBody } from './errors';

/**
 * Sesión en memoria + cliente HTTP con "Silent Refresh Queue".
 *
 * - access_token: SOLO en esta variable de módulo (RAM). Se destruye al matar el proceso.
 * - refresh_token: SOLO en SecureStore (Keychain / Keystore).
 *
 * Ante un 401:
 *   1. Todas las peticiones que fallen (y las nuevas) esperan la MISMA promesa de renovación.
 *   2. Se dispara una única llamada a POST /auth/refresh.
 *   3. Éxito → se actualiza el access_token y se reintenta cada petición original.
 *   4. Fallo → se limpia SecureStore y se notifica para volver a la pantalla de bienvenida.
 */

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: 'Bearer';
}

export type SessionEvent =
  | { kind: 'request'; path: string }
  | { kind: 'unauthorized'; path: string }
  | { kind: 'queued'; path: string }
  | { kind: 'refresh_start' }
  | { kind: 'refresh_ok' }
  | { kind: 'refresh_failed' }
  | { kind: 'retry'; path: string; status: number }
  | { kind: 'token_changed' }
  | { kind: 'logged_out' };

type Listener = (e: SessionEvent) => void;

let accessToken: string | null = null;
let refreshPromise: Promise<string> | null = null;
const listeners = new Set<Listener>();

function emit(e: SessionEvent): void {
  listeners.forEach((l) => l(e));
}

export function subscribe(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getAccessToken(): string | null {
  return accessToken;
}

export async function setSession(tokens: TokenResponse): Promise<void> {
  accessToken = tokens.access_token;
  await secureStorage.setRefreshToken(tokens.refresh_token);
  emit({ kind: 'token_changed' });
}

/** Borra todo rastro de sesión (memoria + enclave seguro) y avisa a la UI. */
export async function clearSession(): Promise<void> {
  accessToken = null;
  await secureStorage.clearRefreshToken();
  emit({ kind: 'logged_out' });
}

async function rawFetch(path: string, init: RequestInit = {}): Promise<Response> {
  assertApiConfigured();
  try {
    return await fetch(API_URL + path, init);
  } catch (e) {
    throw new NetworkError(e);
  }
}

async function doRefresh(): Promise<string> {
  emit({ kind: 'refresh_start' });
  const refreshToken = await secureStorage.getRefreshToken();
  if (!refreshToken) {
    emit({ kind: 'refresh_failed' });
    await clearSession();
    throw new SessionExpiredError();
  }
  const res = await rawFetch('/auth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
  if (!res.ok) {
    emit({ kind: 'refresh_failed' });
    if (res.status === 400 || res.status === 401) {
      await clearSession();
      throw new SessionExpiredError();
    }
    throw new ApiError(res.status, await readJson<ApiErrorBody>(res));
  }
  await setSession(await readJson<TokenResponse>(res));
  emit({ kind: 'refresh_ok' });
  return accessToken!;
}

/** Garantiza una ÚNICA renovación en vuelo; todos los llamadores comparten la misma promesa. */
export function refreshAccessToken(): Promise<string> {
  if (!refreshPromise) {
    refreshPromise = doRefresh().finally(() => {
      refreshPromise = null;
    });
  }
  return refreshPromise;
}

async function validAccessToken(path: string): Promise<string> {
  // Cola: si hay una renovación en curso, esta petición espera en vez de salir con un token viejo
  if (refreshPromise) {
    emit({ kind: 'queued', path });
    return refreshPromise;
  }
  // Tras reabrir la app solo existe el refresh_token: obtener un access_token antes de llamar
  if (!accessToken) return refreshAccessToken();
  return accessToken;
}

function withBearer(init: RequestInit, token: string): RequestInit {
  return { ...init, headers: { ...(init.headers as Record<string, string>), Authorization: `Bearer ${token}` } };
}

/**
 * Petición autenticada con el access_token. Resuelve con la Response (el llamador decide qué hacer con
 * 403 mfa_required, etc.). Solo el 401 se intercepta aquí.
 */
export async function authFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const token = await validAccessToken(path);
  emit({ kind: 'request', path });
  const res = await rawFetch(path, withBearer(init, token));
  if (res.status !== 401) return res;

  emit({ kind: 'unauthorized', path });
  // Si otro llamador ya renovó mientras esta petición viajaba, no renovar de nuevo
  const fresh = accessToken && accessToken !== token ? accessToken : await refreshAccessToken();
  const retry = await rawFetch(path, withBearer(init, fresh));
  emit({ kind: 'retry', path, status: retry.status });
  if (retry.status === 401) {
    await clearSession();
    throw new SessionExpiredError();
  }
  return retry;
}

/** JSON autenticado; lanza ApiError en estados != 2xx. */
export async function authJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await authFetch(path, init);
  if (!res.ok) throw new ApiError(res.status, await readJson<ApiErrorBody>(res));
  return readJson<T>(res);
}

/** Petición pública (sin token) que devuelve JSON o lanza ApiError. */
export async function publicJson<T>(path: string, body: Record<string, string>): Promise<T> {
  const res = await rawFetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new ApiError(res.status, await readJson<ApiErrorBody>(res));
  return readJson<T>(res);
}

/** Petición con un bearer explícito (p. ej. elevated_token), sin la lógica de refresh. */
export async function bearerFetch(path: string, token: string): Promise<Response> {
  return rawFetch(path, withBearer({}, token));
}

export async function logout(): Promise<void> {
  const refreshToken = await secureStorage.getRefreshToken();
  if (refreshToken) {
    // Revocación en el servidor (best effort: si no hay red, igual se limpia localmente)
    rawFetch('/auth/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    }).catch(() => undefined);
  }
  await clearSession();
}

// ── Utilidades de demostración (sustentación) ─────────────────────────────────

/** Simula que el access_token expiró: el siguiente request recibirá 401 y activará la cola. */
export function debugInvalidateAccessToken(): void {
  if (accessToken) accessToken = `${accessToken.slice(0, -4)}XXXX`;
  emit({ kind: 'token_changed' });
}

/** Simula un refresh_token revocado: la renovación fallará y la app cerrará sesión. */
export async function debugRevokeRefreshToken(): Promise<void> {
  await secureStorage.setRefreshToken('revocado-' + Date.now());
  debugInvalidateAccessToken();
}
