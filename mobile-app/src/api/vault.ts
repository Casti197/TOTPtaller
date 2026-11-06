import { isExpired } from '../auth/jwt';
import { ApiError, readJson, type ApiErrorBody } from './errors';
import { authFetch, bearerFetch, publicJson } from './session';

/**
 * Step-Up Authentication para la Bóveda Crítica.
 * El elevated_token (mfa_verified: true, 10 min) también vive solo en memoria.
 */

export interface VaultData {
  titular: string;
  cuenta: string;
  saldo: string;
  notas_confidenciales: string[];
  acceso_valido_hasta: string;
}

export type VaultResult =
  | { kind: 'ok'; data: VaultData }
  | { kind: 'mfa_required'; stepUpToken: string };

const VAULT_PATH = '/api/boveda-critica';

let elevatedToken: string | null = null;

export function getElevatedToken(): string | null {
  if (elevatedToken && isExpired(elevatedToken, 0)) elevatedToken = null;
  return elevatedToken;
}

export function clearElevatedToken(): void {
  elevatedToken = null;
}

/** Intenta abrir la bóveda: con elevated_token si existe; si no, con el access_token estándar → 403. */
export async function fetchVault(): Promise<VaultResult> {
  const elevated = getElevatedToken();
  if (elevated) {
    const res = await bearerFetch(VAULT_PATH, elevated);
    if (res.ok) return { kind: 'ok', data: await readJson<VaultData>(res) };
    elevatedToken = null; // expiró o fue rechazado: volver al flujo estándar
  }

  const res = await authFetch(VAULT_PATH);
  if (res.ok) return { kind: 'ok', data: await readJson<VaultData>(res) };
  const body = await readJson<ApiErrorBody & { step_up_token?: string }>(res);
  if (res.status === 403 && body.error === 'mfa_required' && body.step_up_token) {
    return { kind: 'mfa_required', stepUpToken: body.step_up_token };
  }
  throw new ApiError(res.status, body);
}

/** Obtiene un step_up_token nuevo pidiendo la bóveda con el access_token estándar (siempre 403). */
export async function requestStepUpToken(): Promise<string> {
  const res = await authFetch(VAULT_PATH);
  const body = await readJson<ApiErrorBody & { step_up_token?: string }>(res);
  if (res.status === 403 && body.step_up_token) return body.step_up_token;
  throw new ApiError(res.status, body);
}

/** POST /auth/mfa/verify → guarda el elevated_token en memoria. Lanza ApiError (401 / 409 replay). */
export async function verifyMfa(stepUpToken: string, code: string): Promise<void> {
  const res = await publicJson<{ elevated_token: string }>('/auth/mfa/verify', {
    step_up_token: stepUpToken,
    code,
  });
  elevatedToken = res.elevated_token;
}

/** Mensaje legible para errores de verificación. */
export function describeMfaError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 409) return '409 Conflict · Replay Attack Detected: este código ya fue usado. Espera el siguiente código.';
    if (e.body.error === 'invalid_step_up_token') return 'La solicitud de verificación expiró. Cierra e intenta abrir la bóveda de nuevo.';
    if (e.status === 401) return 'Código incorrecto o fuera de la ventana de tiempo (±30 s).';
    return e.message;
  }
  return e instanceof Error ? e.message : 'Error desconocido';
}
