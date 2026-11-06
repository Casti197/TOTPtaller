import { randomBytes } from 'node:crypto';
import { config } from './config.js';

/** Almacenamiento en memoria (prueba de concepto). */

export interface AuthCode {
  userId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  expiresAt: number;
}

export interface RefreshRecord {
  userId: string;
  expiresAt: number;
}

export const authCodes = new Map<string, AuthCode>();
export const refreshTokens = new Map<string, RefreshRecord>();
/** clave `${userId}:${code}` → expiración (ms) */
const replayCache = new Map<string, number>();

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function issueRefreshToken(userId: string): string {
  const token = randomToken(48);
  refreshTokens.set(token, { userId, expiresAt: Date.now() + config.ttl.refresh * 1000 });
  return token;
}

/** Devuelve true si el código YA fue usado (replay); si no, lo registra con TTL de 90 s. */
export function checkAndMarkReplay(userId: string, code: string): boolean {
  const key = `${userId}:${code}`;
  const now = Date.now();
  const exp = replayCache.get(key);
  if (exp && exp > now) return true;
  replayCache.set(key, now + config.ttl.replay * 1000);
  return false;
}

// Limpieza periódica de entradas expiradas
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of authCodes) if (v.expiresAt <= now) authCodes.delete(k);
  for (const [k, v] of refreshTokens) if (v.expiresAt <= now) refreshTokens.delete(k);
  for (const [k, v] of replayCache) if (v <= now) replayCache.delete(k);
}, 30_000).unref();
