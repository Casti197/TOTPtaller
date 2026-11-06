/**
 * Lectura (NO verificación) del payload de un JWT, solo para la UI (p. ej. mostrar la expiración).
 * La validez la decide siempre el backend.
 */
export interface TokenClaims {
  sub?: string;
  typ?: string;
  mfa_verified?: boolean;
  exp?: number;
}

export function decodeJwtPayload(token: string): TokenClaims | null {
  const part = token.split('.')[1];
  if (!part) return null;
  try {
    const b64 = part.replace(/-/g, '+').replace(/_/g, '/');
    const json = decodeURIComponent(
      Array.from(atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, '=')), (c) =>
        `%${c.charCodeAt(0).toString(16).padStart(2, '0')}`,
      ).join(''),
    );
    return JSON.parse(json) as TokenClaims;
  } catch {
    return null;
  }
}

/** true si el token expira en menos de `skewSeconds`. */
export function isExpired(token: string, skewSeconds = 5): boolean {
  const exp = decodeJwtPayload(token)?.exp;
  return !exp || exp * 1000 - skewSeconds * 1000 <= Date.now();
}
