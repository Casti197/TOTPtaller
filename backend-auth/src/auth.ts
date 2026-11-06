import type { Request, Response, NextFunction } from 'express';
import { verify, type Claims } from './jwt.js';

export interface AuthedRequest extends Request {
  claims?: Claims;
}

export function bearer(req: Request): string | null {
  const h = req.headers.authorization;
  return h?.startsWith('Bearer ') ? h.slice(7) : null;
}

/** Exige un access_token o elevated_token válido; 401 si falta o expiró. */
export function requireAuth(req: AuthedRequest, res: Response, next: NextFunction): void {
  const token = bearer(req);
  const claims = token ? verify(token) : null;
  if (!claims || (claims.typ !== 'access' && claims.typ !== 'elevated')) {
    res.status(401).json({ error: 'invalid_token', error_description: 'Token ausente, inválido o expirado' });
    return;
  }
  req.claims = claims;
  next();
}
