import jwt from 'jsonwebtoken';
import { randomUUID } from 'node:crypto';
import { config } from './config.js';

/** login_mfa: ticket del login (contraseña ya validada, falta el TOTP). Nunca sirve como bearer de la API. */
export type TokenType = 'access' | 'step_up' | 'elevated' | 'login_mfa';

export interface Claims {
  sub: string;
  typ: TokenType;
  mfa_verified: boolean;
  /** Solo en login_mfa: code_challenge al que queda atado el ticket. */
  cc?: string;
  jti: string;
  iat: number;
  exp: number;
}

const TTL: Record<TokenType, number> = {
  access: config.ttl.access,
  step_up: config.ttl.stepUp,
  elevated: config.ttl.elevated,
  login_mfa: config.ttl.loginMfa,
};

export function sign(sub: string, typ: TokenType, extra: Record<string, string> = {}): string {
  return jwt.sign({ ...extra, typ, mfa_verified: typ === 'elevated' }, config.jwtSecret, {
    algorithm: 'HS256',
    subject: sub,
    expiresIn: TTL[typ],
    jwtid: randomUUID(),
  });
}

export function verify(token: string): Claims | null {
  try {
    return jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] }) as Claims;
  } catch {
    return null;
  }
}

export function ttlOf(typ: TokenType): number {
  return TTL[typ];
}
