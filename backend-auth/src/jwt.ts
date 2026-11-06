import jwt from 'jsonwebtoken';
import { randomUUID } from 'node:crypto';
import { config } from './config.js';

export type TokenType = 'access' | 'step_up' | 'elevated';

export interface Claims {
  sub: string;
  typ: TokenType;
  mfa_verified: boolean;
  jti: string;
  iat: number;
  exp: number;
}

const TTL: Record<TokenType, number> = {
  access: config.ttl.access,
  step_up: config.ttl.stepUp,
  elevated: config.ttl.elevated,
};

export function sign(sub: string, typ: TokenType): string {
  return jwt.sign({ typ, mfa_verified: typ === 'elevated' }, config.jwtSecret, {
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
