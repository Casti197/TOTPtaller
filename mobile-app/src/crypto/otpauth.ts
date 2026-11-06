import { validateBase32Secret } from './base32';

/**
 * Parser de URIs de Google Authenticator:
 *   otpauth://totp/UniSabana:estudiante@unisabana.edu.co?secret=JBSWY3DPEHPK3PXP&issuer=UniSabana
 * Implementado sin `URL` porque la implementación de Hermes/React Native es incompleta.
 */

export interface OtpAccount {
  secret: string;
  issuer: string;
  account: string;
}

export type OtpAuthResult = { ok: true; account: OtpAccount } | { ok: false; error: string };

function decode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '));
  } catch {
    return s;
  }
}

export function parseOtpAuthUri(uri: string): OtpAuthResult {
  const match = /^otpauth:\/\/([^/?#]+)\/([^?#]*)\?([^#]*)$/i.exec(uri.trim());
  if (!match) return { ok: false, error: 'El QR no es un URI otpauth:// válido' };

  const [, type, rawLabel, query] = match;
  if (type.toLowerCase() !== 'totp') return { ok: false, error: `Tipo "${type}" no soportado: solo TOTP` };

  const params: Record<string, string> = {};
  for (const pair of query.split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    const key = decode(eq === -1 ? pair : pair.slice(0, eq)).toLowerCase();
    params[key] = decode(eq === -1 ? '' : pair.slice(eq + 1));
  }

  const secret = validateBase32Secret(params.secret ?? '');
  if (!secret.ok) return { ok: false, error: secret.error };

  if (params.algorithm && params.algorithm.toUpperCase() !== 'SHA1')
    return { ok: false, error: `Algoritmo ${params.algorithm} no soportado (solo SHA1)` };
  if (params.digits && params.digits !== '6') return { ok: false, error: 'Solo se soportan códigos de 6 dígitos' };
  if (params.period && params.period !== '30') return { ok: false, error: 'Solo se soporta un periodo de 30 s' };

  const label = decode(rawLabel);
  const colon = label.indexOf(':');
  const labelIssuer = colon === -1 ? '' : label.slice(0, colon).trim();
  const account = (colon === -1 ? label : label.slice(colon + 1)).trim();

  return {
    ok: true,
    account: { secret: secret.value, issuer: params.issuer || labelIssuer || 'Sin emisor', account },
  };
}
