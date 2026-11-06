import * as Crypto from 'expo-crypto';

/** PKCE (RFC 7636) con fuentes de aleatoriedad criptográfica del sistema operativo. */

const UNRESERVED = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'; // 66 símbolos

/**
 * Cadena aleatoria sobre el alfabeto "unreserved" usando muestreo por rechazo
 * (descartamos bytes ≥ 198 = 66·3 para no introducir sesgo modular).
 */
export function randomUnreserved(length: number): string {
  const limit = Math.floor(256 / UNRESERVED.length) * UNRESERVED.length;
  let out = '';
  while (out.length < length) {
    for (const b of Crypto.getRandomBytes(length * 2)) {
      if (b < limit) out += UNRESERVED[b % UNRESERVED.length];
      if (out.length === length) break;
    }
  }
  return out;
}

function base64ToBase64Url(b64: string): string {
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
  method: 'S256';
}

/** code_verifier de 64 caracteres; code_challenge = BASE64URL(SHA256(verifier)) sin relleno. */
export async function createPkcePair(): Promise<PkcePair> {
  const codeVerifier = randomUnreserved(64);
  const digest = await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, codeVerifier, {
    encoding: Crypto.CryptoEncoding.BASE64,
  });
  return { codeVerifier, codeChallenge: base64ToBase64Url(digest), method: 'S256' };
}

/** state anti-CSRF: 128 bits en hexadecimal. */
export function createState(): string {
  return Array.from(Crypto.getRandomBytes(16), (b) => b.toString(16).padStart(2, '0')).join('');
}
