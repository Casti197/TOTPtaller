import { base32Decode } from './base32';
import { hmacSha1 } from './hmac';

/**
 * TOTP (RFC 6238) implementado desde cero sobre HOTP (RFC 4226).
 * Sin librerías de alto nivel (otplib, speakeasy, …): solo HMAC-SHA1 propio.
 */

export const PERIOD_SECONDS = 30;
export const DIGITS = 6;

/** T = floor(UnixTimestamp / 30) */
export function timeStep(unixMs: number = Date.now(), period: number = PERIOD_SECONDS): number {
  return Math.floor(unixMs / 1000 / period);
}

/** Entero de 64 bits Big-Endian en un buffer de 8 bytes. */
export function counterToBytes(counter: number): Uint8Array {
  const bytes = new Uint8Array(8);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000)); // 32 bits altos
  view.setUint32(4, counter >>> 0); // 32 bits bajos
  return bytes;
}

/** Truncamiento dinámico (RFC 4226 §5.3). */
export function dynamicTruncate(h: Uint8Array, digits: number = DIGITS): string {
  const offset = h[h.length - 1] & 0x0f; // H[19] & 0x0F
  const binCode =
    ((h[offset] & 0x7f) << 24) |
    ((h[offset + 1] & 0xff) << 16) |
    ((h[offset + 2] & 0xff) << 8) |
    (h[offset + 3] & 0xff);
  return (binCode % 10 ** digits).toString().padStart(digits, '0');
}

export function hotp(key: Uint8Array, counter: number, digits: number = DIGITS): string {
  return dynamicTruncate(hmacSha1(key, counterToBytes(counter)), digits);
}

export function totp(key: Uint8Array, unixMs: number = Date.now()): string {
  return hotp(key, timeStep(unixMs));
}

export function totpFromBase32(secret: string, unixMs: number = Date.now()): string {
  return totp(base32Decode(secret), unixMs);
}

/** Milisegundos que le quedan a la ventana actual de 30 s. */
export function msRemaining(unixMs: number = Date.now(), period: number = PERIOD_SECONDS): number {
  const periodMs = period * 1000;
  return periodMs - (unixMs % periodMs);
}

/** "054231" → "054 231" (legibilidad). */
export function formatCode(code: string): string {
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}
