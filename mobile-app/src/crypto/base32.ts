/** Decodificador Base32 (RFC 4648 §6), sin dependencias. */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Normaliza una semilla: mayúsculas, sin espacios, guiones ni relleno '='. */
export function normalizeBase32(input: string): string {
  return input.toUpperCase().replace(/[\s=-]/g, '');
}

export type Base32Validation = { ok: true; value: string } | { ok: false; error: string };

/** Valida una semilla TOTP. Exige al menos 16 caracteres (80 bits), como Google Authenticator. */
export function validateBase32Secret(input: string): Base32Validation {
  const value = normalizeBase32(input);
  if (value.length === 0) return { ok: false, error: 'Ingresa la semilla Base32' };
  const bad = value.match(/[^A-Z2-7]/);
  if (bad) return { ok: false, error: `Carácter inválido "${bad[0]}": Base32 solo admite A–Z y 2–7` };
  if (value.length < 16) return { ok: false, error: 'La semilla debe tener al menos 16 caracteres (80 bits)' };
  return { ok: true, value };
}

export function base32Decode(input: string): Uint8Array {
  const clean = normalizeBase32(input);
  const out = new Uint8Array(Math.floor((clean.length * 5) / 8));
  let bits = 0;
  let value = 0;
  let index = 0;
  for (const ch of clean) {
    const v = ALPHABET.indexOf(ch);
    if (v === -1) throw new Error(`Carácter Base32 inválido: ${ch}`);
    value = ((value << 5) | v) & 0xffff; // solo necesitamos los últimos 13 bits como máximo
    bits += 5;
    if (bits >= 8) {
      out[index++] = (value >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return out;
}
