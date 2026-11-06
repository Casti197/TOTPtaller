import { createHmac, timingSafeEqual } from 'node:crypto';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Decodificador Base32 (RFC 4648). Ignora espacios, guiones y relleno '='. */
export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/[\s=-]/g, '');
  if (!clean.length || /[^A-Z2-7]/.test(clean)) throw new Error('Base32 inválido');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** HOTP (RFC 4226) con truncamiento dinámico, implementado desde cero. */
export function hotp(key: Buffer, counter: number, digits = 6): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter)); // entero de 64 bits Big-Endian
  const h = createHmac('sha1', key).update(msg).digest();
  const offset = h[h.length - 1] & 0x0f;
  const bin =
    ((h[offset] & 0x7f) << 24) |
    ((h[offset + 1] & 0xff) << 16) |
    ((h[offset + 2] & 0xff) << 8) |
    (h[offset + 3] & 0xff);
  return (bin % 10 ** digits).toString().padStart(digits, '0');
}

export function counterAt(unixSeconds: number, step = 30): number {
  return Math.floor(unixSeconds / step);
}

export function totp(secretB32: string, unixSeconds = Date.now() / 1000, digits = 6): string {
  return hotp(base32Decode(secretB32), counterAt(unixSeconds), digits);
}

/**
 * Verifica un código en las ventanas C-1, C, C+1 (tolerancia de desfase de reloj).
 * Devuelve el contador que coincidió o null.
 */
export function verifyTotp(secretB32: string, code: string, unixSeconds = Date.now() / 1000): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const key = base32Decode(secretB32);
  const c = counterAt(unixSeconds);
  let match: number | null = null;
  for (const w of [-1, 0, 1]) {
    const expected = Buffer.from(hotp(key, c + w));
    // Comparación en tiempo constante; no se corta el bucle para no filtrar la ventana por timing
    if (timingSafeEqual(expected, Buffer.from(code)) && match === null) match = c + w;
  }
  return match;
}
