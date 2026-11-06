import { describe, expect, it } from 'vitest';
import { hotp, totp, verifyTotp, base32Decode } from './totp.js';

// RFC 6238 Apéndice B (SHA1, semilla ASCII "12345678901234567890", 8 dígitos)
const rfcKey = Buffer.from('12345678901234567890', 'ascii');
const vectors: Array<[number, string]> = [
  [59, '94287082'],
  [1111111109, '07081804'],
  [1111111111, '14050471'],
  [1234567890, '89005924'],
  [2000000000, '69279037'],
  [20000000000, '65353130'],
];

describe('TOTP RFC 6238', () => {
  it.each(vectors)('t=%i → %s', (t, expected) => {
    expect(hotp(rfcKey, Math.floor(t / 30), 8)).toBe(expected);
  });

  it('RFC 4226 HOTP vectores 0..2 (6 dígitos)', () => {
    expect(hotp(rfcKey, 0)).toBe('755224');
    expect(hotp(rfcKey, 1)).toBe('287082');
    expect(hotp(rfcKey, 2)).toBe('359152');
  });

  it('decodifica Base32', () => {
    expect(base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ').toString()).toBe('12345678901234567890');
  });

  it('acepta ventanas C-1, C, C+1 y rechaza C+2', () => {
    const s = 'JBSWY3DPEHPK3PXP';
    const now = 1_700_000_000;
    expect(verifyTotp(s, totp(s, now - 30), now)).not.toBeNull();
    expect(verifyTotp(s, totp(s, now), now)).not.toBeNull();
    expect(verifyTotp(s, totp(s, now + 30), now)).not.toBeNull();
    expect(verifyTotp(s, totp(s, now + 90), now)).toBeNull();
    expect(verifyTotp(s, '12ab56', now)).toBeNull();
  });
});
