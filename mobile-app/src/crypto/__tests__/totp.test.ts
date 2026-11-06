/// <reference types="node" />
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { base32Decode, validateBase32Secret } from '../base32';
import { sha1 } from '../sha1';
import { hmacSha1 } from '../hmac';
import { counterToBytes, hotp, msRemaining, timeStep, totpFromBase32 } from '../totp';
import { parseOtpAuthUri } from '../otpauth';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

describe('SHA-1 propio', () => {
  it('vectores FIPS', () => {
    expect(hex(sha1(new Uint8Array()))).toBe('da39a3ee5e6b4b0d3255bfef95601890afd80709');
    expect(hex(sha1(Buffer.from('abc')))).toBe('a9993e364706816aba3e25717850c26c9cd0d89d');
  });
  it('coincide con node:crypto en longitudes 0..200', () => {
    for (let n = 0; n <= 200; n++) {
      const m = randomBytes(n);
      expect(hex(sha1(m))).toBe(createHash('sha1').update(m).digest('hex'));
    }
  });
});

describe('HMAC-SHA1 propio', () => {
  it('coincide con node:crypto (claves cortas y > 64 bytes)', () => {
    for (const keyLen of [0, 10, 20, 64, 65, 100]) {
      const key = randomBytes(keyLen);
      const msg = randomBytes(37);
      expect(hex(hmacSha1(key, msg))).toBe(createHmac('sha1', key).update(msg).digest('hex'));
    }
  });
});

describe('TOTP RFC 6238 Apéndice B (SHA1)', () => {
  const key = Buffer.from('12345678901234567890', 'ascii');
  const vectors: [number, string][] = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'], // contador > 2^32: prueba el Big-Endian de 64 bits
  ];
  it.each(vectors)('t=%i → %s', (t, code) => {
    expect(hotp(key, timeStep(t * 1000), 8)).toBe(code);
  });
  it('RFC 4226 HOTP 6 dígitos', () => {
    const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
    expected.forEach((code, i) => expect(hotp(key, i)).toBe(code));
  });
});

describe('Paridad con implementación de referencia', () => {
  it('coincide con un TOTP calculado con node:crypto para JBSWY3DPEHPK3PXP', () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    for (let i = 0; i < 50; i++) {
      const t = Date.now() + i * 30_000;
      const msg = Buffer.alloc(8);
      msg.writeBigUInt64BE(BigInt(Math.floor(t / 30_000)));
      const h = createHmac('sha1', Buffer.from(base32Decode(secret))).update(msg).digest();
      const o = h[19] & 0xf;
      const ref = ((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0');
      expect(totpFromBase32(secret, t)).toBe(ref);
    }
  });
  it('contador en Big-Endian', () => {
    expect(hex(counterToBytes(1))).toBe('0000000000000001');
    expect(hex(counterToBytes(0x1_0000_0002))).toBe('0000000100000002');
  });
  it('ms restantes de la ventana', () => {
    expect(msRemaining(30_000)).toBe(30_000);
    expect(msRemaining(59_000)).toBe(1_000);
  });
});

describe('Base32 y otpauth://', () => {
  it('decodifica', () => {
    expect(Buffer.from(base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')).toString()).toBe('12345678901234567890');
    expect(Buffer.from(base32Decode('jbsw y3dp ehpk 3pxp')).toString('hex')).toBe('48656c6c6f21deadbeef'); // "Hello!" + DEADBEEF
  });
  it('valida', () => {
    expect(validateBase32Secret('JBSWY3DPEHPK3PX1').ok).toBe(false);
    expect(validateBase32Secret('JBSWY3DP').ok).toBe(false);
    expect(validateBase32Secret('jbsw-y3dp-ehpk-3pxp')).toEqual({ ok: true, value: 'JBSWY3DPEHPK3PXP' });
  });
  it('parsea el URI de la guía', () => {
    const r = parseOtpAuthUri('otpauth://totp/UniSabana:estudiante@unisabana.edu.co?secret=JBSWY3DPEHPK3PXP&issuer=UniSabana');
    expect(r).toEqual({ ok: true, account: { secret: 'JBSWY3DPEHPK3PXP', issuer: 'UniSabana', account: 'estudiante@unisabana.edu.co' } });
  });
  it('parsea etiqueta codificada del backend', () => {
    const r = parseOtpAuthUri('otpauth://totp/UniSabana%3Aestudiante%40unisabana.edu.co?secret=JBSWY3DPEHPK3PXP&issuer=UniSabana&algorithm=SHA1&digits=6&period=30');
    expect(r.ok && r.account.account).toBe('estudiante@unisabana.edu.co');
  });
  it('rechaza HOTP y basura', () => {
    expect(parseOtpAuthUri('otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP').ok).toBe(false);
    expect(parseOtpAuthUri('https://example.com').ok).toBe(false);
  });
});
