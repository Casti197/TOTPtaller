import { Router } from 'express';
import QRCode from 'qrcode';
import { config } from '../config.js';
import { sign, ttlOf, verify } from '../jwt.js';
import { verifyTotp } from '../totp.js';
import { checkAndMarkReplay } from '../store.js';

export const mfaRouter = Router();

export function otpauthUri(): string {
  const u = config.demoUser;
  const label = encodeURIComponent(`${config.issuer}:${u.email}`);
  return `otpauth://totp/${label}?secret=${u.totpSecret}&issuer=${config.issuer}&algorithm=SHA1&digits=6&period=30`;
}

mfaRouter.post('/auth/mfa/verify', (req, res) => {
  const { step_up_token, code } = (req.body ?? {}) as Record<string, string>;
  const claims = step_up_token ? verify(step_up_token) : null;
  if (!claims || claims.typ !== 'step_up') {
    res.status(401).json({ error: 'invalid_step_up_token', error_description: 'step_up_token inválido o expirado' });
    return;
  }
  const normalized = String(code ?? '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(normalized)) {
    res.status(400).json({ error: 'invalid_code', error_description: 'El código debe tener 6 dígitos' });
    return;
  }
  // Ventanas C-1, C, C+1
  if (verifyTotp(config.demoUser.totpSecret, normalized) === null) {
    res.status(401).json({ error: 'invalid_code', error_description: 'Código TOTP incorrecto o fuera de la ventana de tiempo' });
    return;
  }
  // Caché Anti-Replay (TTL 90 s, cubre las 3 ventanas aceptadas)
  if (checkAndMarkReplay(claims.sub, normalized)) {
    res.status(409).json({ error: 'replay_detected', error_description: 'Replay Attack Detected: este código ya fue usado' });
    return;
  }
  res.json({
    token_type: 'Bearer',
    elevated_token: sign(claims.sub, 'elevated'),
    expires_in: ttlOf('elevated'),
  });
});

/** Datos de enrolamiento del usuario demo (semilla para la app y Google Authenticator). */
mfaRouter.get('/auth/mfa/enroll', (_req, res) => {
  res.json({ otpauth_uri: otpauthUri(), secret: config.demoUser.totpSecret });
});

mfaRouter.get('/auth/mfa/enroll/qr', async (_req, res) => {
  const uri = otpauthUri();
  const dataUrl = await QRCode.toDataURL(uri, { width: 320, margin: 2 });
  res.type('html').send(`<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Enrolamiento TOTP</title>
<style>body{font-family:system-ui,sans-serif;text-align:center;padding:24px;background:#f4f6fa;color:#13315c}
img{background:#fff;padding:8px;border-radius:12px}code{background:#fff;padding:4px 8px;border-radius:6px;font-size:18px;letter-spacing:2px}</style>
</head><body><h1>Enrolamiento TOTP · UniSabana</h1>
<p>Escanea este QR con la app del equipo <b>y</b> con Google Authenticator.</p>
<img src="${dataUrl}" alt="QR otpauth"><p>Semilla manual: <code>${config.demoUser.totpSecret}</code></p>
<p style="font-size:12px;color:#666;word-break:break-all">${uri.replace(/&/g, '&amp;')}</p></body></html>`);
});
