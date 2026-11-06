import { Router } from 'express';
import { createHash, timingSafeEqual } from 'node:crypto';
import { config } from '../config.js';
import { sign, ttlOf } from '../jwt.js';
import { authCodes, issueRefreshToken, randomToken, refreshTokens } from '../store.js';

export const oauthRouter = Router();

export const CLIENT_ID = 'unisabana-mobile';
const VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;
const CHALLENGE_RE = /^[A-Za-z0-9\-_]{43}$/;

/**
 * Redirecciones permitidas: el esquema propio, exp:// (Expo Go en desarrollo) y la versión web de la app
 * servida en el propio PC (http://localhost o http://127.0.0.1, cualquier puerto). Ningún otro host http.
 */
function allowedRedirect(uri: string): boolean {
  try {
    const u = new URL(uri);
    if (u.protocol === 'http:' || u.protocol === 'https:') {
      return u.hostname === 'localhost' || u.hostname === '127.0.0.1';
    }
    return u.protocol === 'unisabana-auth:' || u.protocol === 'exp:';
  } catch {
    return false;
  }
}

const ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ESCAPES[c] ?? c);
}

interface AuthorizeParams {
  response_type: string;
  client_id: string;
  redirect_uri: string;
  state: string;
  code_challenge: string;
  code_challenge_method: string;
}

function readParams(src: Record<string, unknown>): AuthorizeParams | string {
  const p: AuthorizeParams = {
    response_type: String(src.response_type ?? ''),
    client_id: String(src.client_id ?? ''),
    redirect_uri: String(src.redirect_uri ?? ''),
    state: String(src.state ?? ''),
    code_challenge: String(src.code_challenge ?? ''),
    code_challenge_method: String(src.code_challenge_method ?? ''),
  };
  if (p.response_type !== 'code') return 'response_type debe ser "code"';
  if (p.client_id !== CLIENT_ID) return 'client_id desconocido';
  if (!allowedRedirect(p.redirect_uri)) return 'redirect_uri no permitido';
  if (!p.state) return 'state requerido';
  if (p.code_challenge_method !== 'S256') return 'Solo se admite code_challenge_method=S256';
  if (!CHALLENGE_RE.test(p.code_challenge)) return 'code_challenge inválido';
  return p;
}

function loginPage(p: AuthorizeParams, error?: string): string {
  const hidden = Object.entries(p)
    .map(([k, v]) => `<input type="hidden" name="${k}" value="${esc(v)}">`)
    .join('');
  return `<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>UniSabana · Iniciar sesión</title>
<style>
 body{font-family:system-ui,sans-serif;background:#0b2545;color:#fff;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}
 form{background:#fff;color:#13315c;padding:28px;border-radius:16px;width:min(360px,90vw);box-shadow:0 10px 30px #0006}
 h1{font-size:20px;margin:0 0 4px} p{margin:0 0 18px;color:#555;font-size:14px}
 label{display:block;font-size:13px;margin:12px 0 4px;font-weight:600}
 input[type=email],input[type=password]{width:100%;box-sizing:border-box;padding:12px;border:1px solid #ccd;border-radius:10px;font-size:16px}
 button{margin-top:20px;width:100%;padding:13px;border:0;border-radius:10px;background:#134074;color:#fff;font-size:16px;font-weight:600}
 .err{background:#fde8e8;color:#9b1c1c;padding:10px;border-radius:8px;font-size:14px;margin-bottom:8px}
 small{display:block;margin-top:14px;color:#777;font-size:12px}
</style></head><body>
<form method="post" action="/oauth/authorize">
 <h1>Universidad de La Sabana</h1>
 <p>Proveedor de identidad · OAuth 2.0 + PKCE</p>
 ${error ? `<div class="err">${esc(error)}</div>` : ''}
 ${hidden}
 <label for="email">Correo institucional</label>
 <input id="email" name="email" type="email" autocomplete="username" value="${esc(config.demoUser.email)}" required>
 <label for="password">Contraseña</label>
 <input id="password" name="password" type="password" autocomplete="current-password" required>
 <button type="submit">Iniciar sesión</button>
 <small>Estás en el navegador del sistema: la app nunca ve tu contraseña.</small>
</form></body></html>`;
}

oauthRouter.get('/oauth/authorize', (req, res) => {
  const p = readParams(req.query as Record<string, unknown>);
  if (typeof p === 'string') {
    res.status(400).send(`Solicitud de autorización inválida: ${esc(p)}`);
    return;
  }
  res.type('html').send(loginPage(p));
});

oauthRouter.post('/oauth/authorize', (req, res) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const p = readParams(body);
  if (typeof p === 'string') {
    res.status(400).send(`Solicitud de autorización inválida: ${esc(p)}`);
    return;
  }
  const u = config.demoUser;
  if (body.email !== u.email || body.password !== u.password) {
    res.status(401).type('html').send(loginPage(p, 'Credenciales incorrectas'));
    return;
  }
  const code = randomToken(32);
  authCodes.set(code, {
    userId: u.id,
    clientId: p.client_id,
    redirectUri: p.redirect_uri,
    codeChallenge: p.code_challenge,
    expiresAt: Date.now() + config.ttl.authCode * 1000,
  });
  const redirect = new URL(p.redirect_uri);
  redirect.searchParams.set('code', code);
  redirect.searchParams.set('state', p.state);
  // Chrome (Android) suele ignorar en silencio un 302 hacia un esquema propio (exp://, unisabana-auth://)
  // cuando viene tras un POST. Se entrega una página que abre el deep link por JS y ofrece un botón
  // (gesto del usuario, siempre permitido) como respaldo.
  const target = redirect.toString();  const android = /Android/i.test(req.get('user-agent') ?? '');
  res.type('html').send(callbackPage(android ? androidIntent(redirect) : target, target));
});

/**
 * En Android, Chrome/Custom Tabs ignoran a menudo los enlaces a esquemas propios (exp://…).
 * La sintaxis intent:// la entrega directamente al sistema, que abre la app indicada.
 * exp://host:8081/--/oauth/callback?x → intent://host:8081/--/oauth/callback?x#Intent;scheme=exp;package=…;end
 */
function androidIntent(u: URL): string {
  const scheme = u.protocol.slice(0, -1);
  const rest = u.toString().slice(u.protocol.length).replace(/^\/\//, '');
  // Sin package=: si el paquete no coincide exactamente, Chrome manda a Play Store. Android resuelve por esquema.
  return `intent://${rest}#Intent;scheme=${scheme};end`;
}

function callbackPage(target: string, plain: string = target): string {
  // JSON con "<" escapado para que no pueda cerrar el <script>
  const js = JSON.stringify(target).replace(/</g, '\\u003c');
  return `<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>UniSabana · Volviendo a la app</title>
<style>
 body{font-family:system-ui,sans-serif;background:#0b2545;color:#fff;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}
 div{background:#fff;color:#13315c;padding:28px;border-radius:16px;width:min(360px,90vw);text-align:center}
 a{display:block;margin-top:18px;padding:13px;border-radius:10px;background:#134074;color:#fff;font-weight:600;text-decoration:none}
</style></head><body><div>
 <h1 style="font-size:20px;margin:0 0 8px">Inicio de sesión correcto</h1>
 <p style="margin:0;color:#555;font-size:14px">Volviendo a la app…</p>
 <a id="back" href="${esc(target)}">Volver a la app</a>
 ${plain !== target ? `<a id="plain" href="${esc(plain)}" style="background:none;color:#134074;font-size:13px;font-weight:400">¿No funciona? Abrir enlace directo</a>` : ''}
</div><script>window.location.replace(${js});</script></body></html>`;
}

oauthRouter.post('/auth/oauth/token', (req, res) => {
  const { grant_type, code, code_verifier, redirect_uri, client_id } = (req.body ?? {}) as Record<string, string>;
  if (grant_type !== 'authorization_code') {
    res.status(400).json({ error: 'unsupported_grant_type' });
    return;
  }
  const record = code ? authCodes.get(code) : undefined;
  // El código es de un solo uso: se elimina de inmediato
  if (code) authCodes.delete(code);
  if (!record || record.expiresAt < Date.now()) {
    res.status(400).json({ error: 'invalid_grant', error_description: 'Código inválido o expirado' });
    return;
  }
  if (record.clientId !== client_id || record.redirectUri !== redirect_uri) {
    res.status(400).json({ error: 'invalid_grant', error_description: 'client_id o redirect_uri no coinciden' });
    return;
  }
  if (!code_verifier || !VERIFIER_RE.test(code_verifier)) {
    res.status(400).json({ error: 'invalid_request', error_description: 'code_verifier inválido' });
    return;
  }
  // PKCE: BASE64URL(SHA256(code_verifier)) === code_challenge
  const computed = Buffer.from(createHash('sha256').update(code_verifier, 'ascii').digest('base64url'));
  const expected = Buffer.from(record.codeChallenge);
  if (computed.length !== expected.length || !timingSafeEqual(computed, expected)) {
    res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE: code_verifier no coincide con code_challenge' });
    return;
  }
  res.json({
    token_type: 'Bearer',
    access_token: sign(record.userId, 'access'),
    expires_in: ttlOf('access'),
    refresh_token: issueRefreshToken(record.userId),
  });
});

oauthRouter.post('/auth/refresh', (req, res) => {
  const { refresh_token } = (req.body ?? {}) as Record<string, string>;
  const record = refresh_token ? refreshTokens.get(refresh_token) : undefined;
  if (!refresh_token || !record || record.expiresAt < Date.now()) {
    if (refresh_token) refreshTokens.delete(refresh_token);
    res.status(401).json({ error: 'invalid_grant', error_description: 'refresh_token vencido o revocado' });
    return;
  }
  // Rotación: el refresh_token anterior queda invalidado
  refreshTokens.delete(refresh_token);
  res.json({
    token_type: 'Bearer',
    access_token: sign(record.userId, 'access'),
    expires_in: ttlOf('access'),
    refresh_token: issueRefreshToken(record.userId),
  });
});

oauthRouter.post('/auth/logout', (req, res) => {
  const { refresh_token } = (req.body ?? {}) as Record<string, string>;
  if (refresh_token) refreshTokens.delete(refresh_token);
  res.status(204).end();
});
