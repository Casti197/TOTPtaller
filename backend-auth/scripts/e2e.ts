/**
 * Prueba de humo end-to-end contra el backend en ejecución (simula a la app móvil).
 * Uso: npm run dev   (en otra terminal)  →  npm run e2e
 */
import { createHash, randomBytes } from 'node:crypto';
import { totp } from '../src/totp.js';
import { config } from '../src/config.js';

const BASE = process.env.API_URL ?? `http://localhost:${config.port}`;
const REDIRECT = 'unisabana-auth://oauth/callback';

let failures = 0;
function check(name: string, ok: boolean, extra?: unknown): void {
  console.log(`${ok ? 'OK  ' : 'FAIL'} ${name}`, ok ? '' : (extra ?? ''));
  if (!ok) failures++;
}

/** El login exitoso devuelve una página que abre el deep link: se extrae del enlace "Volver a la app". */
async function deepLinkOf(r: Response): Promise<string> {
  const href = /id="back" href="([^"]+)"/.exec(await r.text())?.[1] ?? '';
  return href.replace(/&amp;/g, '&');
}

async function post(path: string, body: Record<string, string>, form = false): Promise<Response> {
  return fetch(BASE + path, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'Content-Type': form ? 'application/x-www-form-urlencoded' : 'application/json' },
    body: form ? new URLSearchParams(body).toString() : JSON.stringify(body),
  });
}

async function main(): Promise<void> {
  // 1) PKCE
  const verifier = randomBytes(48).toString('base64url'); // 64 chars URL-safe
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const state = randomBytes(16).toString('hex');
  const params = {
    response_type: 'code',
    client_id: 'unisabana-mobile',
    redirect_uri: REDIRECT,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  };

  const page = await fetch(`${BASE}/oauth/authorize?${new URLSearchParams(params)}`);
  check('GET /oauth/authorize muestra login', page.status === 200);

  const bad = await post('/oauth/authorize', { ...params, email: config.demoUser.email, password: 'x' }, true);
  check('Login con contraseña incorrecta → 401', bad.status === 401);

  const login = await post('/oauth/authorize', { ...params, email: config.demoUser.email, password: config.demoUser.password }, true);
  const location = await deepLinkOf(login);
  check('Login → página que abre el deep link', login.status === 200 && location.startsWith(REDIRECT), location);
  const cb = new URL(location);
  check('state regresa intacto', cb.searchParams.get('state') === state);
  const code = cb.searchParams.get('code') ?? '';

  // 2) Token exchange: primero con verifier incorrecto (el código queda consumido) → hacemos un login nuevo
  const wrong = await post('/auth/oauth/token', {
    grant_type: 'authorization_code', code, code_verifier: randomBytes(48).toString('base64url'),
    redirect_uri: REDIRECT, client_id: 'unisabana-mobile',
  });
  check('PKCE con code_verifier incorrecto → 400', wrong.status === 400);

  const login2 = await post('/oauth/authorize', { ...params, email: config.demoUser.email, password: config.demoUser.password }, true);
  const code2 = new URL(await deepLinkOf(login2)).searchParams.get('code') ?? '';
  const tokRes = await post('/auth/oauth/token', {
    grant_type: 'authorization_code', code: code2, code_verifier: verifier,
    redirect_uri: REDIRECT, client_id: 'unisabana-mobile',
  });
  const tok = (await tokRes.json()) as { access_token: string; refresh_token: string };
  check('Token exchange con PKCE válido → 200', tokRes.status === 200 && !!tok.access_token && !!tok.refresh_token);

  const reuse = await post('/auth/oauth/token', {
    grant_type: 'authorization_code', code: code2, code_verifier: verifier,
    redirect_uri: REDIRECT, client_id: 'unisabana-mobile',
  });
  check('Reuso del authorization_code → 400', reuse.status === 400);

  // 3) Perfil y 401
  const auth = (t: string) => ({ headers: { Authorization: `Bearer ${t}` } });
  check('GET /api/perfil con access_token → 200', (await fetch(`${BASE}/api/perfil`, auth(tok.access_token))).status === 200);
  check('GET /api/perfil con token basura → 401', (await fetch(`${BASE}/api/perfil`, auth('xxx'))).status === 401);

  // 4) Refresh con rotación
  const ref = await post('/auth/refresh', { refresh_token: tok.refresh_token });
  const refJson = (await ref.json()) as { access_token: string; refresh_token: string };
  check('POST /auth/refresh → 200', ref.status === 200 && !!refJson.access_token);
  check('refresh_token anterior revocado (rotación) → 401', (await post('/auth/refresh', { refresh_token: tok.refresh_token })).status === 401);

  // 5) Step-up
  const vault = await fetch(`${BASE}/api/boveda-critica`, auth(refJson.access_token));
  const vaultJson = (await vault.json()) as { error: string; step_up_token: string };
  check('Bóveda con access_token estándar → 403 mfa_required', vault.status === 403 && vaultJson.error === 'mfa_required');

  const wrongCode = await post('/auth/mfa/verify', { step_up_token: vaultJson.step_up_token, code: '000000' === totp(config.demoUser.totpSecret) ? '111111' : '000000' });
  check('MFA con código incorrecto → 401', wrongCode.status === 401);

  let otp = totp(config.demoUser.totpSecret);
  let mfa = await post('/auth/mfa/verify', { step_up_token: vaultJson.step_up_token, code: otp });
  if (mfa.status === 409) {
    // Este código ya se usó en una ejecución anterior (<90 s): esperar a la siguiente ventana de 30 s
    let fresh = otp;
    console.log(`     (código ${otp} ya usado antes; esperando nuevo código...)`);
    while (fresh === otp) {
      await new Promise((r) => setTimeout(r, 1000));
      fresh = totp(config.demoUser.totpSecret);
    }
    otp = fresh;
    mfa = await post('/auth/mfa/verify', { step_up_token: vaultJson.step_up_token, code: otp });
  }
  const mfaJson = (await mfa.json()) as { elevated_token: string };
  check(`MFA con código ${otp} → 200 elevated_token`, mfa.status === 200 && !!mfaJson.elevated_token);

  const replay = await post('/auth/mfa/verify', { step_up_token: vaultJson.step_up_token, code: otp });
  check('Mismo código otra vez → 409 Replay', replay.status === 409);

  const vault2 = await fetch(`${BASE}/api/boveda-critica`, auth(mfaJson.elevated_token));
  check('Bóveda con elevated_token → 200', vault2.status === 200);

  console.log(failures ? `\n${failures} fallo(s)` : '\nTodos los escenarios pasaron');
  process.exitCode = failures ? 1 : 0;
}

main().catch((e: unknown) => {
  console.error(e);
  process.exitCode = 1;
});
