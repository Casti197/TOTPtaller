import Constants from 'expo-constants';
import * as Linking from 'expo-linking';
import * as WebBrowser from 'expo-web-browser';
import { API_URL, CLIENT_ID, assertApiConfigured } from '../config';
import { createPkcePair, createState } from '../crypto/pkce';
import { publicJson, setSession, type TokenResponse } from '../api/session';

/**
 * OAuth 2.0 Authorization Code + PKCE (RFC 7636) con el navegador del sistema
 * (ASWebAuthenticationSession en iOS, Custom Tabs en Android). Nunca WebView embebida.
 */

export type LoginResult = { ok: true } | { ok: false; reason: 'cancelled' | 'error'; message: string };

/**
 * URI de redirección (deep link):
 *  - Build propia / dev build: unisabana-auth://oauth/callback
 *  - Expo Go: exp://<IP>:8081/--/oauth/callback (Expo Go no puede registrar esquemas propios)
 */
export function getRedirectUri(): string {
  // Dentro de Expo Go solo existe exp:// (el esquema propio no está instalado en el teléfono).
  // expoGoConfig solo está presente en Expo Go. En este SDK Expo Go reporta executionEnvironment="bare",
  // así que createURL devuelve unisabana-auth:// (que ninguna app atiende): se construye la URI explícitamente.
  const hostUri = Constants.expoConfig?.hostUri;
  if (Constants.expoGoConfig && hostUri) {
    return `exp://${hostUri.replace(/\/+$/, '')}/--/oauth/callback`;
  }
  return Linking.createURL('oauth/callback');
}

function buildQuery(params: Record<string, string>): string {
  return Object.entries(params)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}

export async function loginWithOAuth(): Promise<LoginResult> {
  try {
    assertApiConfigured();
  } catch (e) {
    return { ok: false, reason: 'error', message: (e as Error).message };
  }

  // 1. PKCE + state, solo en memoria durante este intento de login
  const { codeVerifier, codeChallenge, method } = await createPkcePair();
  const state = createState();
  const redirectUri = getRedirectUri();

  const authorizeUrl =
    `${API_URL}/oauth/authorize?` +
    buildQuery({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: redirectUri,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: method,
    });

  // 2. Navegador seguro del sistema
  let result: WebBrowser.WebBrowserAuthSessionResult;
  try {
    result = await WebBrowser.openAuthSessionAsync(authorizeUrl, redirectUri);
  } catch (e) {
    return { ok: false, reason: 'error', message: `No se pudo abrir el navegador: ${(e as Error).message}` };
  }
  if (result.type !== 'success') {
    return { ok: false, reason: 'cancelled', message: 'Inicio de sesión cancelado' };
  }

  // 3. Deep link de regreso: validar state (anti-CSRF) antes de cualquier otra cosa
  const { queryParams } = Linking.parse(result.url);
  const returnedState = typeof queryParams?.state === 'string' ? queryParams.state : null;
  const code = typeof queryParams?.code === 'string' ? queryParams.code : null;
  const error = typeof queryParams?.error === 'string' ? queryParams.error : null;

  if (returnedState !== state) {
    return { ok: false, reason: 'error', message: 'state no coincide: posible ataque CSRF. Intercambio abortado.' };
  }
  if (error || !code) {
    return { ok: false, reason: 'error', message: `El proveedor devolvió un error: ${error ?? 'sin código'}` };
  }

  // 4. Token exchange: code + code_verifier (el backend verifica SHA256(verifier) === challenge)
  try {
    const tokens = await publicJson<TokenResponse>('/auth/oauth/token', {
      grant_type: 'authorization_code',
      code,
      code_verifier: codeVerifier,
      redirect_uri: redirectUri,
      client_id: CLIENT_ID,
    });
    await setSession(tokens); // access_token → RAM, refresh_token → SecureStore
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: 'error', message: (e as Error).message };
  }
}
