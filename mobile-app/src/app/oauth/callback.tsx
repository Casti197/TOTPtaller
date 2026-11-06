import { Redirect } from 'expo-router';

/**
 * Destino del deep link .../oauth/callback?code=…&state=…
 * openAuthSessionAsync ya capturó la URL y hace el intercambio en auth/oauth.ts; en Android el router
 * también puede recibir el deep link, así que esta ruta solo devuelve al usuario al inicio.
 */
export default function OAuthCallback() {
  return <Redirect href="/" />;
}
