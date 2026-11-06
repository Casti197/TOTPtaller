/**
 * Configuración de la app. EXPO_PUBLIC_API_URL debe apuntar a la IP LAN del PC que corre el backend,
 * p. ej. http://192.168.1.20:4000 (el teléfono no puede usar "localhost").
 *
 * Nota de seguridad: la app es un cliente PÚBLICO. Aquí NO hay client_secret; solo un client_id.
 */
export const API_URL = (process.env.EXPO_PUBLIC_API_URL ?? '').replace(/\/+$/, '');
export const CLIENT_ID = 'unisabana-mobile';

export function assertApiConfigured(): void {
  if (!API_URL) {
    throw new Error('Falta EXPO_PUBLIC_API_URL en mobile-app/.env (ej. http://192.168.1.20:4000) — reinicia Expo con --clear');
  }
}
