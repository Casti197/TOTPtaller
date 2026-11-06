/**
 * Versión web de secureStorage (Metro la elige automáticamente al empaquetar para web).
 *
 * El navegador no tiene Keychain ni Keystore: localStorage y sessionStorage son texto plano legible por
 * cualquier script de la página (XSS). Por eso en web los secretos (refresh_token y semilla TOTP) viven
 * SOLO en memoria: se pierden al recargar la pestaña, que es el comportamiento seguro para un cliente
 * público en el navegador. En iOS y Android se usa expo-secure-store (ver secureStorage.ts).
 */

const memory = new Map<string, string>();

const KEYS = {
  refreshToken: 'unisabana.refresh_token',
  totpAccount: 'unisabana.totp_account',
} as const;

const get = async (k: string): Promise<string | null> => memory.get(k) ?? null;
const set = async (k: string, v: string): Promise<void> => {
  memory.set(k, v);
};
const del = async (k: string): Promise<void> => {
  memory.delete(k);
};

export const secureStorage = {
  getRefreshToken: () => get(KEYS.refreshToken),
  setRefreshToken: (token: string) => set(KEYS.refreshToken, token),
  clearRefreshToken: () => del(KEYS.refreshToken),

  getTotpAccount: () => get(KEYS.totpAccount),
  setTotpAccount: (json: string) => set(KEYS.totpAccount, json),
  clearTotpAccount: () => del(KEYS.totpAccount),
};
