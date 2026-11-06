import * as SecureStore from 'expo-secure-store';

/**
 * Persistencia en el enclave seguro: iOS Keychain / Android Keystore (vía expo-secure-store).
 * Nunca AsyncStorage. Solo datos duraderos viven aquí: el refresh_token y la semilla TOTP.
 * El access_token NO se persiste (vive en memoria, ver session.ts).
 */

const OPTIONS: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

const KEYS = {
  refreshToken: 'unisabana.refresh_token',
  totpAccount: 'unisabana.totp_account',
} as const;

export const secureStorage = {
  getRefreshToken: () => SecureStore.getItemAsync(KEYS.refreshToken, OPTIONS),
  setRefreshToken: (token: string) => SecureStore.setItemAsync(KEYS.refreshToken, token, OPTIONS),
  clearRefreshToken: () => SecureStore.deleteItemAsync(KEYS.refreshToken, OPTIONS),

  getTotpAccount: () => SecureStore.getItemAsync(KEYS.totpAccount, OPTIONS),
  setTotpAccount: (json: string) => SecureStore.setItemAsync(KEYS.totpAccount, json, OPTIONS),
  clearTotpAccount: () => SecureStore.deleteItemAsync(KEYS.totpAccount, OPTIONS),
};
