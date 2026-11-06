import { useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useRouter } from 'expo-router';
import { Button } from '../components/Button';
import { Notice } from '../components/Notice';
import { useAuth } from '../auth/AuthContext';
import { getRedirectUri } from '../auth/oauth';
import { API_URL } from '../config';
import { colors, mono } from '../theme';

export function WelcomeScreen() {
  const { login } = useAuth();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onLogin = async () => {
    setBusy(true);
    setError(null);
    const r = await login();
    if (!r.ok && r.reason === 'error') setError(r.message);
    setBusy(false);
  };

  return (
    <SafeAreaView style={styles.root}>
      <View style={styles.hero}>
        <Text style={styles.shield}>🛡️</Text>
        <Text style={styles.title}>UniSabana Secure</Text>
        <Text style={styles.subtitle}>OAuth 2.0 + PKCE · SecureStore · Step-Up 2FA (TOTP)</Text>
      </View>

      <View style={styles.actions}>
        {error ? <Notice tone="error">{error}</Notice> : null}
        <Button title="Iniciar sesión" onPress={() => void onLogin()} loading={busy} />
        <Text style={styles.hint}>Se abrirá el navegador seguro del sistema (no un WebView).</Text>
        <Button title="Abrir Authenticator (offline)" variant="secondary" onPress={() => router.push('/totp')} />
        <Text style={styles.debug}>
          API: {API_URL || '⚠ EXPO_PUBLIC_API_URL sin configurar'}
          {'\n'}redirect_uri: {getRedirectUri()}
        </Text>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.navy, padding: 24, justifyContent: 'space-between' },
  hero: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 8 },
  shield: { fontSize: 64 },
  title: { color: '#fff', fontSize: 30, fontWeight: '800' },
  subtitle: { color: colors.accent, fontSize: 14, textAlign: 'center' },
  actions: { gap: 12 },
  hint: { color: colors.accent, fontSize: 12, textAlign: 'center' },
  debug: { color: '#6f86a3', fontSize: 10, fontFamily: mono, textAlign: 'center', marginTop: 8 },
});
