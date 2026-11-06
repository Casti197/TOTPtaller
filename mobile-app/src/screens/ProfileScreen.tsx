import { useCallback, useEffect, useRef, useState } from 'react';
import { ScrollView, StyleSheet, Text, View } from 'react-native';
import { Button } from '../components/Button';
import { Notice } from '../components/Notice';
import { useAuth } from '../auth/AuthContext';
import { decodeJwtPayload } from '../auth/jwt';
import {
  authJson,
  debugInvalidateAccessToken,
  debugRevokeRefreshToken,
  getAccessToken,
  subscribe,
  type SessionEvent,
} from '../api/session';
import { SessionExpiredError } from '../api/errors';
import { colors, mono, ui } from '../theme';

interface Profile {
  email: string;
  name: string;
  served_at: string;
}

interface LogLine {
  id: number;
  time: string;
  text: string;
}

function describe(e: SessionEvent): string | null {
  switch (e.kind) {
    case 'request':
      return `→ ${e.path}`;
    case 'unauthorized':
      return `✗ 401 en ${e.path}`;
    case 'queued':
      return `⏸ ${e.path} en cola (esperando refresh)`;
    case 'refresh_start':
      return '⟳ POST /auth/refresh (única llamada)';
    case 'refresh_ok':
      return '✓ access_token renovado · refresh_token rotado';
    case 'refresh_failed':
      return '✗ refresh_token inválido → cerrando sesión';
    case 'retry':
      return `↻ reintento ${e.path} → ${e.status}`;
    default:
      return null;
  }
}

export function ProfileScreen() {
  const { logout } = useAuth();
  const [profile, setProfile] = useState<Profile | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [log, setLog] = useState<LogLine[]>([]);
  const [now, setNow] = useState(() => Date.now());
  const seq = useRef(0);

  useEffect(() => {
    const unsub = subscribe((e) => {
      const text = describe(e);
      if (!text) return;
      const line = { id: ++seq.current, time: new Date().toLocaleTimeString(), text };
      setLog((l) => [line, ...l].slice(0, 20));
    });
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => {
      unsub();
      clearInterval(id);
    };
  }, []);

  const run = useCallback(async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      if (!(e instanceof SessionExpiredError)) setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, []);

  const loadProfile = useCallback(() => run(async () => setProfile(await authJson<Profile>('/api/perfil'))), [run]);

  useEffect(() => {
    // Carga inicial: el setState ocurre en callbacks asíncronos, no de forma síncrona en el efecto
    authJson<Profile>('/api/perfil')
      .then(setProfile)
      .catch((e: unknown) => {
        if (!(e instanceof SessionExpiredError)) setError((e as Error).message);
      });
  }, []);

  const concurrent = () =>
    run(async () => {
      const results = await Promise.all([1, 2, 3].map(() => authJson<Profile>('/api/perfil')));
      setProfile(results[0]);
    });

  const token = getAccessToken();
  const exp = token ? decodeJwtPayload(token)?.exp : undefined;
  const left = exp ? Math.max(0, Math.round(exp - now / 1000)) : null;

  return (
    <ScrollView style={ui.screen} contentContainerStyle={ui.content}>
      <View style={ui.card}>
        <Text style={ui.title}>{profile?.name ?? 'Perfil'}</Text>
        <Text style={ui.body}>{profile?.email ?? 'Cargando…'}</Text>
        <View style={styles.kv}>
          <Text style={ui.small}>access_token (RAM)</Text>
          <Text style={ui.monoSmall}>
            {token ? `${token.slice(0, 16)}… · expira en ${left !== null ? `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}` : '?'}` : 'ninguno (se obtendrá con refresh)'}
          </Text>
          <Text style={ui.small}>refresh_token</Text>
          <Text style={ui.monoSmall}>Keychain / Keystore (expo-secure-store)</Text>
        </View>
        <Button title="Recargar perfil" variant="secondary" onPress={() => void loadProfile()} loading={busy} />
      </View>

      {error ? <Notice tone="error">{error}</Notice> : null}

      <View style={ui.card}>
        <Text style={ui.subtitle}>Demo · Silent Refresh Queue</Text>
        <Text style={ui.body}>
          Invalida el access_token y dispara 3 peticiones a la vez: verás tres 401, una sola llamada a /auth/refresh y tres
          reintentos exitosos, sin salir de la pantalla.
        </Text>
        <Button title="1 · Simular access_token expirado" variant="secondary" onPress={debugInvalidateAccessToken} />
        <Button title="2 · Lanzar 3 peticiones concurrentes" onPress={() => void concurrent()} disabled={busy} />
        <Button
          title="Simular refresh_token revocado"
          variant="danger"
          onPress={() => void debugRevokeRefreshToken().then(loadProfile)}
          disabled={busy}
        />
      </View>

      <View style={ui.card}>
        <Text style={ui.subtitle}>Registro del interceptor</Text>
        {log.length === 0 ? <Text style={ui.small}>Sin eventos todavía</Text> : null}
        {log.map((l) => (
          <Text key={l.id} style={styles.logLine}>
            <Text style={styles.logTime}>{l.time} </Text>
            {l.text}
          </Text>
        ))}
      </View>

      <Button title="Cerrar sesión" variant="ghost" onPress={() => void logout()} />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  kv: { gap: 2, backgroundColor: colors.bg, borderRadius: 10, padding: 10 },
  logLine: { fontFamily: mono, fontSize: 12, color: colors.text, lineHeight: 18 },
  logTime: { color: colors.muted },
});
