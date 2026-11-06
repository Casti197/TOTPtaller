import { useState } from 'react';
import { ScrollView, StyleSheet, Text, View } from 'react-native';
import { Button } from '../components/Button';
import { MfaModal } from '../components/MfaModal';
import { Notice } from '../components/Notice';
import {
  clearElevatedToken,
  describeMfaError,
  fetchVault,
  requestStepUpToken,
  verifyMfa,
  type VaultData,
} from '../api/vault';
import { SessionExpiredError } from '../api/errors';
import { colors, mono, ui } from '../theme';

type Phase =
  | { name: 'locked' }
  | { name: 'loading' }
  | { name: 'mfa'; stepUpToken: string }
  | { name: 'open'; data: VaultData };

export function VaultScreen() {
  const [phase, setPhase] = useState<Phase>({ name: 'locked' });
  const [error, setError] = useState<string | null>(null);
  const [mfaError, setMfaError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [lastCode, setLastCode] = useState<string | null>(null);
  const [replayResult, setReplayResult] = useState<{ tone: 'success' | 'error'; text: string } | null>(null);

  const open = async () => {
    setError(null);
    setReplayResult(null);
    setPhase({ name: 'loading' });
    try {
      const r = await fetchVault();
      if (r.kind === 'ok') setPhase({ name: 'open', data: r.data });
      else {
        setMfaError(null);
        setPhase({ name: 'mfa', stepUpToken: r.stepUpToken }); // 403 mfa_required atrapado
      }
    } catch (e) {
      if (!(e instanceof SessionExpiredError)) setError((e as Error).message);
      setPhase({ name: 'locked' });
    }
  };

  const verify = async (code: string) => {
    if (phase.name !== 'mfa') return;
    setVerifying(true);
    setMfaError(null);
    try {
      await verifyMfa(phase.stepUpToken, code);
      setLastCode(code);
      const r = await fetchVault(); // reintento con elevated_token
      if (r.kind === 'ok') setPhase({ name: 'open', data: r.data });
      else setMfaError('El servidor aún exige MFA. Intenta de nuevo.');
    } catch (e) {
      setMfaError(describeMfaError(e));
    } finally {
      setVerifying(false);
    }
  };

  /** Prueba 5: reenviar inmediatamente el mismo código ya usado → el backend debe responder 409. */
  const replay = async () => {
    if (!lastCode) return;
    setReplayResult(null);
    try {
      const stepUp = await requestStepUpToken();
      await verifyMfa(stepUp, lastCode);
      setReplayResult({ tone: 'error', text: `⚠️ El backend aceptó de nuevo el código ${lastCode}. ¡Anti-replay falló!` });
    } catch (e) {
      setReplayResult({ tone: 'success', text: `Código ${lastCode} reenviado → ${describeMfaError(e)}` });
    }
  };

  const lock = () => {
    clearElevatedToken();
    setReplayResult(null);
    setPhase({ name: 'locked' });
  };

  return (
    <ScrollView style={ui.screen} contentContainerStyle={ui.content}>
      {phase.name === 'open' ? (
        <>
          <Notice tone="success">Acceso autorizado con segundo factor (mfa_verified: true)</Notice>
          <View style={[ui.card, styles.vault]}>
            <Text style={styles.vaultLabel}>Titular</Text>
            <Text style={styles.vaultValue}>{phase.data.titular}</Text>
            <Text style={styles.vaultLabel}>Cuenta</Text>
            <Text style={[styles.vaultValue, styles.mono]}>{phase.data.cuenta}</Text>
            <Text style={styles.vaultLabel}>Saldo</Text>
            <Text style={styles.balance}>{phase.data.saldo}</Text>
            <Text style={styles.vaultLabel}>Notas confidenciales</Text>
            {phase.data.notas_confidenciales.map((n) => (
              <Text key={n} style={styles.note}>• {n}</Text>
            ))}
            <Text style={styles.expiry}>
              Sesión elevada válida hasta {new Date(phase.data.acceso_valido_hasta).toLocaleTimeString()}
            </Text>
          </View>
          {lastCode ? (
            <View style={ui.card}>
              <Text style={ui.subtitle}>Prueba Anti-Replay</Text>
              <Text style={ui.body}>Reenvía ahora mismo el código {lastCode}, que ya se usó, a /auth/mfa/verify.</Text>
              <Button title="Reenviar el mismo código" variant="danger" onPress={() => void replay()} />
              {replayResult ? <Notice tone={replayResult.tone}>{replayResult.text}</Notice> : null}
            </View>
          ) : null}
          <Button title="Cerrar bóveda (descartar elevated_token)" variant="secondary" onPress={lock} />
        </>
      ) : (
        <View style={ui.card}>
          <Text style={styles.lockIcon}>🔒</Text>
          <Text style={[ui.title, styles.center]}>Bóveda Crítica</Text>
          <Text style={[ui.body, styles.center]}>
            Recurso protegido con Step-Up Authentication. Tu sesión normal no basta: se requiere verificar un código TOTP.
          </Text>
          <Button title="Abrir Bóveda Crítica" onPress={() => void open()} loading={phase.name === 'loading'} />
        </View>
      )}

      {error ? <Notice tone="error">{error}</Notice> : null}

      <MfaModal
        visible={phase.name === 'mfa'}
        busy={verifying}
        error={mfaError}
        onSubmit={(c) => void verify(c)}
        onCancel={() => setPhase({ name: 'locked' })}
      />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  lockIcon: { fontSize: 48, textAlign: 'center' },
  center: { textAlign: 'center' },
  vault: { backgroundColor: colors.navy, borderColor: colors.navy, gap: 4 },
  vaultLabel: { color: colors.accent, fontSize: 12, textTransform: 'uppercase', letterSpacing: 1, marginTop: 8 },
  vaultValue: { color: '#fff', fontSize: 17, fontWeight: '600' },
  balance: { color: '#fff', fontSize: 30, fontWeight: '800' },
  mono: { fontFamily: mono },
  note: { color: '#dbe4ef', fontSize: 14, lineHeight: 20 },
  expiry: { color: colors.accent, fontSize: 12, marginTop: 12 },
});
