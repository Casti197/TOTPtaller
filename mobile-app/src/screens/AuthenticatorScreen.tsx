import { useState } from 'react';
import { Alert, ScrollView, StyleSheet, Text, View } from 'react-native';
import { Button } from '../components/Button';
import { ManualSecretForm } from '../components/ManualSecretForm';
import { Notice } from '../components/Notice';
import { QrScannerModal } from '../components/QrScannerModal';
import { TotpDisplay } from '../components/TotpDisplay';
import type { OtpAccount } from '../crypto/otpauth';
import { removeAccount, saveAccount, useTotpAccount } from '../totp/accountStore';
import { colors, ui } from '../theme';

/** Módulo Authenticator propio (RFC 6238). Funciona 100% offline. */
export function AuthenticatorScreen() {
  const { account, loaded } = useTotpAccount();
  const [scanning, setScanning] = useState(false);
  const [manual, setManual] = useState(false);
  const [saved, setSaved] = useState<string | null>(null);

  const save = async (a: OtpAccount) => {
    await saveAccount(a);
    setScanning(false);
    setManual(false);
    setSaved(`Cuenta ${a.issuer} · ${a.account} guardada en el almacenamiento seguro`);
  };

  const confirmRemove = () =>
    Alert.alert('Eliminar cuenta', 'Se borrará la semilla de este dispositivo.', [
      { text: 'Cancelar', style: 'cancel' },
      { text: 'Eliminar', style: 'destructive', onPress: () => void removeAccount().then(() => setSaved(null)) },
    ]);

  return (
    <ScrollView style={ui.screen} contentContainerStyle={ui.content} keyboardShouldPersistTaps="handled">
      <View style={styles.badge}>
        <Text style={styles.badgeText}>● Cálculo local · HMAC-SHA1 · sin red (Modo Avión OK)</Text>
      </View>

      {!loaded ? null : account ? (
        <View style={ui.card}>
          <Text style={styles.issuer}>{account.issuer}</Text>
          <Text style={ui.small}>{account.account}</Text>
          <TotpDisplay secret={account.secret} />
        </View>
      ) : !manual ? (
        <View style={ui.card}>
          <Text style={ui.subtitle}>Aún no hay cuentas</Text>
          <Text style={ui.body}>
            Escanea el QR de enrolamiento (backend: /auth/mfa/enroll/qr) — el mismo que escaneas en Google
            Authenticator — o pega la semilla Base32.
          </Text>
        </View>
      ) : null}

      {saved ? <Notice tone="success">{saved}</Notice> : null}

      {manual ? (
        <ManualSecretForm onSave={(a) => void save(a)} onCancel={() => setManual(false)} />
      ) : (
        <View style={styles.actions}>
          <Button title={account ? 'Reemplazar con QR' : 'Escanear código QR'} onPress={() => setScanning(true)} />
          <Button title="Ingresar semilla manualmente" variant="secondary" onPress={() => setManual(true)} />
          {account ? <Button title="Eliminar cuenta" variant="ghost" onPress={confirmRemove} /> : null}
        </View>
      )}

      <QrScannerModal visible={scanning} onClose={() => setScanning(false)} onScanned={(a) => void save(a)} />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  badge: { alignSelf: 'flex-start', backgroundColor: colors.successBg, borderRadius: 999, paddingHorizontal: 12, paddingVertical: 6 },
  badgeText: { color: colors.success, fontSize: 12, fontWeight: '600' },
  issuer: { fontSize: 18, fontWeight: '700', color: colors.text },
  actions: { gap: 10 },
});
