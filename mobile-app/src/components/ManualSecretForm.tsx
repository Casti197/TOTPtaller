import { useState } from 'react';
import { StyleSheet, Text, TextInput, View } from 'react-native';
import { validateBase32Secret } from '../crypto/base32';
import type { OtpAccount } from '../crypto/otpauth';
import { Button } from './Button';
import { colors, mono, ui } from '../theme';

interface Props {
  onSave: (account: OtpAccount) => void;
  onCancel: () => void;
}

/** Ingreso manual de la semilla Base32 (indispensable en emuladores sin cámara). */
export function ManualSecretForm({ onSave, onCancel }: Props) {
  const [secret, setSecret] = useState('');
  const [account, setAccount] = useState('estudiante@unisabana.edu.co');
  const [touched, setTouched] = useState(false);
  const validation = validateBase32Secret(secret);

  return (
    <View style={ui.card}>
      <Text style={ui.subtitle}>Semilla Base32</Text>
      <TextInput
        style={[styles.input, styles.mono, touched && !validation.ok && styles.inputError]}
        value={secret}
        onChangeText={setSecret}
        onBlur={() => setTouched(true)}
        placeholder="JBSWY3DPEHPK3PXP"
        autoCapitalize="characters"
        autoCorrect={false}
        autoComplete="off"
        spellCheck={false}
        secureTextEntry={false}
        accessibilityLabel="Semilla Base32"
      />
      {touched && !validation.ok ? <Text style={styles.error}>{validation.error}</Text> : null}
      <Text style={ui.subtitle}>Cuenta</Text>
      <TextInput
        style={styles.input}
        value={account}
        onChangeText={setAccount}
        autoCapitalize="none"
        keyboardType="email-address"
        accessibilityLabel="Cuenta"
      />
      <View style={styles.row}>
        <Button title="Cancelar" variant="secondary" onPress={onCancel} style={styles.flex} />
        <Button
          title="Guardar"
          style={styles.flex}
          disabled={!validation.ok}
          onPress={() => {
            setTouched(true);
            if (validation.ok) onSave({ secret: validation.value, issuer: 'UniSabana', account: account.trim() });
          }}
        />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  input: {
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 10,
    padding: 12,
    fontSize: 16,
    color: colors.text,
    backgroundColor: '#fff',
  },
  mono: { fontFamily: mono, letterSpacing: 2 },
  inputError: { borderColor: colors.danger },
  error: { color: colors.danger, fontSize: 13 },
  row: { flexDirection: 'row', gap: 10, marginTop: 6 },
  flex: { flex: 1 },
});
