import { useRef, useState, type ComponentRef } from 'react';
import { KeyboardAvoidingView, Modal, Platform, Pressable, StyleSheet, Text, TextInput, View } from 'react-native';
import { Button } from './Button';
import { Notice } from './Notice';
import { TotpDisplay } from './TotpDisplay';
import { totpFromBase32 } from '../crypto/totp';
import { useTotpAccount } from '../totp/accountStore';
import { colors, mono, ui } from '../theme';

interface Props {
  visible: boolean;
  busy: boolean;
  error: string | null;
  onCancel: () => void;
  onSubmit: (code: string) => void;
}

/** Modal de Step-Up 2FA: teclado numérico, 6 dígitos, autocompletar desde el Authenticator local. */
export function MfaModal({ visible, busy, error, onCancel, onSubmit }: Props) {
  const [code, setCode] = useState('');
  const inputRef = useRef<ComponentRef<typeof TextInput>>(null);
  const { account } = useTotpAccount();

  const submit = (value: string) => {
    if (/^\d{6}$/.test(value) && !busy) onSubmit(value);
  };

  return (
    <Modal visible={visible} transparent animationType="fade" onRequestClose={onCancel}
      onShow={() => {
        setCode(''); // cada apertura empieza limpia
        inputRef.current?.focus();
      }}
    >
      <KeyboardAvoidingView style={styles.backdrop} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
        <View style={[ui.card, styles.sheet]}>
          <Text style={ui.title}>Verificación en dos pasos</Text>
          <Text style={ui.body}>
            La Bóveda Crítica requiere un segundo factor. Ingresa el código de 6 dígitos de tu Authenticator.
          </Text>

          <Pressable onPress={() => inputRef.current?.focus()} accessibilityLabel="Campo de código">
            <TextInput
              ref={inputRef}
              value={code}
              onChangeText={(t) => {
                const digits = t.replace(/\D/g, '').slice(0, 6);
                setCode(digits);
                if (digits.length === 6) submit(digits);
              }}
              keyboardType="number-pad"
              inputMode="numeric"
              textContentType="oneTimeCode"
              autoComplete="one-time-code"
              maxLength={6}
              style={styles.input}
              placeholder="000000"
              placeholderTextColor="#b8c2d1"
              editable={!busy}
              accessibilityLabel="Código TOTP de 6 dígitos"
            />
          </Pressable>

          {error ? <Notice tone="error">{error}</Notice> : null}

          {account ? (
            <View style={styles.local}>
              <Text style={ui.small}>Tu Authenticator local ({account.issuer}):</Text>
              <TotpDisplay secret={account.secret} compact />
              <Button
                title="Usar código local"
                variant="secondary"
                disabled={busy}
                onPress={() => {
                  const c = totpFromBase32(account.secret);
                  setCode(c);
                  submit(c);
                }}
              />
            </View>
          ) : null}

          <View style={styles.row}>
            <Button title="Cancelar" variant="secondary" onPress={onCancel} disabled={busy} style={styles.flex} />
            <Button title="Verificar" onPress={() => submit(code)} loading={busy} disabled={code.length !== 6} style={styles.flex} />
          </View>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

const styles = StyleSheet.create({
  backdrop: { flex: 1, backgroundColor: 'rgba(11,37,69,0.6)', justifyContent: 'center', padding: 20 },
  sheet: { gap: 14 },
  input: {
    fontFamily: mono,
    fontSize: 36,
    letterSpacing: 10,
    textAlign: 'center',
    color: colors.primary,
    borderWidth: 2,
    borderColor: colors.border,
    borderRadius: 12,
    paddingVertical: 12,
    backgroundColor: '#fff',
  },
  local: { gap: 8, backgroundColor: colors.bg, borderRadius: 12, padding: 12 },
  row: { flexDirection: 'row', gap: 10 },
  flex: { flex: 1 },
});
