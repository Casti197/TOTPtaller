import { useRef, useState } from 'react';
import { Modal, StyleSheet, Text, View } from 'react-native';
import { CameraView, useCameraPermissions, type BarcodeScanningResult } from 'expo-camera';
import { SafeAreaView } from 'react-native-safe-area-context';
import { parseOtpAuthUri, type OtpAccount } from '../crypto/otpauth';
import { Button } from './Button';
import { Notice } from './Notice';
import { colors, ui } from '../theme';

interface Props {
  visible: boolean;
  onClose: () => void;
  onScanned: (account: OtpAccount) => void;
}

export function QrScannerModal({ visible, onClose, onScanned }: Props) {
  const [permission, requestPermission] = useCameraPermissions();
  const [error, setError] = useState<string | null>(null);
  const handled = useRef(false);

  const handleScan = ({ data }: BarcodeScanningResult) => {
    if (handled.current) return; // el callback se dispara varias veces por segundo
    const result = parseOtpAuthUri(data);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    handled.current = true;
    onScanned(result.account);
  };

  return (
    <Modal
      visible={visible}
      animationType="slide"
      onRequestClose={onClose}
      onShow={() => {
        handled.current = false;
        setError(null);
      }}
    >
      <SafeAreaView style={styles.root}>
        <Text style={styles.title}>Escanear QR otpauth://</Text>
        {!permission ? null : !permission.granted ? (
          <View style={[ui.card, styles.permission]}>
            <Text style={ui.body}>Necesitamos la cámara para leer el QR de enrolamiento. La imagen no sale del teléfono.</Text>
            <Button title="Permitir cámara" onPress={requestPermission} />
          </View>
        ) : (
          <View style={styles.cameraWrap}>
            <CameraView
              style={StyleSheet.absoluteFill}
              facing="back"
              barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
              onBarcodeScanned={handleScan}
            />
            <View style={styles.frame} pointerEvents="none" />
          </View>
        )}
        {error ? <Notice tone="error">{error}</Notice> : null}
        <Button title="Cancelar" variant="secondary" onPress={onClose} />
      </SafeAreaView>
    </Modal>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.navy, padding: 20, gap: 16 },
  title: { color: '#fff', fontSize: 20, fontWeight: '700', textAlign: 'center' },
  permission: { marginTop: 40 },
  cameraWrap: { flex: 1, borderRadius: 20, overflow: 'hidden', alignItems: 'center', justifyContent: 'center' },
  frame: { width: 240, height: 240, borderWidth: 3, borderColor: '#fff', borderRadius: 20 },
});
