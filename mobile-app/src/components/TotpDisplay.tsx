import { Animated, StyleSheet, Text, View } from 'react-native';
import { colors, mono } from '../theme';
import { formatCode } from '../crypto/totp';
import { useTotp } from '../totp/useTotp';

interface Props {
  secret: string;
  compact?: boolean;
}

/** Código de 6 dígitos (monoespaciado grande) + barra de progreso 30 → 0 s. */
export function TotpDisplay({ secret, compact = false }: Props) {
  const { code, nextCode, secondsLeft, progress } = useTotp(secret);
  const urgent = secondsLeft <= 5;
  const width = progress.interpolate({ inputRange: [0, 1], outputRange: ['0%', '100%'] });

  return (
    <View style={styles.wrap}>
      <Text
        style={[styles.code, compact && styles.codeCompact, urgent && styles.codeUrgent]}
        accessibilityLabel={code ? `Código ${code.split('').join(' ')}` : 'Sin código'}
        selectable
      >
        {code ? formatCode(code) : '--- ---'}
      </Text>
      <View style={styles.track} accessibilityRole="progressbar" accessibilityValue={{ min: 0, max: 30, now: secondsLeft }}>
        <Animated.View style={[styles.bar, { width }, urgent && styles.barUrgent]} />
      </View>
      <View style={styles.row}>
        <Text style={[styles.seconds, urgent && styles.secondsUrgent]}>{secondsLeft}s</Text>
        {!compact && nextCode ? <Text style={styles.next}>Siguiente: {formatCode(nextCode)}</Text> : null}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { gap: 10 },
  code: {
    fontFamily: mono,
    fontSize: 52,
    fontWeight: '700',
    letterSpacing: 4,
    color: colors.primary,
    textAlign: 'center',
    fontVariant: ['tabular-nums'],
  },
  codeCompact: { fontSize: 34 },
  codeUrgent: { color: colors.danger },
  track: { height: 8, borderRadius: 4, backgroundColor: '#e3e9f2', overflow: 'hidden' },
  bar: { height: '100%', backgroundColor: colors.primary, borderRadius: 4 },
  barUrgent: { backgroundColor: colors.danger },
  row: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  seconds: { fontFamily: mono, fontSize: 14, color: colors.muted, fontVariant: ['tabular-nums'] },
  secondsUrgent: { color: colors.danger, fontWeight: '700' },
  next: { fontFamily: mono, fontSize: 13, color: colors.muted },
});
