import { StyleSheet, Text, View } from 'react-native';
import { colors } from '../theme';

type Tone = 'error' | 'success' | 'warning' | 'info';

const TONES: Record<Tone, { bg: string; fg: string }> = {
  error: { bg: colors.dangerBg, fg: colors.danger },
  success: { bg: colors.successBg, fg: colors.success },
  warning: { bg: colors.warningBg, fg: colors.warning },
  info: { bg: '#e8eef7', fg: colors.primaryDark },
};

export function Notice({ tone, children }: { tone: Tone; children: string }) {
  const t = TONES[tone];
  return (
    <View style={[styles.box, { backgroundColor: t.bg }]} accessibilityLiveRegion="polite">
      <Text style={[styles.text, { color: t.fg }]}>{children}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  box: { borderRadius: 10, padding: 12 },
  text: { fontSize: 14, lineHeight: 20, fontWeight: '500' },
});
