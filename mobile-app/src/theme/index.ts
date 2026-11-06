import { Platform, StyleSheet } from 'react-native';

export const colors = {
  navy: '#0b2545',
  primary: '#134074',
  primaryDark: '#13315c',
  accent: '#8da9c4',
  bg: '#f4f6fa',
  card: '#ffffff',
  text: '#13315c',
  muted: '#5c6b80',
  border: '#d9e0ea',
  danger: '#b42318',
  dangerBg: '#fdecea',
  success: '#1e7a46',
  successBg: '#e7f6ee',
  warning: '#b54708',
  warningBg: '#fef4e6',
} as const;

export const mono = Platform.select({ ios: 'Menlo', android: 'monospace', default: 'monospace' });

export const ui = StyleSheet.create({
  screen: { flex: 1, backgroundColor: colors.bg },
  content: { padding: 20, gap: 16 },
  card: {
    backgroundColor: colors.card,
    borderRadius: 16,
    padding: 18,
    gap: 10,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
  },
  title: { fontSize: 22, fontWeight: '700', color: colors.text },
  subtitle: { fontSize: 15, fontWeight: '600', color: colors.text },
  body: { fontSize: 14, color: colors.muted, lineHeight: 20 },
  small: { fontSize: 12, color: colors.muted },
  monoSmall: { fontFamily: mono, fontSize: 12, color: colors.muted },
});
