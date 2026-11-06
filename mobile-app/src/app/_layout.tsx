import { ActivityIndicator, StyleSheet, View } from 'react-native';
import { Stack } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import * as WebBrowser from 'expo-web-browser';
import { AuthProvider, useAuth } from '../auth/AuthContext';
import { colors } from '../theme';

// Necesario en web para cerrar la ventana emergente del auth session; no-op en iOS/Android.
WebBrowser.maybeCompleteAuthSession();

function RootNavigator() {
  const { status } = useAuth();
  const signedIn = status === 'signedIn';

  return (
    <View style={styles.flex}>
      <Stack screenOptions={{ headerShown: false }}>
        <Stack.Protected guard={!signedIn}>
          <Stack.Screen name="index" />
        </Stack.Protected>
        <Stack.Protected guard={signedIn}>
          <Stack.Screen name="(tabs)" />
        </Stack.Protected>
        {/* Authenticator accesible siempre, incluso sin sesión y en Modo Avión */}
        <Stack.Screen
          name="totp"
          options={{ headerShown: true, title: 'Authenticator', headerTintColor: colors.primary }}
        />
        <Stack.Screen name="oauth/callback" />
      </Stack>
      {status === 'loading' ? (
        <View style={[StyleSheet.absoluteFill, styles.splash]}>
          <ActivityIndicator color="#fff" size="large" />
        </View>
      ) : null}
    </View>
  );
}

export default function RootLayout() {
  return (
    <AuthProvider>
      <StatusBar style="auto" />
      <RootNavigator />
    </AuthProvider>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1 },
  splash: { backgroundColor: colors.navy, alignItems: 'center', justifyContent: 'center' },
});
