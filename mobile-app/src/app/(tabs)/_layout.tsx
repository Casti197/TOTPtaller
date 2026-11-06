import { Text } from 'react-native';
import { Tabs } from 'expo-router';
import { colors } from '../../theme';

function TabIcon({ glyph, focused }: { glyph: string; focused: boolean }) {
  return <Text style={{ fontSize: 20, opacity: focused ? 1 : 0.5 }}>{glyph}</Text>;
}

export default function TabsLayout() {
  return (
    <Tabs
      screenOptions={{
        headerStyle: { backgroundColor: colors.navy },
        headerTintColor: '#fff',
        tabBarActiveTintColor: colors.primary,
      }}
    >
      <Tabs.Screen
        name="authenticator"
        options={{ title: 'Authenticator', tabBarIcon: ({ focused }) => <TabIcon glyph="🔢" focused={focused} /> }}
      />
      <Tabs.Screen
        name="boveda"
        options={{
          title: 'Bóveda Crítica',
          tabBarLabel: 'Bóveda',
          tabBarIcon: ({ focused }) => <TabIcon glyph="🔒" focused={focused} />,
        }}
      />
      <Tabs.Screen
        name="perfil"
        options={{
          title: 'Perfil y sesión',
          tabBarLabel: 'Perfil',
          tabBarIcon: ({ focused }) => <TabIcon glyph="👤" focused={focused} />,
        }}
      />
    </Tabs>
  );
}
