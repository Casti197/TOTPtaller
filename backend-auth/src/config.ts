import 'dotenv/config';

function num(name: string, def: number): number {
  const v = process.env[name];
  const n = v ? Number(v) : def;
  return Number.isFinite(n) && n > 0 ? n : def;
}

export const config = {
  port: num('PORT', 4000),
  jwtSecret: process.env.JWT_SECRET ?? 'dev-only-secret-change-me',
  demoUser: {
    id: 'u-001',
    email: process.env.DEMO_EMAIL ?? 'estudiante@unisabana.edu.co',
    password: process.env.DEMO_PASSWORD ?? 'Sabana2026!',
    totpSecret: process.env.DEMO_TOTP_SECRET ?? 'JBSWY3DPEHPK3PXP',
    name: 'Estudiante UniSabana',
  },
  issuer: 'UniSabana',
  ttl: {
    access: num('ACCESS_TTL_SECONDS', 300), // 5 min
    refresh: 30 * 24 * 3600, // 30 días
    stepUp: 300, // 5 min
    elevated: 600, // 10 min
    authCode: 60, // 1 min
    loginMfa: 300, // 5 min para ingresar el TOTP tras la contraseña
    replay: 90, // 90 s
  },
} as const;
