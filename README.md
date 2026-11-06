# UniSabana Secure — OAuth 2.0 + PKCE, Almacenamiento Seguro y Step-Up 2FA (TOTP)

Laboratorio de Seguridad Móvil · Desarrollo Móvil (React Native) · Universidad de La Sabana — Sesión 14.

| Carpeta | Contenido |
| --- | --- |
| [`/mobile-app`](mobile-app) | App Expo (React Native + TypeScript estricto, Expo Router) |
| [`/backend-auth`](backend-auth) | Backend ligero Node.js + Express + TypeScript (almacenamiento en memoria) |

---

## 1. Requisitos

- Node.js 20+ (probado con Node 24) y npm.
- Un teléfono con **Expo Go** (Android o iOS) en la **misma red Wi-Fi** que el PC.
- Google Authenticator en el teléfono (prueba de paridad).

## 2. Backend (`/backend-auth`)

```bash
cd backend-auth
npm install
cp .env.example .env        # en Windows PowerShell: Copy-Item .env.example .env
npm run dev                 # escucha en 0.0.0.0:4000
```

Al arrancar imprime las IP LAN disponibles, por ejemplo:

```
backend-auth escuchando en el puerto 4000
  -> http://192.168.1.20:4000   (QR TOTP: /auth/mfa/enroll/qr)
```

Usa la IP de la interfaz Wi-Fi. En Windows se ve con `ipconfig`, en "Adaptador de LAN inalámbrica Wi-Fi".
Si el teléfono no logra conectarse, permite Node.js en el **Firewall de Windows** para redes privadas.

### Variables de entorno (`backend-auth/.env`)

| Variable | Por defecto | Descripción |
| --- | --- | --- |
| `PORT` | `4000` | Puerto HTTP |
| `JWT_SECRET` | — | Secreto HS256 para firmar los JWT. **Cámbialo** |
| `DEMO_EMAIL` / `DEMO_PASSWORD` | `estudiante@unisabana.edu.co` / `Sabana2026!` | Usuario demo |
| `DEMO_TOTP_SECRET` | `JBSWY3DPEHPK3PXP` | Semilla TOTP Base32 del usuario demo |
| `ACCESS_TTL_SECONDS` | `300` | Vida del `access_token` (5 min). Bájala (p. ej. `20`) para ver el Silent Refresh en vivo |

### Pruebas del backend

```bash
npm test          # vectores RFC 6238 / RFC 4226 + ventanas C-1, C, C+1
npm run e2e       # (con el servidor corriendo) recorre el flujo completo: PKCE → token → refresh → 403 → MFA → 409 replay → bóveda
```

## 3. App móvil (`/mobile-app`)

```bash
cd mobile-app
npm install
cp .env.example .env        # edita EXPO_PUBLIC_API_URL=http://<IP-LAN-DEL-PC>:4000
npx expo start --clear
```

Escanea el QR de Metro con Expo Go (Android) o con la cámara (iOS).

> Cada vez que cambies `.env` reinicia con `npx expo start --clear`: las variables `EXPO_PUBLIC_*` se incrustan al empaquetar.

Calidad de código:

```bash
npm test          # SHA-1/HMAC/TOTP propios vs. vectores RFC y node:crypto + cola de Silent Refresh
npm run typecheck # TypeScript estricto
npm run lint
```

### Deep link / redirect_uri

- **Build propia** (`npx expo run:android` o EAS): esquema propio `unisabana-auth://oauth/callback`, configurado en `app.json` → `"scheme": "unisabana-auth"`.
- **Expo Go**: Expo Go no puede registrar esquemas propios, así que `Linking.createURL('oauth/callback')` produce `exp://<IP>:8081/--/oauth/callback`.
  El backend acepta únicamente los esquemas `unisabana-auth:` y `exp:` como `redirect_uri`. La pantalla de bienvenida muestra el valor exacto en uso.

---

## 4. Arquitectura

```
 App (cliente público, SIN client_secret)        Navegador del sistema           backend-auth
 ─────────────────────────────────────────        ─────────────────────           ────────────
 1. code_verifier (64 chars, CSPRNG)
    code_challenge = B64URL(SHA256(verifier))
    state = 128 bits aleatorios
 2. openAuthSessionAsync ───────────────────────▶ GET /oauth/authorize ─────────▶ formulario de login
                                                  POST credenciales ────────────▶ guarda {challenge, redirect_uri}
    ◀── deep link ?code&state ◀──────────────────  302 redirect_uri ◀───────────  code (60 s, un solo uso)
 3. state == state guardado? (si no → abortar)
 4. POST /auth/oauth/token {code, code_verifier} ───────────────────────────────▶ B64URL(SHA256(verifier)) == challenge?
    ◀──────────── access_token (5 min) + refresh_token (30 días) ◀─────────────
       access_token  → RAM (variable de módulo)
       refresh_token → SecureStore (Keychain / Keystore)

 5. GET /api/boveda-critica (access_token) ─────────────────────────────────────▶ 403 mfa_required + step_up_token
 6. TOTP local = HOTP(K, floor(t/30))  ← HMAC-SHA1 propio, sin red
    POST /auth/mfa/verify {step_up_token, code} ────────────────────────────────▶ ventanas C-1, C, C+1
                                                                                  caché anti-replay (90 s) → 409
    ◀──────────── elevated_token (mfa_verified: true, 10 min) ◀────────────────
 7. GET /api/boveda-critica (elevated_token) ───────────────────────────────────▶ 200 datos sensibles
```

### Mapa del código

| Requisito | Archivo |
| --- | --- |
| PKCE (verifier, challenge S256, state) | `mobile-app/src/crypto/pkce.ts` |
| Navegador seguro + validación de `state` + token exchange | `mobile-app/src/auth/oauth.ts` |
| Verificación PKCE, code de un solo uso, rotación de refresh | `backend-auth/src/routes/oauth.ts` |
| SecureStore (Keychain/Keystore) | `mobile-app/src/auth/secureStorage.ts` |
| access_token en RAM + **Silent Refresh Queue** | `mobile-app/src/api/session.ts` |
| SHA-1 y HMAC-SHA1 desde cero | `mobile-app/src/crypto/sha1.ts`, `hmac.ts` |
| TOTP RFC 6238 (contador Big-Endian, truncamiento dinámico) | `mobile-app/src/crypto/totp.ts` |
| Base32 y parser `otpauth://` | `mobile-app/src/crypto/base32.ts`, `otpauth.ts` |
| UI del Authenticator (temporizador 30→0, QR, ingreso manual) | `mobile-app/src/screens/AuthenticatorScreen.tsx`, `components/TotpDisplay.tsx` |
| Step-Up (403 → modal 2FA → elevated_token) | `mobile-app/src/api/vault.ts`, `screens/VaultScreen.tsx`, `components/MfaModal.tsx` |
| Bóveda, ventanas de reloj, anti-replay 409 | `backend-auth/src/routes/api.ts`, `routes/mfa.ts`, `store.ts` |

### Decisiones de seguridad

- **Sin librerías TOTP de alto nivel.** Tampoco se usó HMAC nativo: `expo-crypto` no lo expone, así que SHA-1 y HMAC-SHA1 están escritos en TypeScript puro y probados byte a byte contra `node:crypto`. `expo-crypto` se usa solo para el CSPRNG y el SHA-256 de PKCE.
- **Sin WebView.** El login ocurre en `ASWebAuthenticationSession` (iOS) o Chrome Custom Tabs (Android) mediante `WebBrowser.openAuthSessionAsync`. La app nunca ve la contraseña.
- **Sin `client_secret`.** La app es un cliente público: solo envía `client_id`. PKCE reemplaza al secreto.
- **El `state` se valida antes del intercambio.** Si no coincide, el intercambio se aborta (anti-CSRF).
- **El `authorization_code` es de un solo uso**, expira en 60 s y queda ligado a `redirect_uri`, `client_id` y `code_challenge`.
- **Rotación de `refresh_token`.** Cada renovación invalida el token anterior.
- **La semilla TOTP vive en SecureStore**, nunca en AsyncStorage.
- **La comparación TOTP es en tiempo constante** (`timingSafeEqual`) y no corta el bucle de ventanas.
- **TTL anti-replay de 90 s**, que cubre exactamente las tres ventanas aceptadas (C-1, C, C+1).
- **Alcance de la PoC.** Se usa HTTP en LAN para la demo. En producción: HTTPS, Universal Links / App Links para la redirección, almacenamiento persistente con hash de los refresh tokens, y limitación de intentos en `/auth/mfa/verify`.

---

## 5. Guion de sustentación (5 minutos)

**Preparación:**
1. Backend corriendo.
2. En el PC, abrir `http://<IP>:4000/auth/mfa/enroll/qr`.
3. En la app: pestaña **Authenticator** → *Escanear código QR*. En Google Authenticator: *+ → Escanear QR* con el mismo código.

| # | Prueba | Cómo demostrarla |
| --- | --- | --- |
| 1 | OAuth + PKCE con navegador del sistema | *Iniciar sesión* → se abre el navegador nativo (con barra de URL, no un WebView) → contraseña `Sabana2026!` → la app regresa por deep link a las pestañas. El `refresh_token` queda en SecureStore (Perfil → "Keychain / Keystore"). |
| 2 | Paridad con Google Authenticator | Poner los dos teléfonos o apps lado a lado: los mismos 6 dígitos y el mismo cambio de código cada 30 s. |
| 3 | Modo Avión | Activar Modo Avión → pestaña Authenticator → esperar a que la barra llegue a 0 → aparece el nuevo código. Sin red. También funciona sin sesión, desde *Abrir Authenticator (offline)*. |
| 4 | Step-Up y Bóveda | Desactivar Modo Avión → **Bóveda** → *Abrir Bóveda Crítica* → la app atrapa el `403 mfa_required` y abre el modal 2FA → *Usar código local* o escribir el código → se abre la bóveda. |
| 5 | Anti-Replay | Dentro de la bóveda → *Reenviar el mismo código* → aparece **409 Conflict · Replay Attack Detected**. También se puede *Cerrar bóveda*, abrirla de nuevo y escribir a mano el mismo código. |

**Extra (Silent Refresh Queue):** pestaña **Perfil** → *1 · Simular access_token expirado* → *2 · Lanzar 3 peticiones concurrentes*. El registro muestra tres `401`, **una sola** llamada `POST /auth/refresh` y tres reintentos `200`, sin salir de la pantalla. *Simular refresh_token revocado* limpia SecureStore y regresa a la pantalla de bienvenida.

## 6. Endpoints

| Método | Ruta | Descripción |
| --- | --- | --- |
| GET | `/oauth/authorize` | Página de login (parámetros: `response_type=code`, `client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method=S256`) |
| POST | `/oauth/authorize` | Valida credenciales → `302 redirect_uri?code=…&state=…` |
| POST | `/auth/oauth/token` | `{grant_type, code, code_verifier, redirect_uri, client_id}` → `access_token` + `refresh_token` |
| POST | `/auth/refresh` | `{refresh_token}` → tokens nuevos (rotación) · `401` si venció o fue revocado |
| POST | `/auth/logout` | Revoca el `refresh_token` |
| GET | `/api/perfil` | Requiere `access_token` (`401` si expiró) |
| GET | `/api/boveda-critica` (alias `/api/boveda`) | `403 mfa_required` + `step_up_token` sin MFA · `200` con `elevated_token` |
| POST | `/auth/mfa/verify` | `{step_up_token, code}` → `elevated_token` · `401` código inválido · `409` replay |
| GET | `/auth/mfa/enroll`, `/auth/mfa/enroll/qr` | URI `otpauth://` y QR del usuario demo |
