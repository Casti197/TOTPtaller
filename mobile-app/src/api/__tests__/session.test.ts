/// <reference types="node" />
import { beforeEach, describe, expect, it, vi } from 'vitest';

// Simulación del enclave seguro (expo-secure-store no existe en Node)
const vault = new Map<string, string>();
vi.mock('../../auth/secureStorage', () => ({
  secureStorage: {
    getRefreshToken: async () => vault.get('rt') ?? null,
    setRefreshToken: async (t: string) => void vault.set('rt', t),
    clearRefreshToken: async () => void vault.delete('rt'),
  },
}));
vi.mock('../../config', () => ({ API_URL: 'http://api.test', CLIENT_ID: 'unisabana-mobile', assertApiConfigured: () => {} }));

type Handler = (url: string, init: RequestInit) => Response | Promise<Response>;
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
const bearer = (init: RequestInit) => (init.headers as Record<string, string> | undefined)?.Authorization;

async function load() {
  vi.resetModules();
  return import('../session');
}

describe('Silent Refresh Queue', () => {
  beforeEach(() => {
    vault.clear();
  });

  it('3 peticiones concurrentes con 401 → UNA sola renovación y 3 reintentos', async () => {
    let refreshCalls = 0;
    let validToken = 'A1';
    const handler: Handler = async (url, init) => {
      if (url.endsWith('/auth/refresh')) {
        refreshCalls++;
        await new Promise((r) => setTimeout(r, 30)); // renovación lenta: obliga a encolar
        validToken = 'A2';
        return json(200, { access_token: 'A2', refresh_token: 'R2', expires_in: 300, token_type: 'Bearer' });
      }
      return bearer(init) === `Bearer ${validToken}` ? json(200, { ok: true }) : json(401, { error: 'invalid_token' });
    };
    vi.stubGlobal('fetch', vi.fn((u: string, i: RequestInit) => handler(u, i)));

    const s = await load();
    await s.setSession({ access_token: 'A1', refresh_token: 'R1', expires_in: 300, token_type: 'Bearer' });
    s.debugInvalidateAccessToken();

    const results = await Promise.all([1, 2, 3].map(() => s.authJson<{ ok: boolean }>('/api/perfil')));
    expect(results).toEqual([{ ok: true }, { ok: true }, { ok: true }]);
    expect(refreshCalls).toBe(1);
    expect(s.getAccessToken()).toBe('A2');
    expect(vault.get('rt')).toBe('R2'); // refresh_token rotado guardado en el enclave

    // Una petición nueva lanzada durante una renovación espera en cola en vez de salir con token viejo
    const events: string[] = [];
    s.subscribe((e) => events.push(e.kind));
    s.debugInvalidateAccessToken();
    const first = s.authJson('/api/perfil');
    await new Promise((r) => setTimeout(r, 5));
    const second = s.authJson('/api/perfil');
    await Promise.all([first, second]);
    expect(refreshCalls).toBe(2);
    expect(events).toContain('queued');
  });

  it('refresh_token revocado → limpia el enclave, emite logged_out y lanza SessionExpiredError', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => (url.endsWith('/auth/refresh') ? json(401, { error: 'invalid_grant' }) : json(401, {}))),
    );
    const s = await load();
    const { SessionExpiredError } = await import('../errors');
    await s.setSession({ access_token: 'A1', refresh_token: 'R1', expires_in: 300, token_type: 'Bearer' });
    const events: string[] = [];
    s.subscribe((e) => events.push(e.kind));

    await expect(s.authJson('/api/perfil')).rejects.toBeInstanceOf(SessionExpiredError);
    expect(vault.has('rt')).toBe(false);
    expect(s.getAccessToken()).toBeNull();
    expect(events).toContain('logged_out');
  });

  it('sin access_token en RAM (app recién abierta) → renueva antes de llamar', async () => {
    vault.set('rt', 'R1');
    const calls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init: RequestInit) => {
        calls.push(url.replace('http://api.test', ''));
        if (url.endsWith('/auth/refresh')) return json(200, { access_token: 'A9', refresh_token: 'R9', expires_in: 300, token_type: 'Bearer' });
        return bearer(init) === 'Bearer A9' ? json(200, { ok: true }) : json(401, {});
      }),
    );
    const s = await load();
    await expect(s.authJson('/api/perfil')).resolves.toEqual({ ok: true });
    expect(calls).toEqual(['/auth/refresh', '/api/perfil']);
  });
});
