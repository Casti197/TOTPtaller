export interface ApiErrorBody {
  error?: string;
  error_description?: string;
  [key: string]: unknown;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: ApiErrorBody,
  ) {
    super(body.error_description ?? body.error ?? `HTTP ${status}`);
    this.name = 'ApiError';
  }
}

/** Sesión irrecuperable: el refresh_token venció o fue revocado. */
export class SessionExpiredError extends Error {
  constructor() {
    super('Tu sesión expiró. Inicia sesión de nuevo.');
    this.name = 'SessionExpiredError';
  }
}

export class NetworkError extends Error {
  constructor(cause: unknown) {
    super('No se pudo contactar al servidor. ¿Estás en la misma red Wi-Fi y el backend está corriendo?');
    this.name = 'NetworkError';
    this.cause = cause;
  }
}

export async function readJson<T>(res: Response): Promise<T> {
  const text = await res.text();
  try {
    return (text ? JSON.parse(text) : {}) as T;
  } catch {
    return { error: 'invalid_response', error_description: text.slice(0, 200) } as T;
  }
}
