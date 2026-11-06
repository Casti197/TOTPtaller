import { Router, type Response } from 'express';
import { config } from '../config.js';
import { sign, ttlOf } from '../jwt.js';
import { requireAuth, type AuthedRequest } from '../auth.js';

export const apiRouter = Router();

apiRouter.get('/api/perfil', requireAuth, (req: AuthedRequest, res: Response) => {
  const u = config.demoUser;
  res.json({
    id: u.id,
    email: u.email,
    name: u.name,
    mfa_verified: req.claims!.mfa_verified,
    token_exp: req.claims!.exp,
    served_at: new Date().toISOString(),
  });
});

function vaultHandler(req: AuthedRequest, res: Response): void {
  const claims = req.claims!;
  if (claims.typ !== 'elevated' || claims.mfa_verified !== true) {
    res.status(403).json({
      error: 'mfa_required',
      error_description: 'Este recurso requiere verificación de segundo factor (TOTP)',
      step_up_token: sign(claims.sub, 'step_up'),
      step_up_expires_in: ttlOf('step_up'),
    });
    return;
  }
  res.json({
    titular: config.demoUser.name,
    cuenta: 'UNISABANA-****-4821',
    saldo: 'COP 12.480.000',
    notas_confidenciales: [
      'Calificación final Desarrollo Móvil: pendiente de sustentación',
      'Llave de recuperación: 7F3K-9QPL-22XZ',
    ],
    acceso_valido_hasta: new Date(claims.exp * 1000).toISOString(),
  });
}

apiRouter.get('/api/boveda-critica', requireAuth, vaultHandler);
// Alias según el diagrama de arquitectura de la guía
apiRouter.get('/api/boveda', requireAuth, vaultHandler);
