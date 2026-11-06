import express from 'express';
import cors from 'cors';
import { networkInterfaces } from 'node:os';
import { config } from './config.js';
import { oauthRouter } from './routes/oauth.js';
import { apiRouter } from './routes/api.js';
import { mfaRouter } from './routes/mfa.js';

const app = express();
app.disable('x-powered-by');
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use((req, _res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});
app.use(oauthRouter);
app.use(mfaRouter);
app.use(apiRouter);

app.listen(config.port, '0.0.0.0', () => {
  const ips = Object.values(networkInterfaces())
    .flat()
    .filter((i) => i !== undefined && i.family === 'IPv4' && !i.internal)
    .map((i) => i!.address);
  console.log(`backend-auth escuchando en el puerto ${config.port}`);
  for (const ip of ips) console.log(`  -> http://${ip}:${config.port}   (QR TOTP: /auth/mfa/enroll/qr)`);
  console.log(`  access_token TTL: ${config.ttl.access}s`);
});
