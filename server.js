// server.js — Express + sesiones, login y /inicio protegido (CSP forzada)
import express from 'express';
import path from 'path';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import compression from 'compression';
import helmet from 'helmet';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// ---------- Seguridad / básicos ----------
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false })); // no metas CSP automáticas
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ---------- CSP (forzada justo antes de enviar headers) ----------
const CSP_VALUE = [
  "default-src 'self'",
  "script-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://www.gstatic.com",
  "style-src-elem 'self' 'unsafe-inline' https://fonts.googleapis.com https://www.gstatic.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' data:",
  "connect-src 'self' https://api.weather.com https://api.open-meteo.com",
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'self'",
  "upgrade-insecure-requests"
].join('; ');

app.use((req, res, next) => {
  const originalWriteHead = res.writeHead;
  res.writeHead = function patchedWriteHead(statusCode, reasonPhrase, headers) {
    try {
      // borra cualquier CSP previa y coloca la nuestra
      res.removeHeader('Content-Security-Policy');
      res.setHeader('Content-Security-Policy', CSP_VALUE);
    } catch (_) {}
    return originalWriteHead.call(this, statusCode, reasonPhrase, headers);
  };
  next();
});

// ---------- Estáticos ----------
app.get('/inicio.html', (_req, res) => res.redirect('/inicio'));
// compatibilidad: sirve en /public/... y en /...
app.use('/public', express.static(path.join(__dirname, 'public'), { index: false }));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Evitar 404 típico por favicon
app.get('/favicon.ico', (_req, res) => res.status(204).end());

// ---------- Home ----------
app.get('/', (req, res) => {
  if (req.session?.user) return res.redirect('/inicio');
  return res.redirect('/login');
});

// ---------- Guardia global ----------
function hasSession(req) {
  return !!(req.session && req.session.user);
}
app.use((req, res, next) => {
  const protegido =
    /^\/inicio(\/|$)/i.test(req.path) ||
    (/^\/api\//i.test(req.path) && !/^\/api\/(login|salud)/i.test(req.path));
  if (protegido && !hasSession(req)) {
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'unauthorized' });
    return res.redirect('/login');
  }
  next();
});

// ---------- Helper: servir HTML quitando meta-CSP ----------
function sendHTMLWithoutMetaCSP(absPath, res) {
  try {
    let html = fs.readFileSync(absPath, 'utf8');
    html = html.replace(/<meta[^>]*http-equiv=["']Content-Security-Policy["'][^>]*>/gi, '');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(html);
  } catch (e) {
    console.error('Error leyendo vista:', absPath, e);
    return res.status(500).send('Error cargando la vista');
  }
}

// ---------- Login / Logout ----------
app.get('/login', (_req, res) => {
  const file = path.join(__dirname, 'views', 'login.html');
  return sendHTMLWithoutMetaCSP(file, res);
});

const DEMO_USER = process.env.DEMO_USER || 'prueba';
const DEMO_PASS = process.env.DEMO_PASS || '1234';

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === DEMO_USER && password === DEMO_PASS) {
    req.session.user = { username };
    return res.redirect('/inicio');
  }
  return res.status(401).send('Usuario o contraseña incorrectos');
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// ---------- Rutas protegidas ----------
app.get('/inicio', (_req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  const file = path.join(__dirname, 'views', 'inicio.html');
  return sendHTMLWithoutMetaCSP(file, res);
});

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user });
});

app.get('/api/datos', (_req, res) => {
  res.json({ ok: true, msg: 'Solo con sesión', ts: Date.now() });
});

// ---------- Healthcheck ----------
app.get('/health', (_req, res) => res.status(200).send('ok'));
app.get('/salud',  (_req, res) => res.status(200).send('ok'));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';
app.listen(PORT, HOST, () => {
  console.log(`✅ Servidor escuchando en http://${HOST}:${PORT}`);
  console.log(`   DEMO_USER=${DEMO_USER} DEMO_PASS=${DEMO_PASS}`);
});
