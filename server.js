import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(morgan('tiny'));

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const TOKEN_TTL_SECONDS = parseInt(process.env.TOKEN_TTL_SECONDS || '604800', 10); // 7 Tage

// CORS: nur erlaubte Origins (Kommagetrennt in ALLOWED_ORIGINS)
const ALLOWED = (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean);
app.use(cors({
  origin: function (origin, cb) {
    if (!origin) return cb(null, true); // z.B. curl
    if (ALLOWED.includes(origin)) return cb(null, true);
    return cb(new Error('CORS: Origin not allowed'));
  },
  credentials: false,
}));

// In-Memory Stores (MVP)
const users = (() => {
  try { return JSON.parse(process.env.USERS_JSON || '[]'); } catch { return []; }
})();
const brands = (() => {
  try { return JSON.parse(process.env.BRANDS_JSON || '{}'); } catch { return {}; }
})();

function findUserByEmail(email) {
  return users.find(u => u.email.toLowerCase() === String(email).toLowerCase());
}
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256', expiresIn: TOKEN_TTL_SECONDS });
}
function auth(req, res, next) {
  const hdr = req.headers['authorization'] || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { sub, email, name, locationId }
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Health
app.get('/api/health', (_, res) => res.json({ ok: true }));

// POST /api/session/login { email, password } -> { token }
app.post('/api/session/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  const user = findUserByEmail(email);
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = signToken({ sub: user.id, email: user.email, name: user.name, locationId: user.locationId });
  return res.json({ token });
});

// GET /api/me -> { user, brand }
app.get('/api/me', auth, (req, res) => {
  const { sub, email, name, locationId } = req.user;
  const brand = brands[locationId] || null;
  return res.json({
    user: { id: sub, email, name, locationId },
    brand
  });
});

// POST /api/brand/sync -> upsert brand by locationId
app.post('/api/brand/sync', (req, res) => {
  const b = req.body || {};
  const locationId = b.locationId;
  if (!locationId) return res.status(400).json({ error: 'locationId required' });
  const allowed = [
    'logo','name','street','zipcity','person','phone','mail','web',
    'validity_days','payment_terms','cancellation_notice','agb_link'
  ];
  const clean = {};
  for (const k of allowed) if (b[k] !== undefined) clean[k] = String(b[k]);
  brands[locationId] = { ...(brands[locationId] || {}), ...clean };
  return res.json({ ok: true, brand: brands[locationId] });
});

app.listen(PORT, () => console.log(`RR-SSO listening on :${PORT}`));
