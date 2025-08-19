import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
import bcrypt from 'bcryptjs';
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
// POST /api/users/provision
// Body: { email, password, name, locationId?, brand?: { logo, name, street, zipcity, person, phone, mail, web, validity_days, payment_terms, cancellation_notice, agb_link } }
// Antwort: { ok:true, user:{...}, brand:{...}, token:"..." }
app.post('/api/users/provision', async (req, res) => {
  try {
    const { email, password, name, locationId, brand } = req.body || {};

    // Minimal-Validierung
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'email, password, name required' });
    }

    // Existiert der User schon?
    const existing = await prisma.user.findUnique({ where: { email: String(email).toLowerCase() } });
    if (existing) {
      return res.status(409).json({ error: 'user_already_exists' });
    }

    // locationId wählen/erzeugen
    const locId = locationId && String(locationId).trim()
      ? String(locationId).trim()
      : `loc_${Math.random().toString(36).slice(2, 8)}`;

    // Brand (optional) upsert (ID = locationId)
    let savedBrand = null;
    if (brand && typeof brand === 'object') {
      const clean = {
        id: locId,
        logo:               brand.logo ?? null,
        name:               brand.name ?? null,
        street:             brand.street ?? null,
        zipcity:            brand.zipcity ?? null,
        person:             brand.person ?? null,
        phone:              brand.phone ?? null,
        mail:               brand.mail ?? null,
        web:                brand.web ?? null,
        validity_days:      brand.validity_days ?? null,
        payment_terms:      brand.payment_terms ?? null,
        cancellation_notice:brand.cancellation_notice ?? null,
        agb_link:           brand.agb_link ?? null
      };
      savedBrand = await prisma.brand.upsert({
        where: { id: locId },
        update: clean,
        create: clean
      });
    } else {
      // falls keine Brand übergeben wurde, aber es existiert schon eine, holen wir sie später nochmal
      savedBrand = await prisma.brand.findUnique({ where: { id: locId } });
    }

    // Passwort hashen (sicher!)
    const passwordHash = await bcrypt.hash(String(password), 10);

    // User anlegen
    const user = await prisma.user.create({
      data: {
        email: String(email).toLowerCase(),
        password: passwordHash,
        name: String(name),
        locationId: locId
      },
      select: { id: true, email: true, name: true, locationId: true }
    });

    // JWT bauen (nutzt deine vorhandene signToken-Funktion)
    // Falls du signToken noch nicht hast, sag Bescheid – ich gebe dir den Helper.
    const token = signToken({
      sub: user.id,
      email: user.email,
      name: user.name,
      locationId: user.locationId
    });

    // Brand ggf. nachladen (falls oben nicht angelegt)
    if (!savedBrand) {
      savedBrand = await prisma.brand.findUnique({ where: { id: user.locationId } });
    }

    return res.json({ ok: true, user, brand: savedBrand, token });
  } catch (err) {
    console.error('provision error', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});


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
