// server.js — RR-SSO (Postgres + Prisma + JWT + bcrypt)

import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import { PrismaClient } from '@prisma/client';

dotenv.config();

const app = express();
const prisma = new PrismaClient();
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID;
const ALLOWED_PRICE_IDS = (process.env.ALLOWED_PRICE_IDS || STRIPE_PRICE_ID || '')
  .split(',').map(s => s.trim()).filter(Boolean);


// ----------- Basics -----------
app.use(express.json({ limit: '1mb' }));
app.use(morgan('tiny'));

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const TOKEN_TTL_SECONDS = parseInt(process.env.TOKEN_TTL_SECONDS || '604800', 10); // 7 Tage

// ----------- CORS -----------
const ALLOWED = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: function (origin, cb) {
    // curl / server-to-server hat oft kein origin -> erlauben
    if (!origin) return cb(null, true);
    if (ALLOWED.includes(origin)) return cb(null, true);
    return cb(new Error('CORS: Origin not allowed'));
  },
  credentials: false,
}));

// ----------- Helpers -----------
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: TOKEN_TTL_SECONDS,
  });
}

function auth(req, res, next) {
  const hdr = req.headers['authorization'] || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { sub, email, name, locationId, iat, exp }
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ----------- Health -----------
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// Zeigt, ob Billing serverseitig aktiv ist (Stripe Keys vorhanden)
app.get('/api/billing/enabled', (_req, res) => {
  const enabled = !!(process.env.STRIPE_SECRET_KEY && process.env.STRIPE_PRICE_ID);
  res.json({ enabled });
});


// ----------- Provision: User + (optional) Brand anlegen -----------
/**
 * POST /api/users/provision
 * Body:
 * {
 *   email, password, name, locationId?,
 *   brand?: { logo,name,street,zipcity,person,phone,mail,web,validity_days,payment_terms,cancellation_notice,agb_link }
 * }
 * Response: { ok:true, user:{...}, brand:{...|null}, token:"..." }
 */
app.post('/api/users/provision', async (req, res) => {
  try {
    const { email, password, name, locationId, brand } = req.body || {};
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'email, password, name required' });
    }

    const emailLc = String(email).toLowerCase();

    const exists = await prisma.user.findUnique({ where: { email: emailLc } });
    if (exists) return res.status(409).json({ error: 'user_already_exists' });

    const locId = (locationId && String(locationId).trim())
      ? String(locationId).trim()
      : `loc_${Math.random().toString(36).slice(2, 8)}`;

    // Optional: Brand upsert
    let savedBrand = null;
    if (brand && typeof brand === 'object') {
      const clean = {
        id: locId,
        logo: brand.logo ?? null,
        name: brand.name ?? null,
        street: brand.street ?? null,
        zipcity: brand.zipcity ?? null,
        person: brand.person ?? null,
        phone: brand.phone ?? null,
        mail: brand.mail ?? null,
        web: brand.web ?? null,
        validity_days: brand.validity_days ?? null,
        payment_terms: brand.payment_terms ?? null,
        cancellation_notice: brand.cancellation_notice ?? null,
        agb_link: brand.agb_link ?? null,
      };
      savedBrand = await prisma.brand.upsert({
        where: { id: locId },
        update: clean,
        create: clean,
      });
    }

    // Passwort sicher speichern
    const passwordHash = await bcrypt.hash(String(password), 10);

    const user = await prisma.user.create({
      data: {
        email: emailLc,
        password: passwordHash,
        name: String(name),
        locationId: locId,
      },
      select: { id: true, email: true, name: true, locationId: true },
    });

    // Brand ggf. nachladen, falls nicht mitgeliefert
    if (!savedBrand) {
      savedBrand = await prisma.brand.findUnique({ where: { id: user.locationId } });
    }

    const token = signToken({
      sub: user.id,
      email: user.email,
      name: user.name,
      locationId: user.locationId,
    });

    return res.json({ ok: true, user, brand: savedBrand || null, token });
  } catch (err) {
    console.error('provision error', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ----------- Login: bcrypt + JWT -----------
/**
 * POST /api/session/login
 * Body: { email, password }
 * Response: { token }
 */
app.post('/api/session/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password required' });
    }

    const emailLc = String(email).toLowerCase();

    const user = await prisma.user.findUnique({ where: { email: emailLc } });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(String(password), user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken({
      sub: user.id,
      email: user.email,
      name: user.name,
      locationId: user.locationId,
    });

    return res.json({ token });
  } catch (err) {
    console.error('login error', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ----------- Me: User + Brand laden -----------
/**
 * GET /api/me
 * Header: Authorization: Bearer <token>
 * Response: { user:{...}, brand:{...|null} }
 */
app.get('/api/me', auth, async (req, res) => {
  try {
    const { sub, email, name, locationId } = req.user || {};
    // Zur Sicherheit User und Brand aus DB ziehen (falls sich was geändert hat)
    const user = await prisma.user.findUnique({
      where: { id: sub },
      select: { id: true, email: true, name: true, locationId: true },
    });
    if (!user) return res.status(401).json({ error: 'user_not_found' });

    const brand = await prisma.brand.findUnique({ where: { id: user.locationId } });
    return res.json({ user, brand: brand || null });
  } catch (err) {
    console.error('me error', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ----------- Brand Sync (PATCH/MERGE): nur gesendete Felder ändern, Rest behalten -----------
/**
 * POST /api/brand/sync  (Patch-Semantik)
 * PATCH /api/brand/sync (Alias)
 * Body (Beispiele):
 *   { locationId, name: "Neu GmbH" }                    -> nur Name ändern
 *   { locationId, logo: null }                          -> Logo explizit löschen
 *   { locationId, logo: "data:image/png;base64,..." }   -> Logo setzen
 *
 * Regel:
 *   - Felder, die im Body NICHT vorkommen (=== undefined), bleiben unverändert.
 *   - Felder, die mit "null" kommen, werden auf null gesetzt (explizites Löschen).
 */
async function brandSyncHandler(req, res) {
  try {
    const body = req.body || {};
    const locationId = body.locationId && String(body.locationId).trim();
    if (!locationId) return res.status(400).json({ error: 'locationId required' });

    const allowedFields = [
      'logo','name','street','zipcity','person','phone','mail','web',
      'validity_days','payment_terms','cancellation_notice','agb_link'
    ];

    // Vorhandene Brand holen (kann null sein)
    const existing = await prisma.brand.findUnique({ where: { id: locationId } });

    // Patch bauen: nur gesendete Keys überschreiben; undefined = unverändert; null = löschen
    const patch = {};
    for (const k of allowedFields) {
      if (Object.prototype.hasOwnProperty.call(body, k)) {
        patch[k] = body[k]; // kann Wert oder null sein
      }
    }

    let saved;
    if (existing) {
      // Merge: vorhandene + Patch (nur gesendete Keys überschreiben)
      const merged = { ...existing, ...patch };
      // Prisma-update: keine id in data mitschicken
      const { id, ...data } = merged;
      saved = await prisma.brand.update({ where: { id: locationId }, data });
    } else {
      // Neu anlegen: id + Patch; nicht gesendete Keys = null
      const data = { id: locationId };
      for (const k of allowedFields) {
        data[k] = Object.prototype.hasOwnProperty.call(patch, k) ? patch[k] : null;
      }
      saved = await prisma.brand.create({ data });
    }

    return res.json({ ok: true, brand: saved });
  } catch (err) {
    console.error('brand sync error', err);
    return res.status(500).json({ error: 'internal_error' });
  }
}
app.post('/api/brand/sync', brandSyncHandler);
app.patch('/api/brand/sync', brandSyncHandler); // optional: echter PATCH


// ----------- Start -----------
app.listen(PORT, () => {
  console.log(`RR-SSO listening on :${PORT}`);
});
