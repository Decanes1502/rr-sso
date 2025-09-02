// server.js — RR-SSO (Postgres + Prisma + JWT + bcrypt + Stripe Checkout)
// Kopierfähige Komplettversion, ESM (package.json: { "type": "module" })

import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import { PrismaClient } from '@prisma/client';
import Stripe from 'stripe';

dotenv.config();

const app = express();
const prisma = new PrismaClient();

// ======== ENV / Konfiguration ========
const PORT = process.env.PORT || 8080;

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const TOKEN_TTL_SECONDS = parseInt(process.env.TOKEN_TTL_SECONDS || '604800', 10); // 7 Tage

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const APP_BASE_URL = (process.env.APP_BASE_URL || '').trim() // z.B. https://reinigungsrechner.de/unterhaltesreinigung
  || 'http://localhost:5173';

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_PRICE_ID = (process.env.STRIPE_PRICE_ID || '').trim();
const ALLOWED_PRICE_IDS = (process.env.ALLOWED_PRICE_IDS || STRIPE_PRICE_ID || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const TRIAL_DAYS = parseInt(process.env.TRIAL_DAYS || '0', 10);

const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';

const GHL_WEBHOOK_URL = process.env.GHL_WEBHOOK_URL || '';          // optional
const GHL_WEBHOOK_SECRET = process.env.GHL_WEBHOOK_SECRET || '';    // optional (x-ghl-signature Header)

// Stripe initialisieren (optional)
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY, { apiVersion: '2023-10-16' }) : null;

// ======== Logging & CORS ========
app.use(morgan('tiny'));
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);                // z.B. curl / server-to-server
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('CORS: Origin not allowed'));
  },
  credentials: false,
}));

// ============================================================
// 1) STRIPE WEBHOOK — muss VOR express.json registriert werden
// ============================================================
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    console.log('[webhook] Stripe/WebhookSecret fehlt – noop');
    return res.status(200).send('[ok]');
  }
  const sig = req.headers['stripe-signature'];
  try {
    const event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    console.log('[webhook] type=', event.type);

    // Optional: an GHL weiterleiten (JSON passthrough)
    if (GHL_WEBHOOK_URL) {
      try {
        await fetch(GHL_WEBHOOK_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(GHL_WEBHOOK_SECRET ? { 'x-ghl-signature': GHL_WEBHOOK_SECRET } : {}),
          },
          body: JSON.stringify({
            source: 'rr-sso',
            eventType: event.type,
            data: event.data?.object || null
          }),
        });
      } catch (fwdErr) {
        console.warn('[webhook] GHL forward failed:', fwdErr?.message);
      }
    }

    // Du KANNST hier noch DB-Flags setzen, E-Mails auslösen, etc.
    // Wir brauchen es für den Live-Status nicht zwingend, weil /status direkt bei Stripe prüft.

    return res.status(200).send('[ok]');
  } catch (err) {
    console.error('[webhook] verify failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
});

// ============================================================
// 2) Alle anderen JSON-Routen
// ============================================================
app.use(express.json({ limit: '2mb' }));

// ======== Helpers ========
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256', expiresIn: TOKEN_TTL_SECONDS });
}

function auth(req, res, next) {
  const hdr = req.headers['authorization'] || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);     // { sub, email, name, locationId, iat, exp }
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function billingEnabled() {
  return !!(STRIPE_SECRET_KEY && ALLOWED_PRICE_IDS.length > 0);
}

// ======== Health & Billing Flag ========
app.get('/api/health', (_req, res) => res.json({ ok: true }));

app.get('/api/billing/enabled', (_req, res) => {
  res.json({ enabled: billingEnabled() });
});

// ======== Signup / Provision ========
/**
 * POST /api/users/provision
 * Body: { email, password, name, locationId?, brand?: {...} }
 * Returns: { ok:true, user:{...}, brand:{...|null}, token }
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
      await prisma.brand.upsert({
        where: { id: locId },
        update: clean,
        create: clean,
      });
    }

    // Passwort sichern
    const passwordHash = await bcrypt.hash(String(password), 10);

    const user = await prisma.user.create({
      data: { email: emailLc, password: passwordHash, name: String(name), locationId: locId },
      select: { id: true, email: true, name: true, locationId: true },
    });

    const savedBrand = await prisma.brand.findUnique({ where: { id: user.locationId } });

    const token = signToken({ sub: user.id, email: user.email, name: user.name, locationId: user.locationId });
    return res.json({ ok: true, user, brand: savedBrand || null, token });
  } catch (err) {
    console.error('provision error', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ======== Login ========
/**
 * POST /api/session/login
 * Body: { email, password }
 * Returns: { token }
 */
app.post('/api/session/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const emailLc = String(email).toLowerCase();
    const user = await prisma.user.findUnique({ where: { email: emailLc } });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(String(password), user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken({ sub: user.id, email: user.email, name: user.name, locationId: user.locationId });
    return res.json({ token });
  } catch (err) {
    console.error('login error', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// ======== Me ========
/**
 * GET /api/me  (Authorization: Bearer <token>)
 * Returns: { user, brand }
 */
app.get('/api/me', auth, async (req, res) => {
  try {
    const { sub } = req.user || {};
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

// ======== Brand Sync (PATCH/MERGE) ========
/**
 * POST /api/brand/sync  (Patch-Semantik)
 * PATCH /api/brand/sync
 * Body: { locationId, [logo,name,street,zipcity,person,phone,mail,web,validity_days,payment_terms,cancellation_notice,agb_link] }
 * Regeln:
 *   - Felder, die fehlen (undefined), bleiben unverändert
 *   - Felder, die explizit null sind, werden auf null gesetzt (löschen)
 */
async function brandSyncHandler(req, res) {
  try {
    const body = req.body || {};
    const locationId = body.locationId && String(body.locationId).trim();
    if (!locationId) return res.status(400).json({ error: 'locationId required' });

    const allowed = [
      'logo','name','street','zipcity','person','phone','mail','web',
      'validity_days','payment_terms','cancellation_notice','agb_link'
    ];

    const existing = await prisma.brand.findUnique({ where: { id: locationId } });

    const patch = {};
    for (const k of allowed) {
      if (Object.prototype.hasOwnProperty.call(body, k)) {
        patch[k] = body[k]; // kann Wert oder null sein
      }
    }

    let saved;
    if (existing) {
      const merged = { ...existing, ...patch };
      const { id, ...data } = merged;            // id nicht updaten
      saved = await prisma.brand.update({ where: { id: locationId }, data });
    } else {
      const data = { id: locationId };
      for (const k of allowed) data[k] = Object.prototype.hasOwnProperty.call(patch, k) ? patch[k] : null;
      saved = await prisma.brand.create({ data });
    }

    return res.json({ ok: true, brand: saved });
  } catch (err) {
    console.error('brand sync error', err);
    return res.status(500).json({ error: 'internal_error' });
  }
}
app.post('/api/brand/sync', brandSyncHandler);
app.patch('/api/brand/sync', brandSyncHandler);

// ======== Billing: Checkout & Status ========

/**
 * POST /api/billing/checkout  (Authorization: Bearer <token>)
 * Starts Stripe Checkout (Subscription). Returns: { url }
 */
app.post('/api/billing/checkout', auth, async (req, res) => {
  try {
    if (!stripe || !billingEnabled()) return res.status(400).json({ error: 'billing_disabled' });

    const { price_id } = req.body || {};
    const chosenPrice = (price_id && ALLOWED_PRICE_IDS.includes(price_id))
      ? price_id
      : (STRIPE_PRICE_ID || ALLOWED_PRICE_IDS[0]);

    if (!chosenPrice) return res.status(400).json({ error: 'no_price_configured' });

    const success = `${APP_BASE_URL}?checkout=success`;
    const cancel  = `${APP_BASE_URL}?checkout=cancel`;

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      allow_promotion_codes: true,
      customer_email: req.user.email,
      client_reference_id: req.user.sub,
      line_items: [{ price: chosenPrice, quantity: 1 }],
      success_url: success,
      cancel_url: cancel,
      subscription_data: TRIAL_DAYS > 0 ? { trial_period_days: TRIAL_DAYS } : undefined,
      metadata: {
        rr_user_id: req.user.sub,
        rr_location_id: req.user.locationId,
        rr_email: req.user.email,
      },
    });

    return res.json({ url: session.url });
  } catch (err) {
    console.error('checkout error', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

/**
 * GET /api/subscription/status  (Authorization: Bearer <token>)
 * Returns: { status: 'active'|'trialing'|'past_due'|'incomplete'|'canceled'|'none' }
 * Logik: Sucht Stripe-Customer(s) via E-Mail und prüft Subscriptions auf zugelassene Preise.
 */
app.get('/api/subscription/status', auth, async (req, res) => {
  try {
    if (!stripe || !billingEnabled()) return res.json({ status: 'none' });

    const email = (req.user?.email || '').toLowerCase();
    if (!email) return res.json({ status: 'none' });

    // 1) Customer(s) nach E-Mail suchen
    const customers = await stripe.customers.list({ email, limit: 10 });
    if (!customers?.data?.length) return res.json({ status: 'none' });

    // 2) Für alle Customers Subscriptions prüfen
    const allowed = new Set(ALLOWED_PRICE_IDS);
    const interestingStatuses = ['active', 'trialing', 'past_due', 'incomplete', 'canceled', 'unpaid', 'incomplete_expired'];

    for (const c of customers.data) {
      const subs = await stripe.subscriptions.list({ customer: c.id, status: 'all', limit: 20, expand: ['data.items'] });
      for (const s of subs.data) {
        if (!interestingStatuses.includes(s.status)) continue;
        const hasAllowedPrice = (s.items?.data || []).some(it => it.price && allowed.has(it.price.id));
        if (!hasAllowedPrice) continue;

        // Priorität: active/trialing > past_due/incomplete > canceled/none
        if (s.status === 'active' || s.status === 'trialing') {
          return res.json({ status: s.status });
        }
        // ansonsten merken, falls nichts Besseres kommt
        var fallback = s.status; // eslint-disable-line no-var
      }
    }

    return res.json({ status: fallback || 'none' });
  } catch (err) {
    console.error('status error', err);
    return res.status(500).json({ status: 'none', error: 'internal_error' });
  }
});

// ======== Start ========
console.log('RR-SSO boot:', {
  port: PORT,
  appBaseUrl: APP_BASE_URL,
  billingEnabled: billingEnabled(),
  hasStripeSecret: !!STRIPE_SECRET_KEY,
  allowedPriceIds: ALLOWED_PRICE_IDS,
  trialDays: TRIAL_DAYS,
  hasWebhookSecret: !!STRIPE_WEBHOOK_SECRET,
  allowedOrigins: ALLOWED_ORIGINS,
});

// ===== Debug: Version + alle registrierten Routen (nur fürs Troubleshooting)
app.get('/api/_ping', (_req, res) => {
  res.json({ ok: true, version: 'serverjs-2025-09-02-18h' });
});

function listRoutes() {
  const routes = [];
  (app._router?.stack || []).forEach((m) => {
    if (m.route && m.route.path) {
      const methods = Object.keys(m.route.methods || {}).map(x => x.toUpperCase()).join(',');
      routes.push(`${methods} ${m.route.path}`);
    } else if (m.name === 'router' && m.handle?.stack) {
      m.handle.stack.forEach((h) => {
        const p = h.route && h.route.path;
        const mth = h.route && Object.keys(h.route.methods || {}).map(x => x.toUpperCase()).join(',');
        if (p && mth) routes.push(`${mth} ${p}`);
      });
    }
  });
  return routes.sort();
}
app.get('/api/_routes', (_req, res) => res.json({ routes: listRoutes() }));
app.get('/api/subscription/status', async (req, res) => {
  try {
    const hdr = req.headers['authorization'] || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : '';
    if (!token) return res.status(401).json({ error: 'Missing token' });

    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
    } catch {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    const secret = process.env.STRIPE_SECRET_KEY || '';
    const allowedIds = (process.env.ALLOWED_PRICE_IDS || process.env.STRIPE_PRICE_ID || '')
      .split(',').map(s => s.trim()).filter(Boolean);
    if (!secret || allowedIds.length === 0) return res.json({ status: 'none' });

    const stripe = new Stripe(secret, { apiVersion: '2023-10-16' });

    const email = (payload.email || '').toLowerCase();
    if (!email) return res.json({ status: 'none' });

    const customers = await stripe.customers.list({ email, limit: 10 });
    if (!customers?.data?.length) return res.json({ status: 'none' });

    const allowed = new Set(allowedIds);
    const interesting = new Set(['active','trialing','past_due','incomplete','canceled','unpaid','incomplete_expired']);
    let fallback = null;

    for (const c of customers.data) {
      const subs = await stripe.subscriptions.list({
        customer: c.id, status: 'all', limit: 20, expand: ['data.items']
      });
      for (const s of subs.data) {
        if (!interesting.has(s.status)) continue;
        const okPrice = (s.items?.data || []).some(it => it.price && allowed.has(it.price.id));
        if (!okPrice) continue;

        if (s.status === 'active' || s.status === 'trialing') return res.json({ status: s.status });
        fallback = fallback || s.status;
      }
    }
    return res.json({ status: fallback || 'none' });
  } catch (err) {
    console.error('[status] error', err);
    return res.status(500).json({ status: 'none', error: 'internal_error' });
  }
});

app.listen(PORT, () => {
  console.log(`RR-SSO listening on :${PORT}`);
});
