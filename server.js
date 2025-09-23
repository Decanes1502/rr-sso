// server.js — RR-SSO (Postgres + Prisma + JWT + bcrypt + Stripe Checkout)
// Läuft als ESM (package.json: { "type": "module" })

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

// z.B. https://reinigungsrechner.de/unterhaltesreinigung  (für Stripe success/cancel)
const APP_BASE_URL = (process.env.APP_BASE_URL || '').trim() || 'http://localhost:5173';

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_PRICE_ID   = (process.env.STRIPE_PRICE_ID || '').trim();
const ALLOWED_PRICE_IDS = (process.env.ALLOWED_PRICE_IDS || STRIPE_PRICE_ID || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const TRIAL_DAYS = parseInt(process.env.TRIAL_DAYS || '0', 10);
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';

const GHL_WEBHOOK_URL    = process.env.GHL_WEBHOOK_URL || '';   // optional
const GHL_WEBHOOK_SECRET = process.env.GHL_WEBHOOK_SECRET || ''; // optional

// Stripe initialisieren (nur wenn Key vorhanden)
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY, { apiVersion: '2023-10-16' }) : null;

// ======== Logging & CORS ========
app.use(morgan('tiny'));
app.use(cors({
  origin(origin, cb) {
    // curl/server-to-server hat meist keinen Origin → erlauben
    if (!origin) return cb(null, true);
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

    // === Name & Metadaten bei erfolgreichem Checkout einsammeln / speichern ===
    if (event.type === 'checkout.session.completed') {
      const sess = event.data.object; // Checkout Session

      // 1) Namen bevorzugt aus custom_fields holen (Vorname/Nachname separat)
      const cf = Array.isArray(sess.custom_fields) ? sess.custom_fields : [];
      const getCF = (key) => cf.find(f => f.key === key)?.text?.value || '';
      let firstName = getCF('first_name');
      let lastName  = getCF('last_name');

      // 2) Fallback: gesamten Namen splitten
      if (!firstName && sess?.customer_details?.name) {
        const parts = String(sess.customer_details.name).trim().split(/\s+/);
        firstName = parts.shift() || '';
        lastName  = parts.join(' ');
      }

      // rr_checkout_ref ggf. aus Session-Metadata mitnehmen
      const rrCheckoutRef = sess?.metadata?.rr_checkout_ref || '';

      // In Subscription & Customer-Metadata persistieren (damit GHL später leicht rankommt)
      try {
        if (sess.subscription && stripe) {
          await stripe.subscriptions.update(sess.subscription, {
            metadata: {
              ...(sess.metadata || {}),
              rr_first_name: firstName || '',
              rr_last_name: lastName || '',
              rr_checkout_ref: rrCheckoutRef || '',
            },
          });
        }
        if (sess.customer && stripe) {
          await stripe.customers.update(sess.customer, {
            name: [firstName, lastName].filter(Boolean).join(' ') || undefined,
            metadata: {
              rr_first_name: firstName || '',
              rr_last_name: lastName || '',
              rr_checkout_ref: rrCheckoutRef || '',
            },
          });
        }
      } catch (e) {
        console.warn('[webhook] name/metadata propagate failed:', e?.message);
      }

      // Optional: an GHL weiterleiten (pass-through) – mit flachen Zusatzfeldern
      if (GHL_WEBHOOK_URL) {
        try {
          const payload = {
            source: 'rr-sso',
            eventType: event.type,
            data: sess, // Originalobjekt
            // flach dazu:
            rr_first_name: firstName || '',
            rr_last_name: lastName || '',
            rr_checkout_ref: rrCheckoutRef || '',
          };
          await fetch(GHL_WEBHOOK_URL, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              ...(GHL_WEBHOOK_SECRET ? { 'x-ghl-signature': GHL_WEBHOOK_SECRET } : {}),
            },
            body: JSON.stringify(payload),
          });
        } catch (fwdErr) {
          console.warn('[webhook] GHL forward failed:', fwdErr?.message);
        }
      }
    } else {
      // andere Events optional ebenfalls forwarden
      if (GHL_WEBHOOK_URL) {
        try {
          await fetch(GHL_WEBHOOK_URL, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              ...(GHL_WEBHOOK_SECRET ? { 'x-ghl-signature': GHL_WEBHOOK_SECRET } : {}),
            },
            body: JSON.stringify({ source: 'rr-sso', eventType: event.type, data: event.data?.object || null }),
          });
        } catch (fwdErr) {
          console.warn('[webhook] GHL forward failed:', fwdErr?.message);
        }
      }
    }

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
    const decoded = jwt.verify(token, JWT_SECRET); // { sub, email, name, locationId, iat, exp }
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

async function ensureBrandExists(locId, brandInput) {
  const clean = {
    id: String(locId),
    logo: brandInput?.logo ?? null,
    name: brandInput?.name ?? null,
    street: brandInput?.street ?? null,
    zipcity: brandInput?.zipcity ?? null,
    person: brandInput?.person ?? null,
    phone: brandInput?.phone ?? null,
    mail: brandInput?.mail ?? null,
    web: brandInput?.web ?? null,
    validity_days: brandInput?.validity_days ?? null,
    payment_terms: brandInput?.payment_terms ?? null,
    cancellation_notice: brandInput?.cancellation_notice ?? null,
    agb_link: brandInput?.agb_link ?? null,
  };
  return prisma.brand.upsert({
    where: { id: clean.id },
    update: clean,
    create: clean,
  });
}

function billingEnabled() {
  return !!(STRIPE_SECRET_KEY && ALLOWED_PRICE_IDS.length > 0);
}

// Eindeutige Checkout-Ref für GHL/Debug
function makeCheckoutRef(userId) {
  const rand = Math.random().toString(36).slice(2, 8);
  return `rr_${(userId || 'anon').toString().slice(-6)}_${rand}`;
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

    try {
      await ensureBrandExists(locId, (typeof brand === 'object') ? brand : undefined);
    } catch (err) {
      console.error('[provision] brand.ensure failed', { message: err?.message, code: err?.code, meta: err?.meta });
      return res.status(500).json({ error: 'brand_upsert_failed' });
    }

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

/**
 * POST /api/session/signup  — Alias zu /api/users/provision
 * Body: { email, password, name?, brand? }
 */
app.post('/api/session/signup', async (req, res) => {
  try {
    const { email, password, name, brand } = req.body || {};

    const displayName =
      (name && String(name).trim()) ||
      (brand && typeof brand === 'object' && brand.name && String(brand.name).trim()) ||
      (brand && typeof brand === 'string' && brand.trim()) ||
      (email ? String(email).split('@')[0] : '');

    if (!email || !password || !displayName) {
      return res.status(400).json({ error: 'email, password, name required' });
    }

    const emailLc = String(email).toLowerCase();

    const exists = await prisma.user.findUnique({ where: { email: emailLc } });
    if (exists) return res.status(409).json({ error: 'user_already_exists' });

    const locId = `loc_${Math.random().toString(36).slice(2, 8)}`;

    try {
      await ensureBrandExists(locId, (typeof brand === 'object') ? brand : undefined);
    } catch (err) {
      console.error('[signup] brand.ensure failed', { message: err?.message, code: err?.code, meta: err?.meta });
      return res.status(500).json({ error: 'brand_upsert_failed' });
    }

    const passwordHash = await bcrypt.hash(String(password), 10);

    let user;
    try {
      user = await prisma.user.create({
        data: { email: emailLc, password: passwordHash, name: String(displayName), locationId: locId },
        select: { id: true, email: true, name: true, locationId: true },
      });
    } catch (err) {
      console.error('[signup] user.create failed', { message: err?.message, code: err?.code, meta: err?.meta });
      if (err?.code === 'P2002') return res.status(409).json({ error: 'user_already_exists' });
      return res.status(400).json({ error: 'user_create_failed' });
    }

    let savedBrand = null;
    try { savedBrand = await prisma.brand.findUnique({ where: { id: user.locationId } }); } catch {}

    const token = signToken({ sub: user.id, email: user.email, name: user.name, locationId: user.locationId });

    return res.json({ ok: true, user, brand: savedBrand || null, token });
  } catch (err) {
    console.error('[signup] fatal', { message: err?.message, code: err?.code, meta: err?.meta, stack: err?.stack });
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
      const { id, ...data } = merged; // id nicht updaten
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

// ======== Billing: Checkout (Stripe Tax aktiviert) ========
app.post('/api/billing/checkout', auth, async (req, res) => {
  try {
    if (!stripe || !billingEnabled()) {
      return res.status(400).json({ error: 'billing_disabled' });
    }

    const { price_id } = req.body || {};
    const chosenPrice = (price_id && ALLOWED_PRICE_IDS.includes(price_id))
      ? price_id
      : (STRIPE_PRICE_ID || ALLOWED_PRICE_IDS[0]);
    if (!chosenPrice) {
      return res.status(400).json({ error: 'no_price_configured' });
    }

    const success = `${APP_BASE_URL}?checkout=success`;
    const cancel  = `${APP_BASE_URL}?checkout=cancel`;

    const subscription_data = {
      metadata: {
        rr_user_id: req.user.sub,
        rr_location_id: req.user.locationId,
        rr_email: req.user.email,
      },
      ...(TRIAL_DAYS > 0 ? { trial_period_days: TRIAL_DAYS } : {}),
    };

    // Eindeutige Referenz, die wir später im Webhook wiedersehen
    const rr_ref = makeCheckoutRef(req.user.sub);

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_email: req.user.email,
      line_items: [{ price: chosenPrice, quantity: 1 }],
      allow_promotion_codes: true,
      client_reference_id: req.user.sub,
      success_url: success,
      cancel_url: cancel,

      // sorgt dafür, dass ein Stripe-Customer persistiert wird (mit Name etc.)
      customer_creation: 'always',

      // Steuer + Adress-/USt-ID-Abfrage
      automatic_tax: { enabled: true },
      billing_address_collection: 'required',
      tax_id_collection: { enabled: true },

      subscription_data,

      // Eigene Metadaten für Zuordnung in GHL/Workflows
      metadata: {
        rr_user_id: req.user.sub,
        rr_location_id: req.user.locationId,
        rr_email: req.user.email,
        rr_checkout_ref: rr_ref,
        rr_price_id: chosenPrice,
      },

      // >>> NEU: Eigene Felder im Checkout (Variante A+B gleichzeitig)
      custom_fields: [
        {
          key: 'first_name',
          label: { type: 'custom', custom: 'Vorname' },
          type: 'text',
          optional: false,
        },
        {
          key: 'last_name',
          label: { type: 'custom', custom: 'Nachname' },
          type: 'text',
          optional: true,
        },
      ],
    });

    return res.json({ url: session.url });
  } catch (err) {
    console.error('checkout error:', {
      message: err?.message,
      rawMessage: err?.raw?.message,
      rawParam: err?.raw?.param,
      statusCode: err?.statusCode
    });
    return res.status(500).json({ error: 'internal_error' });
  }
});

/**
 * GET /api/subscription/status
 * Defensiv: immer 200 + JSON. Prüft zuerst per rr_user_id (metadata), dann per E-Mail.
 */
app.get('/api/subscription/status', async (req, res) => {
  try {
    const ok = (obj) => res.status(200).json(obj);

    // Token lesen
    const hdr = req.headers['authorization'] || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : '';
    if (!token) return ok({ status: 'none', reason: 'missing_token' });

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch {
      return ok({ status: 'none', reason: 'invalid_token' });
    }

    // Stripe konfiguriert?
    if (!stripe || ALLOWED_PRICE_IDS.length === 0) {
      return ok({ status: 'none', reason: 'not_configured' });
    }

    const allowed = new Set(ALLOWED_PRICE_IDS);

    // 1) Primär: per rr_user_id in Subscription-Metadata (Search API)
    try {
      const q = `metadata['rr_user_id']:"${payload.sub}" AND (status:"active" OR status:"trialing")`;
      const found = await stripe.subscriptions.search({ query: q, limit: 5, expand: ['data.items'] });
      for (const s of (found?.data || [])) {
        const match = (s.items?.data || []).some(it => it.price && allowed.has(it.price.id));
        if (match) return ok({ status: s.status });
      }
    } catch {
      // weiter mit E-Mail-Fallback
    }

    // 2) Fallback: per E-Mail
    const email = String(payload.email || '').toLowerCase();
    if (!email) return ok({ status: 'none', reason: 'token_without_email' });

    let customers = [];
    try {
      const list = await stripe.customers.list({ email, limit: 10 });
      customers = list?.data || [];
    } catch {
      return ok({ status: 'none', reason: 'stripe_customers_error' });
    }
    if (customers.length === 0) {
      return ok({ status: 'none', reason: 'no_customer' });
    }

    const interesting = new Set([
      'active','trialing','past_due','incomplete','canceled','unpaid','incomplete_expired'
    ]);
    let fallback = null;

    for (const c of customers) {
      let subs = [];
      try {
        const list = await stripe.subscriptions.list({
          customer: c.id,
          status: 'all',
          limit: 20,
          expand: ['data.items']
        });
        subs = list?.data || [];
      } catch {
        continue;
      }

      for (const s of subs) {
        if (!interesting.has(s.status)) continue;
        const matches = (s.items?.data || []).some(it => it.price && allowed.has(it.price.id));
        if (!matches) continue;

        if (s.status === 'active' || s.status === 'trialing') {
          return ok({ status: s.status });
        }
        fallback = fallback || s.status; // z.B. past_due
      }
    }

    return ok({ status: 'none', reason: fallback ? 'non_active_subscription' : 'no_subscription' });
  } catch (err) {
    console.error('[subscription/status] fatal', err);
    // Wichtig: niemals 500
    return res.status(200).json({ status: 'none', reason: 'fatal_error' });
  }
});

// ===== Debug: Ping & Routenliste
app.get('/api/_ping', (_req, res) => {
  res.json({ ok: true, version: 'serverjs-2025-09-03-tax-enabled-namefields' });
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

// ===== Start-Log & Serverstart
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

app.listen(PORT, () => {
  console.log(`RR-SSO listening on :${PORT}`);
});
