require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { promisify } = require('util');
const { Pool } = require('pg');
const path = require('path');

const scrypt = promisify(crypto.scrypt);

const app = express();
const PORT = process.env.PORT || 3000;

// Render (and most hosts) sit behind a proxy; needed so req.ip is the real client IP
app.set('trust proxy', 1);
app.disable('x-powered-by');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // staff sessions last 12 hours
const MIN_PASSWORD_LEN = 8;
const LEGACY_DEFAULT_ADMIN_PASS = 'QRHR2026'; // was hard-coded in the old index.html (public)

let AUTH_SECRET = process.env.AUTH_SECRET;
if (!AUTH_SECRET || AUTH_SECRET.length < 16) {
  AUTH_SECRET = crypto.randomBytes(32).toString('hex');
  console.warn(
    '[security] AUTH_SECRET is not set (or too short). Using a random one for this run: ' +
      'staff will be logged out on every restart. Set AUTH_SECRET to a long random string.'
  );
}

// Extra browser origins allowed to call the API (comma-separated). The portal itself is
// same-origin and needs nothing here.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim().replace(/\/$/, ''))
  .filter(Boolean);
if (process.env.RENDER_EXTERNAL_URL) ALLOWED_ORIGINS.push(process.env.RENDER_EXTERNAL_URL.replace(/\/$/, ''));

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
// /health is public and harmless, so the standalone loading page (hosted on another
// origin) can call it. It is registered BEFORE the restricted CORS policy below.
app.get('/health', cors({ origin: '*', methods: ['GET'] }), (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.status(200).json({ ok: true, service: 'qr-assessment-portal' });
});

app.use(
  cors({
    origin: (origin, cb) => cb(null, !origin || ALLOWED_ORIGINS.includes(origin)),
  })
);

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
  });
  next();
});

app.use(express.json({ limit: '2mb' }));

// Serve ONLY the public/ folder (never the project root: server.js, .env, package.json...)
app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'ignore' }));

// ---------------------------------------------------------------------------
// Tiny in-memory rate limiter (no extra dependency)
// ---------------------------------------------------------------------------
function makeLimiter({ windowMs, max }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
  }, windowMs).unref();
  return {
    // returns true if this call is over the limit
    hit(key) {
      const now = Date.now();
      let e = hits.get(key);
      if (!e || e.reset <= now) e = { count: 0, reset: now + windowMs };
      e.count++;
      hits.set(key, e);
      return e.count > max;
    },
    isBlocked(key) {
      const e = hits.get(key);
      return !!e && e.reset > Date.now() && e.count > max;
    },
    clear(key) {
      hits.delete(key);
    },
  };
}
const loginFailLimiter = makeLimiter({ windowMs: 15 * 60 * 1000, max: 10 });
// Walk-in candidates often share one office IP, so keep this generous.
const publicWriteLimiter = makeLimiter({ windowMs: 60 * 1000, max: 300 });

// ---------------------------------------------------------------------------
// Database (Neon / any Postgres via DATABASE_URL)
// ---------------------------------------------------------------------------
const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        // Verify the server certificate (Neon uses publicly trusted certs).
        // Escape hatch only if your provider uses a self-signed cert:
        //   DATABASE_SSL_INSECURE=true
        ssl: { rejectUnauthorized: process.env.DATABASE_SSL_INSECURE !== 'true' },
      }
    : {
        host: process.env.PGHOST || 'localhost',
        port: process.env.PGPORT || 5432,
        user: process.env.PGUSER || 'postgres',
        password: process.env.PGPASSWORD,
        database: process.env.PGDATABASE || 'postgres',
      }
);

async function kvGet(key, shared = true) {
  const { rows } = await pool.query('SELECT value FROM kv_store WHERE store_key = $1 AND shared = $2', [key, shared]);
  return rows.length ? rows[0].value : null;
}
async function kvUpsert(key, value, shared = true) {
  await pool.query(
    `INSERT INTO kv_store (store_key, shared, value) VALUES ($1, $2, $3)
     ON CONFLICT (store_key, shared) DO UPDATE SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP`,
    [key, shared, value]
  );
}
async function kvInsertOnly(key, value, shared = true) {
  await pool.query(
    `INSERT INTO kv_store (store_key, shared, value) VALUES ($1, $2, $3)
     ON CONFLICT (store_key, shared) DO NOTHING`,
    [key, shared, value]
  );
}
const escapeLike = s => s.replace(/[\\%_]/g, c => '\\' + c);

// ---------------------------------------------------------------------------
// Passwords & credentials
// ---------------------------------------------------------------------------
const CREDS_KEY = 'app:credentials';

async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(pw, salt, 64);
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}
async function verifyPassword(pw, stored) {
  try {
    const [alg, saltHex, hashHex] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(hashHex, 'hex');
    const actual = await scrypt(pw, Buffer.from(saltHex, 'hex'), expected.length);
    return crypto.timingSafeEqual(actual, expected);
  } catch (_) {
    return false;
  }
}
// Used to keep response time similar when the login ID does not exist
let DUMMY_HASH = null;

async function loadCreds() {
  const raw = await kvGet(CREDS_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}
async function saveCreds(creds) {
  await kvUpsert(CREDS_KEY, JSON.stringify(creds));
}

// Seeds credentials on first run and upgrades the old plaintext format in place.
async function initCredentials() {
  DUMMY_HASH = await hashPassword(crypto.randomBytes(8).toString('hex'));
  let creds = await loadCreds();
  const envId = process.env.ADMIN_ID || 'admin';
  const envPass = process.env.ADMIN_PASS;

  if (!creds || !creds.admin) {
    let pass = envPass;
    if (!pass) {
      pass = crypto.randomBytes(9).toString('base64url');
      console.warn('='.repeat(70));
      console.warn(`[security] No ADMIN_PASS set. Generated first-run admin login:`);
      console.warn(`           ID: ${envId}    Password: ${pass}`);
      console.warn('           Log in and change it, or set ADMIN_PASS and redeploy.');
      console.warn('='.repeat(70));
    }
    creds = { admin: { id: envId, hash: await hashPassword(pass) }, coordinators: [] };
    await saveCreds(creds);
    console.log('Admin account created.');
    return;
  }

  let changed = false;
  if (!creds.coordinators) {
    creds.coordinators = [];
    changed = true;
  }

  // Legacy plaintext -> hashed
  if (creds.admin.pass !== undefined) {
    const wasDefault = creds.admin.pass === LEGACY_DEFAULT_ADMIN_PASS;
    if (wasDefault && envPass) {
      creds.admin.hash = await hashPassword(envPass); // replace the publicly known default
      console.log('Admin password replaced with ADMIN_PASS (old one was the public default).');
    } else {
      creds.admin.hash = await hashPassword(String(creds.admin.pass));
      if (wasDefault) {
        console.warn(
          '[security] Admin password is still the old public default. ' +
            'Log in and change it now, or set ADMIN_PASS and redeploy to replace it.'
        );
      }
    }
    delete creds.admin.pass;
    changed = true;
  }
  for (const c of creds.coordinators) {
    if (c.pass !== undefined) {
      c.hash = await hashPassword(String(c.pass));
      delete c.pass;
      changed = true;
    }
  }
  if (changed) {
    await saveCreds(creds);
    console.log('Credentials upgraded to hashed format.');
  }
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS kv_store (
      store_key VARCHAR(255) NOT NULL,
      shared BOOLEAN NOT NULL,
      value TEXT,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (store_key, shared)
    )
  `);
  await initCredentials();
  console.log('Database ready.');
}
initDb().catch(err => console.error('DB init failed:', err));

// ---------------------------------------------------------------------------
// Session tokens (stateless, HMAC-signed)
// ---------------------------------------------------------------------------
function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifyToken(token) {
  if (typeof token !== 'string') return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expected = crypto.createHmac('sha256', AUTH_SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

// Attaches req.user = { role: 'admin'|'coordinator', sub, name } or null.
// Coordinators are re-checked against the DB so "Remove access" takes effect immediately.
async function authenticate(req, res, next) {
  req.user = null;
  const m = /^Bearer (.+)$/.exec(req.get('Authorization') || '');
  if (m) {
    const p = verifyToken(m[1]);
    if (p) {
      try {
        if (p.role === 'admin') {
          req.user = { role: 'admin', sub: 'admin', name: 'Admin' };
        } else if (p.role === 'coordinator') {
          const creds = await loadCreds();
          const c = creds && creds.coordinators.find(x => x.id === p.sub);
          if (c) req.user = { role: 'coordinator', sub: c.id, name: c.name };
        }
      } catch (err) {
        console.error(err);
      }
    }
  }
  next();
}
app.use('/api', authenticate);

const requireStaff = (req, res, next) =>
  req.user ? next() : res.status(401).json({ error: 'Login required' });
const requireAdmin = (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
};

// ---------------------------------------------------------------------------
// Auth endpoints
// ---------------------------------------------------------------------------
app.post('/api/login', async (req, res) => {
  const ip = req.ip;
  if (loginFailLimiter.isBlocked(ip)) {
    return res.status(429).json({ error: 'Too many failed attempts. Try again in a few minutes.' });
  }
  try {
    const id = String((req.body && req.body.id) || '').trim();
    const pass = String((req.body && req.body.pass) || '').trim();
    const creds = await loadCreds();
    if (!creds || !id || !pass) {
      loginFailLimiter.hit(ip);
      return res.status(401).json({ error: 'Incorrect ID or password.' });
    }

    let role = null;
    let name = null;
    let sub = null;
    let hash = DUMMY_HASH;
    if (id === creds.admin.id) {
      hash = creds.admin.hash;
      role = 'admin';
      name = 'Admin';
      sub = 'admin';
    } else {
      const c = creds.coordinators.find(x => x.id === id);
      if (c) {
        hash = c.hash;
        role = 'coordinator';
        name = c.name;
        sub = c.id;
      }
    }
    const ok = await verifyPassword(pass, hash);
    if (!ok || !role) {
      loginFailLimiter.hit(ip);
      return res.status(401).json({ error: 'Incorrect ID or password.' });
    }
    loginFailLimiter.clear(ip);
    const token = signToken({ role, sub, name, exp: Date.now() + TOKEN_TTL_MS });
    res.json({ token, role, name });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin: list accounts (never returns passwords or hashes)
app.get('/api/admin/accounts', requireAdmin, async (req, res) => {
  try {
    const creds = await loadCreds();
    res.json({
      admin: { id: creds.admin.id },
      coordinators: creds.coordinators.map(c => ({ id: c.id, name: c.name })),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/coordinators', requireAdmin, async (req, res) => {
  try {
    const name = String((req.body && req.body.name) || '').trim().slice(0, 100);
    const id = String((req.body && req.body.id) || '').trim().slice(0, 64);
    const pass = String((req.body && req.body.pass) || '').trim();
    if (!name || !id || !pass) return res.status(400).json({ error: 'Enter a name, login ID, and password.' });
    if (pass.length < MIN_PASSWORD_LEN)
      return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LEN} characters.` });
    const creds = await loadCreds();
    if (id === creds.admin.id || creds.coordinators.some(c => c.id === id))
      return res.status(409).json({ error: 'That login ID is already in use — choose a unique one.' });
    creds.coordinators.push({ id, name, hash: await hashPassword(pass) });
    await saveCreds(creds);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/coordinators/:id', requireAdmin, async (req, res) => {
  try {
    const creds = await loadCreds();
    creds.coordinators = creds.coordinators.filter(c => c.id !== req.params.id);
    await saveCreds(creds);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/account', requireAdmin, async (req, res) => {
  try {
    const id = String((req.body && req.body.id) || '').trim().slice(0, 64);
    const pass = String((req.body && req.body.pass) || '').trim();
    if (!id) return res.status(400).json({ error: 'Admin ID cannot be empty.' });
    if (pass && pass.length < MIN_PASSWORD_LEN)
      return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LEN} characters.` });
    const creds = await loadCreds();
    if (creds.coordinators.some(c => c.id === id))
      return res.status(409).json({ error: 'That ID is already used by a coordinator.' });
    creds.admin.id = id;
    if (pass) creds.admin.hash = await hashPassword(pass);
    await saveCreds(creds);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------------------------------------------------------------------------
// Candidate-facing endpoints (no login, tightly scoped)
// ---------------------------------------------------------------------------
const RESULT_KEY_RE = /^result:([a-z0-9_-]{1,40}):\d{10,15}_[a-z0-9]{3,10}$/;
const PROGRESS_KEY_RE = /^progress:[a-z0-9_-]{1,40}:\d{10,15}$/;
const MAX_RESULT_BYTES = 1024 * 1024;
const MAX_PROGRESS_BYTES = 64 * 1024;

// "Has this person already taken this role's test?" without exposing anyone's results.
app.post('/api/check-attempt', async (req, res) => {
  if (publicWriteLimiter.hit(req.ip)) return res.status(429).json({ error: 'Too many requests' });
  try {
    const roleId = String((req.body && req.body.roleId) || '');
    const name = String((req.body && req.body.name) || '').trim().toLowerCase();
    if (!/^[a-z0-9_-]{1,40}$/.test(roleId) || !name) return res.json({ already: false });
    const { rows } = await pool.query(
      `SELECT value FROM kv_store WHERE shared = TRUE AND store_key LIKE $1 ESCAPE '\\'`,
      [escapeLike(`result:${roleId}:`) + '%']
    );
    let already = false;
    for (const r of rows) {
      try {
        const rec = JSON.parse(r.value);
        if (rec && typeof rec.name === 'string' && rec.name.trim().toLowerCase() === name) {
          already = true;
          break;
        }
      } catch (_) {}
    }
    res.json({ already });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// ---------------------------------------------------------------------------
// Key/value storage API
//   - staff (admin + coordinator): read results and settings
//   - admin: everything else (settings, delete, restore backups)
//   - public: may only SUBMIT a result (insert-only) or write a progress snapshot
//   - app:credentials is never reachable through this API
// ---------------------------------------------------------------------------
const isCredKey = k => k === CREDS_KEY;

app.get('/api/storage/:key', requireStaff, async (req, res) => {
  try {
    if (isCredKey(req.params.key)) return res.status(403).json({ error: 'Forbidden' });
    const shared = req.query.shared === 'true';
    const value = await kvGet(req.params.key, shared);
    if (value === null) return res.json(null);
    res.json({ key: req.params.key, value, shared });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/storage', async (req, res) => {
  try {
    const { key, value, shared } = req.body || {};
    if (typeof key !== 'string' || !key || key.length > 255) return res.status(400).json({ error: 'key required' });
    if (typeof value !== 'string') return res.status(400).json({ error: 'value must be a string' });
    if (isCredKey(key)) return res.status(403).json({ error: 'Forbidden' });
    const isShared = !!shared;

    // Admin: full write access (settings, restoring backups)
    if (req.user && req.user.role === 'admin') {
      await kvUpsert(key, value, isShared);
      return res.json({ key, value, shared: isShared });
    }
    if (req.user) return res.status(403).json({ error: 'Admin only' });

    // Public: only candidate submissions / progress snapshots
    if (publicWriteLimiter.hit(req.ip)) return res.status(429).json({ error: 'Too many requests' });
    const rm = RESULT_KEY_RE.exec(key);
    if (rm && isShared) {
      if (Buffer.byteLength(value) > MAX_RESULT_BYTES) return res.status(413).json({ error: 'Too large' });
      let rec;
      try {
        rec = JSON.parse(value);
      } catch (_) {
        return res.status(400).json({ error: 'Invalid result' });
      }
      if (!rec || typeof rec !== 'object' || typeof rec.name !== 'string' || !rec.name.trim() || rec.name.length > 200)
        return res.status(400).json({ error: 'Invalid result' });
      if (rec.roleId !== rm[1]) return res.status(400).json({ error: 'Invalid result' });
      await kvInsertOnly(key, value, true); // a submitted result can never be overwritten
      return res.json({ key, value, shared: true });
    }
    if (PROGRESS_KEY_RE.test(key) && isShared) {
      if (Buffer.byteLength(value) > MAX_PROGRESS_BYTES) return res.status(413).json({ error: 'Too large' });
      await kvUpsert(key, value, true);
      return res.json({ key, value, shared: true });
    }
    return res.status(401).json({ error: 'Login required' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/storage/:key', requireAdmin, async (req, res) => {
  try {
    if (isCredKey(req.params.key)) return res.status(403).json({ error: 'Forbidden' });
    const shared = req.query.shared === 'true';
    await pool.query('DELETE FROM kv_store WHERE store_key = $1 AND shared = $2', [req.params.key, shared]);
    res.json({ key: req.params.key, deleted: true, shared });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/storage-list', requireStaff, async (req, res) => {
  try {
    const shared = req.query.shared === 'true';
    const prefix = String(req.query.prefix || '');
    const { rows } = await pool.query(
      `SELECT store_key FROM kv_store WHERE shared = $1 AND store_key LIKE $2 ESCAPE '\\' AND store_key <> $3`,
      [shared, escapeLike(prefix) + '%', CREDS_KEY]
    );
    res.json({ keys: rows.map(r => r.store_key), prefix, shared });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Unknown API routes -> JSON 404 (express.static already serves public/index.html at "/")
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, () => {
  console.log(`QR Assessment Portal running on port ${PORT}`);
});
