require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '2mb' }));

// Fast health check (useful for loading page / keep-alive pings)
app.get('/health', (req, res) => {
  res.status(200).json({ ok: true, service: 'qr-assessment-portal' });
});

// Serve the assessment portal (index.html and any other static files in root)
app.use(express.static(__dirname));

// ----- Database connection (Neon / any Postgres via DATABASE_URL) -----
const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
      }
    : {
        host: process.env.PGHOST || 'localhost',
        port: process.env.PGPORT || 5432,
        user: process.env.PGUSER || 'postgres',
        password: process.env.PGPASSWORD,
        database: process.env.PGDATABASE || 'postgres',
      }
);

// Create the table we need if it doesn't already exist
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
  console.log('Database ready.');
}
initDb().catch(err => console.error('DB init failed:', err));

// ----- API endpoints (storage for results, credentials, config) -----
app.get('/api/storage/:key', async (req, res) => {
  try {
    const shared = req.query.shared === 'true';
    const { rows } = await pool.query(
      'SELECT value FROM kv_store WHERE store_key = $1 AND shared = $2',
      [req.params.key, shared]
    );
    if (rows.length === 0) return res.json(null);
    res.json({ key: req.params.key, value: rows[0].value, shared });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/storage', async (req, res) => {
  try {
    const { key, value, shared } = req.body;
    if (!key) return res.status(400).json({ error: 'key required' });

    await pool.query(
      `INSERT INTO kv_store (store_key, shared, value)
       VALUES ($1, $2, $3)
       ON CONFLICT (store_key, shared)
       DO UPDATE SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP`,
      [key, !!shared, value]
    );
    res.json({ key, value, shared: !!shared });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/storage/:key', async (req, res) => {
  try {
    const shared = req.query.shared === 'true';
    await pool.query(
      'DELETE FROM kv_store WHERE store_key = $1 AND shared = $2',
      [req.params.key, shared]
    );
    res.json({ key: req.params.key, deleted: true, shared });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/storage-list', async (req, res) => {
  try {
    const shared = req.query.shared === 'true';
    const prefix = req.query.prefix || '';
    const { rows } = await pool.query(
      'SELECT store_key FROM kv_store WHERE shared = $1 AND store_key LIKE $2',
      [shared, prefix + '%']
    );
    res.json({ keys: rows.map(r => r.store_key), prefix, shared });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Fallback: serve index.html for the root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`QR Assessment Portal running on port ${PORT}`);
});
