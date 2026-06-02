// ═══════════════════════════════════════════════════════════════
//  BLIZZARD BACKEND  —  server.js
//  Run with: node server.js
//  Requires: npm install express cors better-sqlite3 uuid
// ═══════════════════════════════════════════════════════════════

const express  = require('express');
const cors     = require('cors');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const path     = require('path');
const fs       = require('fs');

const app = express();
const db  = new Database('blizzard.db');

// ── CONFIG ────────────────────────────────────────────────────
const PORT         = 8000;
const BOT_SECRET   = process.env.BOT_SECRET || 'change-this-secret-123'; // same in bot.js
const DOWNLOAD_DIR = path.join(__dirname, 'downloads');                   // put your .jar here
const JAR_NAME     = 'blizzard-latest.jar';

// ── CORS: allow your Netlify site ─────────────────────────────
app.use(cors({
  origin: [
    'https://blizzardclient.netlify.app',
    'http://localhost:3000',
    'http://127.0.0.1:5500'   // Live Server for local dev
  ]
}));
app.use(express.json());

// ── DATABASE SETUP ────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS license_keys (
    key         TEXT PRIMARY KEY,
    plan        TEXT NOT NULL,           -- 'monthly' | 'lifetime'
    expires_at  TEXT,                    -- ISO date string, NULL for lifetime
    used        INTEGER DEFAULT 0,       -- 0 = unused, 1 = redeemed
    discord_id  TEXT,                    -- set when redeemed
    redeemed_at TEXT,                    -- ISO date string
    created_at  TEXT NOT NULL,
    note        TEXT                     -- optional label (e.g. "order #123")
  );

  CREATE TABLE IF NOT EXISTS downloads (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    discord_id  TEXT NOT NULL,
    key_used    TEXT NOT NULL,
    downloaded_at TEXT NOT NULL
  );
`);

// ── HELPERS ───────────────────────────────────────────────────
function generateKey(plan) {
  // Format: BLIZZ-XXXX-XXXX-XXXX-XXXX  (random hex segments)
  const seg = () => Math.random().toString(16).slice(2, 6).toUpperCase();
  const prefix = plan === 'lifetime' ? 'BLZLT' : 'BLZMN';
  return `${prefix}-${seg()}-${seg()}-${seg()}-${seg()}`;
}

function addMonths(date, n) {
  const d = new Date(date);
  d.setMonth(d.getMonth() + n);
  return d.toISOString();
}

function isExpired(key_row) {
  if (key_row.plan === 'lifetime') return false;
  if (!key_row.expires_at) return false;
  return new Date(key_row.expires_at) < new Date();
}

// ── MIDDLEWARE: verify bot secret ─────────────────────────────
function requireBotSecret(req, res, next) {
  const secret = req.headers['x-bot-secret'];
  if (secret !== BOT_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ════════════════════════════════════════════════════════════════
//  BOT-FACING ROUTES  (protected by BOT_SECRET header)
// ════════════════════════════════════════════════════════════════

// POST /bot/genkey   { plan: 'monthly'|'lifetime', note?: string }
app.post('/bot/genkey', requireBotSecret, (req, res) => {
  const { plan, note } = req.body;
  if (!['monthly', 'lifetime'].includes(plan)) {
    return res.status(400).json({ error: 'plan must be monthly or lifetime' });
  }

  const key        = generateKey(plan);
  const created_at = new Date().toISOString();

  db.prepare(`
    INSERT INTO license_keys (key, plan, expires_at, used, created_at, note)
    VALUES (?, ?, NULL, 0, ?, ?)
  `).run(key, plan, created_at, note || null);

  res.json({ success: true, key, plan });
});

// POST /bot/bulkgen  { plan, amount (1-50), note? }
app.post('/bot/bulkgen', requireBotSecret, (req, res) => {
  const { plan, note } = req.body;
  let { amount } = req.body;
  amount = parseInt(amount, 10);

  if (!['monthly', 'lifetime'].includes(plan)) {
    return res.status(400).json({ error: 'plan must be monthly or lifetime' });
  }
  if (!amount || amount < 1 || amount > 50) {
    return res.status(400).json({ error: 'amount must be 1–50' });
  }

  const created_at = new Date().toISOString();
  const insert     = db.prepare(`
    INSERT INTO license_keys (key, plan, expires_at, used, created_at, note)
    VALUES (?, ?, NULL, 0, ?, ?)
  `);

  // Run all inserts in a single transaction for speed
  const insertMany = db.transaction((keys) => {
    for (const k of keys) insert.run(k, plan, created_at, note || null);
  });

  const keys = Array.from({ length: amount }, () => generateKey(plan));
  insertMany(keys);

  res.json({ success: true, keys, plan, amount: keys.length });
});

// GET /bot/keyinfo/:key
app.get('/bot/keyinfo/:key', requireBotSecret, (req, res) => {
  const row = db.prepare('SELECT * FROM license_keys WHERE key = ?').get(req.params.key);
  if (!row) return res.status(404).json({ error: 'Key not found' });
  res.json({ ...row, expired: isExpired(row) });
});

// POST /bot/revokekey  { key: string }
app.post('/bot/revokekey', requireBotSecret, (req, res) => {
  const { key } = req.body;
  const row = db.prepare('SELECT * FROM license_keys WHERE key = ?').get(key);
  if (!row) return res.status(404).json({ error: 'Key not found' });

  db.prepare('DELETE FROM license_keys WHERE key = ?').run(key);
  res.json({ success: true });
});

// GET /bot/listkeys?plan=monthly  (optional filter)
app.get('/bot/listkeys', requireBotSecret, (req, res) => {
  const { plan, unused } = req.query;
  let sql = 'SELECT * FROM license_keys WHERE 1=1';
  const params = [];
  if (plan)   { sql += ' AND plan = ?';   params.push(plan); }
  if (unused) { sql += ' AND used = 0';  }
  sql += ' ORDER BY created_at DESC LIMIT 50';
  const rows = db.prepare(sql).all(...params);
  res.json(rows);
});

// ════════════════════════════════════════════════════════════════
//  WEBSITE-FACING ROUTES  (called by your dashboard JS)
// ════════════════════════════════════════════════════════════════

// POST /redeem  { discord_id, key }
// Returns the license object if valid, error otherwise
app.post('/redeem', (req, res) => {
  const { discord_id, key } = req.body;
  if (!discord_id || !key) {
    return res.status(400).json({ success: false, error: 'Missing fields' });
  }

  const row = db.prepare('SELECT * FROM license_keys WHERE key = ?').get(key);

  if (!row) {
    return res.json({ success: false, error: 'Invalid or unknown key.' });
  }
  if (row.used) {
    // If already redeemed by THIS user, return their license (re-login case)
    if (row.discord_id === discord_id) {
      return res.json({
        success: true,
        license: {
          key:         row.key,
          plan:        row.plan,
          expires_at:  row.expires_at,
          redeemed_at: row.redeemed_at,
          expired:     isExpired(row)
        }
      });
    }
    return res.json({ success: false, error: 'Key already used by another account.' });
  }

  // First-time redeem: set expiry now
  const now        = new Date().toISOString();
  const expires_at = row.plan === 'monthly' ? addMonths(new Date(), 1) : null;

  db.prepare(`
    UPDATE license_keys
    SET used=1, discord_id=?, redeemed_at=?, expires_at=?
    WHERE key=?
  `).run(discord_id, now, expires_at, key);

  res.json({
    success: true,
    license: {
      key,
      plan:        row.plan,
      expires_at,
      redeemed_at: now,
      expired:     false
    }
  });
});

// GET /license/:discord_id
// Called on page load to check if user already has an active license
app.get('/license/:discord_id', (req, res) => {
  const row = db.prepare(
    'SELECT * FROM license_keys WHERE discord_id = ? ORDER BY redeemed_at DESC LIMIT 1'
  ).get(req.params.discord_id);

  if (!row) return res.json({ has_license: false });

  res.json({
    has_license: true,
    license: {
      key:         row.key,
      plan:        row.plan,
      expires_at:  row.expires_at,
      redeemed_at: row.redeemed_at,
      expired:     isExpired(row)
    }
  });
});

// GET /download/blizzard-latest.jar
// Only serves the file if discord_id + key are valid and not expired
// Called with ?discord_id=xxx&key=BLIZZ-...
app.get('/download/:filename', (req, res) => {
  const { discord_id, key } = req.query;
  if (!discord_id || !key) {
    return res.status(403).send('Missing credentials');
  }

  const row = db.prepare(
    'SELECT * FROM license_keys WHERE key = ? AND discord_id = ?'
  ).get(key, discord_id);

  if (!row || !row.used) {
    return res.status(403).send('No valid license found');
  }
  if (isExpired(row)) {
    return res.status(403).send('License expired');
  }

  const filePath = path.join(DOWNLOAD_DIR, req.params.filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).send('File not found — ask admin to upload the jar');
  }

  // Log the download
  db.prepare(
    'INSERT INTO downloads (discord_id, key_used, downloaded_at) VALUES (?, ?, ?)'
  ).run(discord_id, key, new Date().toISOString());

  res.download(filePath);
});

// ── START ─────────────────────────────────────────────────────
if (!fs.existsSync(DOWNLOAD_DIR)) fs.mkdirSync(DOWNLOAD_DIR);

app.listen(PORT, () => {
  console.log(`✅ Blizzard API running on http://localhost:${PORT}`);
  console.log(`   Bot secret: ${BOT_SECRET}`);
  console.log(`   Drop your .jar in: ${DOWNLOAD_DIR}/`);
});
