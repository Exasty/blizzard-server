// ═══════════════════════════════════════════════════════════════
//  BLIZZARD BACKEND  —  server.js  (HWID + reset limit)
//  npm install express cors better-sqlite3 uuid
// ═══════════════════════════════════════════════════════════════

const express  = require('express');
const cors     = require('cors');
const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');

const app = express();
const db  = new Database('blizzard.db');

const PORT       = process.env.PORT || 8000;
const BOT_SECRET = process.env.BOT_SECRET || 'change-this-secret-123';
const MOD_SECRET = process.env.MOD_SECRET || 'mod-secret-change-this-456';
const DOWNLOAD_DIR = path.join(__dirname, 'downloads');

app.use(cors({
  origin: [
    'https://blizzardclient.netlify.app',
    'http://localhost:3000',
    'http://127.0.0.1:5500'
  ]
}));
app.use(express.json());

// ── DATABASE ──────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS license_keys (
    key             TEXT PRIMARY KEY,
    plan            TEXT NOT NULL,
    expires_at      TEXT,
    used            INTEGER DEFAULT 0,
    discord_id      TEXT,
    redeemed_at     TEXT,
    created_at      TEXT NOT NULL,
    note            TEXT,
    hwid            TEXT,
    hwid_locked_at  TEXT,
    hwid_reset_count INTEGER DEFAULT 0,
    hwid_reset_month TEXT
  );

  CREATE TABLE IF NOT EXISTS downloads (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    discord_id    TEXT NOT NULL,
    key_used      TEXT NOT NULL,
    downloaded_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS auth_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    key_used  TEXT NOT NULL,
    hwid      TEXT NOT NULL,
    result    TEXT NOT NULL,
    ip        TEXT,
    timestamp TEXT NOT NULL
  );
`);

// ── HELPERS ───────────────────────────────────────────────────
function generateKey(plan) {
  const seg    = () => Math.random().toString(16).slice(2, 6).toUpperCase();
  const prefix = plan === 'lifetime' ? 'BLZLT' : 'BLZMN';
  return `${prefix}-${seg()}-${seg()}-${seg()}-${seg()}`;
}

function addMonths(date, n) {
  const d = new Date(date);
  d.setMonth(d.getMonth() + n);
  return d.toISOString();
}

function isExpired(row) {
  if (row.plan === 'lifetime') return false;
  if (!row.expires_at) return false;
  return new Date(row.expires_at) < new Date();
}

function verifyModSignature(key, hwid, signature) {
  const expected = crypto
    .createHash('sha256')
    .update(key + hwid + MOD_SECRET)
    .digest('hex');
  return expected === signature;
}

function requireBotSecret(req, res, next) {
  if (req.headers['x-bot-secret'] !== BOT_SECRET)
    return res.status(401).json({ error: 'Unauthorized' });
  next();
}

function logAuth(key, hwid, result, ip) {
  db.prepare(
    'INSERT INTO auth_log (key_used, hwid, result, ip, timestamp) VALUES (?, ?, ?, ?, ?)'
  ).run(key, hwid, result, ip, new Date().toISOString());
}

// Get current month string e.g. "2026-06"
function currentMonth() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

// ════════════════════════════════════════════════════════════════
//  MOD AUTH  —  POST /auth
//  Called by the Minecraft mod on every single launch
//  Body: { key, hwid, signature }
// ════════════════════════════════════════════════════════════════
app.post('/auth', (req, res) => {
  const { key, hwid, signature } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!key || !hwid || !signature) {
    return res.json({ valid: false, reason: 'MISSING_FIELDS' });
  }

  // 1. Signature — proves request came from YOUR jar not someone faking it
  if (!verifyModSignature(key, hwid, signature)) {
    logAuth(key, hwid, 'bad_signature', ip);
    return res.json({ valid: false, reason: 'BAD_SIGNATURE' });
  }

  // 2. Key must exist and be redeemed
  const row = db.prepare('SELECT * FROM license_keys WHERE key = ?').get(key);
  if (!row || !row.used) {
    logAuth(key, hwid, 'invalid', ip);
    return res.json({ valid: false, reason: 'INVALID_KEY' });
  }

  // 3. Expiry
  if (isExpired(row)) {
    logAuth(key, hwid, 'expired', ip);
    return res.json({ valid: false, reason: 'EXPIRED' });
  }

  // 4. HWID lock
  if (!row.hwid) {
    // First launch — bind HWID now
    db.prepare(
      'UPDATE license_keys SET hwid=?, hwid_locked_at=? WHERE key=?'
    ).run(hwid, new Date().toISOString(), key);
    logAuth(key, hwid, 'ok_hwid_bound', ip);
  } else if (row.hwid !== hwid) {
    // Wrong PC
    logAuth(key, hwid, 'hwid_mismatch', ip);
    return res.json({ valid: false, reason: 'HWID_MISMATCH' });
  }

  // 5. All good
  logAuth(key, hwid, 'ok', ip);
  res.json({
    valid:         true,
    plan:          row.plan,
    expires_at:    row.expires_at,
    session_token: crypto
      .createHash('sha256')
      .update(key + hwid + MOD_SECRET + new Date().toDateString())
      .digest('hex')
  });
});

// ════════════════════════════════════════════════════════════════
//  HWID RESET  —  POST /hwid-reset
//  Called from the dashboard. Max 2 resets per calendar month.
//  Body: { discord_id, key }
// ════════════════════════════════════════════════════════════════
app.post('/hwid-reset', (req, res) => {
  const { discord_id, key } = req.body;
  if (!discord_id || !key)
    return res.status(400).json({ success: false, error: 'Missing fields' });

  const row = db.prepare('SELECT * FROM license_keys WHERE key = ? AND discord_id = ?').get(key, discord_id);

  if (!row)
    return res.json({ success: false, error: 'License not found.' });
  if (!row.used)
    return res.json({ success: false, error: 'Key not yet activated.' });
  if (isExpired(row))
    return res.json({ success: false, error: 'Your license has expired.' });
  if (!row.hwid)
    return res.json({ success: false, error: 'No HWID is bound yet.' });

  const month = currentMonth();

  // Reset counter if it's a new month
  let resetCount = row.hwid_reset_count || 0;
  if (row.hwid_reset_month !== month) {
    resetCount = 0;
  }

  if (resetCount >= 2) {
    return res.json({
      success: false,
      error:   `You have used both HWID resets for ${month}. Resets refresh on the 1st of next month.`,
      resets_used: resetCount,
      resets_left: 0
    });
  }

  // Do the reset
  db.prepare(`
    UPDATE license_keys
    SET hwid=NULL, hwid_locked_at=NULL,
        hwid_reset_count=?, hwid_reset_month=?
    WHERE key=?
  `).run(resetCount + 1, month, key);

  res.json({
    success:     true,
    resets_used: resetCount + 1,
    resets_left: 2 - (resetCount + 1),
    message:     `HWID reset! Your next launch will bind to your new PC. You have ${2 - (resetCount + 1)} reset${2 - (resetCount + 1) !== 1 ? 's' : ''} left this month.`
  });
});

// GET /hwid-status/:discord_id  — used by dashboard to show reset count
app.get('/hwid-status/:discord_id', (req, res) => {
  const row = db.prepare(
    'SELECT hwid, hwid_reset_count, hwid_reset_month FROM license_keys WHERE discord_id = ? AND used = 1 ORDER BY redeemed_at DESC LIMIT 1'
  ).get(req.params.discord_id);

  if (!row) return res.json({ found: false });

  const month      = currentMonth();
  const resetCount = row.hwid_reset_month === month ? (row.hwid_reset_count || 0) : 0;

  res.json({
    found:       true,
    hwid_bound:  !!row.hwid,
    resets_used: resetCount,
    resets_left: 2 - resetCount
  });
});

// ════════════════════════════════════════════════════════════════
//  BOT ROUTES
// ════════════════════════════════════════════════════════════════
app.post('/bot/genkey', requireBotSecret, (req, res) => {
  const { plan, note } = req.body;
  if (!['monthly', 'lifetime'].includes(plan))
    return res.status(400).json({ error: 'plan must be monthly or lifetime' });
  const key = generateKey(plan);
  db.prepare('INSERT INTO license_keys (key, plan, expires_at, used, created_at, note) VALUES (?, ?, NULL, 0, ?, ?)')
    .run(key, plan, new Date().toISOString(), note || null);
  res.json({ success: true, key, plan });
});

app.post('/bot/bulkgen', requireBotSecret, (req, res) => {
  const { plan, note } = req.body;
  let { amount } = req.body;
  amount = parseInt(amount, 10);
  if (!['monthly', 'lifetime'].includes(plan)) return res.status(400).json({ error: 'plan must be monthly or lifetime' });
  if (!amount || amount < 1 || amount > 50) return res.status(400).json({ error: 'amount must be 1-50' });
  const insert     = db.prepare('INSERT INTO license_keys (key, plan, expires_at, used, created_at, note) VALUES (?, ?, NULL, 0, ?, ?)');
  const insertMany = db.transaction(keys => { for (const k of keys) insert.run(k, plan, new Date().toISOString(), note || null); });
  const keys       = Array.from({ length: amount }, () => generateKey(plan));
  insertMany(keys);
  res.json({ success: true, keys, plan, amount: keys.length });
});

// GET /bot/keyinfo/by-discord/:discord_id  ← MUST be before /bot/keyinfo/:key
// Lookup a license by Discord user ID (for !lookup command)
app.get('/bot/keyinfo/by-discord/:discord_id', requireBotSecret, (req, res) => {
  const row = db.prepare(
    'SELECT * FROM license_keys WHERE discord_id = ? ORDER BY redeemed_at DESC LIMIT 1'
  ).get(req.params.discord_id);
  if (!row) return res.status(404).json({ error: 'No license found for this Discord user' });
  res.json({ ...row, expired: isExpired(row) });
});

app.get('/bot/keyinfo/:key', requireBotSecret, (req, res) => {
  const row = db.prepare('SELECT * FROM license_keys WHERE key = ?').get(req.params.key);
  if (!row) return res.status(404).json({ error: 'Key not found' });
  res.json({ ...row, expired: isExpired(row) });
});

app.post('/bot/revokekey', requireBotSecret, (req, res) => {
  const { key } = req.body;
  if (!db.prepare('SELECT key FROM license_keys WHERE key = ?').get(key))
    return res.status(404).json({ error: 'Key not found' });
  db.prepare('DELETE FROM license_keys WHERE key = ?').run(key);
  res.json({ success: true });
});

// Admin HWID reset (no limit)
app.post('/bot/resethwid', requireBotSecret, (req, res) => {
  const { key } = req.body;
  if (!db.prepare('SELECT key FROM license_keys WHERE key = ?').get(key))
    return res.status(404).json({ error: 'Key not found' });
  db.prepare('UPDATE license_keys SET hwid=NULL, hwid_locked_at=NULL, hwid_reset_count=0, hwid_reset_month=NULL WHERE key=?').run(key);
  res.json({ success: true, message: 'HWID reset. Next launch will bind to new PC.' });
});

app.get('/bot/listkeys', requireBotSecret, (req, res) => {
  const { plan, unused } = req.query;
  let sql = 'SELECT * FROM license_keys WHERE 1=1';
  const params = [];
  if (plan)   { sql += ' AND plan = ?'; params.push(plan); }
  if (unused) { sql += ' AND used = 0'; }
  sql += ' ORDER BY created_at DESC LIMIT 50';
  res.json(db.prepare(sql).all(...params));
});

app.get('/bot/authlog', requireBotSecret, (req, res) => {
  res.json(db.prepare('SELECT * FROM auth_log ORDER BY timestamp DESC LIMIT 50').all());
});

// ════════════════════════════════════════════════════════════════
//  WEBSITE ROUTES
// ════════════════════════════════════════════════════════════════
app.post('/redeem', (req, res) => {
  const { discord_id, key } = req.body;
  if (!discord_id || !key) return res.status(400).json({ success: false, error: 'Missing fields' });
  const row = db.prepare('SELECT * FROM license_keys WHERE key = ?').get(key);
  if (!row) return res.json({ success: false, error: 'Invalid or unknown key.' });
  if (row.used) {
    if (row.discord_id === discord_id)
      return res.json({ success: true, license: { key: row.key, plan: row.plan, expires_at: row.expires_at, redeemed_at: row.redeemed_at, expired: isExpired(row) } });
    return res.json({ success: false, error: 'Key already used by another account.' });
  }
  const now        = new Date().toISOString();
  const expires_at = row.plan === 'monthly' ? addMonths(new Date(), 1) : null;
  db.prepare('UPDATE license_keys SET used=1, discord_id=?, redeemed_at=?, expires_at=? WHERE key=?')
    .run(discord_id, now, expires_at, key);
  res.json({ success: true, license: { key, plan: row.plan, expires_at, redeemed_at: now, expired: false } });
});

app.get('/license/:discord_id', (req, res) => {
  const row = db.prepare('SELECT * FROM license_keys WHERE discord_id = ? ORDER BY redeemed_at DESC LIMIT 1').get(req.params.discord_id);
  if (!row) return res.json({ has_license: false });
  res.json({ has_license: true, license: { key: row.key, plan: row.plan, expires_at: row.expires_at, redeemed_at: row.redeemed_at, expired: isExpired(row) } });
});

app.get('/download/:filename', (req, res) => {
  const { discord_id, key } = req.query;
  if (!discord_id || !key) return res.status(403).send('Missing credentials');
  const row = db.prepare('SELECT * FROM license_keys WHERE key = ? AND discord_id = ?').get(key, discord_id);
  if (!row || !row.used || isExpired(row)) return res.status(403).send('No valid license.');
  const filePath = path.join(DOWNLOAD_DIR, req.params.filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('File not found');
  db.prepare('INSERT INTO downloads (discord_id, key_used, downloaded_at) VALUES (?, ?, ?)').run(discord_id, key, new Date().toISOString());
  res.download(filePath);
});

if (!fs.existsSync(DOWNLOAD_DIR)) fs.mkdirSync(DOWNLOAD_DIR);
app.listen(PORT, () => {
  console.log(`✅ Blizzard API running on port ${PORT}`);
  console.log(`   MOD_SECRET (put in your jar): ${MOD_SECRET}`);
});
