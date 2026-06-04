// ═══════════════════════════════════════════════════════════════
//  BLIZZARD BACKEND  —  server.js
//  npm install express cors better-sqlite3 uuid
//
//  ENV VARS (set these in Railway/Render/Fly.io):
//    PORT         (optional, defaults to 8000)
//    BOT_SECRET   — secret header for Discord bot routes
//    MOD_SECRET   — MUST match the secret compiled into your jar
// ═══════════════════════════════════════════════════════════════

const express  = require('express');
const cors     = require('cors');
const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');

const app = express();

const PORT       = process.env.PORT       || 8000;
const BOT_SECRET = process.env.BOT_SECRET || 'change-this-secret-123';
const MOD_SECRET = process.env.MOD_SECRET || 'mod-secret-change-this-456';

// ── IMPORTANT: on Railway/Render the working dir is ephemeral.
//   Use /tmp for SQLite so it survives restarts within a session.
//   For true persistence, swap to a mounted volume or Turso/PlanetScale.
const DB_PATH      = process.env.DB_PATH || path.join('/tmp', 'blizzard.db');
const DOWNLOAD_DIR = process.env.DOWNLOAD_DIR || path.join('/tmp', 'downloads');

const db = new Database(DB_PATH);

// ── MIDDLEWARE ─────────────────────────────────────────────────
app.use(cors({
  origin: [
    'https://blizzardclient.netlify.app',
    'http://localhost:3000',
    'http://127.0.0.1:5500'
  ]
}));

// Parse JSON for all routes — placed BEFORE route definitions
app.use(express.json());

// ── DATABASE SCHEMA ────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS license_keys (
    key              TEXT PRIMARY KEY,
    plan             TEXT NOT NULL,
    expires_at       TEXT,
    used             INTEGER DEFAULT 0,
    discord_id       TEXT,
    redeemed_at      TEXT,
    created_at       TEXT NOT NULL,
    note             TEXT,
    hwid             TEXT,
    hwid_locked_at   TEXT,
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

// ── HELPERS ────────────────────────────────────────────────────
function generateKey(plan) {
  const seg    = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  const prefix = plan === 'lifetime' ? 'BLZLT' : 'BLZMN';
  return `${prefix}-${seg()}-${seg()}-${seg()}-${seg()}`;
}

function addMonths(date, n) {
  const d = new Date(date);
  d.setMonth(d.getMonth() + n);
  return d.toISOString();
}

function isExpired(row) {
  if (!row) return true;
  if (row.plan === 'lifetime') return false;
  if (!row.expires_at) return false;
  return new Date(row.expires_at) < new Date();
}

// Signature: sha256(key + hwid + MOD_SECRET)
// Your jar must compute the same hash before sending the request.
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
  try {
    db.prepare(
      'INSERT INTO auth_log (key_used, hwid, result, ip, timestamp) VALUES (?, ?, ?, ?, ?)'
    ).run(key, hwid, result, ip || 'unknown', new Date().toISOString());
  } catch (e) {
    console.error('[logAuth error]', e.message);
  }
}

function currentMonth() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

// ════════════════════════════════════════════════════════════════
//  HEALTH CHECK  —  GET /
// ════════════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'Blizzard API' });
});

// ════════════════════════════════════════════════════════════════
//  MOD AUTH  —  POST /auth
//  Called by the Minecraft mod on every launch.
//  Body: { key, hwid, signature }
//
//  The jar must send:
//    signature = sha256(key + hwid + MOD_SECRET)
// ════════════════════════════════════════════════════════════════
app.post('/auth', (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim()
           || req.socket.remoteAddress
           || 'unknown';

  const { key, hwid, signature } = req.body || {};

  console.log(`[AUTH] key=${key} hwid=${hwid} sig=${signature} ip=${ip}`);

  // 1. Required fields
  if (!key || !hwid || !signature) {
    console.log('[AUTH] → MISSING_FIELDS');
    return res.json({ valid: false, reason: 'MISSING_FIELDS' });
  }

  // 2. Signature check — proves the request came from YOUR jar
  if (!verifyModSignature(key, hwid, signature)) {
    console.log('[AUTH] → BAD_SIGNATURE');
    logAuth(key, hwid, 'bad_signature', ip);
    return res.json({ valid: false, reason: 'BAD_SIGNATURE' });
  }

  // 3. Key must exist and be redeemed
  const row = db.prepare('SELECT * FROM license_keys WHERE key = ?').get(key);
  if (!row) {
    console.log('[AUTH] → KEY_NOT_FOUND');
    logAuth(key, hwid, 'key_not_found', ip);
    return res.json({ valid: false, reason: 'INVALID_KEY' });
  }
  if (!row.used) {
    console.log('[AUTH] → KEY_NOT_REDEEMED');
    logAuth(key, hwid, 'not_redeemed', ip);
    return res.json({ valid: false, reason: 'INVALID_KEY' });
  }

  // 4. Expiry
  if (isExpired(row)) {
    console.log('[AUTH] → EXPIRED');
    logAuth(key, hwid, 'expired', ip);
    return res.json({ valid: false, reason: 'EXPIRED' });
  }

  // 5. HWID binding
  if (!row.hwid) {
    // First launch on any PC — bind HWID now
    db.prepare(
      'UPDATE license_keys SET hwid=?, hwid_locked_at=? WHERE key=?'
    ).run(hwid, new Date().toISOString(), key);
    console.log(`[AUTH] → ok_hwid_bound (${hwid})`);
    logAuth(key, hwid, 'ok_hwid_bound', ip);
  } else if (row.hwid !== hwid) {
    // Different PC, HWID already locked
    console.log(`[AUTH] → HWID_MISMATCH (expected ${row.hwid}, got ${hwid})`);
    logAuth(key, hwid, 'hwid_mismatch', ip);
    return res.json({ valid: false, reason: 'HWID_MISMATCH' });
  } else {
    console.log('[AUTH] → ok');
    logAuth(key, hwid, 'ok', ip);
  }

  // 6. All good — return a daily session token
  const sessionToken = crypto
    .createHash('sha256')
    .update(key + hwid + MOD_SECRET + new Date().toDateString())
    .digest('hex');

  res.json({
    valid:         true,
    plan:          row.plan,
    expires_at:    row.expires_at || null,
    session_token: sessionToken
  });
});

// ════════════════════════════════════════════════════════════════
//  HWID RESET  —  POST /hwid-reset
//  Max 2 resets per calendar month per user.
//  Body: { discord_id, key }
// ════════════════════════════════════════════════════════════════
app.post('/hwid-reset', (req, res) => {
  const { discord_id, key } = req.body || {};
  if (!discord_id || !key)
    return res.status(400).json({ success: false, error: 'Missing fields.' });

  const row = db.prepare(
    'SELECT * FROM license_keys WHERE key = ? AND discord_id = ?'
  ).get(key, discord_id);

  if (!row)
    return res.json({ success: false, error: 'License not found.' });
  if (!row.used)
    return res.json({ success: false, error: 'Key not yet activated.' });
  if (isExpired(row))
    return res.json({ success: false, error: 'Your license has expired.' });
  if (!row.hwid)
    return res.json({ success: false, error: 'No HWID is bound yet.' });

  const month = currentMonth();
  let resetCount = (row.hwid_reset_month === month) ? (row.hwid_reset_count || 0) : 0;

  if (resetCount >= 2) {
    return res.json({
      success:     false,
      error:       `You have used both HWID resets for ${month}. Resets refresh on the 1st of next month.`,
      resets_used: resetCount,
      resets_left: 0
    });
  }

  db.prepare(`
    UPDATE license_keys
    SET hwid=NULL, hwid_locked_at=NULL,
        hwid_reset_count=?, hwid_reset_month=?
    WHERE key=?
  `).run(resetCount + 1, month, key);

  const left = 2 - (resetCount + 1);
  res.json({
    success:     true,
    resets_used: resetCount + 1,
    resets_left: left,
    message:     `HWID reset! Your next launch will bind to your new PC. You have ${left} reset${left !== 1 ? 's' : ''} left this month.`
  });
});

// GET /hwid-status/:discord_id — used by dashboard
app.get('/hwid-status/:discord_id', (req, res) => {
  const row = db.prepare(
    'SELECT hwid, hwid_reset_count, hwid_reset_month FROM license_keys WHERE discord_id = ? AND used = 1 ORDER BY redeemed_at DESC LIMIT 1'
  ).get(req.params.discord_id);

  if (!row) return res.json({ found: false });

  const month      = currentMonth();
  const resetCount = (row.hwid_reset_month === month) ? (row.hwid_reset_count || 0) : 0;

  res.json({
    found:       true,
    hwid_bound:  !!row.hwid,
    resets_used: resetCount,
    resets_left: 2 - resetCount
  });
});

// ════════════════════════════════════════════════════════════════
//  BOT ROUTES  (require X-Bot-Secret header)
// ════════════════════════════════════════════════════════════════

// Generate a single key
app.post('/bot/genkey', requireBotSecret, (req, res) => {
  const { plan, note } = req.body || {};
  if (!['monthly', 'lifetime'].includes(plan))
    return res.status(400).json({ error: 'plan must be monthly or lifetime' });
  const key = generateKey(plan);
  db.prepare(
    'INSERT INTO license_keys (key, plan, used, created_at, note) VALUES (?, ?, 0, ?, ?)'
  ).run(key, plan, new Date().toISOString(), note || null);
  res.json({ success: true, key, plan });
});

// Generate multiple keys
app.post('/bot/bulkgen', requireBotSecret, (req, res) => {
  const { plan, note } = req.body || {};
  let { amount } = req.body || {};
  amount = parseInt(amount, 10);
  if (!['monthly', 'lifetime'].includes(plan))
    return res.status(400).json({ error: 'plan must be monthly or lifetime' });
  if (!amount || amount < 1 || amount > 50)
    return res.status(400).json({ error: 'amount must be 1–50' });

  const insert = db.prepare(
    'INSERT INTO license_keys (key, plan, used, created_at, note) VALUES (?, ?, 0, ?, ?)'
  );
  const now  = new Date().toISOString();
  const keys = Array.from({ length: amount }, () => generateKey(plan));
  const insertMany = db.transaction(ks => { for (const k of ks) insert.run(k, plan, now, note || null); });
  insertMany(keys);
  res.json({ success: true, keys, plan, amount: keys.length });
});

// Key info by Discord ID (define BEFORE /:key route)
app.get('/bot/keyinfo/by-discord/:discord_id', requireBotSecret, (req, res) => {
  const row = db.prepare(
    'SELECT * FROM license_keys WHERE discord_id = ? ORDER BY redeemed_at DESC LIMIT 1'
  ).get(req.params.discord_id);
  if (!row) return res.status(404).json({ error: 'No license found for this Discord user.' });
  res.json({ ...row, expired: isExpired(row) });
});

// Key info by key string
app.get('/bot/keyinfo/:key', requireBotSecret, (req, res) => {
  const row = db.prepare('SELECT * FROM license_keys WHERE key = ?').get(req.params.key);
  if (!row) return res.status(404).json({ error: 'Key not found.' });
  res.json({ ...row, expired: isExpired(row) });
});

// Revoke a key
app.post('/bot/revokekey', requireBotSecret, (req, res) => {
  const { key } = req.body || {};
  if (!db.prepare('SELECT key FROM license_keys WHERE key = ?').get(key))
    return res.status(404).json({ error: 'Key not found.' });
  db.prepare('DELETE FROM license_keys WHERE key = ?').run(key);
  res.json({ success: true });
});

// Admin HWID reset (no monthly limit)
app.post('/bot/resethwid', requireBotSecret, (req, res) => {
  const { key } = req.body || {};
  if (!db.prepare('SELECT key FROM license_keys WHERE key = ?').get(key))
    return res.status(404).json({ error: 'Key not found.' });
  db.prepare(
    'UPDATE license_keys SET hwid=NULL, hwid_locked_at=NULL, hwid_reset_count=0, hwid_reset_month=NULL WHERE key=?'
  ).run(key);
  res.json({ success: true, message: 'HWID cleared. Next launch will bind to the new PC.' });
});

// List keys (optional ?plan=monthly|lifetime&unused=1)
app.get('/bot/listkeys', requireBotSecret, (req, res) => {
  const { plan, unused } = req.query;
  let sql    = 'SELECT * FROM license_keys WHERE 1=1';
  const params = [];
  if (plan)   { sql += ' AND plan = ?';  params.push(plan); }
  if (unused) { sql += ' AND used = 0'; }
  sql += ' ORDER BY created_at DESC LIMIT 50';
  res.json(db.prepare(sql).all(...params));
});

// Auth log (last 50)
app.get('/bot/authlog', requireBotSecret, (req, res) => {
  res.json(db.prepare('SELECT * FROM auth_log ORDER BY timestamp DESC LIMIT 50').all());
});

// ════════════════════════════════════════════════════════════════
//  WEBSITE ROUTES
// ════════════════════════════════════════════════════════════════

// Redeem a key
app.post('/redeem', (req, res) => {
  const { discord_id, key } = req.body || {};
  if (!discord_id || !key)
    return res.status(400).json({ success: false, error: 'Missing fields.' });

  const row = db.prepare('SELECT * FROM license_keys WHERE key = ?').get(key);
  if (!row)
    return res.json({ success: false, error: 'Invalid or unknown key.' });

  if (row.used) {
    // Already redeemed — return success if it's the same Discord account
    if (row.discord_id === discord_id)
      return res.json({
        success: true,
        license: {
          key:          row.key,
          plan:         row.plan,
          expires_at:   row.expires_at,
          redeemed_at:  row.redeemed_at,
          expired:      isExpired(row)
        }
      });
    return res.json({ success: false, error: 'Key already used by another account.' });
  }

  const now        = new Date().toISOString();
  const expires_at = row.plan === 'monthly' ? addMonths(now, 1) : null;

  db.prepare(
    'UPDATE license_keys SET used=1, discord_id=?, redeemed_at=?, expires_at=? WHERE key=?'
  ).run(discord_id, now, expires_at, key);

  res.json({
    success: true,
    license: { key, plan: row.plan, expires_at, redeemed_at: now, expired: false }
  });
});

// Look up a license by Discord ID
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

// Authenticated file download
app.get('/download/:filename', (req, res) => {
  const { discord_id, key } = req.query;
  if (!discord_id || !key)
    return res.status(403).json({ error: 'Missing credentials.' });

  const row = db.prepare(
    'SELECT * FROM license_keys WHERE key = ? AND discord_id = ?'
  ).get(key, discord_id);

  if (!row || !row.used || isExpired(row))
    return res.status(403).json({ error: 'No valid license.' });

  const filePath = path.join(DOWNLOAD_DIR, path.basename(req.params.filename));
  if (!fs.existsSync(filePath))
    return res.status(404).json({ error: 'File not found.' });

  db.prepare(
    'INSERT INTO downloads (discord_id, key_used, downloaded_at) VALUES (?, ?, ?)'
  ).run(discord_id, key, new Date().toISOString());

  res.download(filePath);
});

// ── STARTUP ────────────────────────────────────────────────────
if (!fs.existsSync(DOWNLOAD_DIR)) fs.mkdirSync(DOWNLOAD_DIR, { recursive: true });

app.listen(PORT, () => {
  console.log(`✅ Blizzard API running on port ${PORT}`);
  console.log(`   DB path:    ${DB_PATH}`);
  console.log(`   MOD_SECRET: ${MOD_SECRET}`);
  console.log(`   BOT_SECRET: ${BOT_SECRET}`);
  console.log('');
  console.log('⚠️  Make sure MOD_SECRET here matches the one compiled into your jar!');
});
