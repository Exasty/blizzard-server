// ═══════════════════════════════════════════════════════════════
//  BLIZZARD BACKEND  —  server.js
//  npm install express cors better-sqlite3
//
//  ENV VARS (set in Railway/Render/Fly.io):
//    PORT        — optional, defaults to 8000
//    BOT_SECRET  — secret header for Discord bot routes
//    MOD_SECRET  — MUST exactly match BlizzardAuth.java MOD_SECRET
//    DB_PATH     — optional, defaults to /tmp/blizzard.db
// ═══════════════════════════════════════════════════════════════

const express  = require('express');
const cors     = require('cors');
const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');

const app = express();

const PORT       = process.env.PORT       || 8000;
const BOT_SECRET = process.env.BOT_SECRET || 'mEreY3QpPbyzZJgqYPrHtTG$p2wByHv';

// ⚠️  THIS MUST MATCH BlizzardAuth.java MOD_SECRET EXACTLY
const MOD_SECRET = process.env.MOD_SECRET || 'mgvSs0NvrAqFubgMpdEaXS1TFNz2W3GDJcJGA6Tu8qz3Am3V7GaS8gfnDWqZrDK7';

const DB_PATH      = process.env.DB_PATH      || path.join('/tmp', 'blizzard.db');
const DOWNLOAD_DIR = process.env.DOWNLOAD_DIR || path.join(__dirname, 'downloads');

const db = new Database(DB_PATH);

// ── MIDDLEWARE ─────────────────────────────────────────────────
// Allow all origins for /mod-auth so the Minecraft mod (not a browser) can reach it
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, X-Bot-Secret');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.use(express.json());

// ── DATABASE ───────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS license_keys (
    key              TEXT PRIMARY KEY,
    plan             TEXT NOT NULL,
    expires_at       TEXT,
    used             INTEGER DEFAULT 0,
    discord_id       TEXT UNIQUE,
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
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    discord_id TEXT NOT NULL,
    hwid       TEXT NOT NULL,
    result     TEXT NOT NULL,
    ip         TEXT,
    timestamp  TEXT NOT NULL
  );
`);

// ── HELPERS ────────────────────────────────────────────────────
function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

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

function requireBotSecret(req, res, next) {
  if (req.headers['x-bot-secret'] !== BOT_SECRET)
    return res.status(401).json({ error: 'Unauthorized' });
  next();
}

function logAuth(discordId, hwid, result, ip) {
  try {
    db.prepare(
      'INSERT INTO auth_log (discord_id, hwid, result, ip, timestamp) VALUES (?, ?, ?, ?, ?)'
    ).run(discordId, hwid, result, ip || 'unknown', new Date().toISOString());
  } catch (e) {
    console.error('[logAuth error]', e.message);
  }
}

function currentMonth() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

function getIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket.remoteAddress
    || 'unknown';
}

// ════════════════════════════════════════════════════════════════
//  HEALTH CHECK  —  GET /
// ════════════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'Blizzard API' });
});

// ════════════════════════════════════════════════════════════════
//  MOD AUTH  —  POST /mod-auth
//
//  Called by BlizzardAuth.java on every Minecraft launch.
//
//  What the jar sends:
//    { discord_id, hwid, signature }
//    signature = sha256(discord_id + hwid + MOD_SECRET)
//
//  What this endpoint does:
//    1. Verifies the signature (proves request is from YOUR jar)
//    2. Looks up the license by discord_id
//    3. Checks expiry
//    4. Binds HWID on first launch, or verifies it on subsequent ones
//    5. Returns { valid, plan, expires_at, session_token }
// ════════════════════════════════════════════════════════════════
app.post('/mod-auth', (req, res) => {
  const ip = getIp(req);
  const { discord_id, hwid, signature } = req.body || {};

  console.log(`[MOD-AUTH] discord_id=${discord_id} hwid=${hwid} ip=${ip}`);

  // 1. Required fields
  if (!discord_id || !hwid || !signature) {
    console.log('[MOD-AUTH] → MISSING_FIELDS');
    return res.json({ valid: false, reason: 'MISSING_FIELDS' });
  }

  // 2. Signature: sha256(discord_id + hwid + MOD_SECRET)
  //    Must match exactly what BlizzardAuth.java computes
  const expected = sha256(discord_id + hwid + MOD_SECRET);
  if (signature !== expected) {
    console.log(`[MOD-AUTH] → BAD_SIGNATURE (got ${signature}, expected ${expected})`);
    logAuth(discord_id, hwid, 'bad_signature', ip);
    return res.json({ valid: false, reason: 'BAD_SIGNATURE' });
  }

  // 3. Look up license by discord_id
  const row = db.prepare(
    'SELECT * FROM license_keys WHERE discord_id = ? AND used = 1'
  ).get(discord_id);

  if (!row) {
    console.log('[MOD-AUTH] → NO_LICENSE');
    logAuth(discord_id, hwid, 'no_license', ip);
    return res.json({ valid: false, reason: 'NO_LICENSE' });
  }

  // 4. Expiry check
  if (isExpired(row)) {
    console.log('[MOD-AUTH] → EXPIRED');
    logAuth(discord_id, hwid, 'expired', ip);
    return res.json({ valid: false, reason: 'EXPIRED' });
  }

  // 5. HWID binding
  if (!row.hwid) {
    // First launch — bind this HWID to the license
    db.prepare(
      'UPDATE license_keys SET hwid=?, hwid_locked_at=? WHERE discord_id=?'
    ).run(hwid, new Date().toISOString(), discord_id);
    console.log(`[MOD-AUTH] → ok_hwid_bound (${hwid})`);
    logAuth(discord_id, hwid, 'ok_hwid_bound', ip);
  } else if (row.hwid !== hwid) {
    console.log(`[MOD-AUTH] → HWID_MISMATCH (bound=${row.hwid}, got=${hwid})`);
    logAuth(discord_id, hwid, 'hwid_mismatch', ip);
    return res.json({ valid: false, reason: 'HWID_MISMATCH' });
  } else {
    console.log('[MOD-AUTH] → ok');
    logAuth(discord_id, hwid, 'ok', ip);
  }

  // 6. All good — issue a daily session token
  const sessionToken = sha256(discord_id + hwid + MOD_SECRET + new Date().toDateString());

  res.json({
    valid:         true,
    plan:          row.plan,
    expires_at:    row.expires_at || null,
    session_token: sessionToken
  });
});

// ════════════════════════════════════════════════════════════════
//  HWID RESET  —  POST /hwid-reset
//  Max 2 resets per calendar month.
//  Body: { discord_id, key }
// ════════════════════════════════════════════════════════════════
app.post('/hwid-reset', (req, res) => {
  const { discord_id, key } = req.body || {};
  if (!discord_id || !key)
    return res.status(400).json({ success: false, error: 'Missing fields.' });

  const row = db.prepare(
    'SELECT * FROM license_keys WHERE key = ? AND discord_id = ?'
  ).get(key, discord_id);

  if (!row)  return res.json({ success: false, error: 'License not found.' });
  if (!row.used) return res.json({ success: false, error: 'Key not yet activated.' });
  if (isExpired(row)) return res.json({ success: false, error: 'Your license has expired.' });
  if (!row.hwid) return res.json({ success: false, error: 'No HWID is bound yet.' });

  const month = currentMonth();
  const resetCount = (row.hwid_reset_month === month) ? (row.hwid_reset_count || 0) : 0;

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
    SET hwid=NULL, hwid_locked_at=NULL, hwid_reset_count=?, hwid_reset_month=?
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

// GET /hwid-status/:discord_id
app.get('/hwid-status/:discord_id', (req, res) => {
  const row = db.prepare(
    'SELECT hwid, hwid_reset_count, hwid_reset_month FROM license_keys WHERE discord_id = ? AND used = 1'
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
//  BOT ROUTES  (X-Bot-Secret header required)
// ════════════════════════════════════════════════════════════════
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

app.post('/bot/bulkgen', requireBotSecret, (req, res) => {
  const { plan, note } = req.body || {};
  let { amount } = req.body || {};
  amount = parseInt(amount, 10);
  if (!['monthly', 'lifetime'].includes(plan))
    return res.status(400).json({ error: 'plan must be monthly or lifetime' });
  if (!amount || amount < 1 || amount > 50)
    return res.status(400).json({ error: 'amount must be 1-50' });
  const insert     = db.prepare('INSERT INTO license_keys (key, plan, used, created_at, note) VALUES (?, ?, 0, ?, ?)');
  const now        = new Date().toISOString();
  const keys       = Array.from({ length: amount }, () => generateKey(plan));
  const insertMany = db.transaction(ks => { for (const k of ks) insert.run(k, plan, now, note || null); });
  insertMany(keys);
  res.json({ success: true, keys, plan, amount: keys.length });
});

app.get('/bot/keyinfo/by-discord/:discord_id', requireBotSecret, (req, res) => {
  const row = db.prepare(
    'SELECT * FROM license_keys WHERE discord_id = ? ORDER BY redeemed_at DESC LIMIT 1'
  ).get(req.params.discord_id);
  if (!row) return res.status(404).json({ error: 'No license found for this Discord user.' });
  res.json({ ...row, expired: isExpired(row) });
});

app.get('/bot/keyinfo/:key', requireBotSecret, (req, res) => {
  const row = db.prepare('SELECT * FROM license_keys WHERE key = ?').get(req.params.key);
  if (!row) return res.status(404).json({ error: 'Key not found.' });
  res.json({ ...row, expired: isExpired(row) });
});

app.post('/bot/revokekey', requireBotSecret, (req, res) => {
  const { key } = req.body || {};
  if (!db.prepare('SELECT key FROM license_keys WHERE key = ?').get(key))
    return res.status(404).json({ error: 'Key not found.' });
  db.prepare('DELETE FROM license_keys WHERE key = ?').run(key);
  res.json({ success: true });
});

app.post('/bot/resethwid', requireBotSecret, (req, res) => {
  const { key } = req.body || {};
  if (!db.prepare('SELECT key FROM license_keys WHERE key = ?').get(key))
    return res.status(404).json({ error: 'Key not found.' });
  db.prepare(
    'UPDATE license_keys SET hwid=NULL, hwid_locked_at=NULL, hwid_reset_count=0, hwid_reset_month=NULL WHERE key=?'
  ).run(key);
  res.json({ success: true, message: 'HWID cleared. Next launch will bind to the new PC.' });
});

app.get('/bot/listkeys', requireBotSecret, (req, res) => {
  const { plan, unused } = req.query;
  let sql      = 'SELECT * FROM license_keys WHERE 1=1';
  const params = [];
  if (plan)   { sql += ' AND plan = ?'; params.push(plan); }
  if (unused) { sql += ' AND used = 0'; }
  sql += ' ORDER BY created_at DESC LIMIT 50';
  res.json(db.prepare(sql).all(...params));
});

app.get('/bot/authlog', requireBotSecret, (req, res) => {
  res.json(db.prepare('SELECT * FROM auth_log ORDER BY timestamp DESC LIMIT 100').all());
});

// ════════════════════════════════════════════════════════════════
//  WEBSITE ROUTES
// ════════════════════════════════════════════════════════════════
app.post('/redeem', (req, res) => {
  const { discord_id, key } = req.body || {};
  if (!discord_id || !key)
    return res.status(400).json({ success: false, error: 'Missing fields.' });

  const row = db.prepare('SELECT * FROM license_keys WHERE key = ?').get(key);
  if (!row)
    return res.json({ success: false, error: 'Invalid or unknown key.' });

  if (row.used) {
    if (row.discord_id === discord_id)
      return res.json({
        success: true,
        license: { key: row.key, plan: row.plan, expires_at: row.expires_at, redeemed_at: row.redeemed_at, expired: isExpired(row) }
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

app.get('/license/:discord_id', (req, res) => {
  const row = db.prepare(
    'SELECT * FROM license_keys WHERE discord_id = ? ORDER BY redeemed_at DESC LIMIT 1'
  ).get(req.params.discord_id);
  if (!row) return res.json({ has_license: false });
  res.json({
    has_license: true,
    license: { key: row.key, plan: row.plan, expires_at: row.expires_at, redeemed_at: row.redeemed_at, expired: isExpired(row) }
  });
});

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
  console.log(`   DB:         ${DB_PATH}`);
  console.log(`   MOD_SECRET: ${MOD_SECRET}`);
  console.log('');
  console.log('Routes:');
  console.log('  POST /mod-auth     ← Minecraft mod calls this');
  console.log('  POST /redeem       ← Website key redemption');
  console.log('  POST /hwid-reset   ← User HWID reset (2/month)');
  console.log('  GET  /license/:id  ← Check license by Discord ID');
  console.log('  POST /bot/*        ← Discord bot routes');
});
