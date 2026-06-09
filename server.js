// ═══════════════════════════════════════════════════════════════
//  BLIZZARD BACKEND  —  server.js
//  npm install express cors pg uuid adm-zip
// ═══════════════════════════════════════════════════════════════

const express  = require('express');
const cors     = require('cors');
const { Pool } = require('pg');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');
const AdmZip   = require('adm-zip');

const app  = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway.internal')
    ? false
    : { rejectUnauthorized: false }
});

const db = {
  get:  async (sql, params = []) => { const r = await pool.query(sql, params); return r.rows[0] ?? null; },
  all:  async (sql, params = []) => { const r = await pool.query(sql, params); return r.rows; },
  run:  async (sql, params = []) => { await pool.query(sql, params); },
};

const PORT       = process.env.PORT || 8000;
const BOT_SECRET = process.env.BOT_SECRET || 'change-this-secret-123';
const MOD_SECRET = process.env.MOD_SECRET || 'mgvSs0NvrAqFubgMpdEaXS1TFNz2W3GDJcJGA6Tu8qz3Am3V7GaS8gfnDWqZrDK7';

// ── Robust download directory resolution ──────────────────────
// Try multiple candidate paths so it works regardless of CWD or __dirname
const DOWNLOAD_CANDIDATES = [
  path.join(__dirname, 'downloads'),
  path.join(process.cwd(), 'downloads'),
  '/app/downloads',
];

function findJar() {
  for (const dir of DOWNLOAD_CANDIDATES) {
    const jarPath = path.join(dir, 'blizzard-obfuscated.jar');
    if (fs.existsSync(jarPath)) {
      console.log(`✅ Found jar at: ${jarPath}`);
      return jarPath;
    }
    console.log(`   Not found: ${jarPath}`);
  }
  return null;
}

// Log paths at startup so you can see exactly what's happening in Railway logs
console.log('=== PATH DIAGNOSTICS ===');
console.log('__dirname  :', __dirname);
console.log('process.cwd:', process.cwd());
DOWNLOAD_CANDIDATES.forEach(d => {
  console.log(`  ${d} → exists: ${fs.existsSync(d)}`);
  if (fs.existsSync(d)) {
    try { console.log('    contents:', fs.readdirSync(d)); } catch(e) {}
  }
});
console.log('========================');

app.use(cors({
  origin: [
    'https://blizzardclient.netlify.app',
    'http://localhost:3000',
    'http://127.0.0.1:5500'
  ]
}));
app.use(express.json());

// ── DATABASE ──────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS license_keys (
      key              TEXT PRIMARY KEY,
      plan             TEXT NOT NULL,
      expires_at       TIMESTAMPTZ,
      used             INTEGER DEFAULT 0,
      discord_id       TEXT,
      redeemed_at      TIMESTAMPTZ,
      created_at       TIMESTAMPTZ NOT NULL,
      note             TEXT,
      hwid             TEXT,
      hwid_locked_at   TIMESTAMPTZ,
      hwid_reset_count INTEGER DEFAULT 0,
      hwid_reset_month TEXT
    );

    CREATE TABLE IF NOT EXISTS downloads (
      id            SERIAL PRIMARY KEY,
      discord_id    TEXT NOT NULL,
      key_used      TEXT NOT NULL,
      downloaded_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS auth_log (
      id        SERIAL PRIMARY KEY,
      key_used  TEXT NOT NULL,
      hwid      TEXT NOT NULL,
      result    TEXT NOT NULL,
      ip        TEXT,
      timestamp TIMESTAMPTZ NOT NULL
    );
  `);
}

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

function requireBotSecret(req, res, next) {
  if (req.headers['x-bot-secret'] !== BOT_SECRET)
    return res.status(401).json({ error: 'Unauthorized' });
  next();
}

async function logAuth(key, hwid, result, ip) {
  await db.run(
    'INSERT INTO auth_log (key_used, hwid, result, ip, timestamp) VALUES ($1, $2, $3, $4, $5)',
    [key, hwid, result, ip, new Date().toISOString()]
  );
}

function currentMonth() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

// ════════════════════════════════════════════════════════════════
//  MOD AUTH  —  POST /mod-auth
// ════════════════════════════════════════════════════════════════
app.post('/mod-auth', async (req, res) => {
  const { discord_id, hwid, signature } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!discord_id || !hwid || !signature) {
    return res.json({ valid: false, reason: 'MISSING_FIELDS' });
  }

  const expected = crypto.createHash('sha256')
    .update(discord_id + hwid + MOD_SECRET)
    .digest('hex');

  if (expected !== signature) {
    await logAuth('none', hwid, 'bad_signature', ip);
    return res.json({ valid: false, reason: 'BAD_SIGNATURE' });
  }

  const row = await db.get(
    'SELECT * FROM license_keys WHERE discord_id = $1 AND used = 1 ORDER BY redeemed_at DESC LIMIT 1',
    [discord_id]
  );

  if (!row) {
    await logAuth('none', hwid, 'no_license', ip);
    return res.json({ valid: false, reason: 'NO_LICENSE' });
  }

  if (isExpired(row)) {
    await logAuth(row.key, hwid, 'expired', ip);
    return res.json({ valid: false, reason: 'EXPIRED' });
  }

  if (!row.hwid) {
    await db.run(
      'UPDATE license_keys SET hwid=$1, hwid_locked_at=$2 WHERE key=$3',
      [hwid, new Date().toISOString(), row.key]
    );
    await logAuth(row.key, hwid, 'ok_hwid_bound', ip);
  } else if (row.hwid !== hwid) {
    await logAuth(row.key, hwid, 'hwid_mismatch', ip);
    return res.json({ valid: false, reason: 'HWID_MISMATCH' });
  } else {
    await logAuth(row.key, hwid, 'ok', ip);
  }

  res.json({
    valid: true,
    plan: row.plan,
    expires_at: row.expires_at,
    session_token: crypto.createHash('sha256')
      .update(discord_id + hwid + MOD_SECRET + new Date().toDateString())
      .digest('hex')
  });
});

// ════════════════════════════════════════════════════════════════
//  HWID RESET  —  POST /hwid-reset
// ════════════════════════════════════════════════════════════════
app.post('/hwid-reset', async (req, res) => {
  const { discord_id, key } = req.body;
  if (!discord_id || !key)
    return res.status(400).json({ success: false, error: 'Missing fields' });

  const row = await db.get(
    'SELECT * FROM license_keys WHERE key = $1 AND discord_id = $2',
    [key, discord_id]
  );

  if (!row)           return res.json({ success: false, error: 'License not found.' });
  if (!row.used)      return res.json({ success: false, error: 'Key not yet activated.' });
  if (isExpired(row)) return res.json({ success: false, error: 'Your license has expired.' });
  if (!row.hwid)      return res.json({ success: false, error: 'No HWID is bound yet.' });

  const month = currentMonth();
  let resetCount = row.hwid_reset_count || 0;
  if (row.hwid_reset_month !== month) resetCount = 0;

  if (resetCount >= 2) {
    return res.json({
      success: false,
      error: `You have used both HWID resets for ${month}. Resets refresh on the 1st of next month.`,
      resets_used: resetCount,
      resets_left: 0
    });
  }

  await db.run(
    'UPDATE license_keys SET hwid=NULL, hwid_locked_at=NULL, hwid_reset_count=$1, hwid_reset_month=$2 WHERE key=$3',
    [resetCount + 1, month, key]
  );

  res.json({
    success: true,
    resets_used: resetCount + 1,
    resets_left: 2 - (resetCount + 1),
    message: `HWID reset! Your next launch will bind to your new PC. You have ${2 - (resetCount + 1)} reset(s) left this month.`
  });
});

app.get('/hwid-status/:discord_id', async (req, res) => {
  const row = await db.get(
    'SELECT hwid, hwid_reset_count, hwid_reset_month FROM license_keys WHERE discord_id = $1 AND used = 1 ORDER BY redeemed_at DESC LIMIT 1',
    [req.params.discord_id]
  );

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
app.post('/bot/genkey', requireBotSecret, async (req, res) => {
  const { plan, note } = req.body;
  if (!['monthly', 'lifetime'].includes(plan))
    return res.status(400).json({ error: 'plan must be monthly or lifetime' });
  const key = generateKey(plan);
  await db.run(
    'INSERT INTO license_keys (key, plan, expires_at, used, created_at, note) VALUES ($1, $2, NULL, 0, $3, $4)',
    [key, plan, new Date().toISOString(), note || null]
  );
  res.json({ success: true, key, plan });
});

app.post('/bot/bulkgen', requireBotSecret, async (req, res) => {
  const { plan, note } = req.body;
  let { amount } = req.body;
  amount = parseInt(amount, 10);
  if (!['monthly', 'lifetime'].includes(plan))
    return res.status(400).json({ error: 'plan must be monthly or lifetime' });
  if (!amount || amount < 1)
    return res.status(400).json({ error: 'amount must be at least 1' });

  const keys = Array.from({ length: amount }, () => generateKey(plan));
  const now  = new Date().toISOString();

  const values = keys.map((k, i) => `($${i * 4 + 1}, $${i * 4 + 2}, 0, $${i * 4 + 3}, $${i * 4 + 4})`).join(', ');
  const params = keys.flatMap(k => [k, plan, now, note || null]);
  await db.run(
    `INSERT INTO license_keys (key, plan, used, created_at, note) VALUES ${values}`,
    params
  );

  res.json({ success: true, keys, plan, amount: keys.length });
});

app.get('/bot/keyinfo/:key', requireBotSecret, async (req, res) => {
  const row = await db.get('SELECT * FROM license_keys WHERE key = $1', [req.params.key]);
  if (!row) return res.status(404).json({ error: 'Key not found' });
  res.json({ ...row, expired: isExpired(row) });
});

app.get('/bot/keyinfo/by-discord/:discord_id', requireBotSecret, async (req, res) => {
  const row = await db.get(
    'SELECT * FROM license_keys WHERE discord_id = $1 ORDER BY redeemed_at DESC LIMIT 1',
    [req.params.discord_id]
  );
  if (!row) return res.status(404).json({ error: 'No license found for this Discord user' });
  res.json({ ...row, expired: isExpired(row) });
});

app.post('/bot/revokekey', requireBotSecret, async (req, res) => {
  const { key } = req.body;
  if (!await db.get('SELECT key FROM license_keys WHERE key = $1', [key]))
    return res.status(404).json({ error: 'Key not found' });
  await db.run('DELETE FROM license_keys WHERE key = $1', [key]);
  res.json({ success: true });
});

app.post('/bot/resethwid', requireBotSecret, async (req, res) => {
  const { key } = req.body;
  if (!await db.get('SELECT key FROM license_keys WHERE key = $1', [key]))
    return res.status(404).json({ error: 'Key not found' });
  await db.run(
    'UPDATE license_keys SET hwid=NULL, hwid_locked_at=NULL, hwid_reset_count=0, hwid_reset_month=NULL WHERE key=$1',
    [key]
  );
  res.json({ success: true, message: 'HWID reset. Next launch will bind to new PC.' });
});

app.get('/bot/listkeys', requireBotSecret, async (req, res) => {
  const { plan, unused } = req.query;
  let sql = 'SELECT * FROM license_keys WHERE 1=1';
  const params = [];
  let i = 1;
  if (plan)   { sql += ` AND plan = $${i++}`;  params.push(plan); }
  if (unused) { sql += ' AND used = 0'; }
  sql += ' ORDER BY created_at DESC LIMIT 50';
  res.json(await db.all(sql, params));
});

app.get('/bot/authlog', requireBotSecret, async (req, res) => {
  res.json(await db.all('SELECT * FROM auth_log ORDER BY timestamp DESC LIMIT 50'));
});

// ════════════════════════════════════════════════════════════════
//  WEBSITE ROUTES
// ════════════════════════════════════════════════════════════════
app.post('/redeem', async (req, res) => {
  const { discord_id, key } = req.body;
  if (!discord_id || !key)
    return res.status(400).json({ success: false, error: 'Missing fields' });

  const row = await db.get('SELECT * FROM license_keys WHERE key = $1', [key]);
  if (!row) return res.json({ success: false, error: 'Invalid or unknown key.' });

  if (row.used) {
    if (row.discord_id === discord_id)
      return res.json({
        success: true,
        license: {
          key: row.key,
          plan: row.plan,
          expires_at: row.expires_at,
          redeemed_at: row.redeemed_at,
          expired: isExpired(row)
        }
      });
    return res.json({ success: false, error: 'Key already used by another account.' });
  }

  const now        = new Date().toISOString();
  const expires_at = row.plan === 'monthly' ? addMonths(new Date(), 1) : null;
  await db.run(
    'UPDATE license_keys SET used=1, discord_id=$1, redeemed_at=$2, expires_at=$3 WHERE key=$4',
    [discord_id, now, expires_at, key]
  );

  res.json({
    success: true,
    license: { key, plan: row.plan, expires_at, redeemed_at: now, expired: false }
  });
});

app.get('/license/:discord_id', async (req, res) => {
  const row = await db.get(
    'SELECT * FROM license_keys WHERE discord_id = $1 ORDER BY redeemed_at DESC LIMIT 1',
    [req.params.discord_id]
  );
  if (!row) return res.json({ has_license: false });
  res.json({
    has_license: true,
    license: {
      key: row.key,
      plan: row.plan,
      expires_at: row.expires_at,
      redeemed_at: row.redeemed_at,
      expired: isExpired(row)
    }
  });
});

// ════════════════════════════════════════════════════════════════
//  DOWNLOAD  —  GET /download/:filename
// ════════════════════════════════════════════════════════════════
app.get('/download/:filename', async (req, res) => {
  const { discord_id, key } = req.query;
  if (!discord_id || !key) return res.status(403).send('Missing credentials');

  const row = await db.get(
    'SELECT * FROM license_keys WHERE key = $1 AND discord_id = $2',
    [key, discord_id]
  );

  if (!row || !row.used || isExpired(row))
    return res.status(403).send('No valid license.');

  // Find the jar across candidate paths
  const jarPath = findJar();
  if (!jarPath) {
    console.error('Jar not found. Searched:', DOWNLOAD_CANDIDATES.map(d => path.join(d, 'blizzard-obfuscated.jar')));
    return res.status(404).send('File not found. Please contact support.');
  }

  try {
    const zip = new AdmZip(jarPath);
    zip.addFile('blizzard_user.txt', Buffer.from(discord_id, 'utf8'));
    const outputBuffer = zip.toBuffer();

    await db.run(
      'INSERT INTO downloads (discord_id, key_used, downloaded_at) VALUES ($1, $2, $3)',
      [discord_id, key, new Date().toISOString()]
    );

    res.setHeader('Content-Disposition', `attachment; filename="BlizzardClient.jar"`);
    res.setHeader('Content-Type', 'application/java-archive');
    res.send(outputBuffer);

  } catch (err) {
    console.error('Jar injection failed:', err);
    res.status(500).send('Failed to generate mod file.');
  }
});

// ── START ─────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ Blizzard API running on port ${PORT}`);
  });
}).catch(err => {
  console.error('❌ Failed to init DB:', err);
  process.exit(1);
});
