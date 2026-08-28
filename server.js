// ═══════════════════════════════════════════════════════════════
//  BLIZZARD BACKEND — server.js
//  Northflank-ready
// ═══════════════════════════════════════════════════════════════

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

const app = express();

// ── DATABASE ──────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost')
    ? false
    : { rejectUnauthorized: false }
});

const db = {
  get: async (sql, params = []) => {
    const r = await pool.query(sql, params);
    return r.rows[0] ?? null;
  },

  all: async (sql, params = []) => {
    const r = await pool.query(sql, params);
    return r.rows;
  },

  run: async (sql, params = []) => {
    await pool.query(sql, params);
  }
};

// ── CONFIG ────────────────────────────────────────────────────
const PORT = process.env.PORT || 8000;

const BOT_SECRET = process.env.BOT_SECRET;
const MOD_SECRET = process.env.MOD_SECRET;

if (!BOT_SECRET || !MOD_SECRET) {
  console.error('❌ BOT_SECRET and MOD_SECRET must be configured.');
  process.exit(1);
}

// ── MOD SIGNING KEY ───────────────────────────────────────────
const MOD_SIGNING_KEY_B64 = process.env.MOD_SIGNING_KEY;

const signingKey = MOD_SIGNING_KEY_B64
  ? crypto.createPrivateKey({
      key: Buffer.from(MOD_SIGNING_KEY_B64, 'base64'),
      format: 'der',
      type: 'pkcs8'
    })
  : null;

if (!signingKey) {
  console.warn('⚠️ MOD_SIGNING_KEY not set — /mod-auth responses will fail to sign.');
}

function signedResponse(payloadObj) {
  const payload = JSON.stringify(payloadObj);

  if (!signingKey) {
    throw new Error('MOD_SIGNING_KEY not configured');
  }

  const sig = crypto
    .sign(null, Buffer.from(payload, 'utf8'), signingKey)
    .toString('base64');

  return { payload, sig };
}

// ── JAR PATH ──────────────────────────────────────────────────
const JAR_PATH =
  process.env.JAR_PATH ||
  path.join(__dirname, 'downloads', 'blizzard-obfuscated.jar');

console.log('=== PATH DIAGNOSTICS ===');
console.log('__dirname  :', __dirname);
console.log('JAR_PATH   :', JAR_PATH);
console.log('JAR exists :', fs.existsSync(JAR_PATH));
console.log('========================');

function findJar() {
  if (fs.existsSync(JAR_PATH)) {
    console.log(`✅ Found jar at: ${JAR_PATH}`);
    return JAR_PATH;
  }

  console.error(`❌ Jar not found at: ${JAR_PATH}`);
  return null;
}

// ── CORS ──────────────────────────────────────────────────────
app.use(cors({
  origin: [
    'https://blizzardclient.netlify.app',
    'http://localhost:3000',
    'http://127.0.0.1:5500'
  ]
}));

app.use(express.json());

// ═══════════════════════════════════════════════════════════════
//  HEALTH CHECK
// ═══════════════════════════════════════════════════════════════

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

// ═══════════════════════════════════════════════════════════════
//  DATABASE
// ═══════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════

function generateKey(plan) {
  const seg = () =>
    Math.random().toString(16).slice(2, 6).toUpperCase();

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
  if (req.headers['x-bot-secret'] !== BOT_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  next();
}

async function logAuth(key, hwid, result, ip) {
  await db.run(
    `INSERT INTO auth_log
      (key_used, hwid, result, ip, timestamp)
     VALUES ($1, $2, $3, $4, $5)`,
    [
      key,
      hwid,
      result,
      ip,
      new Date().toISOString()
    ]
  );
}

function currentMonth() {
  const d = new Date();

  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

// ═══════════════════════════════════════════════════════════════
//  MOD AUTH
//  POST /mod-auth
// ═══════════════════════════════════════════════════════════════

app.post('/mod-auth', async (req, res) => {
  try {
    const { discord_id, hwid, signature, ts } = req.body;

    const ip =
      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      req.socket.remoteAddress ||
      '';

    if (!discord_id || !hwid || !signature || !ts) {
      return res.json(
        signedResponse({
          valid: false,
          reason: 'MISSING_FIELDS',
          ts: Date.now().toString()
        })
      );
    }

    const age = Date.now() - parseInt(ts, 10);

    if (isNaN(age) || Math.abs(age) > 60_000) {
      return res.json(
        signedResponse({
          valid: false,
          reason: 'STALE_REQUEST',
          ts: Date.now().toString()
        })
      );
    }

    const expected = crypto
      .createHash('sha256')
      .update(discord_id + hwid + ts + MOD_SECRET)
      .digest('hex');

    if (expected !== signature) {
      await logAuth('none', hwid, 'bad_signature', ip);

      return res.json(
        signedResponse({
          valid: false,
          reason: 'BAD_SIGNATURE',
          ts: Date.now().toString()
        })
      );
    }

    const row = await db.get(
      `SELECT *
       FROM license_keys
       WHERE discord_id = $1
         AND used = 1
       ORDER BY redeemed_at DESC
       LIMIT 1`,
      [discord_id]
    );

    if (!row) {
      await logAuth('none', hwid, 'no_license', ip);

      return res.json(
        signedResponse({
          valid: false,
          reason: 'NO_LICENSE',
          ts: Date.now().toString()
        })
      );
    }

    if (isExpired(row)) {
      await logAuth(row.key, hwid, 'expired', ip);

      return res.json(
        signedResponse({
          valid: false,
          reason: 'EXPIRED',
          ts: Date.now().toString()
        })
      );
    }

    if (!row.hwid) {
      await db.run(
        `UPDATE license_keys
         SET hwid = $1,
             hwid_locked_at = $2
         WHERE key = $3`,
        [
          hwid,
          new Date().toISOString(),
          row.key
        ]
      );

      await logAuth(row.key, hwid, 'ok_hwid_bound', ip);
    } else if (row.hwid !== hwid) {
      await logAuth(row.key, hwid, 'hwid_mismatch', ip);

      return res.json(
        signedResponse({
          valid: false,
          reason: 'HWID_MISMATCH',
          ts: Date.now().toString()
        })
      );
    } else {
      await logAuth(row.key, hwid, 'ok', ip);
    }

    return res.json(
      signedResponse({
        valid: true,
        plan: row.plan,
        reason: '',
        session_token: crypto
          .createHash('sha256')
          .update(
            discord_id +
            hwid +
            MOD_SECRET +
            new Date().toDateString()
          )
          .digest('hex'),
        ts: Date.now().toString()
      })
    );

  } catch (err) {
    console.error('❌ /mod-auth error:', err);

    return res.status(500).json({
      error: 'Internal server error'
    });
  }
});

// ═══════════════════════════════════════════════════════════════
//  HWID RESET
// ═══════════════════════════════════════════════════════════════

app.post('/hwid-reset', async (req, res) => {
  try {
    const { discord_id, key } = req.body;

    if (!discord_id || !key) {
      return res.status(400).json({
        success: false,
        error: 'Missing fields'
      });
    }

    const row = await db.get(
      `SELECT *
       FROM license_keys
       WHERE key = $1
         AND discord_id = $2`,
      [key, discord_id]
    );

    if (!row) {
      return res.json({
        success: false,
        error: 'License not found.'
      });
    }

    if (!row.used) {
      return res.json({
        success: false,
        error: 'Key not yet activated.'
      });
    }

    if (isExpired(row)) {
      return res.json({
        success: false,
        error: 'Your license has expired.'
      });
    }

    if (!row.hwid) {
      return res.json({
        success: false,
        error: 'No HWID is bound yet.'
      });
    }

    const month = currentMonth();

    let resetCount = row.hwid_reset_count || 0;

    if (row.hwid_reset_month !== month) {
      resetCount = 0;
    }

    if (resetCount >= 2) {
      return res.json({
        success: false,
        error: `You have used both HWID resets for ${month}. Resets refresh on the 1st of next month.`,
        resets_used: resetCount,
        resets_left: 0
      });
    }

    await db.run(
      `UPDATE license_keys
       SET hwid = NULL,
           hwid_locked_at = NULL,
           hwid_reset_count = $1,
           hwid_reset_month = $2
       WHERE key = $3`,
      [
        resetCount + 1,
        month,
        key
      ]
    );

    return res.json({
      success: true,
      resets_used: resetCount + 1,
      resets_left: 2 - (resetCount + 1),
      message: `HWID reset! Your next launch will bind to your new PC. You have ${2 - (resetCount + 1)} reset(s) left this month.`
    });

  } catch (err) {
    console.error('❌ /hwid-reset error:', err);

    return res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

app.get('/hwid-status/:discord_id', async (req, res) => {
  try {
    const row = await db.get(
      `SELECT
         hwid,
         hwid_reset_count,
         hwid_reset_month
       FROM license_keys
       WHERE discord_id = $1
         AND used = 1
       ORDER BY redeemed_at DESC
       LIMIT 1`,
      [req.params.discord_id]
    );

    if (!row) {
      return res.json({
        found: false
      });
    }

    const month = currentMonth();

    const resetCount =
      row.hwid_reset_month === month
        ? (row.hwid_reset_count || 0)
        : 0;

    return res.json({
      found: true,
      hwid_bound: !!row.hwid,
      resets_used: resetCount,
      resets_left: 2 - resetCount
    });

  } catch (err) {
    console.error('❌ /hwid-status error:', err);

    return res.status(500).json({
      error: 'Internal server error'
    });
  }
});

// ═══════════════════════════════════════════════════════════════
//  BOT ROUTES
// ═══════════════════════════════════════════════════════════════

app.post('/bot/genkey', requireBotSecret, async (req, res) => {
  try {
    const { plan, note } = req.body;

    if (!['monthly', 'lifetime'].includes(plan)) {
      return res.status(400).json({
        error: 'plan must be monthly or lifetime'
      });
    }

    const key = generateKey(plan);

    await db.run(
      `INSERT INTO license_keys
        (key, plan, expires_at, used, created_at, note)
       VALUES ($1, $2, NULL, 0, $3, $4)`,
      [
        key,
        plan,
        new Date().toISOString(),
        note || null
      ]
    );

    return res.json({
      success: true,
      key,
      plan
    });

  } catch (err) {
    console.error('❌ /bot/genkey error:', err);

    return res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.post('/bot/bulkgen', requireBotSecret, async (req, res) => {
  try {
    const { plan, note } = req.body;

    let { amount } = req.body;

    amount = parseInt(amount, 10);

    if (!['monthly', 'lifetime'].includes(plan)) {
      return res.status(400).json({
        error: 'plan must be monthly or lifetime'
      });
    }

    if (!amount || amount < 1) {
      return res.status(400).json({
        error: 'amount must be at least 1'
      });
    }

    const keys = Array.from(
      { length: amount },
      () => generateKey(plan)
    );

    const now = new Date().toISOString();

    const values = keys
      .map(
        (_, i) =>
          `($${i * 4 + 1}, $${i * 4 + 2}, 0, $${i * 4 + 3}, $${i * 4 + 4})`
      )
      .join(', ');

    const params = keys.flatMap(k => [
      k,
      plan,
      now,
      note || null
    ]);

    await db.run(
      `INSERT INTO license_keys
        (key, plan, used, created_at, note)
       VALUES ${values}`,
      params
    );

    return res.json({
      success: true,
      keys,
      plan,
      amount: keys.length
    });

  } catch (err) {
    console.error('❌ /bot/bulkgen error:', err);

    return res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.get('/bot/keyinfo/:key', requireBotSecret, async (req, res) => {
  try {
    const row = await db.get(
      'SELECT * FROM license_keys WHERE key = $1',
      [req.params.key]
    );

    if (!row) {
      return res.status(404).json({
        error: 'Key not found'
      });
    }

    return res.json({
      ...row,
      expired: isExpired(row)
    });

  } catch (err) {
    console.error('❌ /bot/keyinfo error:', err);

    return res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.get('/bot/keyinfo/by-discord/:discord_id', requireBotSecret, async (req, res) => {
  try {
    const row = await db.get(
      `SELECT *
       FROM license_keys
       WHERE discord_id = $1
       ORDER BY redeemed_at DESC
       LIMIT 1`,
      [req.params.discord_id]
    );

    if (!row) {
      return res.status(404).json({
        error: 'No license found for this Discord user'
      });
    }

    return res.json({
      ...row,
      expired: isExpired(row)
    });

  } catch (err) {
    console.error('❌ /bot/keyinfo/by-discord error:', err);

    return res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.post('/bot/revokekey', requireBotSecret, async (req, res) => {
  try {
    const { key } = req.body;

    if (!await db.get(
      'SELECT key FROM license_keys WHERE key = $1',
      [key]
    )) {
      return res.status(404).json({
        error: 'Key not found'
      });
    }

    await db.run(
      'DELETE FROM license_keys WHERE key = $1',
      [key]
    );

    return res.json({
      success: true
    });

  } catch (err) {
    console.error('❌ /bot/revokekey error:', err);

    return res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.post('/bot/resethwid', requireBotSecret, async (req, res) => {
  try {
    const { key } = req.body;

    if (!await db.get(
      'SELECT key FROM license_keys WHERE key = $1',
      [key]
    )) {
      return res.status(404).json({
        error: 'Key not found'
      });
    }

    await db.run(
      `UPDATE license_keys
       SET hwid = NULL,
           hwid_locked_at = NULL,
           hwid_reset_count = 0,
           hwid_reset_month = NULL
       WHERE key = $1`,
      [key]
    );

    return res.json({
      success: true,
      message: 'HWID reset. Next launch will bind to new PC.'
    });

  } catch (err) {
    console.error('❌ /bot/resethwid error:', err);

    return res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.get('/bot/listkeys', requireBotSecret, async (req, res) => {
  try {
    const { plan, unused } = req.query;

    let sql = 'SELECT * FROM license_keys WHERE 1=1';

    const params = [];

    let i = 1;

    if (plan) {
      sql += ` AND plan = $${i++}`;
      params.push(plan);
    }

    if (unused) {
      sql += ' AND used = 0';
    }

    sql += ' ORDER BY created_at DESC LIMIT 50';

    return res.json(
      await db.all(sql, params)
    );

  } catch (err) {
    console.error('❌ /bot/listkeys error:', err);

    return res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.get('/bot/authlog', requireBotSecret, async (req, res) => {
  try {
    return res.json(
      await db.all(
        'SELECT * FROM auth_log ORDER BY timestamp DESC LIMIT 50'
      )
    );

  } catch (err) {
    console.error('❌ /bot/authlog error:', err);

    return res.status(500).json({
      error: 'Internal server error'
    });
  }
});

// ═══════════════════════════════════════════════════════════════
//  WEBSITE ROUTES
// ═══════════════════════════════════════════════════════════════

app.post('/redeem', async (req, res) => {
  try {
    const { discord_id, key } = req.body;

    if (!discord_id || !key) {
      return res.status(400).json({
        success: false,
        error: 'Missing fields'
      });
    }

    const row = await db.get(
      'SELECT * FROM license_keys WHERE key = $1',
      [key]
    );

    if (!row) {
      return res.json({
        success: false,
        error: 'Invalid or unknown key.'
      });
    }

    if (row.used) {
      if (row.discord_id === discord_id) {
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
      }

      return res.json({
        success: false,
        error: 'Key already used by another account.'
      });
    }

    const now = new Date().toISOString();

    const expires_at =
      row.plan === 'monthly'
        ? addMonths(new Date(), 1)
        : null;

    await db.run(
      `UPDATE license_keys
       SET used = 1,
           discord_id = $1,
           redeemed_at = $2,
           expires_at = $3
       WHERE key = $4`,
      [
        discord_id,
        now,
        expires_at,
        key
      ]
    );

    return res.json({
      success: true,
      license: {
        key,
        plan: row.plan,
        expires_at,
        redeemed_at: now,
        expired: false
      }
    });

  } catch (err) {
    console.error('❌ /redeem error:', err);

    return res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

app.get('/license/:discord_id', async (req, res) => {
  try {
    const row = await db.get(
      `SELECT *
       FROM license_keys
       WHERE discord_id = $1
       ORDER BY redeemed_at DESC
       LIMIT 1`,
      [req.params.discord_id]
    );

    if (!row) {
      return res.json({
        has_license: false
      });
    }

    return res.json({
      has_license: true,
      license: {
        key: row.key,
        plan: row.plan,
        expires_at: row.expires_at,
        redeemed_at: row.redeemed_at,
        expired: isExpired(row)
      }
    });

  } catch (err) {
    console.error('❌ /license error:', err);

    return res.status(500).json({
      error: 'Internal server error'
    });
  }
});

// ═══════════════════════════════════════════════════════════════
//  DOWNLOAD
//  GET /download/:filename
// ═══════════════════════════════════════════════════════════════

app.get('/download/:filename', async (req, res) => {
  try {
    const { discord_id, key } = req.query;

    if (!discord_id || !key) {
      return res.status(403).send('Missing credentials');
    }

    const row = await db.get(
      `SELECT *
       FROM license_keys
       WHERE key = $1
         AND discord_id = $2`,
      [key, discord_id]
    );

    if (!row || !row.used || isExpired(row)) {
      return res.status(403).send('No valid license.');
    }

    const jarPath = findJar();

    if (!jarPath) {
      return res.status(404).send(
        'File not found. Please contact support.'
      );
    }

    const zip = new AdmZip(jarPath);

    zip.addFile(
      'blizzard_user.txt',
      Buffer.from(discord_id, 'utf8')
    );

    const outputBuffer = zip.toBuffer();

    await db.run(
      `INSERT INTO downloads
        (discord_id, key_used, downloaded_at)
       VALUES ($1, $2, $3)`,
      [
        discord_id,
        key,
        new Date().toISOString()
      ]
    );

    res.setHeader(
      'Content-Disposition',
      'attachment; filename="BlizzardClient.jar"'
    );

    res.setHeader(
      'Content-Type',
      'application/java-archive'
    );

    return res.send(outputBuffer);

  } catch (err) {
    console.error('❌ Jar injection failed:', err);

    return res.status(500).send(
      'Failed to generate mod file.'
    );
  }
});

// ═══════════════════════════════════════════════════════════════
//  START
// ═══════════════════════════════════════════════════════════════

app.listen(PORT, () => {
  console.log(`✅ Blizzard API running on port ${PORT}`);
  console.log(`🌐 Listening on port ${PORT}`);
});

// ── DATABASE INITIALIZATION ──────────────────────────────────
pool.connect()
  .then(client => {
    client.release();

    console.log('✅ DB connected');

    return initDB();
  })
  .then(() => {
    console.log('✅ DB initialised');
  })
  .catch(err => {
    console.error('❌ DB init failed:', err.message);
    process.exit(1);
  });
