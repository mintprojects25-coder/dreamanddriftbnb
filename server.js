// Dream & Drift — Railway Express Server
// Full API backend connecting to Neon PostgreSQL

require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ─────────────────────────────────────────────────────────────
app.use(express.json());
app.use((req, res, next) => {
  // Allow all origins — Netlify frontend needs to reach this Railway API
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.setHeader('Access-Control-Allow-Credentials', 'false');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

// ── Database ───────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on('error', (err) => console.error('DB pool error:', err.message));

// ── JWT (no external lib) ──────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'dreamdrift-change-in-production';

function signToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body   = Buffer.from(JSON.stringify({ ...payload, iat: Date.now() })).toString('base64url');
  const sig    = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (Date.now() - payload.iat > 86400000) return null; // 24h expiry
    return payload;
  } catch { return null; }
}

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  const user = verifyToken(token);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  req.user = user;
  next();
}

// ── PUBLIC ROUTES ──────────────────────────────────────────────────────────

// Root route (Railway health check)
app.get('/', (req, res) => res.json({ service: 'Dream & Drift API', status: 'running' }));

// Health check
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected', ts: new Date().toISOString() });
  } catch (e) {
    res.json({ status: 'error', db: 'disconnected', error: e.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    const result = await pool.query('SELECT * FROM admin_users WHERE username = $1', [username]);
    if (!result.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    await pool.query('UPDATE admin_users SET last_login = NOW() WHERE id = $1', [user.id]);
    const token = signToken({ id: user.id, username: user.username });
    res.json({ success: true, token, username: user.username });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Settings (public — for rate display on frontend)
app.get('/api/settings', async (req, res) => {
  try {
    const result = await pool.query('SELECT setting_key, setting_value FROM settings');
    const s = {};
    result.rows.forEach(r => { s[r.setting_key] = r.setting_value; });
    res.json(s);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Pricing (public — for rate display on frontend)
app.get('/api/pricing', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM pricing WHERE active = true ORDER BY id');
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Submit enquiry (public — from contact form)
app.post('/api/enquiry', async (req, res) => {
  const { name, email, phone, checkin, checkout, guests, message } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email required' });
  try {
    const result = await pool.query(
      `INSERT INTO enquiries (name,email,phone,checkin,checkout,guests,message)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
      [name, email, phone||null, checkin||null, checkout||null, guests||2, message||'']
    );
    // Email via Resend (optional)
    if (process.env.RESEND_API_KEY) {
      try {
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from: 'Dream & Drift <notifications@driftanddream.co.za>',
            to: ['info@driftanddream.co.za'],
            subject: `New Enquiry from ${name}`,
            html: `<h2>New Enquiry — Dream &amp; Drift</h2>
              <p><b>Name:</b> ${name}</p><p><b>Email:</b> ${email}</p>
              <p><b>Phone:</b> ${phone||'—'}</p><p><b>Check-in:</b> ${checkin||'—'}</p>
              <p><b>Check-out:</b> ${checkout||'—'}</p><p><b>Guests:</b> ${guests||2}</p>
              <p><b>Message:</b><br>${message||'—'}</p>`
          })
        });
      } catch (emailErr) { console.warn('Email failed:', emailErr.message); }
    }
    res.json({ success: true, id: result.rows[0].id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Availability check (public)
app.get('/api/availability', async (req, res) => {
  const { checkin, checkout } = req.query;
  if (!checkin || !checkout) return res.status(400).json({ error: 'checkin and checkout required' });
  try {
    const conflicts = await pool.query(
      `SELECT id FROM bookings WHERE status != 'cancelled' AND checkin < $2 AND checkout > $1`,
      [checkin, checkout]
    );
    const blocked = await pool.query(
      `SELECT id FROM blocked_dates WHERE date_from < $2 AND date_to > $1`,
      [checkin, checkout]
    );
    res.json({ available: conflicts.rows.length === 0 && blocked.rows.length === 0 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── PROTECTED ROUTES ───────────────────────────────────────────────────────

// Bookings
app.get('/api/bookings', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM bookings ORDER BY checkin DESC');
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bookings', auth, async (req, res) => {
  const { name, email, phone, checkin, checkout, guests, amount, status, source, notes } = req.body;
  if (!name || !email || !checkin || !checkout) return res.status(400).json({ error: 'Missing required fields' });
  try {
    const result = await pool.query(
      `INSERT INTO bookings (guest_name,guest_email,guest_phone,checkin,checkout,guests,amount,status,source,notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [name, email, phone||'', checkin, checkout, guests||2, amount||0, status||'pending', source||'Direct', notes||'']
    );
    res.json({ success: true, booking: result.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/bookings/:id', auth, async (req, res) => {
  const { name, email, phone, checkin, checkout, guests, amount, status, source, notes } = req.body;
  try {
    await pool.query(
      `UPDATE bookings SET guest_name=$1,guest_email=$2,guest_phone=$3,checkin=$4,checkout=$5,
       guests=$6,amount=$7,status=$8,source=$9,notes=$10,updated_at=NOW() WHERE id=$11`,
      [name, email, phone||'', checkin, checkout, guests||2, amount||0, status||'pending', source||'Direct', notes||'', req.params.id]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/bookings/:id', auth, async (req, res) => {
  const { status } = req.body;
  if (!status) return res.status(400).json({ error: 'status required' });
  try {
    await pool.query('UPDATE bookings SET status=$1, updated_at=NOW() WHERE id=$2', [status, req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/bookings/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM bookings WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Enquiries
app.get('/api/enquiries', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM enquiries ORDER BY received_at DESC');
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/enquiries/:id', auth, async (req, res) => {
  const { status } = req.body;
  try {
    await pool.query('UPDATE enquiries SET status=$1 WHERE id=$2', [status||'read', req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/enquiries/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM enquiries WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Settings (protected PUT)
app.put('/api/settings', auth, async (req, res) => {
  try {
    for (const [key, value] of Object.entries(req.body)) {
      await pool.query(
        `INSERT INTO settings (setting_key, setting_value, updated_at) VALUES ($1,$2,NOW())
         ON CONFLICT (setting_key) DO UPDATE SET setting_value=$2, updated_at=NOW()`,
        [key, String(value)]
      );
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Pricing (protected PUT) - upsert each rate type
app.put('/api/pricing', auth, async (req, res) => {
  const { weeknight, weekend, longstay, holiday } = req.body;
  try {
    const upsert = async (rate_type, rate_name, amount) => {
      await pool.query(
        `INSERT INTO pricing (rate_name, rate_type, amount, active)
         VALUES ($1, $2, $3, true)
         ON CONFLICT (rate_type) DO UPDATE SET amount=$3, active=true`,
        [rate_name, rate_type, parseFloat(amount)]
      ).catch(async () => {
        // If ON CONFLICT on rate_type fails (no unique constraint), use UPDATE
        await pool.query(`UPDATE pricing SET amount=$1 WHERE rate_type=$2`, [parseFloat(amount), rate_type]);
      });
    };
    if (weeknight !== undefined) await upsert('base',         'Weeknight Rate (Mon-Thu)', weeknight);
    if (weekend   !== undefined) await upsert('weekend',      'Weekend Rate (Fri-Sat)',   weekend);
    if (longstay  !== undefined) await upsert('longstay',     'Long Stay (7+ nights)',    longstay);
    if (holiday   !== undefined) await upsert('public_holiday','Public Holiday Rate',     holiday);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Blocked dates
app.get('/api/blocked', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM blocked_dates ORDER BY date_from');
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/blocked', auth, async (req, res) => {
  const { date_from, date_to, reason } = req.body;
  if (!date_from || !date_to) return res.status(400).json({ error: 'date_from and date_to required' });
  try {
    const result = await pool.query(
      'INSERT INTO blocked_dates (date_from,date_to,reason) VALUES ($1,$2,$3) RETURNING *',
      [date_from, date_to, reason||'Blocked']
    );
    res.json({ success: true, blocked: result.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/blocked/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM blocked_dates WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Promotions
app.get('/api/promotions', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM promotions ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/promotions', auth, async (req, res) => {
  const { code, description, discount_type, discount_value, valid_from, valid_to, usage_limit, active } = req.body;
  if (!code || !discount_value) return res.status(400).json({ error: 'Code and discount_value required' });
  try {
    const result = await pool.query(
      `INSERT INTO promotions (code,description,discount_type,discount_value,valid_from,valid_to,usage_limit,active)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [code.toUpperCase(), description||'', discount_type||'percent', discount_value, valid_from||null, valid_to||null, usage_limit||null, active!==false]
    );
    res.json({ success: true, promotion: result.rows[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/promotions/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM promotions WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Reports
app.get('/api/reports', auth, async (req, res) => {
  try {
    const monthly = await pool.query(
      `SELECT DATE_TRUNC('month', checkin) AS month, SUM(amount) AS total, COUNT(*) AS bookings
       FROM bookings WHERE status != 'cancelled' GROUP BY month ORDER BY month DESC LIMIT 12`
    );
    const sources = await pool.query(
      `SELECT source, COUNT(*) AS count FROM bookings GROUP BY source ORDER BY count DESC`
    );
    res.json({ monthly: monthly.rows, sources: sources.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// iCal export
app.get('/api/calendar/export', auth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM bookings WHERE status != 'cancelled' ORDER BY checkin`);
    let lines = ['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//Dream & Drift//EN','CALSCALE:GREGORIAN','METHOD:PUBLISH'];
    for (const b of result.rows) {
      const ci = new Date(b.checkin).toISOString().split('T')[0].replace(/-/g,'');
      const co = new Date(b.checkout).toISOString().split('T')[0].replace(/-/g,'');
      lines.push('BEGIN:VEVENT',`UID:booking-${b.id}@driftanddream.co.za`,
        `DTSTART;VALUE=DATE:${ci}`,`DTEND;VALUE=DATE:${co}`,
        `SUMMARY:Booked - ${b.guest_name}`,'STATUS:CONFIRMED','END:VEVENT');
    }
    lines.push('END:VCALENDAR');
    res.setHeader('Content-Type','text/calendar');
    res.setHeader('Content-Disposition','attachment; filename="dreamdrift.ics"');
    res.send(lines.join('\r\n'));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Start Server ───────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Dream & Drift API running on port ${PORT}`);
  console.log(`   DB: ${process.env.DATABASE_URL ? 'configured' : '⚠️  DATABASE_URL not set'}`);
});

module.exports = app;
