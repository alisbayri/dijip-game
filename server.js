const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-please-set-env';
const DATABASE_URL = process.env.DATABASE_URL;

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(__dirname, { maxAge: '1h', setHeaders: (res, p) => { if (p.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache'); } }));

const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL, ssl: false }) : null;

async function initDb() {
  if (!pool) { console.warn('No DATABASE_URL — running without DB'); return; }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS game_states (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      state JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_game_states_updated ON game_states(updated_at DESC);
    CREATE TABLE IF NOT EXISTS surveys (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      answers JSONB NOT NULL,
      submitted_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_surveys_user ON surveys(user_id);
  `);
  console.log('DB schema ready');
}

function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '90d' });
}

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'Yetki yok' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Oturum süresi doldu' });
  }
}

function requireDb(_req, res, next) {
  if (!pool) return res.status(503).json({ error: 'Veritabanı hazır değil' });
  next();
}

const EMAIL_RX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.post('/api/register', requireDb, async (req, res) => {
  const { email, name, password } = req.body || {};
  if (!email || !name || !password) return res.status(400).json({ error: 'Tüm alanları doldur' });
  if (!EMAIL_RX.test(email)) return res.status(400).json({ error: 'Geçersiz e-posta adresi' });
  if (password.length < 6) return res.status(400).json({ error: 'Şifre en az 6 karakter olmalı' });
  if (name.trim().length < 2) return res.status(400).json({ error: 'İsim en az 2 karakter olmalı' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      'INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3) RETURNING id, email, name',
      [email.toLowerCase().trim(), name.trim(), hash]
    );
    const user = r.rows[0];
    const token = signToken(user);
    res.json({ token, user });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Bu e-posta zaten kayıtlı' });
    console.error('register error:', e);
    res.status(500).json({ error: 'Kayıt sırasında bir hata oluştu' });
  }
});

app.post('/api/login', requireDb, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'E-posta ve şifre gerekli' });
  try {
    const r = await pool.query(
      'SELECT id, email, name, password_hash FROM users WHERE email = $1',
      [email.toLowerCase().trim()]
    );
    if (!r.rows.length) return res.status(401).json({ error: 'E-posta ya da şifre hatalı' });
    const u = r.rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'E-posta ya da şifre hatalı' });
    const token = signToken(u);
    res.json({ token, user: { id: u.id, email: u.email, name: u.name } });
  } catch (e) {
    console.error('login error:', e);
    res.status(500).json({ error: 'Giriş sırasında bir hata oluştu' });
  }
});

app.get('/api/me', auth, (req, res) => {
  res.json({ user: { id: req.user.id, email: req.user.email, name: req.user.name } });
});

app.get('/api/state', auth, requireDb, async (req, res) => {
  try {
    const r = await pool.query('SELECT state FROM game_states WHERE user_id = $1', [req.user.id]);
    res.json({ state: r.rows[0]?.state || null });
  } catch (e) {
    console.error('state get error:', e);
    res.status(500).json({ error: 'Veri yüklenemedi' });
  }
});

app.post('/api/state', auth, requireDb, async (req, res) => {
  const state = req.body || {};
  if (typeof state !== 'object') return res.status(400).json({ error: 'Geçersiz veri' });
  try {
    await pool.query(
      `INSERT INTO game_states (user_id, state, updated_at) VALUES ($1, $2, NOW())
       ON CONFLICT (user_id) DO UPDATE SET state = EXCLUDED.state, updated_at = NOW()`,
      [req.user.id, state]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('state save error:', e);
    res.status(500).json({ error: 'Kaydedilemedi' });
  }
});

app.get('/api/leaderboard', requireDb, async (_req, res) => {
  try {
    const r = await pool.query(`
      SELECT u.name, gs.state
      FROM game_states gs
      JOIN users u ON gs.user_id = u.id
    `);
    const list = r.rows.map(row => {
      const s = row.state || {};
      const history = Array.isArray(s.history) ? s.history : [];
      const totalRev = history.reduce((sum, h) => sum + (h?.metrics?.revenue || 0), 0);
      const totalRoi = history.reduce((sum, h) => sum + (h?.metrics?.roi || 0), 0);
      const completed = history.length;
      const avgScore = completed ? Math.round(history.reduce((sum, h) => sum + (h.score || 0), 0) / completed) : 0;
      const threeStar = history.filter(h => h.stars === 3).length;
      return { name: row.name, totalRev, completed, avgScore, threeStar, level: s.level || 1, xp: s.xp || 0 };
    }).filter(x => x.completed > 0)
      .sort((a, b) => b.totalRev - a.totalRev || b.avgScore - a.avgScore)
      .slice(0, 50);
    res.json({ leaderboard: list });
  } catch (e) {
    console.error('leaderboard error:', e);
    res.status(500).json({ error: 'Lider tablosu yüklenemedi' });
  }
});

app.post('/api/survey', auth, requireDb, async (req, res) => {
  const answers = req.body || {};
  try {
    await pool.query('INSERT INTO surveys (user_id, answers) VALUES ($1, $2)', [req.user.id, answers]);
    res.json({ ok: true });
  } catch (e) {
    console.error('survey error:', e);
    res.status(500).json({ error: 'Anket kaydedilemedi' });
  }
});

app.get('/api/admin/surveys', auth, requireDb, async (req, res) => {
  // Sadece ilk kullanıcı (admin) görebilsin — basit kontrol
  if (req.user.id !== 1) return res.status(403).json({ error: 'Yetkisiz' });
  try {
    const r = await pool.query(`
      SELECT s.id, s.answers, s.submitted_at, u.email, u.name
      FROM surveys s
      JOIN users u ON s.user_id = u.id
      ORDER BY s.submitted_at DESC
      LIMIT 200
    `);
    res.json({ surveys: r.rows });
  } catch (e) {
    res.status(500).json({ error: 'Yüklenemedi' });
  }
});

app.get('/api/health', async (_req, res) => {
  let dbOk = false;
  try { if (pool) { await pool.query('SELECT 1'); dbOk = true; } } catch {}
  res.json({ ok: true, db: dbOk });
});

app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

initDb().catch(e => console.error('Init error:', e));
app.listen(PORT, () => console.log(`DijiP server listening on ${PORT}`));
