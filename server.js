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
      is_admin BOOLEAN DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT false;
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
  // Otomatik admin atama: ilk kullanıcı ya da ADMIN_EMAILS env'inde olanlar
  const adminEmails = (process.env.ADMIN_EMAILS || 'alisbayri@gmail.com').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  if (adminEmails.length) {
    await pool.query(`UPDATE users SET is_admin = true WHERE LOWER(email) = ANY($1::text[])`, [adminEmails]);
  }
  console.log('DB schema ready');
}

async function isAdmin(userId) {
  if (!pool) return false;
  const r = await pool.query('SELECT is_admin FROM users WHERE id = $1', [userId]);
  return !!r.rows[0]?.is_admin;
}

function requireAdmin(req, res, next) {
  isAdmin(req.user.id).then(ok => {
    if (!ok) return res.status(403).json({ error: 'Sadece admin erişebilir' });
    next();
  }).catch(() => res.status(500).json({ error: 'Yetki kontrolü hata' }));
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

app.get('/api/me', auth, async (req, res) => {
  let admin = false;
  try { admin = await isAdmin(req.user.id); } catch {}
  res.json({ user: { id: req.user.id, email: req.user.email, name: req.user.name, isAdmin: admin } });
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

app.get('/api/admin/surveys', auth, requireDb, requireAdmin, async (_req, res) => {
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

app.get('/api/admin/users', auth, requireDb, requireAdmin, async (_req, res) => {
  try {
    const r = await pool.query(`
      SELECT u.id, u.email, u.name, u.is_admin, u.created_at,
        gs.updated_at as last_active,
        COALESCE(jsonb_array_length(gs.state->'history'), 0) as completed_briefs,
        COALESCE((gs.state->>'level')::int, 1) as level,
        COALESCE((gs.state->>'xp')::int, 0) as xp,
        COALESCE((gs.state->>'money')::int, 0) as money,
        (
          SELECT COUNT(*) FROM jsonb_object_keys(gs.state->'lessons') l
          WHERE (gs.state->'lessons'->l->>'completed')::boolean = true
        ) as lessons_done,
        gs.state->'quizScores' as quiz_scores,
        gs.state as full_state
      FROM users u
      LEFT JOIN game_states gs ON gs.user_id = u.id
      ORDER BY gs.updated_at DESC NULLS LAST, u.created_at DESC
      LIMIT 500
    `);
    res.json({ users: r.rows });
  } catch (e) {
    console.error('admin/users error:', e);
    res.status(500).json({ error: 'Yüklenemedi' });
  }
});

app.get('/api/admin/stats', auth, requireDb, requireAdmin, async (_req, res) => {
  try {
    const totalUsers = (await pool.query('SELECT COUNT(*)::int FROM users')).rows[0].count;
    const totalSurveys = (await pool.query('SELECT COUNT(*)::int FROM surveys')).rows[0].count;
    const activeStates = (await pool.query('SELECT COUNT(*)::int FROM game_states')).rows[0].count;
    const totals = await pool.query(`
      SELECT
        COALESCE(SUM(jsonb_array_length(state->'history')), 0)::int as total_campaigns,
        AVG((state->>'xp')::int)::int as avg_xp
      FROM game_states
    `);
    const surveysByDay = await pool.query(`
      SELECT date_trunc('day', submitted_at) as day, COUNT(*)::int as cnt
      FROM surveys
      WHERE submitted_at > NOW() - INTERVAL '30 days'
      GROUP BY day ORDER BY day
    `);
    // NPS dağılımı
    const npsRows = await pool.query(`SELECT (answers->>'nps')::int as nps FROM surveys WHERE answers ? 'nps'`);
    const npsValues = npsRows.rows.map(r => r.nps).filter(n => n !== null);
    const npsAvg = npsValues.length ? +(npsValues.reduce((a,b)=>a+b,0) / npsValues.length).toFixed(1) : null;
    const promoters = npsValues.filter(n => n >= 9).length;
    const detractors = npsValues.filter(n => n <= 6).length;
    const npsScore = npsValues.length ? Math.round(((promoters - detractors) / npsValues.length) * 100) : null;
    res.json({
      totalUsers, totalSurveys, activeStates,
      totalCampaigns: totals.rows[0].total_campaigns,
      avgXP: totals.rows[0].avg_xp,
      surveysByDay: surveysByDay.rows,
      npsAvg, npsScore, npsCount: npsValues.length
    });
  } catch (e) {
    console.error('admin/stats error:', e);
    res.status(500).json({ error: 'İstatistik hatası' });
  }
});

// ============== AI BRIEF MODU ==============
const AI_KEY = process.env.ANTHROPIC_API_KEY;
const AI_MODEL = 'claude-sonnet-4-5';

app.get('/api/ai/status', (_req, res) => res.json({ enabled: !!AI_KEY }));

async function callClaude(prompt) {
  if (!AI_KEY) throw new Error('AI henüz aktif değil');
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': AI_KEY,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      model: AI_MODEL,
      max_tokens: 1500,
      messages: [{ role: 'user', content: prompt }]
    })
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error('AI hatası: ' + t.slice(0, 200));
  }
  const data = await r.json();
  return data.content?.[0]?.text || '';
}

function safeJsonParse(text) {
  const m = text.match(/\{[\s\S]*\}/);
  if (!m) return null;
  try { return JSON.parse(m[0]); } catch { return null; }
}

app.post('/api/ai/brief', auth, async (req, res) => {
  if (!AI_KEY) return res.status(503).json({ error: 'AI modu henüz aktif değil. Yöneticiye danış.' });
  const { briefText, budget, goal, industry } = req.body || {};
  if (!briefText || briefText.length < 30) return res.status(400).json({ error: 'Brief en az 30 karakter olmalı' });
  try {
    const prompt = `Sen deneyimli bir Türk dijital pazarlama mentörüsün. Aşağıdaki müşteri brief'ini analiz et ve ideal stratejiyi öner.

MÜŞTERİ BRIEF'İ:
Sektör: ${industry || 'belirtilmemiş'}
Bütçe: ₺${budget || 'belirtilmemiş'}
Hedef: ${goal || 'belirtilmemiş'}
Açıklama: ${briefText}

Şu seçeneklerden ideal olanı seç ve sadece JSON döndür (başka metin yok):

{
  "audience": "lokal_ilgi|profesyonel|genc_mobil|yuksek_niyet|genis",
  "channels": {"google": SAYI, "meta": SAYI, "email": SAYI, "seo": SAYI},
  "creative": "fiyat|duygusal|sosyal_kanit|urun_ozelligi",
  "difficulty": 1-5 arası tam sayı,
  "reasoning": "neden bu stratejinin doğru olduğunu 2-3 cümleyle Türkçe açıkla",
  "warnings": ["dikkat edilecek 1. nokta", "dikkat edilecek 2. nokta"],
  "estimatedSuccess": 0-100 (bu brief'in bu bütçeyle başarı olasılığı)
}

channels değerleri toplamı 100 olmalı. Bütçe küçükse genis kitle kötü, niyetli kanal iyi.`;
    const txt = await callClaude(prompt);
    const json = safeJsonParse(txt);
    if (!json) return res.status(500).json({ error: 'AI yanıtı çözümlenemedi', raw: txt.slice(0, 300) });
    res.json(json);
  } catch (e) {
    console.error('ai/brief error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/ai/feedback', auth, async (req, res) => {
  if (!AI_KEY) return res.status(503).json({ error: 'AI modu aktif değil' });
  const { brief, decisions, idealStrategy, metrics } = req.body || {};
  try {
    const prompt = `Sen Türkçe konuşan deneyimli bir dijital pazarlama mentörüsün. Oyuncu bir brief için strateji kurdu, sonuçları aldı. Detaylı, yapıcı bir geri bildirim yaz.

BRIEF: ${JSON.stringify(brief)}
İDEAL STRATEJİ: ${JSON.stringify(idealStrategy)}
OYUNCUNUN KARARI: ${JSON.stringify(decisions)}
SONUÇ METRİKLERİ: ${JSON.stringify(metrics)}

3 paragraf yaz:
1. Genel değerlendirme (1-2 cümle, dürüst tonla)
2. En önemli iyi karar (varsa)
3. En kritik iyileştirme önerisi (somut, uygulanabilir)

Sadece Türkçe metin döndür, başlık yok, JSON yok.`;
    const txt = await callClaude(prompt);
    res.json({ feedback: txt.trim() });
  } catch (e) {
    res.status(500).json({ error: e.message });
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
