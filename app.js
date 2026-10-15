const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'shop_secure.db');

if (fs.existsSync(DB_PATH)) fs.unlinkSync(DB_PATH);
const db = new DatabaseSync(DB_PATH);

db.exec(`
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  email TEXT,
  password TEXT,
  role TEXT DEFAULT 'customer',
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  description TEXT,
  price REAL,
  stock INTEGER
);
CREATE TABLE cart_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  product_id INTEGER,
  quantity INTEGER
);
CREATE TABLE orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  total REAL,
  status TEXT DEFAULT 'placed',
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER,
  product_id INTEGER,
  quantity INTEGER,
  price REAL
);
`);

const seedProducts = [
  ['Laptop Pro 15', 'High performance laptop', 1299.99, 10],
  ['Wireless Mouse', 'Ergonomic mouse', 29.99, 50],
  ['Mechanical Keyboard', 'RGB mechanical keyboard', 89.99, 25],
  ['USB-C Hub', '7-in-1 hub', 39.99, 40],
  ['Noise Cancelling Headphones', 'Premium ANC headphones', 199.99, 15],
];
const insertProduct = db.prepare('INSERT INTO products (name, description, price, stock) VALUES (?,?,?,?)');
seedProducts.forEach(p => insertProduct.run(...p));

const insertUser = db.prepare('INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)');
insertUser.run('admin','admin@shop.local', hashPassword('admin123'), 'admin');
insertUser.run('alice','alice@shop.local', hashPassword('password'), 'customer');

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const parts = String(stored || '').split(':');
  if (parts.length !== 2) return false;
  const [salt, hash] = parts;
  if (!salt || !hash) return false;
  let candidate;
  try { candidate = crypto.scryptSync(password, salt, 64); } catch(e){ return false; }
  const storedBuf = Buffer.from(hash, 'hex');
  if (storedBuf.length !== candidate.length) return false;
  return crypto.timingSafeEqual(storedBuf, candidate);
}

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

// sessions: random opaque token -> server-side record
const sessions = new Map();
function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || '';
  raw.split(';').forEach(part => {
    const [k,...v] = part.trim().split('=');
    if (k) out[k] = decodeURIComponent(v.join('='));
  });
  return out;
}
function getSession(req) {
  const cookies = parseCookies(req);
  const token = cookies.session;
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  return { token, ...s };
}
function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { userId: user.id, username: user.username, role: user.role, createdAt: Date.now() });
  return token;
}
function destroySession(token) { if (token) sessions.delete(token); }

function requireAuth(req, res, next) {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: 'authentication required' });
  req.session = s;
  req.user = { id: s.userId, username: s.username, role: s.role };
  const row = db.prepare('SELECT id, username, email, role FROM users WHERE id = ?').get(s.userId);
  if (!row) { destroySession(s.token); return res.status(401).json({ error: 'authentication required' }); }
  req.dbUser = row;
  next();
}
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  next();
}

function isInt(v) {
  return Number.isInteger(v) && v > 0;
}
function safeInt(v) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  if (!/^\d+$/.test(s)) return null;
  const n = Number(s);
  if (!Number.isSafeInteger(n) || n <= 0) return null;
  return n;
}

// rate limit login by IP (in-memory)
const loginAttempts = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip);
  if (!rec) return true;
  if (now - rec.start > 15 * 60 * 1000) { loginAttempts.delete(ip); return true; }
  return rec.count < 5;
}
function recordFailure(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip);
  if (!rec || now - rec.start > 15 * 60 * 1000) {
    loginAttempts.set(ip, { start: now, count: 1 });
  } else {
    rec.count++;
  }
}
function recordSuccess(ip) { loginAttempts.delete(ip); }

// Register
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body || {};
  if (typeof username !== 'string' || !/^[a-zA-Z0-9_]{3,30}$/.test(username)) return res.status(400).json({ error: 'invalid username' });
  if (typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'password must be at least 8 chars' });
  const cleanEmail = typeof email === 'string' ? email.slice(0, 200) : '';
  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (exists) return res.status(409).json({ error: 'username taken' });
  const info = db.prepare('INSERT INTO users (username, email, password) VALUES (?,?,?)').run(username, cleanEmail, hashPassword(password));
  res.status(201).json({ ok: true, id: info.lastInsertRowid });
});

// Login
app.post('/api/login', (req, res) => {
  const ip = req.ip;
  if (!checkRateLimit(ip)) return res.status(429).json({ error: 'too many attempts, try later' });
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'invalid credentials' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  const ok = user ? verifyPassword(password, user.password) : false;
  if (!user || !ok) { recordFailure(ip); return res.status(401).json({ error: 'invalid credentials' }); }
  recordSuccess(ip);
  const token = createSession(user);
  res.cookie('session', token, { httpOnly: true, sameSite: 'lax', path: '/', secure: false, maxAge: 1000*60*60*8 });
  res.json({ ok: true, user: { id: user.id, username: user.username, role: user.role } });
});

app.post('/api/logout', requireAuth, (req, res) => {
  destroySession(req.session.token);
  res.clearCookie('session', { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const u = db.prepare('SELECT id, username, email, role, created_at FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: u });
});

// Products
app.get('/api/products', (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q.slice(0, 100) : '';
  let rows;
  if (q) {
    const like = `%${q.replace(/[%_]/g, (c) => (c === '%' ? '\\%' : '\\_'))}%`;
    // node:sqlite doesn't support ESCAPE? use simple LIKE with parameters; wildcards in q could broaden but not inject
    rows = db.prepare("SELECT id, name, description, price, stock FROM products WHERE name LIKE ? OR description LIKE ?").all(`%${q}%`, `%${q}%`);
    return res.json({ products: rows });
  }
  rows = db.prepare('SELECT id, name, description, price, stock FROM products').all();
  res.json({ products: rows });
});

app.get('/api/products/:id', (req, res) => {
  const id = safeInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid id' });
  const row = db.prepare('SELECT id, name, description, price, stock FROM products WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json({ product: row });
});

// Users: admin list (no passwords)
app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id, username, email, role, created_at FROM users').all();
  res.json({ users: rows });
});

app.get('/api/users/:id', requireAuth, (req, res) => {
  const id = safeInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid id' });
  if (id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  const row = db.prepare('SELECT id, username, email, role, created_at FROM users WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json({ user: row });
});

app.put('/api/users/:id', requireAuth, (req, res) => {
  const id = safeInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid id' });
  if (id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  const body = req.body || {};
  // whitelist fields
  const allowed = ['username', 'email', 'password'];
  const keys = Object.keys(body).filter(k => allowed.includes(k));
  if (req.user.role === 'admin' && body.role && ['admin','customer'].includes(body.role)) keys.push('role');
  if (keys.length === 0) return res.status(400).json({ error: 'no valid fields' });
  const sets = [];
  const vals = [];
  for (const k of keys) {
    if (k === 'password') {
      if (typeof body.password !== 'string' || body.password.length < 8) return res.status(400).json({ error: 'invalid password' });
      sets.push('password = ?'); vals.push(hashPassword(body.password));
    } else if (k === 'username') {
      if (typeof body.username !== 'string' || !/^[a-zA-Z0-9_]{3,30}$/.test(body.username)) return res.status(400).json({ error: 'invalid username' });
      sets.push('username = ?'); vals.push(body.username);
    } else if (k === 'email') {
      sets.push('email = ?'); vals.push(String(body.email || '').slice(0,200));
    } else if (k === 'role') {
      sets.push('role = ?'); vals.push(body.role);
    }
  }
  vals.push(id);
  db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
  res.json({ ok: true });
});

// Cart
app.get('/api/cart', requireAuth, (req, res) => {
  const rows = db.prepare(`SELECT c.id, c.product_id, c.quantity, p.name, p.price
    FROM cart_items c JOIN products p ON p.id=c.product_id WHERE c.user_id = ?`).all(req.user.id);
  res.json({ items: rows });
});

app.post('/api/cart', requireAuth, (req, res) => {
  const productId = safeInt(req.body && req.body.productId);
  const quantity = parseInt(req.body && req.body.quantity, 10);
  if (!productId) return res.status(400).json({ error: 'invalid product' });
  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 1000) return res.status(400).json({ error: 'invalid quantity' });
  const prod = db.prepare('SELECT id, stock FROM products WHERE id = ?').get(productId);
  if (!prod) return res.status(404).json({ error: 'product not found' });
  db.prepare('INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?,?,?)').run(req.user.id, productId, quantity);
  res.status(201).json({ ok: true });
});

app.delete('/api/cart/:id', requireAuth, (req, res) => {
  const id = safeInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid id' });
  const info = db.prepare('DELETE FROM cart_items WHERE id = ? AND user_id = ?').run(id, req.user.id);
  if (info.changes === 0) return res.status(404).json({ error: 'not found' });
  res.json({ ok: true });
});

// Checkout: server-side prices, stock check
app.post('/api/checkout', requireAuth, (req, res) => {
  const body = req.body || {};
  const items = Array.isArray(body.items) ? body.items : [];
  if (items.length === 0) return res.status(400).json({ error: 'empty cart' });
  if (items.length > 50) return res.status(400).json({ error: 'too many items' });

  // validate and compute
  const prepared = [];
  for (const it of items) {
    const pid = safeInt(it.productId);
    const qty = parseInt(it.quantity, 10);
    if (!pid) return res.status(400).json({ error: 'invalid product id' });
    if (!Number.isInteger(qty) || qty < 1 || qty > 1000) return res.status(400).json({ error: 'invalid quantity' });
    const prod = db.prepare('SELECT id, price, stock FROM products WHERE id = ?').get(pid);
    if (!prod) return res.status(404).json({ error: 'product not found' });
    if (prod.stock < qty) return res.status(409).json({ error: `insufficient stock for ${pid}` });
    prepared.push({ productId: pid, quantity: qty, price: prod.price, newStock: prod.stock - qty });
  }
  const total = prepared.reduce((a, it) => a + it.price * it.quantity, 0);

  // transactional-ish
  try {
    db.exec('BEGIN');
    const info = db.prepare('INSERT INTO orders (user_id, total, status) VALUES (?,?,?)').run(req.user.id, Math.round(total * 100) / 100, 'placed');
    const orderId = info.lastInsertRowid;
    const insertItem = db.prepare('INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?,?,?,?)');
    const updateStock = db.prepare('UPDATE products SET stock = ? WHERE id = ?');
    for (const it of prepared) {
      insertItem.run(orderId, it.productId, it.quantity, it.price);
      updateStock.run(it.newStock, it.productId);
    }
    db.exec('COMMIT');
    res.status(201).json({ ok: true, orderId, charged: Math.round(total * 100) / 100 });
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch (_) {}
    res.status(500).json({ error: 'checkout failed' });
  }
});

// Orders
app.get('/api/orders', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT id, user_id, total, status, created_at FROM orders WHERE user_id = ? ORDER BY id DESC').all(req.user.id);
  res.json({ orders: rows });
});

app.get('/api/orders/:id', requireAuth, (req, res) => {
  const id = safeInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid id' });
  const order = db.prepare('SELECT id, user_id, total, status, created_at FROM orders WHERE id = ?').get(id);
  if (!order) return res.status(404).json({ error: 'not found' });
  if (order.user_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  const items = db.prepare('SELECT id, order_id, product_id, quantity, price FROM order_items WHERE order_id = ?').all(id);
  res.json({ order, items });
});

// 404 + generic errors
app.use((req, res) => res.status(404).json({ error: 'not found' }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'internal server error' });
});

app.listen(PORT, () => console.log('Secure app running on http://localhost:' + PORT));

module.exports = app;

