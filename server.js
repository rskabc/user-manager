require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const { RouterOSAPI } = require('node-routeros');
const path = require('path');
const fs = require('fs');

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const JWT_SECRET = process.env.JWT_SECRET;
const ENCRYPTION_KEY = process.env.APP_ENCRYPTION_KEY;
const ISOLATION_LIST = process.env.MIKROTIK_ISOLATION_LIST || 'USER_MANAGER_ISOLATED';
const TOKEN_TTL = process.env.TOKEN_TTL || '12h';

if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET wajib diisi minimal 32 karakter.');
if (!ENCRYPTION_KEY || !/^[a-fA-F0-9]{64}$/.test(ENCRYPTION_KEY)) throw new Error('APP_ENCRYPTION_KEY wajib berupa 64 karakter hex (32 byte).');
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'user-manager.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin', created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS routers (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, host TEXT NOT NULL,
 port INTEGER NOT NULL DEFAULT 8728, username TEXT NOT NULL, password_enc TEXT NOT NULL,
 tls INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS isolation_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT, router_id INTEGER NOT NULL, customer_name TEXT NOT NULL,
 address TEXT NOT NULL, action TEXT NOT NULL CHECK(action IN ('isolate','restore')),
 reason TEXT, operator TEXT NOT NULL, result TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')),
 FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_history_created ON isolation_history(created_at DESC);
`);

function encrypt(value) {
 const iv = crypto.randomBytes(12);
 const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
 const encrypted = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
 return [iv.toString('hex'), cipher.getAuthTag().toString('hex'), encrypted.toString('hex')].join(':');
}
function decrypt(value) {
 const [iv, tag, data] = value.split(':');
 const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY, 'hex'), Buffer.from(iv, 'hex'));
 decipher.setAuthTag(Buffer.from(tag, 'hex'));
 return Buffer.concat([decipher.update(Buffer.from(data, 'hex')), decipher.final()]).toString('utf8');
}
const userCount = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
if (!userCount) {
 if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD.length < 12) {
   console.warn('Belum ada admin. Atur ADMIN_USERNAME dan ADMIN_PASSWORD (minimal 12 karakter) di .env lalu restart.');
 } else {
   db.prepare('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)')
     .run(process.env.ADMIN_USERNAME, bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12), 'admin');
   console.log('Admin awal dibuat dari environment.');
 }
}

const app = express();
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
 const header = req.headers.authorization || '';
 const token = header.startsWith('Bearer ') ? header.slice(7) : '';
 try { req.user = jwt.verify(token, JWT_SECRET); next(); }
 catch { return res.status(401).json({ error: 'Sesi tidak valid. Silakan login kembali.' }); }
}
function asyncRoute(fn) { return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); }
function validateIp(ip) {
 if (typeof ip !== 'string' || ip.length > 64) return false;
 const v4 = /^(25[0-5]|2[0-4]\\d|1?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}$/.test(ip);
 const v6 = /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':');
 return v4 || v6;
}
function routerById(id) {
 const router = db.prepare('SELECT * FROM routers WHERE id=?').get(Number(id));
 if (!router) { const e = new Error('Router tidak ditemukan.'); e.status = 404; throw e; }
 return router;
}
async function withRouter(router, callback) {
 const api = new RouterOSAPI({
   host: router.host, user: router.username, password: decrypt(router.password_enc),
   port: router.port, timeout: 8000, keepalive: false, tls: !!router.tls
 });
 try { await api.connect(); return await callback(api); }
 finally { try { await api.close(); } catch (_) {} }
}
function history(routerId, name, address, action, reason, operator, result) {
 db.prepare('INSERT INTO isolation_history(router_id,customer_name,address,action,reason,operator,result) VALUES(?,?,?,?,?,?,?)')
   .run(routerId, name, address, action, reason || null, operator, result);
}

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'MikroTik User Manager' }));
app.post('/api/login', (req, res) => {
 const { username, password } = req.body || {};
 if (typeof username !== 'string' || typeof password !== 'string' || username.length > 100 || password.length > 200)
   return res.status(400).json({ error: 'Username dan password wajib diisi.' });
 const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
 if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Username atau password salah.' });
 const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: TOKEN_TTL });
 res.json({ token, user: { username: user.username, role: user.role } });
});
app.get('/api/me', auth, (req, res) => res.json({ user: req.user }));

app.get('/api/routers', auth, (req, res) => {
 res.json(db.prepare('SELECT id,name,host,port,username,tls,created_at FROM routers ORDER BY name').all());
});
app.post('/api/routers', auth, (req, res) => {
 const { name, host, port = 8728, username, password, tls = false } = req.body || {};
 if (![name, host, username, password].every(v => typeof v === 'string' && v.trim()) || name.length > 100 || host.length > 253 || username.length > 100)
   return res.status(400).json({ error: 'Nama, host, username, dan password wajib diisi.' });
 const p = Number(port);
 if (!Number.isInteger(p) || p < 1 || p > 65535) return res.status(400).json({ error: 'Port tidak valid.' });
 const result = db.prepare('INSERT INTO routers(name,host,port,username,password_enc,tls) VALUES(?,?,?,?,?,?)')
   .run(name.trim(), host.trim(), p, username.trim(), encrypt(password), tls ? 1 : 0);
 res.status(201).json({ id: result.lastInsertRowid, name: name.trim() });
});
app.delete('/api/routers/:id', auth, (req, res) => {
 db.prepare('DELETE FROM routers WHERE id=?').run(Number(req.params.id));
 res.json({ ok: true });
});
app.post('/api/routers/:id/test', auth, asyncRoute(async (req, res) => {
 const router = routerById(req.params.id);
 const data = await withRouter(router, api => api.write('/system/resource/print'));
 res.json({ ok: true, resource: data[0] || {} });
}));
app.get('/api/routers/:id/queues', auth, asyncRoute(async (req, res) => {
 const router = routerById(req.params.id);
 const rows = await withRouter(router, api => api.write('/queue/simple/print'));
 res.json(rows.map(q => ({
   id: q['.id'], name: q.name || '', target: q.target || '',
   maxLimit: q['max-limit'] || '', disabled: q.disabled === 'true',
   bytes: q.bytes || '', packets: q.packets || '', rate: q['rate'] || ''
 })));
}));
app.post('/api/routers/:id/queues', auth, asyncRoute(async (req, res) => {
 const router = routerById(req.params.id);
 const { name, target, maxLimit } = req.body || {};
 if (![name, target, maxLimit].every(v => typeof v === 'string' && v.trim()) || name.length > 100 || target.length > 100 || maxLimit.length > 50)
   return res.status(400).json({ error: 'Nama, target IP/subnet, dan max-limit wajib diisi.' });
 const result = await withRouter(router, api => api.write('/queue/simple/add', [
   '=name=' + name.trim(), '=target=' + target.trim(), '=max-limit=' + maxLimit.trim()
 ]));
 res.status(201).json({ ok: true, result });
}));
app.patch('/api/routers/:id/queues/:queueId', auth, asyncRoute(async (req, res) => {
 const router = routerById(req.params.id);
 const { name, target, maxLimit, disabled } = req.body || {};
 const args = ['=.id=' + req.params.queueId];
 if (typeof name === 'string' && name.trim()) args.push('=name=' + name.trim());
 if (typeof target === 'string' && target.trim()) args.push('=target=' + target.trim());
 if (typeof maxLimit === 'string' && maxLimit.trim()) args.push('=max-limit=' + maxLimit.trim());
 if (typeof disabled === 'boolean') args.push('=disabled=' + (disabled ? 'yes' : 'no'));
 if (args.length === 1) return res.status(400).json({ error: 'Tidak ada perubahan yang dikirim.' });
 await withRouter(router, api => api.write('/queue/simple/set', args));
 res.json({ ok: true });
}));
app.delete('/api/routers/:id/queues/:queueId', auth, asyncRoute(async (req, res) => {
 const router = routerById(req.params.id);
 await withRouter(router, api => api.write('/queue/simple/remove', ['=.id=' + req.params.queueId]));
 res.json({ ok: true });
}));

app.post('/api/routers/:id/isolation', auth, asyncRoute(async (req, res) => {
 const router = routerById(req.params.id);
 const { name, address, reason = '', action } = req.body || {};
 if (!validateIp(address)) return res.status(400).json({ error: 'Masukkan alamat IP pelanggan yang valid.' });
 if (!['isolate', 'restore'].includes(action)) return res.status(400).json({ error: 'Action harus isolate atau restore.' });
 if (typeof name !== 'string' || name.length > 100 || typeof reason !== 'string' || reason.length > 500)
   return res.status(400).json({ error: 'Nama pelanggan atau alasan tidak valid.' });
 const result = await withRouter(router, async api => {
   const existing = await api.write('/ip/firewall/address-list/print', [
     '?list=' + ISOLATION_LIST, '?address=' + address
   ]);
   if (action === 'isolate') {
     if (!existing.length) await api.write('/ip/firewall/address-list/add', [
       '=list=' + ISOLATION_LIST, '=address=' + address,
       '=comment=User Manager | ' + name.trim().slice(0, 80)
     ]);
   } else if (existing.length) {
     for (const row of existing) await api.write('/ip/firewall/address-list/remove', ['=.id=' + row['.id']]);
   }
   const verify = await api.write('/ip/firewall/address-list/print', [
     '?list=' + ISOLATION_LIST, '?address=' + address
   ]);
   const success = action === 'isolate' ? verify.length > 0 : verify.length === 0;
   if (!success) throw new Error('Perintah dikirim tetapi verifikasi kondisi firewall gagal.');
   return { verified: true, changed };
 });
 if (result.changed) history(router.id, name.trim(), address, action, reason.trim(), req.user.username, 'success');
 res.json({ ok: true, result });
}));

app.get('/api/routers/:id/isolated', auth, asyncRoute(async (req, res) => {
 const router = routerById(req.params.id);
 const rows = await withRouter(router, api => api.write('/ip/firewall/address-list/print', ['?list=' + ISOLATION_LIST]));
 res.json(rows.map(row => ({ id: row['.id'], address: row.address || '', name: (row.comment || '').startsWith('User Manager | ') ? row.comment.slice('User Manager | '.length) : (row.comment || ''), comment: row.comment || '' })));
}));

app.get('/api/history', auth, (req, res) => {
 const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
 res.json(db.prepare(`SELECT h.id,h.router_id,r.name AS router_name,h.customer_name,h.address,h.action,h.reason,h.operator,h.result,h.created_at
 FROM isolation_history h JOIN routers r ON r.id=h.router_id ORDER BY h.id DESC LIMIT ?`).all(limit));
});
app.get('/api/dashboard', auth, asyncRoute(async (req, res) => {
 const routers = db.prepare('SELECT * FROM routers ORDER BY name').all();
 const historyToday = db.prepare("SELECT action,COUNT(*) AS n FROM isolation_history WHERE date(created_at,'localtime')=date('now','localtime') AND result='success' GROUP BY action").all();
 const summary = { routers: routers.length, online: 0, queues: 0, isolatedNow: 0, isolatedToday: 0, restoredToday: 0, traffic: [], routerStatus: [] };
 for (const router of routers) {
   try {
     const data = await withRouter(router, async api => {
       const queues = await api.write('/queue/simple/print');
       const isolated = await api.write('/ip/firewall/address-list/print', ['?list=' + ISOLATION_LIST]);
       return { queues, isolated };
     });
     summary.online++; summary.queues += data.queues.length; summary.isolatedNow += data.isolated.length;
     summary.traffic.push(...data.queues.slice(0, 100).map(q => ({ router: router.name, name: q.name || '', target: q.target || '', rate: q.rate || '0/0', maxLimit: q['max-limit'] || '' })));
     summary.routerStatus.push({ id: router.id, name: router.name, online: true, queues: data.queues.length, isolated: data.isolated.length });
   } catch (_) { summary.routerStatus.push({ id: router.id, name: router.name, online: false, queues: 0, isolated: 0 }); }
 }
 summary.isolatedToday = (historyToday.find(x => x.action === 'isolate') || {}).n || 0;
 summary.restoredToday = (historyToday.find(x => x.action === 'restore') || {}).n || 0;
 res.json(summary);
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Endpoint tidak ditemukan.' }));
app.use((err, req, res, next) => {
 console.error(new Date().toISOString(), err.message);
 const status = err.status || 502;
 res.status(status).json({ error: status >= 500 ? 'Operasi gagal. Periksa koneksi router dan log server.' : err.message });
});
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, '0.0.0.0', () => console.log(`User Manager berjalan pada port ${PORT}`));
