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
const ISOLATION_LIST = process.env.MIKROTIK_ISOLATION_LIST || 'blocked_ip';
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
CREATE TABLE IF NOT EXISTS integrations (
 id INTEGER PRIMARY KEY CHECK(id=1),
 zabbix_url TEXT NOT NULL DEFAULT '',
 zabbix_token_enc TEXT NOT NULL DEFAULT '',
 hostgroup TEXT NOT NULL DEFAULT 'MikroTik Queues',
 updated_at TEXT NOT NULL DEFAULT (datetime('now'))
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
CREATE TABLE IF NOT EXISTS traffic_samples (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 router_id INTEGER NOT NULL,
 queue_name TEXT NOT NULL,
 target TEXT NOT NULL DEFAULT '',
 rx_bps REAL NOT NULL DEFAULT 0,
 tx_bps REAL NOT NULL DEFAULT 0,
 sampled_at TEXT NOT NULL DEFAULT (datetime('now')),
 FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_traffic_sampled ON traffic_samples(router_id, sampled_at);
CREATE INDEX IF NOT EXISTS idx_traffic_queue ON traffic_samples(router_id, queue_name, sampled_at);
CREATE TABLE IF NOT EXISTS sync_snapshots (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 router_id INTEGER NOT NULL,
 entity_key TEXT NOT NULL,
 entity_type TEXT NOT NULL,
 state_json TEXT NOT NULL,
 updated_at TEXT NOT NULL DEFAULT (datetime('now')),
 UNIQUE(router_id, entity_key, entity_type),
 FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS sync_changes (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 router_id INTEGER NOT NULL,
 entity_type TEXT NOT NULL,
 entity_key TEXT NOT NULL,
 customer_name TEXT NOT NULL DEFAULT '',
 address TEXT NOT NULL DEFAULT '',
 change_type TEXT NOT NULL,
 old_value TEXT,
 new_value TEXT,
 source TEXT NOT NULL DEFAULT 'external_or_unattributed',
 detected_at TEXT NOT NULL DEFAULT (datetime('now')),
 FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sync_changes_detected ON sync_changes(detected_at DESC);
CREATE TABLE IF NOT EXISTS router_sync_status (
 router_id INTEGER PRIMARY KEY,
 status TEXT NOT NULL DEFAULT 'pending',
 last_sync_at TEXT,
 last_error TEXT,
 changes_detected INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
);
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
 const v4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(ip);
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
function getZabbixConfig() {
 const row = db.prepare('SELECT * FROM integrations WHERE id=1').get();
 return row ? {url:row.zabbix_url,token:row.zabbix_token_enc?decrypt(row.zabbix_token_enc):'',hostgroup:row.hostgroup||'MikroTik Queues',updatedAt:row.updated_at} : {url:'',token:'',hostgroup:'MikroTik Queues',updatedAt:null};
}
async function zabbixCall(config, method, params={}) {
 const isPublicMethod = method === 'apiinfo.version';
 if (!config.url || (!isPublicMethod && !config.token)) {
   throw Object.assign(new Error('Konfigurasi URL dan token Zabbix belum lengkap.'),{status:400});
 }
 const headers = {'Content-Type':'application/json-rpc'};
 // Zabbix 7.2+ rejects Authorization on apiinfo.version.
 if (!isPublicMethod) headers.Authorization = 'Bearer ' + config.token;
 let response;
 try {
   response = await fetch(config.url, {
     method:'POST',
     headers,
     body:JSON.stringify({jsonrpc:'2.0',method,params,id:1}),
     signal:AbortSignal.timeout(10000)
   });
 } catch (error) {
   if (error.name === 'TimeoutError' || error.name === 'AbortError') {
     throw new Error('Koneksi ke Zabbix timeout setelah 10 detik. Periksa URL API dan konektivitas dari container.');
   }
   throw new Error('Tidak dapat menjangkau Zabbix API: ' + (error.cause?.message || error.message || 'network error'));
 }
 if (!response.ok) throw new Error('Zabbix API mengembalikan HTTP '+response.status+'.');
 const data=await response.json();
 if (data.error) throw new Error(data.error.data||data.error.message||'Zabbix API menolak permintaan.');
 return data.result;
}
app.get('/api/integrations/zabbix',auth,(req,res)=>{
 const c=getZabbixConfig();
 res.json({configured:!!(c.url&&c.token),url:c.url,hostgroup:c.hostgroup,tokenConfigured:!!c.token,updatedAt:c.updatedAt});
});
app.put('/api/integrations/zabbix',auth,(req,res)=>{
 const {url,token,hostgroup='MikroTik Queues'}=req.body||{};
 if(typeof url!=='string'||!/^https?:\/\//i.test(url.trim())||url.length>500) return res.status(400).json({error:'URL API Zabbix harus berupa URL http/https yang valid.'});
 if(typeof token!=='string'||token.trim().length<8||token.length>5000) return res.status(400).json({error:'Token API Zabbix wajib diisi.'});
 if(typeof hostgroup!=='string'||hostgroup.trim().length>200) return res.status(400).json({error:'Nama host group tidak valid.'});
 db.prepare("INSERT INTO integrations(id,zabbix_url,zabbix_token_enc,hostgroup,updated_at) VALUES(1,?,?,?,datetime('now')) ON CONFLICT(id) DO UPDATE SET zabbix_url=excluded.zabbix_url,zabbix_token_enc=excluded.zabbix_token_enc,hostgroup=excluded.hostgroup,updated_at=datetime('now')")
  .run(url.trim().replace(/\/+$/,'') ,encrypt(token.trim()),hostgroup.trim()||'MikroTik Queues');
 res.json({ok:true,message:'Konfigurasi Zabbix disimpan terenkripsi.'});
});
app.post('/api/integrations/zabbix/test',auth,asyncRoute(async(req,res)=>{
 const current=getZabbixConfig();
 const url=typeof req.body?.url==='string'&&req.body.url.trim()?req.body.url.trim().replace(/\/+$/,''):current.url;
 const token=typeof req.body?.token==='string'&&req.body.token.trim()?req.body.token.trim():current.token;
 if (!url) throw Object.assign(new Error('URL API Zabbix belum diisi.'),{status:400});
 if (!token) throw Object.assign(new Error('Token API Zabbix belum diisi.'),{status:400});
 // First check reachability/version without Authorization, then verify the token separately.
 const version=await zabbixCall({url,token:''},'apiinfo.version',{});
 const groups=await zabbixCall({url,token},'hostgroup.get',{output:['groupid','name'],limit:1});
 res.json({ok:true,version,tokenValid:true,message:'Koneksi Zabbix berhasil dan token diterima.',accessibleHostgroups:groups.length});
}));
app.get('/api/integrations/zabbix/hosts',auth,asyncRoute(async(req,res)=>{
 const c=getZabbixConfig();
 if(!c.url||!c.token) return res.status(400).json({error:'Konfigurasi Zabbix belum disimpan.'});
 const groups=await zabbixCall(c,'hostgroup.get',{output:['groupid','name'],filter:{name:[c.hostgroup]}});
 const groupIds=groups.map(g=>g.groupid);
 if(!groupIds.length) return res.json({hostgroup:c.hostgroup,hosts:[],count:0,warning:'Host group belum ditemukan di Zabbix.'});
 const hosts=await zabbixCall(c,'host.get',{output:['hostid','host','name','status'],groupids:groupIds,selectInterfaces:['ip','dns']});
 const pingItems=hosts.length?await zabbixCall(c,'item.get',{output:['itemid','hostid','key_','lastvalue','lastclock','status','state'],hostids:hosts.map(h=>h.hostid),filter:{key_:['icmpping']}}):[];
 const pingByHost=new Map();
 for(const item of pingItems){
   if(item.status==='1'||item.state==='1') continue;
   const previous=pingByHost.get(item.hostid);
   if(!previous||Number(item.lastclock)>Number(previous.lastclock)) pingByHost.set(item.hostid,item);
 }
 const now=Math.floor(Date.now()/1000);
 res.json({hostgroup:c.hostgroup,count:hosts.length,hosts:hosts.map(h=>{
   const item=pingByHost.get(h.hostid);
   const fresh=item&&Number(item.lastclock)>0&&(now-Number(item.lastclock)<=300);
   const icmpStatus=h.status!=='0'?'disabled':!item?'unknown':!fresh?'unknown':item.lastvalue==='1'?'connected':item.lastvalue==='0'?'disconnected':'unknown';
   return {hostid:h.hostid,host:h.host,name:h.name,status:h.status==='0'?'enabled':'disabled',interfaces:(h.interfaces||[]).map(i=>({ip:i.ip,dns:i.dns})),icmpStatus,icmpLastCheck:item?.lastclock?new Date(Number(item.lastclock)*1000).toISOString():null,icmpValue:item?.lastvalue??null};
 })});
}));

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
 // Identify parent queues by checking whether another Simple Queue names them as its parent.
 // Keep the full RouterOS data intact; the UI can omit parent-only summary rows.
 const parentNames = new Set(rows.map(q => String(q.parent || '').trim()).filter(p => p && p !== 'none'));
 res.json(rows.map(q => ({
   id: q['.id'], name: q.name || '', target: q.target || '',
   parent: q.parent || 'none', isParent: parentNames.has(String(q.name || '').trim()),
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

async function applyIsolation(router, {name, address, reason = '', action}, operator) {
 if (!validateIp(address)) throw Object.assign(new Error('Alamat IP pelanggan tidak valid.'), {status:400});
 if (!['isolate','restore'].includes(action)) throw Object.assign(new Error('Action harus isolate atau restore.'), {status:400});
 const cleanName = typeof name === 'string' ? name.trim().slice(0,100) : '';
 if (!cleanName) throw Object.assign(new Error('Nama pelanggan wajib diisi.'), {status:400});
 const cleanReason = typeof reason === 'string' ? reason.trim().slice(0,500) : '';
 return withRouter(router, async api => {
   const existing = await api.write('/ip/firewall/address-list/print', ['?list=' + ISOLATION_LIST, '?address=' + address]);
   const isDisabled = row => row.disabled === 'true' || row.disabled === true;
   const activeExisting = existing.filter(row => !isDisabled(row));
   let changed = false;
   if (action === 'isolate' && activeExisting.length === 0) {
     const disabledExisting = existing.filter(isDisabled);
     if (disabledExisting.length) {
       for (const row of disabledExisting) await api.write('/ip/firewall/address-list/set', ['=.id=' + row['.id'], '=disabled=no']);
     } else {
       await api.write('/ip/firewall/address-list/add', ['=list=' + ISOLATION_LIST, '=address=' + address, '=comment=User Manager | ' + cleanName]);
     }
     changed = true;
   } else if (action === 'restore' && existing.length > 0) {
     for (const row of existing) await api.write('/ip/firewall/address-list/remove', ['=.id=' + row['.id']]);
     changed = true;
   }
   const verify = await api.write('/ip/firewall/address-list/print', ['?list=' + ISOLATION_LIST, '?address=' + address]);
   const activeVerify = verify.filter(row => !isDisabled(row));
   const success = action === 'isolate' ? activeVerify.length > 0 : verify.length === 0;
   if (!success) throw new Error('Verifikasi kondisi firewall gagal.');
   if (changed) history(router.id, cleanName, address, action, cleanReason, operator, 'success');
   return {ok:true, verified:true, changed, action, address};
 });
}
app.post('/api/routers/:id/isolation', auth, asyncRoute(async (req, res) => {
 const router = routerById(req.params.id);
 const result = await applyIsolation(router, req.body || {}, req.user.username);
 res.json(result);
}));
app.post('/api/routers/:id/isolation/bulk', auth, asyncRoute(async (req, res) => {
 const router = routerById(req.params.id);
 const {customers, action, reason = ''} = req.body || {};
 if (!Array.isArray(customers) || customers.length < 1 || customers.length > 100)
   return res.status(400).json({error:'Pilih antara 1 sampai 100 pelanggan per proses.'});
 if (!['isolate','restore'].includes(action)) return res.status(400).json({error:'Action tidak valid.'});
 const results = [];
 for (const c of customers) {
   try {
     const result = await applyIsolation(router, {name:c.name, address:c.address, reason, action}, req.user.username);
     results.push({name:c.name, address:c.address, ok:true, changed:result.changed});
   } catch (e) { results.push({name:c.name||'', address:c.address||'', ok:false, error:e.status===400?e.message:'Operasi gagal atau verifikasi router gagal.'}); }
 }
 res.json({ok:results.every(x=>x.ok), total:results.length, succeeded:results.filter(x=>x.ok).length, failed:results.filter(x=>!x.ok).length, results});
}));
app.get('/api/routers/:id/isolated', auth, asyncRoute(async (req, res) => {
 const router = routerById(req.params.id);
 const rows = await withRouter(router, api => api.write('/ip/firewall/address-list/print', ['?list=' + ISOLATION_LIST]));
 res.json(rows.filter(row => row.disabled !== 'true' && row.disabled !== true).map(row => ({ id: row['.id'], address: row.address || '', name: (row.comment || '').startsWith('User Manager | ') ? row.comment.slice('User Manager | '.length) : (row.comment || ''), comment: row.comment || '' })));
}));

function parseRate(value) {
 if (typeof value !== 'string') return [0,0];
 const parts = value.split('/');
 const toBps = v => {
   const n = Number(String(v || '0').trim());
   return Number.isFinite(n) && n >= 0 ? n * 8 : 0;
 };
 return [toBps(parts[0]), toBps(parts[1])];
}
function queueCustomer(q, routerId, routerName, isolatedAddresses) {
 const target = String(q.target || '').split(',')[0].trim().split('/')[0];
 const isolated = isolatedAddresses.has(target);
 const disabled = q.disabled === 'true' || q.disabled === true;
 const [rxBps, txBps] = parseRate(q.rate || '0/0');
 return {routerId, routerName, queueId:q['.id'] || '', name:q.name || '', target:q.target || '', address:target, maxLimit:q['max-limit'] || '', disabled, isolated, status:isolated?'isolated':disabled?'disabled':'active', rxBps, txBps, rate:q.rate || '0/0', bytes:q.bytes || ''};
}
app.post('/api/routers/:id/customers/test', auth, asyncRoute(async (req,res) => {
 const router = routerById(req.params.id);
 const address = String((req.body||{}).address||'').trim().split('/')[0];
 if (!address || !/^[0-9a-fA-F:.]+$/.test(address)) return res.status(400).json({error:'Alamat IP pelanggan tidak valid.'});
 const result = await withRouter(router, async api => {
   const rows = await api.write('/ping', ['=address='+address, '=count=3', '=interval=300ms']);
   const received = rows.reduce((n,row)=>n+Number(row.received||0),0);
   const sent = rows.reduce((n,row)=>n+Number(row.sent||0),0);
   return {address,connected:received>0,sent:sent||3,received,loss:received>0?Math.max(0,100-Math.round(received/Math.max(sent,3)*100)):100,status:received>0?'connected':'disconnected',detail:received>0?'Ping berhasil':'Tidak ada balasan ping (timeout)'};
 });
 res.json(result);
}));
let zabbixHostCache = {at:0, hosts:[], error:''};
async function getZabbixHostIndex() {
 const now=Date.now();
 if(now-zabbixHostCache.at<30000) return zabbixHostCache;
 try {
  const c=getZabbixConfig();
  if(!c.url||!c.token) throw new Error('Zabbix belum dikonfigurasi');
  const groups=await zabbixCall(c,'hostgroup.get',{output:['groupid','name'],filter:{name:[c.hostgroup]}});
  if(!groups.length) throw new Error('Host group tidak ditemukan');
  const hosts=await zabbixCall(c,'host.get',{output:['hostid','host','name','status'],groupids:groups.map(g=>g.groupid),selectInterfaces:['ip','dns','type']});
  const pingItems=hosts.length?await zabbixCall(c,'item.get',{output:['itemid','hostid','key_','lastvalue','lastclock','status','state'],hostids:hosts.map(x=>x.hostid),filter:{key_:['icmpping']}}):[];
  const pingByHost=new Map();
  for(const item of pingItems){
   if(item.status==='1'||item.state==='1') continue;
   const prev=pingByHost.get(item.hostid);
   if(!prev||Number(item.lastclock)>Number(prev.lastclock)) pingByHost.set(item.hostid,item);
  }
  const checkedAt=Math.floor(Date.now()/1000);
  const indexedHosts=hosts.map(host=>{
   const ping=pingByHost.get(host.hostid);
   const fresh=ping&&Number(ping.lastclock)>0&&checkedAt-Number(ping.lastclock)<=300;
   const icmpStatus=host.status!=='0'?'disabled':!ping||!fresh?'unknown':ping.lastvalue==='1'?'available':ping.lastvalue==='0'?'unavailable':'unknown';
   return {...host,icmpStatus,icmpLastCheck:ping?.lastclock||null};
  });
  zabbixHostCache={at:now,hosts:indexedHosts,error:''};
 } catch(e) { zabbixHostCache={at:now,hosts:[],error:e.message||'Zabbix tidak tersedia'}; }
 return zabbixHostCache;
}
function normalizeHostValue(v){return String(v||'').trim().toLowerCase();}
function enrichCustomerWithZabbix(customer, hosts, error) {
 const ip=normalizeHostValue(customer.address);
 const name=normalizeHostValue(customer.name);
 // Queue name and Zabbix technical/display hostname are expected to match exactly.
 // Prefer an exact hostname match; use IP only when no hostname match exists.
 const exactNameMatches=hosts.filter(h=>[h.host,h.name].some(v=>normalizeHostValue(v)===name));
 const matches=exactNameMatches.length ? exactNameMatches : hosts.filter(h=>(h.interfaces||[]).some(i=>normalizeHostValue(i.ip)===ip || normalizeHostValue(i.dns)===ip));
 if(error) return {...customer,zabbixStatus:'unavailable',zabbixHost:'',zabbixHostName:'',zabbixAvailability:'unknown',zabbixMatch:'unavailable',zabbixNote:error};
 if(matches.length===0) return {...customer,zabbixStatus:'unmatched',zabbixHost:'',zabbixHostName:'',zabbixAvailability:'unknown',zabbixMatch:'unmatched',zabbixNote:'Tidak ditemukan di Zabbix'};
 if(matches.length>1) return {...customer,zabbixStatus:'duplicate',zabbixHost:'',zabbixHostName:'',zabbixAvailability:'unknown',zabbixMatch:'duplicate',zabbixNote:'Lebih dari satu host cocok'};
 const h=matches[0];
 const availability=h.icmpStatus||'unknown';
 return {...customer,zabbixStatus:availability,zabbixHost:h.host||'',zabbixHostName:h.name||h.host||'',zabbixAvailability:availability,zabbixMatch:'matched',zabbixLastCheck:h.icmpLastCheck||null,zabbixNote:availability==='unknown'?'Item ICMP tidak ditemukan, belum ada data, atau data lebih lama dari 5 menit':''};
}
app.get('/api/routers/:id/customers', auth, asyncRoute(async (req,res) => {
 const router = routerById(req.params.id);
 const data = await withRouter(router, async api => {
   const [queues, isolated] = await Promise.all([
     api.write('/queue/simple/print'),
     api.write('/ip/firewall/address-list/print', ['?list='+ISOLATION_LIST])
   ]);
   return {queues, isolated};
 });
 const addresses = new Set(data.isolated.map(x=>String(x.address||'').split('/')[0]));
 const zbx=await getZabbixHostIndex();
 res.json(data.queues.map(q=>enrichCustomerWithZabbix(queueCustomer(q,router.id,router.name,addresses),zbx.hosts,zbx.error)));
}));
app.get('/api/traffic/history', auth, (req,res) => {
 const routerId = Number(req.query.routerId);
 const period = ['hour','day','month'].includes(req.query.period) ? req.query.period : 'hour';
 const hours = period==='hour' ? 24 : period==='day' ? 24*7 : 24*30;
 const where = routerId ? 'WHERE s.router_id=? AND s.sampled_at >= datetime(\'now\', ?)' : 'WHERE s.sampled_at >= datetime(\'now\', ?)';
 const args = routerId ? [routerId, '-'+hours+' hours'] : ['-'+hours+' hours'];
 const bucket = period==='hour' ? "strftime('%Y-%m-%d %H:00',s.sampled_at)" : period==='day' ? "strftime('%Y-%m-%d',s.sampled_at)" : "strftime('%Y-%m',s.sampled_at)";
 const rows = db.prepare('SELECT '+bucket+' AS bucket, ROUND(SUM(rx_bps)/COUNT(*),0) AS rx_bps, ROUND(SUM(tx_bps)/COUNT(*),0) AS tx_bps, COUNT(*) AS samples FROM traffic_samples s '+where+' GROUP BY bucket ORDER BY bucket').all(...args);
 res.json({period, points:rows});
});
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


function normalizedAddress(value) { return String(value || '').trim().split('/')[0]; }
function safeJson(value) { return JSON.stringify(value); }
function recordSyncChange(router, entityType, entityKey, customerName, address, changeType, oldValue, newValue) {
 const oldText = oldValue == null ? null : safeJson(oldValue);
 const newText = newValue == null ? null : safeJson(newValue);
 // Avoid double-counting an isolation transition that the application itself logged recently.
 let source = 'external_or_unattributed';
 if (entityType === 'isolation') {
   const expectedAction = newValue ? 'isolate' : 'restore';
   const recent = db.prepare("SELECT id FROM isolation_history WHERE router_id=? AND address=? AND action=? AND result='success' AND created_at >= datetime('now','-90 seconds') ORDER BY id DESC LIMIT 1")
     .get(router.id, address, expectedAction);
   if (recent) source = 'application_action';
 }
 db.prepare('INSERT INTO sync_changes(router_id,entity_type,entity_key,customer_name,address,change_type,old_value,new_value,source) VALUES(?,?,?,?,?,?,?,?,?)')
   .run(router.id, entityType, entityKey, customerName || '', address || '', changeType, oldText, newText, source);
 db.prepare('UPDATE router_sync_status SET changes_detected=changes_detected+1 WHERE router_id=?').run(router.id);
}
function displayQueueState(q) {
 return { name:String(q.name||''), target:String(q.target||''), maxLimit:String(q['max-limit']||''), disabled:q.disabled==='true'||q.disabled===true };
}
async function syncRouter(router) {
 const result = await withRouter(router, async api => {
   const [queues, addressRows] = await Promise.all([
     api.write('/queue/simple/print'),
     api.write('/ip/firewall/address-list/print', ['?list='+ISOLATION_LIST])
   ]);
   return {queues,addressRows};
 });
 const current = new Map();
 for (const q of result.queues) {
   const target = String(q.target||'').split(',')[0].trim();
   const address = normalizedAddress(target);
   const key = String(q.name||q['.id']||'queue')+'|'+address;
   current.set('queue:'+key, {type:'queue', key, name:String(q.name||''), address, state:displayQueueState(q)});
 }
 const isolatedAddresses = new Set(result.addressRows.map(row=>normalizedAddress(row.address)));
 for (const address of isolatedAddresses) {
   const queue = result.queues.find(q => String(q.target||'').split(',').some(t=>normalizedAddress(t.trim())===address));
   const name = queue ? String(queue.name||'') : (result.addressRows.find(row=>normalizedAddress(row.address)===address)?.comment||'');
   current.set('isolation:'+address, {type:'isolation', key:address, name, address, state:{isolated:true}});
 }
 const prior = db.prepare('SELECT entity_key,entity_type,state_json FROM sync_snapshots WHERE router_id=?').all(router.id);
 const priorMap = new Map(prior.map(row=>[row.entity_type+':'+row.entity_key,row]));
 const upsert = db.prepare("INSERT INTO sync_snapshots(router_id,entity_key,entity_type,state_json,updated_at) VALUES(?,?,?,?,datetime('now')) ON CONFLICT(router_id,entity_key,entity_type) DO UPDATE SET state_json=excluded.state_json,updated_at=datetime('now')");
 db.prepare("INSERT INTO router_sync_status(router_id,status,last_sync_at,last_error,changes_detected) VALUES(?,'online',datetime('now'),NULL,0) ON CONFLICT(router_id) DO UPDATE SET status='online',last_sync_at=datetime('now'),last_error=NULL").run(router.id);
 const transaction = db.transaction(() => {
   // First successful scan seeds the baseline and intentionally creates no false change events.
   for (const item of current.values()) {
     const id = item.type+':'+item.key, previous = priorMap.get(id);
     if (previous) {
       let oldState;
       try { oldState = JSON.parse(previous.state_json); } catch { oldState = {}; }
       if (safeJson(oldState) !== safeJson(item.state)) {
         const changeType = item.type==='isolation' ? 'isolation_state_changed' : 'queue_configuration_changed';
         recordSyncChange(router,item.type,item.key,item.name,item.address,changeType,oldState,item.state);
       }
     } else if (prior.length) {
       recordSyncChange(router,item.type,item.key,item.name,item.address,item.type==='isolation'?'isolation_added':'queue_added',null,item.state);
     }
     upsert.run(router.id,item.key,item.type,safeJson(item.state));
   }
   for (const row of prior) {
     const id = row.entity_type+':'+row.entity_key;
     if (current.has(id)) continue;
     let oldState;
     try { oldState = JSON.parse(row.state_json); } catch { oldState = {}; }
     const itemType = row.entity_type;
     const address = itemType==='isolation' ? row.entity_key : (oldState.target||'').split(',')[0].trim().split('/')[0];
     const name = itemType==='queue' ? oldState.name||'' : '';
     recordSyncChange(router,itemType,row.entity_key,name,address,itemType==='isolation'?'isolation_removed':'queue_removed',oldState,null);
     db.prepare('DELETE FROM sync_snapshots WHERE router_id=? AND entity_key=? AND entity_type=?').run(router.id,row.entity_key,row.entity_type);
   }
   db.prepare("INSERT INTO router_sync_status(router_id,status,last_sync_at,last_error) VALUES(?,'online',datetime('now'),NULL) ON CONFLICT(router_id) DO UPDATE SET status='online',last_sync_at=datetime('now'),last_error=NULL").run(router.id);
 });
 transaction();
 return {routerId:router.id,online:true,queues:result.queues.length,isolated:isolatedAddresses.size};
}
let syncRunning = false;
async function syncAllRouters() {
 if (syncRunning) return;
 syncRunning = true;
 try {
   const all = db.prepare('SELECT * FROM routers ORDER BY id').all();
   const known = new Set(all.map(r=>r.id));
   for (const router of all) {
     try { await syncRouter(router); }
     catch (e) {
       db.prepare("INSERT INTO router_sync_status(router_id,status,last_sync_at,last_error) VALUES(?,'offline',datetime('now'),?) ON CONFLICT(router_id) DO UPDATE SET status='offline',last_sync_at=datetime('now'),last_error=excluded.last_error").run(router.id,String(e.message||'Koneksi gagal').slice(0,500));
     }
   }
   db.prepare('DELETE FROM router_sync_status WHERE router_id NOT IN (SELECT id FROM routers)').run();
 } finally { syncRunning = false; }
}
app.get('/api/sync/status', auth, (req,res) => {
 const rows = db.prepare(`SELECT r.id AS router_id,r.name AS router_name,
   COALESCE(s.status,'pending') AS status,s.last_sync_at,s.last_error,COALESCE(s.changes_detected,0) AS changes_detected
   FROM routers r LEFT JOIN router_sync_status s ON s.router_id=r.id ORDER BY r.name`).all();
 const changes = db.prepare('SELECT COUNT(*) AS n FROM sync_changes').get().n;
 res.json({intervalSeconds:30,isolationList:ISOLATION_LIST,totalChanges:changes,routers:rows});
});
app.get('/api/sync/changes', auth, (req,res) => {
 const limit = Math.min(Math.max(Number(req.query.limit)||100,1),500);
 const rows = db.prepare(`SELECT c.*,r.name AS router_name FROM sync_changes c
   JOIN routers r ON r.id=c.router_id ORDER BY c.id DESC LIMIT ?`).all(limit);
 res.json(rows.map(row=>({...row,old_value:row.old_value?JSON.parse(row.old_value):null,new_value:row.new_value?JSON.parse(row.new_value):null})));
});
app.post('/api/sync/run', auth, asyncRoute(async (req,res) => {
 await syncAllRouters();
 res.json({ok:true,status:db.prepare('SELECT router_id,status,last_sync_at,last_error FROM router_sync_status ORDER BY router_id').all()});
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Endpoint tidak ditemukan.' }));
app.use((err, req, res, next) => {
 console.error(new Date().toISOString(), err.message);
 const status = err.status || 502;
 res.status(status).json({ error: status >= 500 ? 'Operasi gagal. Periksa koneksi router dan log server.' : err.message });
});
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
let sampling = false;
async function sampleTraffic() {
 if (sampling) return;
 sampling = true;
 try {
   const allRouters = db.prepare('SELECT * FROM routers ORDER BY id').all();
   for (const router of allRouters) {
     try {
       const queues = await withRouter(router, api => api.write('/queue/simple/print'));
       const insert = db.prepare('INSERT INTO traffic_samples(router_id,queue_name,target,rx_bps,tx_bps,sampled_at) VALUES(?,?,?,?,?,datetime(\'now\'))');
       const transaction = db.transaction(items => {
         for (const q of items) {
           const [rx,tx] = parseRate(q.rate || '0/0');
           insert.run(router.id, q.name || '(tanpa nama)', q.target || '', rx, tx);
         }
       });
       transaction(queues);
     } catch (e) { console.warn('Traffic sampling router '+router.id+' gagal: '+e.message); }
   }
   db.prepare("DELETE FROM traffic_samples WHERE sampled_at < datetime('now','-31 days')").run();
 } finally { sampling = false; }
}
app.listen(PORT, '0.0.0.0', () => console.log(`User Manager berjalan pada port ${PORT}`));
setTimeout(() => sampleTraffic().catch(e=>console.warn('Sampling awal gagal:',e.message)), 5000);
setInterval(() => sampleTraffic().catch(e=>console.warn('Sampling gagal:',e.message)), 60000);
setTimeout(() => syncAllRouters().catch(e=>console.warn('Sinkronisasi awal gagal:',e.message)), 8000);
setInterval(() => syncAllRouters().catch(e=>console.warn('Sinkronisasi gagal:',e.message)), 30000);
