// JD X SIDHU key server (no npm packages needed). Render: Start command = node server.js
// Env vars: ADMIN_PASSWORD, PRIVATE_KEY_PEM (PRIVATE_KEY.pem content), DATA_FILE (optional)
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-me';
const PRIVATE_KEY = process.env.PRIVATE_KEY_PEM ||
  (fs.existsSync(path.join(__dirname, 'PRIVATE_KEY.pem')) ? fs.readFileSync(path.join(__dirname, 'PRIVATE_KEY.pem'), 'utf8') : '');
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'keys.json');
const DAY = 86400000;

let db = { keys: {} };
try { db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch (e) {}
const save = () => fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));

function sign(obj) {
  const payload = JSON.stringify(obj);
  const s = crypto.createSign('SHA256'); s.update(payload);
  return { payload, sig: s.sign({ key: PRIVATE_KEY, dsaEncoding: 'ieee-p1363' }).toString('base64') };
}
const newKey = () => 'JDS-' + [0, 1, 2].map(() => crypto.randomBytes(2).toString('hex').toUpperCase()).join('-');

function check(key, deviceId) {
  const k = db.keys[String(key || '').trim().toUpperCase()];
  if (!k) return { err: 'INVALID KEY' };
  if (k.revoked) return { err: 'KEY EXPIRED / REVOKED BY ADMIN' };
  if (!deviceId || String(deviceId).length < 8) return { err: 'BAD DEVICE ID' };
  if (k.deviceId && k.deviceId !== deviceId) return { err: 'KEY ALREADY USED ON ANOTHER DEVICE' };
  if (!k.deviceId) { k.deviceId = deviceId; k.activatedAt = Date.now(); if (k.days > 0) k.expiresAt = k.activatedAt + k.days * DAY; save(); }
  if (k.expiresAt && Date.now() > k.expiresAt) return { err: 'KEY EXPIRED' };
  return { k };
}
function licence(key, deviceId) {
  const r = check(key, deviceId);
  if (r.err) return { ok: false, error: r.err };
  const token = sign({ key: String(key).trim().toUpperCase(), device: deviceId, exp: r.k.expiresAt || 0, plan: r.k.days || 'LIFETIME', iat: Date.now() });
  return { ok: true, token, expiresAt: r.k.expiresAt || 0, plan: r.k.days || 'LIFETIME' };
}

function handle(req, body) {
  const url = req.url.split('?')[0];
  const isAdmin = req.headers['x-admin-password'] === ADMIN_PASSWORD;
  if (req.method === 'POST' && url === '/api/activate') return licence(body.key, body.deviceId);
  if (req.method === 'POST' && url === '/api/verify') return licence(body.key, body.deviceId);
  if (url.startsWith('/api/admin/')) {
    if (!isAdmin) return { status: 401, ok: false, error: 'bad admin password' };
    if (url === '/api/admin/generate') {
      const days = body.plan === 'lifetime' ? 0 : parseInt(body.plan, 10);
      if (![0, 7, 15, 30].includes(days)) return { status: 400, ok: false, error: 'plan = 7 | 15 | 30 | lifetime' };
      const count = Math.min(parseInt(body.count || 1, 10) || 1, 100), keys = [];
      for (let i = 0; i < count; i++) { const k = newKey(); db.keys[k] = { days, createdAt: Date.now(), deviceId: null, revoked: false, note: body.note || '' }; keys.push(k); }
      save(); return { ok: true, keys };
    }
    const k = db.keys[String(body.key || '').trim().toUpperCase()];
    if (url === '/api/admin/revoke') { if (!k) return { status: 404, ok: false, error: 'not found' }; k.revoked = true; save(); return { ok: true }; }
    if (url === '/api/admin/unbind') { if (!k) return { status: 404, ok: false, error: 'not found' }; k.deviceId = null; save(); return { ok: true }; }
    if (url === '/api/admin/list') return { ok: true, keys: db.keys };
  }
  return { status: 404, ok: false, error: 'not found' };
}

http.createServer((req, res) => {
  const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, x-admin-password', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' };
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
  if (req.method === 'GET' && (req.url === '/admin' || req.url === '/admin/')) {
    res.writeHead(200, Object.assign({ 'Content-Type': 'text/html; charset=utf-8' }, cors));
    return res.end(fs.readFileSync(path.join(__dirname, 'admin.html')));
  }
  if (req.method === 'GET' && req.url === '/') { res.writeHead(200, cors); return res.end('JD X SIDHU key server running'); }
  let raw = '';
  req.on('data', (c) => { raw += c; if (raw.length > 1e5) req.destroy(); });
  req.on('end', () => {
    let body = {}; try { body = raw ? JSON.parse(raw) : {}; } catch (e) {}
    let out; try { out = handle(req, body); } catch (e) { out = { status: 500, ok: false, error: 'server error' }; }
    const status = out.status || 200; delete out.status;
    res.writeHead(status, Object.assign({ 'Content-Type': 'application/json' }, cors));
    res.end(JSON.stringify(out));
  });
}).listen(process.env.PORT || 3000, () => console.log('key server up'));
