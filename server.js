// Minimal HTTP server: create node -> decode gate (alert mode)
// Run: node server.js

const http = require('http');
const crypto = require('crypto');

const SECRET = 'dev-secret-change-me';

// ===== In-memory stores (demo) =====
const NODES = new Map(); // node_id -> node (includes server-only dict)
const ALERT = {
  on: false,
  first_seen_at: null,
  last_seen_at: null,
  count: 0,
  reason: null,
};

// ===== Helpers =====
const hmac = (msg) => crypto.createHmac('sha256', SECRET).update(msg).digest();

const base64url = (buf) =>
  buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

const randId = (n = 12) => crypto.randomBytes(n).toString('hex').slice(0, n);

function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        return resolve(JSON.parse(data));
      } catch (e) {
        return reject(new Error('Invalid JSON'));
      }
    });
  });
}

function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
}

// ===== 2-bit internal symbols =====
const INTERNAL = ['00', '01', '10', '11', '*0', '0*', '*1', '1*', '__', '_'];

// ===== Unicode pools (safe-ish: no emoji, no combining marks) =====
const POOL_ASCII = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split('');
const POOL_THAI =
  'กขคงจฉชซญฎฏฐฑฒณดตถทนบปผพฟภมยรลวศษสหฬอฮ'.split('');
const POOL_AR = 'ابتثجحخدذرزسشصضطظعغفقكلمنهوي'.split('');
const UNICODE_POOL = [...POOL_ASCII, ...POOL_THAI, ...POOL_AR];

function makeDict() {
  const keys = [...Array(10).keys()].map(String);
  const vals = [...INTERNAL];

  // Fisher–Yates shuffle
  for (let i = vals.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [vals[i], vals[j]] = [vals[j], vals[i]];
  }

  const map = {};
  keys.forEach((k, i) => {
    map[k] = vals[i];
  });

  return { dict_id: randId(6), map };
}

function encodeUnicode(internals) {
  // Internal symbol count == token length (fixed length)
  const out = [];
  for (let i = 0; i < internals.length; i += 1) {
    out.push(UNICODE_POOL[Math.floor(Math.random() * UNICODE_POOL.length)]);
  }
  return out.join('');
}

function computeDerived(events) {
  const inEv = events.find((e) => e.t === 'IN');
  const outEv = [...events].reverse().find((e) => e.t === 'OUT');

  // convert HHMM -> minutes from 00:00
  const hhmmToMinutes = (hhmm) => {
    const s = String(hhmm).padStart(4, '0');
    const hh = parseInt(s.slice(0, 2), 10);
    const mm = parseInt(s.slice(2, 4), 10);
    return hh * 60 + mm;
  };

  if (!inEv || !outEv) return { raw_minutes: 0, ext_minutes: 0 };

  const inM = hhmmToMinutes(inEv.at);
  const outM = hhmmToMinutes(outEv.at);
  const raw = Math.max(0, outM - inM);

  // demo rule: base window 07:30-15:30 (480min)
  const base = 8 * 60;
  const ext = Math.max(0, raw - base);

  return { raw_minutes: raw, ext_minutes: ext };
}

function setAlert(reason) {
  const now = new Date().toISOString();
  if (!ALERT.on) {
    ALERT.on = true;
    ALERT.first_seen_at = now;
  }
  ALERT.last_seen_at = now;
  ALERT.count += 1;
  ALERT.reason = reason;
}

// ===== Core: build node =====
function buildNode(child_id, date, events) {
  const nodeKey = hmac(`${child_id}|${date}`);
  const lookup = base64url(nodeKey);
  const prefix12 = lookup.slice(0, 12);
  const { dict_id, map } = makeDict();

  // demo: internal stream from digits 0-9 (replace later with your slot-code stream)
  const digits = '0123456789'.split('');
  const internals = digits.map((d) => map[d]);
  const state_token = encodeUnicode(internals);

  const derived = computeDerived(events);
  const node_id = randId(10);

  const node = {
    v: 1,
    node_id,
    node_key: lookup,
    prefix12,
    date,
    state_token,
    dict_id,
    events,
    derived,
    __server_only: { dict: map }, // never return this
  };

  NODES.set(node_id, node);
  return node;
}

// ===== Core: decode gate =====
function decodeNode(node, allowed_zone) {
  // If zone is not allowed -> block + alert
  if (!allowed_zone) {
    setAlert('DECODE_ATTEMPT_OUTSIDE_ALLOWED_ZONE');
    return { blocked: true, reason: 'outside_allowed_zone' };
  }

  // Missing dict -> block + alert
  if (!node.__server_only || !node.__server_only.dict) {
    setAlert('MISSING_DICT');
    return { blocked: true, reason: 'missing_dict' };
  }

  // demo decode result: show dict mapping count only (avoid leaking)
  return {
    blocked: false,
    dict_id: node.dict_id,
    derived: node.derived,
    note: 'decoded_ok (demo).',
  };
}

// ===== HTTP routes =====
const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return send(res, 200, { ok: true, alert: ALERT });
    }
    if (req.method === 'POST' && req.url === '/node/create') {
      const body = await readJson(req);
      const child_id = body.child_id;
      const date = body.date; // "YYYYMMDD"
      const events = Array.isArray(body.events) ? body.events : [];
      if (!child_id || !date) {
        return send(res, 400, { error: 'child_id and date required' });
      }
      const node = buildNode(child_id, date, events);
      return send(res, 200, {
        node_id: node.node_id,
        v: node.v,
        prefix12: node.prefix12,
        date: node.date,
        state_token: node.state_token,
        dict_id: node.dict_id,
        derived: node.derived,
      });
    }
    if (req.method === 'POST' && req.url === '/node/decode') {
      const body = await readJson(req);
      const node_id = body.node_id;
      const allowed_zone = !!body.allowed_zone;
      const node = NODES.get(node_id);
      if (!node) return send(res, 404, { error: 'node not found' });
      const out = decodeNode(node, allowed_zone);
      if (out.blocked) return send(res, 403, { ...out, alert: ALERT });
      return send(res, 200, { ...out, alert: ALERT });
    }
    return send(res, 404, { error: 'not_found' });
  } catch (e) {
    return send(res, 500, { error: 'server_error', detail: String(e.message || e) });
  }
});

server.listen(8787, () => {
  console.log('Server running on http://localhost:8787');
  console.log('GET  /health');
  console.log('POST /node/create');
  console.log('POST /node/decode');
});
