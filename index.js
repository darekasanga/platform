// ===== Minimal runnable node pipeline =====
// node index.js
// (EnCho/browser runtime supported via Web Crypto)

const hasNodeCrypto = typeof require === 'function';
const nodeCrypto = hasNodeCrypto ? require('crypto') : null;
const webCrypto = globalThis.crypto;
const textEncoder = new TextEncoder();

// --------------------
// Config / Secrets
// --------------------
const SECRET = 'dev-secret-change-me';
const ALLOWED_ZONE = true; // true=園内, false=園外（falseにすると即遮断）

// --------------------
// Helpers
// --------------------
const hmac = async (msg) => {
  if (nodeCrypto) {
    return nodeCrypto.createHmac('sha256', SECRET).update(msg).digest();
  }

  if (!webCrypto?.subtle) {
    throw new Error('Web Crypto API not available for HMAC.');
  }

  const key = await webCrypto.subtle.importKey(
    'raw',
    textEncoder.encode(SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await webCrypto.subtle.sign(
    'HMAC',
    key,
    textEncoder.encode(msg),
  );
  return new Uint8Array(signature);
};

const base64url = (buf) => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let base64 = '';

  if (typeof Buffer !== 'undefined') {
    base64 = Buffer.from(bytes).toString('base64');
  } else {
    let binary = '';
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    base64 = btoa(binary);
  }

  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

const randomBytes = (n) => {
  if (nodeCrypto) {
    return nodeCrypto.randomBytes(n);
  }

  if (!webCrypto?.getRandomValues) {
    throw new Error('Web Crypto API not available for randomness.');
  }

  const bytes = new Uint8Array(n);
  webCrypto.getRandomValues(bytes);
  return bytes;
};

const randId = (n = 6) => {
  const bytes = randomBytes(n);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, n);
};

// --------------------
// 2-bit internal symbols
// --------------------
const INTERNAL = ['00', '01', '10', '11', '*0', '0*', '*1', '1*', '__', '_'];

// --------------------
// Unicode pools (safe, no combining)
// --------------------
const POOL_ASCII = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split('');
const POOL_THAI = 'กขคงจฉชซญฎฏฐฑฒณดตถทนบปผพฟภมยรลวศษสหฬอฮ'.split(
  '',
);
const POOL_AR = 'ابتثجحخدذرزسشصضطظعغفقكلمنهوي'.split('');
const UNICODE_POOL = [...POOL_ASCII, ...POOL_THAI, ...POOL_AR];

// --------------------
// Random dictionary (0-9 -> internal)
// --------------------
function makeDict() {
  const keys = [...Array(10).keys()].map(String);
  const vals = [...INTERNAL];

  // Fisher–Yates
  for (let i = vals.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [vals[i], vals[j]] = [vals[j], vals[i]];
  }

  const map = {};
  keys.forEach((k, i) => {
    map[k] = vals[i];
  });

  return { dict_id: randId(4), map };
}

// --------------------
// Encode internal -> unicode noise
// --------------------
function encodeUnicode(internals) {
  // map each internal symbol to a random unicode char (stable length)
  const out = [];
  for (const sym of internals) {
    const ch = UNICODE_POOL[Math.floor(Math.random() * UNICODE_POOL.length)];
    out.push(ch);
  }
  return out.join('');
}

// --------------------
// Build node
// --------------------
async function buildNode(childId, yyyymmdd, events) {
  const nodeKey = await hmac(`${childId}|${yyyymmdd}`);
  const lookup = base64url(nodeKey);

  const prefix12 = lookup.slice(0, 12);

  // demo: derive minutes trivially from events
  const inEv = events.find((e) => e.t === 'IN');
  const outEv = events.find((e) => e.t === 'OUT');
  const rawMinutes = inEv && outEv ? outEv.at - inEv.at : 0;
  const extMinutes = Math.max(0, rawMinutes - 480); // demo rule

  // make dict and internal stream from digits 0-9 (demo payload)
  const { dict_id, map } = makeDict();
  const digits = '0123456789'.split('');
  const internals = digits.map((d) => map[d]);
  const state_token = encodeUnicode(internals);

  return {
    v: 1,
    node_key: lookup,
    prefix12,
    date: yyyymmdd,
    state_token,
    dict_id,
    events,
    derived: { raw_minutes: rawMinutes, ext_minutes: extMinutes },
    __server_only: { dict: map }, // keep only on server
  };
}

// --------------------
// Decode gate (ALERT MODE)
// --------------------
function decodeGate(node) {
  if (!ALLOWED_ZONE) {
    console.error('⚠️ ALERT: decode attempt from unallowed zone. BLOCKED.');
    return null; // blocked, no decode
  }

  if (!node.__server_only || !node.__server_only.dict) {
    console.error('⚠️ ALERT: missing dict. BLOCKED.');
    return null;
  }

  // decode demo: just show internal symbols resolved by dict
  const resolved = Object.entries(node.__server_only.dict)
    .map(([k, v]) => `${k}->${v}`)
    .join(', ');

  return { ok: true, resolved };
}

// --------------------
// Demo run
// --------------------
const events = [
  { t: 'IN', at: 730 },
  { t: 'OUT', at: 1510 },
  { t: 'CAT', c: '01', at: 1530 },
  { t: 'EX', c: '02', at: 0 },
];

async function main() {
  const node = await buildNode('child-123', '20260119', events);
  console.log('NODE:', {
    v: node.v,
    prefix12: node.prefix12,
    date: node.date,
    state_token: node.state_token,
    dict_id: node.dict_id,
    derived: node.derived,
  });

  const decoded = decodeGate(node);
  console.log('DECODE:', decoded);
}

main().catch((error) => {
  console.error('Failed to run node demo:', error);
});
