// ===== Minimal runnable node pipeline with versioned daily_nodes =====
// node index.js

const crypto = require('crypto');

// --------------------
// Config / Secrets
// --------------------
const SECRET = 'dev-secret-change-me';
const ALLOWED_ZONE = true; // true=園内, false=園外（falseにすると即遮断）

// --------------------
// Helpers
// --------------------
const hmac = (msg) => crypto.createHmac('sha256', SECRET).update(msg).digest();

const base64url = (buf) =>
  buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

const randId = (n = 6) => crypto.randomBytes(n).toString('hex').slice(0, n);

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
// Build node payload
// --------------------
function buildNodePayload(childId, yyyymmdd, events, baseCategoryCode, derivedCategoryCode) {
  const nodeKey = hmac(`${childId}|${yyyymmdd}`);
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
    node_key: lookup,
    prefix12,
    date: yyyymmdd,
    state_token,
    dict_id,
    events,
    base_category_code: baseCategoryCode,
    derived_category_code: derivedCategoryCode,
    derived: { raw_minutes: rawMinutes, ext_minutes: extMinutes },
    __server_only: { dict: map }, // keep only on server
  };
}

// --------------------
// Versioned daily_nodes store (SCD2)
// --------------------
const dailyNodes = [];
const calcHistory = [];

function inputsHash({ events, baseCategoryCode, derivedCategoryCode, policyVersion }) {
  const payload = JSON.stringify({
    events,
    baseCategoryCode,
    derivedCategoryCode,
    policyVersion,
  });
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function findActiveNode(childId, yyyymmdd) {
  return dailyNodes.find(
    (node) => node.child_id === childId && node.date === yyyymmdd && node.status === 'ACTIVE',
  );
}

function supersedeNode(currentNode, nextNodeId) {
  currentNode.status = 'SUPERSEDED';
  currentNode.valid_to = new Date().toISOString();
  currentNode.superseded_by_id = nextNodeId;
}

function createCalcHistory(dailyNode) {
  calcHistory.push({
    id: crypto.randomUUID(),
    daily_node_id: dailyNode.id,
    created_at: new Date().toISOString(),
    snapshot: {
      derived: dailyNode.derived,
      derived_category_code: dailyNode.derived_category_code,
    },
  });
}

function rebuildDailyNode({
  childId,
  yyyymmdd,
  events,
  baseCategoryCode,
  derivedCategoryCode,
  policyVersion,
  changeReasonCode,
  changeNote,
}) {
  const hash = inputsHash({ events, baseCategoryCode, derivedCategoryCode, policyVersion });
  const active = findActiveNode(childId, yyyymmdd);

  if (active && active.inputs_hash === hash) {
    return { node: active, changed: false };
  }

  const nodePayload = buildNodePayload(
    childId,
    yyyymmdd,
    events,
    baseCategoryCode,
    derivedCategoryCode,
  );
  const now = new Date().toISOString();
  const nextId = crypto.randomUUID();
  const nextVersion = active ? active.version + 1 : 1;
  const statementId = active ? active.statement_id : crypto.randomUUID();

  if (active) {
    supersedeNode(active, nextId);
  }

  const nextNode = {
    id: nextId,
    statement_id: statementId,
    child_id: childId,
    date: yyyymmdd,
    version: nextVersion,
    status: 'ACTIVE',
    valid_from: now,
    valid_to: null,
    supersedes_id: active ? active.id : null,
    superseded_by_id: null,
    change_reason_code: changeReasonCode,
    change_note: changeNote ?? null,
    inputs_hash: hash,
    ...nodePayload,
  };

  dailyNodes.push(nextNode);
  createCalcHistory(nextNode);

  return { node: nextNode, changed: true };
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
const baseEvents = [
  { t: 'IN', at: 730 },
  { t: 'OUT', at: 1510 },
  { t: 'CAT', c: '01', at: 1530 },
  { t: 'EX', c: '02', at: 0 },
];

const first = rebuildDailyNode({
  childId: 'child-123',
  yyyymmdd: '20260119',
  events: baseEvents,
  baseCategoryCode: 'A1',
  derivedCategoryCode: 'A1',
  policyVersion: '2026.01',
  changeReasonCode: '01',
  changeNote: 'CSV再取込',
});

const idempotent = rebuildDailyNode({
  childId: 'child-123',
  yyyymmdd: '20260119',
  events: baseEvents,
  baseCategoryCode: 'A1',
  derivedCategoryCode: 'A1',
  policyVersion: '2026.01',
  changeReasonCode: '01',
  changeNote: 'CSV再取込',
});

const updatedEvents = [...baseEvents, { t: 'EX', c: '03', at: 0 }];

const second = rebuildDailyNode({
  childId: 'child-123',
  yyyymmdd: '20260119',
  events: updatedEvents,
  baseCategoryCode: 'A1',
  derivedCategoryCode: 'B2',
  policyVersion: '2026.01',
  changeReasonCode: '03',
  changeNote: '免除追加',
});

console.log('FIRST ACTIVE:', {
  version: first.node.version,
  status: first.node.status,
  prefix12: first.node.prefix12,
  inputs_hash: first.node.inputs_hash.slice(0, 12),
});
console.log('IDEMPOTENT:', { changed: idempotent.changed, version: idempotent.node.version });
console.log('SECOND ACTIVE:', {
  version: second.node.version,
  status: second.node.status,
  supersedes_id: second.node.supersedes_id,
  inputs_hash: second.node.inputs_hash.slice(0, 12),
});

const decoded = decodeGate(second.node);
console.log('DECODE:', decoded);
console.log('HISTORY:', dailyNodes.map((n) => ({ id: n.id, version: n.version, status: n.status })));
console.log(
  'CALC_HISTORY:',
  calcHistory.map((c) => ({ id: c.id, daily_node_id: c.daily_node_id })),
);
