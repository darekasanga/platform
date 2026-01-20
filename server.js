const http = require('http');
const { URL } = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.NOTIFY_SECRET || 'dev-secret-change-me';
const PEPPER = process.env.PHONE_PEPPER || 'dev-pepper-change-me';
const SMS_TTL_MS = 10 * 60 * 1000;
const QR_TTL_MS = 15 * 60 * 1000;

const sessions = new Map();
const users = [];
const userIdentities = [];
const smsChallenges = [];
const guardianLinks = [];
const notificationThreads = [];
const notificationMessages = [];
const notificationReads = [];
const notifyQrTokens = [];

const rateLimits = new Map();

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
};

function jsonResponse(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function notFound(res) {
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not Found');
}

function parseCookies(req) {
  const raw = req.headers.cookie;
  if (!raw) return {};
  return raw.split(';').reduce((acc, part) => {
    const [key, ...rest] = part.trim().split('=');
    acc[key] = decodeURIComponent(rest.join('='));
    return acc;
  }, {});
}

function getSessionUserId(req) {
  const cookies = parseCookies(req);
  const token = cookies.session_token;
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  return session.user_id;
}

function createSession(res, userId) {
  const token = crypto.randomUUID();
  sessions.set(token, { user_id: userId, created_at: new Date().toISOString() });
  res.setHeader('Set-Cookie', `session_token=${token}; Path=/; HttpOnly`);
}

function requireStaff(req, res) {
  const staffId = req.headers['x-staff-id'];
  if (!staffId) {
    jsonResponse(res, 401, { message: 'staff auth required' });
    return null;
  }
  return staffId;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
    });
    req.on('end', () => {
      if (!data) return resolve(null);
      try {
        resolve(JSON.parse(data));
      } catch (error) {
        reject(error);
      }
    });
  });
}

function maskPhone(phone) {
  if (!phone) return null;
  const last4 = phone.slice(-4);
  return `${phone.slice(0, 3)}-****-${last4}`;
}

function hashPhone(phone) {
  return crypto.createHmac('sha256', PEPPER).update(phone).digest('hex');
}

function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

function rateLimit(key, limit, windowMs) {
  const now = Date.now();
  const entry = rateLimits.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + windowMs;
  }
  entry.count += 1;
  rateLimits.set(key, entry);
  return entry.count <= limit;
}

function getOrCreateUserByIdentity(provider, externalId, displayHint) {
  const existingIdentity = userIdentities.find(
    (identity) => identity.provider === provider && identity.external_id === externalId,
  );
  if (existingIdentity) {
    return users.find((user) => user.id === existingIdentity.user_id);
  }
  const now = new Date().toISOString();
  const user = { id: crypto.randomUUID(), created_at: now, updated_at: now };
  users.push(user);
  userIdentities.push({
    id: crypto.randomUUID(),
    user_id: user.id,
    provider,
    external_id: externalId,
    display_hint: displayHint || null,
    created_at: now,
  });
  return user;
}

function upsertGuardianLink(userId, childId) {
  const existing = guardianLinks.find(
    (link) => link.user_id === userId && link.child_id === childId && link.is_active,
  );
  const now = new Date().toISOString();
  if (existing) {
    existing.updated_at = now;
    return existing;
  }
  const link = {
    id: crypto.randomUUID(),
    user_id: userId,
    child_id: childId,
    linked_via: 'NOTIFY_QR',
    valid_from: now,
    valid_to: null,
    is_active: true,
    created_at: now,
    updated_at: now,
  };
  guardianLinks.push(link);
  return link;
}

function createNotificationThread(childId, staffId) {
  const now = new Date().toISOString();
  const thread = {
    id: crypto.randomUUID(),
    child_id: childId,
    status: 'OPEN',
    created_by_staff_id: staffId || null,
    created_at: now,
    updated_at: now,
  };
  notificationThreads.push(thread);
  return thread;
}

function getThreadByChildId(childId) {
  return notificationThreads.find((thread) => thread.child_id === childId);
}

function getMessagesByThread(threadId) {
  return notificationMessages
    .filter((message) => message.thread_id === threadId)
    .sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
}

function updateRead(threadId, readerType, readerId) {
  const now = new Date().toISOString();
  const existing = notificationReads.find(
    (read) =>
      read.thread_id === threadId && read.reader_type === readerType && read.reader_id === readerId,
  );
  if (existing) {
    existing.last_read_at = now;
    return existing;
  }
  const entry = {
    id: crypto.randomUUID(),
    thread_id: threadId,
    reader_type: readerType,
    reader_id: readerId,
    last_read_at: now,
  };
  notificationReads.push(entry);
  return entry;
}

function getUnreadCount(threadId, readerType, readerId) {
  const read = notificationReads.find(
    (entry) =>
      entry.thread_id === threadId && entry.reader_type === readerType && entry.reader_id === readerId,
  );
  const lastReadAt = read ? new Date(read.last_read_at).getTime() : 0;
  return getMessagesByThread(threadId).filter(
    (message) => new Date(message.created_at).getTime() > lastReadAt,
  ).length;
}

function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${signature}`;
}

function verifyToken(token) {
  const [body, signature] = token.split('.');
  if (!body || !signature) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (signature.length !== expected.length) {
    return null;
  }
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return null;
  }
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (error) {
    return null;
  }
}

function createNotifyQrToken(threadId, childId) {
  const now = Date.now();
  const tokenId = crypto.randomUUID();
  const payload = {
    token_id: tokenId,
    thread_id: threadId,
    child_id: childId,
    nonce: crypto.randomBytes(8).toString('hex'),
    exp: now + QR_TTL_MS,
  };
  notifyQrTokens.push({
    id: tokenId,
    thread_id: threadId,
    child_id: childId,
    expires_at: new Date(payload.exp).toISOString(),
    nonce: payload.nonce,
    consumed_at: null,
    created_at: new Date().toISOString(),
  });
  return signToken(payload);
}

function consumeNotifyToken(tokenId) {
  const entry = notifyQrTokens.find((token) => token.id === tokenId);
  if (!entry) return null;
  if (entry.consumed_at) return null;
  if (new Date(entry.expires_at).getTime() < Date.now()) return null;
  entry.consumed_at = new Date().toISOString();
  return entry;
}

function createQrSvg(url) {
  const size = 240;
  const padding = 16;
  return `
    <svg viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="QR">
      <rect width="${size}" height="${size}" fill="#fff" />
      <rect x="${padding}" y="${padding}" width="${size - padding * 2}" height="${size - padding * 2}" fill="#0f172a" />
      <rect x="${padding + 12}" y="${padding + 12}" width="${size - padding * 2 - 24}" height="${size - padding * 2 - 24}" fill="#fff" />
      <text x="${size / 2}" y="${size / 2}" text-anchor="middle" font-size="12" fill="#0f172a">QR ENTRY</text>
    </svg>
  `;
}

function serveStatic(res, filePath) {
  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';
  fs.readFile(filePath, (error, data) => {
    if (error) {
      notFound(res);
      return;
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  if (req.method === 'GET' && pathname === '/') {
    return serveStatic(res, path.join(__dirname, 'index.html'));
  }

  if (req.method === 'GET' && pathname === '/login') {
    return serveStatic(res, path.join(__dirname, 'login.html'));
  }

  if (req.method === 'POST' && pathname === '/auth/sms/start') {
    try {
      const body = await readBody(req);
      const phone = body?.phone_e164?.trim();
      if (!phone) {
        return jsonResponse(res, 400, { message: 'phone required' });
      }
      const ipKey = req.socket.remoteAddress || 'unknown';
      if (!rateLimit(`sms:${ipKey}`, 5, 60 * 1000)) {
        return jsonResponse(res, 429, { message: 'rate limit' });
      }
      const code = `${Math.floor(100000 + Math.random() * 900000)}`;
      const challengeId = crypto.randomUUID();
      const now = Date.now();
      smsChallenges.push({
        id: challengeId,
        phone_e164: null,
        phone_hash: hashPhone(phone),
        code_hash: hashCode(code),
        purpose: body?.purpose || 'LINK_BY_QR',
        expires_at: new Date(now + SMS_TTL_MS).toISOString(),
        tries_left: 5,
        created_at: new Date().toISOString(),
        consumed_at: null,
        display_hint: maskPhone(phone),
      });

      const responsePayload = {
        challenge_id: challengeId,
        ttl_sec: Math.floor(SMS_TTL_MS / 1000),
      };

      if (process.env.NODE_ENV !== 'production') {
        responsePayload.debug_code = code;
      }

      return jsonResponse(res, 200, responsePayload);
    } catch (error) {
      return jsonResponse(res, 400, { message: 'invalid body' });
    }
  }

  if (req.method === 'POST' && pathname === '/auth/sms/verify') {
    try {
      const body = await readBody(req);
      const challengeId = body?.challenge_id;
      const code = body?.code;
      const challenge = smsChallenges.find((entry) => entry.id === challengeId);
      if (!challenge) {
        return jsonResponse(res, 400, { message: 'invalid challenge' });
      }
      if (challenge.consumed_at) {
        return jsonResponse(res, 400, { message: 'challenge used' });
      }
      if (new Date(challenge.expires_at).getTime() < Date.now()) {
        return jsonResponse(res, 400, { message: 'expired' });
      }
      if (challenge.tries_left <= 0) {
        return jsonResponse(res, 400, { message: 'too many tries' });
      }
      challenge.tries_left -= 1;
      if (hashCode(code) !== challenge.code_hash) {
        return jsonResponse(res, 400, { message: 'invalid code' });
      }
      challenge.consumed_at = new Date().toISOString();
      const user = getOrCreateUserByIdentity('sms', challenge.phone_hash, challenge.display_hint);
      createSession(res, user.id);
      return jsonResponse(res, 200, { session_ok: true, user_id: user.id });
    } catch (error) {
      return jsonResponse(res, 400, { message: 'invalid body' });
    }
  }

  if (req.method === 'GET' && pathname.startsWith('/auth/') && pathname.endsWith('/login')) {
    const provider = pathname.split('/')[2];
    const returnTo = url.searchParams.get('return_to') || '/';
    const externalId = crypto.randomUUID();
    const redirectUrl = new URL(`/auth/${provider}/callback`, `http://${req.headers.host}`);
    redirectUrl.searchParams.set('external_id', externalId);
    redirectUrl.searchParams.set('return_to', returnTo);
    res.writeHead(302, { Location: redirectUrl.toString() });
    return res.end();
  }

  if (req.method === 'GET' && pathname.startsWith('/auth/') && pathname.endsWith('/callback')) {
    const provider = pathname.split('/')[2];
    const externalId = url.searchParams.get('external_id');
    const returnTo = url.searchParams.get('return_to') || '/';
    if (!externalId) {
      return jsonResponse(res, 400, { message: 'missing external id' });
    }
    const user = getOrCreateUserByIdentity(provider, externalId, `${provider} account`);
    createSession(res, user.id);
    res.writeHead(302, { Location: returnTo });
    return res.end();
  }

  if (req.method === 'GET' && pathname === '/q/notify') {
    const token = url.searchParams.get('t');
    const payload = token ? verifyToken(token) : null;
    if (!payload) {
      return notFound(res);
    }
    const userId = getSessionUserId(req);
    if (!userId) {
      const returnTo = `/q/notify?t=${encodeURIComponent(token)}`;
      res.writeHead(302, { Location: `/login?return_to=${encodeURIComponent(returnTo)}` });
      return res.end();
    }
    const consumed = consumeNotifyToken(payload.token_id);
    if (!consumed) {
      return notFound(res);
    }
    const thread = notificationThreads.find((entry) => entry.id === payload.thread_id);
    if (!thread) {
      return notFound(res);
    }
    upsertGuardianLink(userId, payload.child_id);
    res.writeHead(302, { Location: `/notify/${payload.thread_id}` });
    return res.end();
  }

  if (req.method === 'GET' && pathname.startsWith('/notify/')) {
    const userId = getSessionUserId(req);
    if (!userId) {
      res.writeHead(302, { Location: `/login?return_to=${encodeURIComponent(pathname)}` });
      return res.end();
    }
    const threadId = pathname.split('/').pop();
    const thread = notificationThreads.find((entry) => entry.id === threadId);
    if (!thread) {
      return notFound(res);
    }
    const linked = guardianLinks.find(
      (link) => link.user_id === userId && link.child_id === thread.child_id && link.is_active,
    );
    if (!linked) {
      return jsonResponse(res, 403, { message: 'not linked' });
    }
    return serveStatic(res, path.join(__dirname, 'notify.html'));
  }

  if (req.method === 'GET' && pathname.startsWith('/api/notify/threads/')) {
    const userId = getSessionUserId(req);
    if (!userId) {
      return jsonResponse(res, 401, { message: 'login required' });
    }
    const threadId = pathname.split('/').pop();
    const thread = notificationThreads.find((entry) => entry.id === threadId);
    if (!thread) {
      return jsonResponse(res, 404, { message: 'thread not found' });
    }
    const linked = guardianLinks.find(
      (link) => link.user_id === userId && link.child_id === thread.child_id && link.is_active,
    );
    if (!linked) {
      return jsonResponse(res, 403, { message: 'not linked' });
    }
    const messages = getMessagesByThread(threadId);
    return jsonResponse(res, 200, { ...thread, messages });
  }

  if (req.method === 'POST' && pathname.startsWith('/notify/') && pathname.endsWith('/reply')) {
    const userId = getSessionUserId(req);
    if (!userId) {
      return jsonResponse(res, 401, { message: 'login required' });
    }
    const threadId = pathname.split('/')[2];
    const thread = notificationThreads.find((entry) => entry.id === threadId);
    if (!thread) {
      return jsonResponse(res, 404, { message: 'thread not found' });
    }
    const linked = guardianLinks.find(
      (link) => link.user_id === userId && link.child_id === thread.child_id && link.is_active,
    );
    if (!linked) {
      return jsonResponse(res, 403, { message: 'not linked' });
    }
    const body = await readBody(req);
    if (!body?.body_text) {
      return jsonResponse(res, 400, { message: 'body required' });
    }
    const now = new Date().toISOString();
    notificationMessages.push({
      id: crypto.randomUUID(),
      thread_id: threadId,
      sender_type: 'GUARDIAN',
      sender_id: userId,
      body_text: body.body_text,
      created_at: now,
    });
    thread.updated_at = now;
    return jsonResponse(res, 200, { ok: true });
  }

  if (req.method === 'POST' && pathname.startsWith('/notify/') && pathname.endsWith('/read')) {
    const userId = getSessionUserId(req);
    if (!userId) {
      return jsonResponse(res, 401, { message: 'login required' });
    }
    const threadId = pathname.split('/')[2];
    const thread = notificationThreads.find((entry) => entry.id === threadId);
    if (!thread) {
      return jsonResponse(res, 404, { message: 'thread not found' });
    }
    const linked = guardianLinks.find(
      (link) => link.user_id === userId && link.child_id === thread.child_id && link.is_active,
    );
    if (!linked) {
      return jsonResponse(res, 403, { message: 'not linked' });
    }
    updateRead(threadId, 'GUARDIAN', userId);
    return jsonResponse(res, 200, { ok: true });
  }

  if (req.method === 'GET' && pathname.startsWith('/admin/notify/threads/')) {
    return serveStatic(res, path.join(__dirname, 'admin', 'notify-thread.html'));
  }

  if (req.method === 'GET' && pathname.startsWith('/admin/api/notify/threads/')) {
    const staffId = requireStaff(req, res);
    if (!staffId) return null;
    const threadId = pathname.split('/').pop();
    const thread = notificationThreads.find((entry) => entry.id === threadId);
    if (!thread) {
      return jsonResponse(res, 404, { message: 'thread not found' });
    }
    const messages = getMessagesByThread(threadId);
    const guardianLinksForChild = guardianLinks.filter(
      (link) => link.child_id === thread.child_id && link.is_active,
    );
    const guardianUnread = guardianLinksForChild.reduce((sum, link) => {
      return sum + getUnreadCount(threadId, 'GUARDIAN', link.user_id);
    }, 0);
    const staffUnread = getUnreadCount(threadId, 'STAFF', staffId);
    return jsonResponse(res, 200, {
      ...thread,
      messages,
      unread_guardian: guardianUnread,
      unread_staff: staffUnread,
    });
  }

  if (req.method === 'POST' && pathname.startsWith('/admin/notify/threads/') && pathname.endsWith('/send')) {
    const staffId = requireStaff(req, res);
    if (!staffId) return null;
    const threadId = pathname.split('/')[4];
    const thread = notificationThreads.find((entry) => entry.id === threadId);
    if (!thread) {
      return jsonResponse(res, 404, { message: 'thread not found' });
    }
    const body = await readBody(req);
    if (!body?.body_text) {
      return jsonResponse(res, 400, { message: 'body required' });
    }
    const now = new Date().toISOString();
    notificationMessages.push({
      id: crypto.randomUUID(),
      thread_id: threadId,
      sender_type: 'STAFF',
      sender_id: staffId,
      body_text: body.body_text,
      created_at: now,
    });
    thread.updated_at = now;
    return jsonResponse(res, 200, { ok: true });
  }

  if (req.method === 'POST' && pathname.startsWith('/admin/notify/threads/') && pathname.endsWith('/read')) {
    const staffId = requireStaff(req, res);
    if (!staffId) return null;
    const threadId = pathname.split('/')[4];
    updateRead(threadId, 'STAFF', staffId);
    return jsonResponse(res, 200, { ok: true });
  }

  if (req.method === 'GET' && pathname.startsWith('/admin/children/')) {
    const staffId = requireStaff(req, res);
    if (!staffId) return null;
    const childId = pathname.split('/')[3];
    const thread = getThreadByChildId(childId);
    const linkCount = guardianLinks.filter(
      (link) => link.child_id === childId && link.is_active,
    ).length;
    const lastMessage = thread
      ? notificationMessages
          .filter((message) => message.thread_id === thread.id)
          .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0]
      : null;
    const unreadCount = thread ? getUnreadCount(thread.id, 'STAFF', staffId) : 0;
    return jsonResponse(res, 200, {
      child_id: childId,
      link_status: linkCount > 0 ? 'LINKED' : 'UNLINKED',
      linked_count: linkCount,
      thread_id: thread ? thread.id : null,
      unread_count: unreadCount,
      last_message_at: lastMessage ? lastMessage.created_at : null,
    });
  }

  if (req.method === 'POST' && pathname === '/admin/notify/thread/upsert') {
    const staffId = requireStaff(req, res);
    if (!staffId) return null;
    const body = await readBody(req);
    const childId = body?.child_id;
    if (!childId) {
      return jsonResponse(res, 400, { message: 'child required' });
    }
    const existing = getThreadByChildId(childId);
    const thread = existing || createNotificationThread(childId, staffId);
    return jsonResponse(res, 200, { thread_id: thread.id });
  }

  if (req.method === 'POST' && pathname === '/admin/notify/qr') {
    const staffId = requireStaff(req, res);
    if (!staffId) return null;
    const body = await readBody(req);
    const childId = body?.child_id;
    const threadId = body?.thread_id;
    if (!childId || !threadId) {
      return jsonResponse(res, 400, { message: 'child/thread required' });
    }
    const signedToken = createNotifyQrToken(threadId, childId);
    const urlValue = `/q/notify?t=${encodeURIComponent(signedToken)}`;
    return jsonResponse(res, 200, {
      url: urlValue,
      expires_at: new Date(Date.now() + QR_TTL_MS).toISOString(),
      qr_svg: createQrSvg(urlValue),
    });
  }

  if (req.method === 'GET' && pathname === '/CalCu.html') {
    return serveStatic(res, path.join(__dirname, 'CalCu.html'));
  }

  if (req.method === 'GET') {
    const assetPath = path.join(__dirname, pathname);
    if (fs.existsSync(assetPath) && fs.statSync(assetPath).isFile()) {
      return serveStatic(res, assetPath);
    }
  }

  return notFound(res);
});

server.listen(PORT, () => {
  console.log(`Notify server running at http://localhost:${PORT}`);
});
