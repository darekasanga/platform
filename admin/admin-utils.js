(() => {
  const ADMIN_USERS_KEY = "platformAdminUsers";
  const ADMIN_SESSION_KEY = "platformAdminSession";
  const ADMIN_REMEMBER_KEY = "platformAdminRemember";
  const ADMIN_LOCK_KEY = "platformAdminLockouts";
  const ADMIN_AUDIT_LOG_KEY = "platformAdminAuditLogs";
  const WIFI_SETTINGS_KEY = "platformWifiLocalSettings";
  const WIFI_SECRET_KEY = "platformWifiSecretKey";
  const SITE_KEY = "platformActiveSite";

  const LOGIN_LOCK_MINUTES = 10;
  const LOGIN_MAX_FAILURES = 5;

  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  function getActiveSite() {
    return localStorage.getItem(SITE_KEY) || "default";
  }

  function getAuditLogKey(siteId = getActiveSite()) {
    return `${ADMIN_AUDIT_LOG_KEY}:${siteId || "default"}`;
  }

  function safeParse(raw, fallback) {
    if (!raw) return fallback;
    try {
      return JSON.parse(raw);
    } catch (error) {
      console.error("Failed to parse JSON", error);
      return fallback;
    }
  }

  function base64FromArrayBuffer(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
  }

  function arrayBufferFromBase64(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function toBase64Url(value) {
    return value.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function randomString(length = 24) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return toBase64Url(base64FromArrayBuffer(bytes.buffer)).slice(0, length);
  }

  async function hashPassword(password, salt = randomString(16)) {
    const iterations = 120000;
    const key = await crypto.subtle.importKey("raw", textEncoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const derived = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt: textEncoder.encode(salt),
        iterations
      },
      key,
      256
    );
    const hash = base64FromArrayBuffer(derived);
    return `pbkdf2$${iterations}$${salt}$${hash}`;
  }

  async function verifyPassword(password, storedHash) {
    if (!storedHash) return false;
    const [scheme, iterations, salt, hash] = storedHash.split("$");
    if (scheme !== "pbkdf2" || !iterations || !salt || !hash) {
      return password === storedHash;
    }
    const key = await crypto.subtle.importKey("raw", textEncoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const derived = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt: textEncoder.encode(salt),
        iterations: Number(iterations)
      },
      key,
      256
    );
    const derivedHash = base64FromArrayBuffer(derived);
    return derivedHash === hash;
  }

  function loadAdminUsers() {
    return safeParse(localStorage.getItem(ADMIN_USERS_KEY), []);
  }

  function saveAdminUsers(users) {
    localStorage.setItem(ADMIN_USERS_KEY, JSON.stringify(users));
  }

  async function ensureSeedAdmin() {
    const existing = loadAdminUsers();
    if (existing.length) return existing;
    const now = new Date().toISOString();
    const passwordHash = await hashPassword("admin001");
    const seeded = [
      {
        id: crypto.randomUUID ? crypto.randomUUID() : `admin-${Date.now()}`,
        username: "admin001",
        password_hash: passwordHash,
        must_change_password: true,
        is_active: true,
        created_at: now,
        updated_at: now
      }
    ];
    saveAdminUsers(seeded);
    return seeded;
  }

  async function getAdminByUsername(username) {
    const users = await ensureSeedAdmin();
    return users.find((user) => user.username.toLowerCase() === username.toLowerCase()) || null;
  }

  function getLockouts() {
    return safeParse(localStorage.getItem(ADMIN_LOCK_KEY), {});
  }

  function saveLockouts(lockouts) {
    localStorage.setItem(ADMIN_LOCK_KEY, JSON.stringify(lockouts));
  }

  function resetLockout(username) {
    const lockouts = getLockouts();
    delete lockouts[username.toLowerCase()];
    saveLockouts(lockouts);
  }

  function registerFailure(username) {
    const key = username.toLowerCase();
    const lockouts = getLockouts();
    const current = lockouts[key] || { attempts: 0, lockUntil: null };
    const attempts = current.attempts + 1;
    let lockUntil = current.lockUntil;
    if (attempts >= LOGIN_MAX_FAILURES) {
      lockUntil = Date.now() + LOGIN_LOCK_MINUTES * 60 * 1000;
    }
    lockouts[key] = { attempts, lockUntil };
    saveLockouts(lockouts);
    return lockouts[key];
  }

  function getLockoutStatus(username) {
    const lockouts = getLockouts();
    return lockouts[username.toLowerCase()] || null;
  }

  function setAdminSession(session, remember = false) {
    sessionStorage.setItem(ADMIN_SESSION_KEY, JSON.stringify(session));
    if (remember) {
      localStorage.setItem(ADMIN_REMEMBER_KEY, JSON.stringify(session));
    }
  }

  function clearAdminSession() {
    sessionStorage.removeItem(ADMIN_SESSION_KEY);
    localStorage.removeItem(ADMIN_REMEMBER_KEY);
  }

  function getAdminSession() {
    const storedSession = sessionStorage.getItem(ADMIN_SESSION_KEY) || localStorage.getItem(ADMIN_REMEMBER_KEY);
    if (!storedSession) return null;
    const session = safeParse(storedSession, null);
    if (!session) return null;
    return session;
  }

  function requireAdminSession(options = {}) {
    const { allowMustChange = false } = options;
    const session = getAdminSession();
    if (!session) {
      window.location.href = "/admin/login.html";
      return null;
    }
    if (!allowMustChange && session.must_change_password) {
      window.location.href = "/admin/change-password.html";
      return null;
    }
    return session;
  }

  async function attemptLogin(username, password) {
    const lockout = getLockoutStatus(username);
    if (lockout?.lockUntil && lockout.lockUntil > Date.now()) {
      return {
        ok: false,
        reason: "lockout",
        lockUntil: lockout.lockUntil,
        attempts: lockout.attempts
      };
    }

    const user = await getAdminByUsername(username);
    if (!user) {
      registerFailure(username);
      return { ok: false, reason: "not_found" };
    }

    if (!user.is_active) {
      return { ok: false, reason: "inactive" };
    }

    const match = await verifyPassword(password, user.password_hash);
    if (!match) {
      const status = registerFailure(username);
      return { ok: false, reason: "invalid", attempts: status.attempts, lockUntil: status.lockUntil };
    }

    resetLockout(username);
    return { ok: true, user };
  }

  async function updateAdminPassword(userId, newPassword) {
    const users = await ensureSeedAdmin();
    const now = new Date().toISOString();
    const updated = users.map((user) => {
      if (user.id !== userId) return user;
      return {
        ...user,
        password_hash: newPassword,
        must_change_password: false,
        updated_at: now
      };
    });
    saveAdminUsers(updated);
    return updated.find((user) => user.id === userId);
  }

  function logAudit({ actorAdminId, action, meta = {}, siteId = getActiveSite() }) {
    const logs = safeParse(localStorage.getItem(getAuditLogKey(siteId)), []);
    logs.unshift({
      id: crypto.randomUUID ? crypto.randomUUID() : `audit-${Date.now()}`,
      actor_admin_id: actorAdminId,
      action,
      meta_json: meta,
      created_at: new Date().toISOString()
    });
    localStorage.setItem(getAuditLogKey(siteId), JSON.stringify(logs.slice(0, 100)));
  }

  function getAuditLogs(siteId = getActiveSite()) {
    return safeParse(localStorage.getItem(getAuditLogKey(siteId)), []);
  }

  async function getCryptoKey() {
    const stored = localStorage.getItem(WIFI_SECRET_KEY);
    if (stored) {
      const keyData = safeParse(stored, null);
      if (keyData) {
        return crypto.subtle.importKey("jwk", keyData, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
      }
    }
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const jwk = await crypto.subtle.exportKey("jwk", key);
    localStorage.setItem(WIFI_SECRET_KEY, JSON.stringify(jwk));
    return key;
  }

  async function encryptSecret(value) {
    if (!value) return "";
    const key = await getCryptoKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, textEncoder.encode(value));
    return `enc:${base64FromArrayBuffer(iv.buffer)}:${base64FromArrayBuffer(encrypted)}`;
  }

  async function decryptSecret(value) {
    if (!value) return "";
    if (!value.startsWith("enc:")) return value;
    const [, ivEncoded, dataEncoded] = value.split(":");
    if (!ivEncoded || !dataEncoded) return "";
    const key = await getCryptoKey();
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(arrayBufferFromBase64(ivEncoded)) },
      key,
      arrayBufferFromBase64(dataEncoded)
    );
    return textDecoder.decode(decrypted);
  }

  function getWifiStorageKey(siteId = getActiveSite()) {
    return `${WIFI_SETTINGS_KEY}:${siteId || "default"}`;
  }

  function getDefaultWifiSettings(siteId = getActiveSite()) {
    return {
      id: crypto.randomUUID ? crypto.randomUUID() : `wifi-${Date.now()}`,
      site_id: siteId || null,
      enabled: false,
      ssid: "",
      local_api_base_url: "http://192.168.10.2:8787",
      local_api_port: null,
      allowed_cidr_list: ["192.168.10.0/24"],
      device_shared_secret: "",
      heartbeat_interval_sec: 15,
      updated_by_admin_id: null,
      updated_at: new Date().toISOString()
    };
  }

  async function getWifiSettings(siteId = getActiveSite()) {
    const stored = safeParse(localStorage.getItem(getWifiStorageKey(siteId)), null);
    if (stored) return stored;
    const seeded = getDefaultWifiSettings(siteId);
    localStorage.setItem(getWifiStorageKey(siteId), JSON.stringify(seeded));
    return seeded;
  }

  async function saveWifiSettings(settings, siteId = getActiveSite()) {
    localStorage.setItem(getWifiStorageKey(siteId), JSON.stringify(settings));
  }

  function ipToInt(ip) {
    const parts = ip.split(".");
    if (parts.length !== 4) return null;
    const nums = parts.map((part) => Number(part));
    if (nums.some((num) => Number.isNaN(num) || num < 0 || num > 255)) return null;
    return nums.reduce((acc, val) => (acc << 8) + val, 0) >>> 0;
  }

  function cidrContains(ip, cidr) {
    const [range, bits] = cidr.split("/");
    const ipInt = ipToInt(ip);
    const rangeInt = ipToInt(range);
    const maskBits = Number(bits);
    if (ipInt === null || rangeInt === null || Number.isNaN(maskBits)) return false;
    const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
    return (ipInt & mask) === (rangeInt & mask);
  }

  function isIpAllowed(ip, cidrs) {
    if (!ip || !Array.isArray(cidrs) || !cidrs.length) return false;
    return cidrs.some((cidr) => cidrContains(ip, cidr.trim()));
  }

  window.AdminUtils = {
    ensureSeedAdmin,
    hashPassword,
    verifyPassword,
    attemptLogin,
    setAdminSession,
    getAdminSession,
    clearAdminSession,
    requireAdminSession,
    updateAdminPassword,
    logAudit,
    getAuditLogs,
    getActiveSite,
    getWifiSettings,
    saveWifiSettings,
    encryptSecret,
    decryptSecret,
    randomString,
    isIpAllowed
  };
})();
