"use strict";

const http = require("node:http");
const crypto = require("node:crypto");
const { Pool } = require("pg");

const HOST = process.env.SESSION_VAULT_HOST || "0.0.0.0";
const PORT = Number(process.env.SESSION_VAULT_PORT || 8787);
const MAX_BODY = 6 * 1024 * 1024;
const TOKEN_TTL_MS = 8 * 60 * 60 * 1000;
const INVITE_CODE = process.env.REGISTRATION_INVITE_CODE || "";
const ALLOWED_ORIGINS = new Set((process.env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean));
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 10, idleTimeoutMillis: 30000, connectionTimeoutMillis: 5000 });
const attempts = new Map();

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS vaults (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      envelope JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS auth_sessions (
      token_hash TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx ON auth_sessions(expires_at);
  `);
}

function send(res, status, body, origin) {
  const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };
  if (status !== 204) headers["Content-Type"] = "application/json; charset=utf-8";
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers.Vary = "Origin";
    headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type";
    headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, OPTIONS";
  }
  res.writeHead(status, headers);
  res.end(status === 204 ? undefined : JSON.stringify(body));
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw Object.assign(new Error("Запрос слишком большой"), { status: 413 });
    chunks.push(chunk);
  }
  if (!size) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw Object.assign(new Error("Некорректный JSON"), { status: 400 }); }
}

function checkRateLimit(req, res, origin) {
  const key = req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const item = attempts.get(key) || { start: now, count: 0 };
  if (now - item.start > 15 * 60 * 1000) { item.start = now; item.count = 0; }
  item.count += 1;
  attempts.set(key, item);
  if (attempts.size > 10000) for (const [address, entry] of attempts) if (now - entry.start > 15 * 60 * 1000) attempts.delete(address);
  if (item.count > 20) { send(res, 429, { error: "Слишком много попыток. Подожди 15 минут." }, origin); return false; }
  return true;
}

function validEmail(email) { return typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function hashToken(token) { return crypto.createHash("sha256").update(token).digest("hex"); }
function sameSecret(a, b) {
  const left = crypto.createHash("sha256").update(a).digest();
  const right = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(left, right);
}
function derivePasswordHash(password, salt) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (error, key) => error ? reject(error) : resolve(key)));
}

async function issueToken(userId) {
  const token = crypto.randomBytes(32).toString("base64url");
  await pool.query("INSERT INTO auth_sessions(token_hash, user_id, expires_at) VALUES($1, $2, now() + interval '8 hours')", [hashToken(token), userId]);
  return token;
}

async function getAuth(req) {
  const match = /^Bearer ([A-Za-z0-9_-]+)$/.exec(req.headers.authorization || "");
  if (!match) return null;
  const result = await pool.query("SELECT user_id FROM auth_sessions WHERE token_hash = $1 AND expires_at > now()", [hashToken(match[1])]);
  return result.rowCount ? { tokenHash: hashToken(match[1]), userId: result.rows[0].user_id } : null;
}

async function handle(req, res) {
  const origin = req.headers.origin;
  if (origin && !ALLOWED_ORIGINS.has(origin)) return send(res, 403, { error: "Источник запроса не разрешён" }, origin);
  if (req.method === "OPTIONS") return send(res, 204, {}, origin);
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  if (req.method === "GET" && url.pathname === "/health") {
    await pool.query("SELECT 1");
    return send(res, 200, { ok: true, service: "session-workspace-api" }, origin);
  }

  if (req.method === "POST" && ["/api/register", "/api/login"].includes(url.pathname)) {
    if (!checkRateLimit(req, res, origin)) return;
    const body = await readBody(req);
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = body.password;
    if (!validEmail(email) || typeof password !== "string" || password.length < 12 || password.length > 1024) {
      return send(res, 400, { error: "Нужна корректная почта и пароль кабинета не короче 12 символов" }, origin);
    }
    let user;
    if (url.pathname === "/api/register") {
      if (!INVITE_CODE || typeof body.inviteCode !== "string" || !sameSecret(body.inviteCode, INVITE_CODE)) {
        return send(res, 403, { error: "Для регистрации нужен действующий код приглашения" }, origin);
      }
      const salt = crypto.randomBytes(16);
      const passwordHash = await derivePasswordHash(password, salt);
      try {
        const result = await pool.query("INSERT INTO users(id, email, salt, password_hash) VALUES($1, $2, $3, $4) RETURNING id, email", [crypto.randomUUID(), email, salt.toString("base64"), passwordHash.toString("base64")]);
        user = result.rows[0];
      } catch (error) {
        if (error.code === "23505") return send(res, 409, { error: "Кабинет с такой почтой уже существует" }, origin);
        throw error;
      }
    } else {
      const result = await pool.query("SELECT id, email, salt, password_hash FROM users WHERE email = $1", [email]);
      user = result.rows[0];
      const salt = user ? Buffer.from(user.salt, "base64") : Buffer.alloc(16);
      const candidate = await derivePasswordHash(password, salt);
      const stored = user ? Buffer.from(user.password_hash, "base64") : Buffer.alloc(64);
      if (!user || candidate.length !== stored.length || !crypto.timingSafeEqual(candidate, stored)) return send(res, 401, { error: "Неверная почта или пароль" }, origin);
    }
    return send(res, 200, { token: await issueToken(user.id), email: user.email }, origin);
  }

  const auth = await getAuth(req);
  if (!auth) return send(res, 401, { error: "Сначала войди в личный кабинет" }, origin);
  if (req.method === "POST" && url.pathname === "/api/logout") {
    await pool.query("DELETE FROM auth_sessions WHERE token_hash = $1", [auth.tokenHash]);
    return send(res, 200, { ok: true }, origin);
  }
  if (req.method === "GET" && url.pathname === "/api/vault") {
    const result = await pool.query("SELECT envelope FROM vaults WHERE user_id = $1", [auth.userId]);
    if (!result.rowCount) return send(res, 404, { error: "Снимок ещё не сохранён" }, origin);
    return send(res, 200, { envelope: result.rows[0].envelope }, origin);
  }
  if (req.method === "PUT" && url.pathname === "/api/vault") {
    const { envelope } = await readBody(req);
    if (!envelope || envelope.version !== 1 || envelope.kdf !== "PBKDF2-SHA256" || typeof envelope.ciphertext !== "string" || envelope.ciphertext.length > 4_000_000) {
      return send(res, 400, { error: "Некорректный зашифрованный снимок" }, origin);
    }
    await pool.query(`INSERT INTO vaults(user_id, envelope, updated_at) VALUES($1, $2::jsonb, now())
      ON CONFLICT(user_id) DO UPDATE SET envelope = EXCLUDED.envelope, updated_at = now()`, [auth.userId, JSON.stringify(envelope)]);
    return send(res, 200, { ok: true, savedAt: new Date().toISOString() }, origin);
  }
  return send(res, 404, { error: "Маршрут не найден" }, origin);
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((error) => {
    console.error("Request failed:", error.code || error.status || "internal");
    send(res, error.status || 500, { error: error.status ? error.message : "Внутренняя ошибка сервера" }, req.headers.origin);
  });
});

async function start() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
  if (process.env.NODE_ENV === "production" && (!INVITE_CODE || !ALLOWED_ORIGINS.size)) throw new Error("REGISTRATION_INVITE_CODE and ALLOWED_ORIGINS are required in production");
  await migrate();
  server.listen(PORT, HOST, () => console.log(`Session Workspace API listening on ${HOST}:${PORT}`));
}

start().catch((error) => { console.error("Startup failed:", error.message); process.exit(1); });
process.on("SIGTERM", () => server.close(() => pool.end().finally(() => process.exit(0))));
process.on("SIGINT", () => server.close(() => pool.end().finally(() => process.exit(0))));
