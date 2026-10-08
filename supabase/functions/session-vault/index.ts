import { createClient } from "npm:@supabase/supabase-js@2.49.4";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const INVITE_CODE = "afb762d18313c4cabfabc418816ff1bd";

const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const PBKDF2_ITERATIONS = 100_000;
const TOKEN_TTL_HOURS = 8;
const MAX_BODY = 6 * 1024 * 1024;

// ── Helpers ──

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function errorResponse(message: string, status: number): Response {
  return json({ error: message }, status);
}

async function readBody(req: Request): Promise<Record<string, unknown>> {
  const text = await req.text();
  if (!text) return {};
  if (text.length > MAX_BODY) throw Object.assign(new Error("Запрос слишком большой"), { status: 413 });
  try {
    return JSON.parse(text);
  } catch {
    throw Object.assign(new Error("Некорректный JSON"), { status: 400 });
  }
}

function validEmail(email: unknown): boolean {
  return typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function base64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function sha256(data: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const hashBuf = await crypto.subtle.digest("SHA-256", encoder.encode(data));
  return new Uint8Array(hashBuf);
}

async function hashToken(token: string): Promise<string> {
  return bytesToHex(await sha256(token));
}

async function sameSecret(a: string, b: string): Promise<boolean> {
  const aBytes = await sha256(a);
  const bBytes = await sha256(b);
  if (aBytes.length !== bBytes.length) return false;
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) diff |= aBytes[i] ^ bBytes[i];
  return diff === 0;
}

async function derivePasswordHash(password: string, saltB64: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const salt = base64ToBytes(saltB64);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    256,
  );
  return bytesToBase64(new Uint8Array(bits));
}

function generateSalt(): string {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
}

function randomToken(): string {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(32)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function extractBearerToken(req: Request): string | null {
  const auth = req.headers.get("Authorization") || "";
  const match = /^Bearer ([A-Za-z0-9_-]+)$/.exec(auth);
  return match ? match[1] : null;
}

async function authenticate(token: string): Promise<string | null> {
  const tokenHash = await hashToken(token);
  const { data, error } = await supabase
    .from("auth_sessions")
    .select("user_id")
    .eq("token_hash", tokenHash)
    .gt("expires_at", new Date().toISOString())
    .maybeSingle();
  if (error || !data) return null;
  return data.user_id as string;
}

// ── Route handlers ──

async function handleRegister(body: Record<string, unknown>): Promise<Response> {
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = body.password;
  const inviteCode = body.inviteCode;

  if (!validEmail(email) || typeof password !== "string" || password.length < 12 || password.length > 1024) {
    return errorResponse("Нужна корректная почта и пароль кабинета не короче 12 символов", 400);
  }

  if (!INVITE_CODE || typeof inviteCode !== "string" || !(await sameSecret(inviteCode, INVITE_CODE))) {
    return errorResponse("Для регистрации нужен действующий код приглашения", 403);
  }

  const salt = generateSalt();
  const passwordHash = await derivePasswordHash(password, salt);

  const { data: existing } = await supabase
    .from("app_users")
    .select("id")
    .eq("email", email)
    .maybeSingle();
  if (existing) return errorResponse("Кабинет с такой почтой уже существует", 409);

  const { data: user, error } = await supabase
    .from("app_users")
    .insert({ email, salt, password_hash: passwordHash })
    .select("id, email")
    .single();
  if (error) throw error;

  const token = randomToken();
  const tokenHash = await hashToken(token);
  const expiresAt = new Date(Date.now() + TOKEN_TTL_HOURS * 60 * 60 * 1000).toISOString();
  const { error: sessError } = await supabase
    .from("auth_sessions")
    .insert({ token_hash: tokenHash, user_id: user.id, expires_at: expiresAt });
  if (sessError) throw sessError;

  return json({ token, email: user.email });
}

async function handleLogin(body: Record<string, unknown>): Promise<Response> {
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = body.password;

  if (!validEmail(email) || typeof password !== "string") {
    return errorResponse("Неверная почта или пароль", 401);
  }

  const { data: user, error } = await supabase
    .from("app_users")
    .select("id, email, salt, password_hash")
    .eq("email", email)
    .maybeSingle();
  if (error) throw error;

  const salt = user?.salt || generateSalt();
  const candidateHash = await derivePasswordHash(password, salt);
  const storedHash = user?.password_hash || "";

  if (!user || candidateHash !== storedHash) {
    return errorResponse("Неверная почта или пароль", 401);
  }

  const token = randomToken();
  const tokenHash = await hashToken(token);
  const expiresAt = new Date(Date.now() + TOKEN_TTL_HOURS * 60 * 60 * 1000).toISOString();
  const { error: sessError } = await supabase
    .from("auth_sessions")
    .insert({ token_hash: tokenHash, user_id: user.id, expires_at: expiresAt });
  if (sessError) throw sessError;

  return json({ token, email: user.email });
}

async function handleVaultGet(userId: string): Promise<Response> {
  const { data, error } = await supabase
    .from("vaults")
    .select("envelope")
    .eq("user_id", userId)
    .maybeSingle();
  if (error) throw error;
  if (!data) return errorResponse("Снимок ещё не сохранён", 404);
  return json({ envelope: data.envelope });
}

async function handleVaultPut(userId: string, body: Record<string, unknown>): Promise<Response> {
  const envelope = body.envelope as Record<string, unknown> | undefined;
  if (
    !envelope ||
    envelope.version !== 1 ||
    envelope.kdf !== "PBKDF2-SHA256" ||
    typeof envelope.ciphertext !== "string" ||
    envelope.ciphertext.length > 4_000_000
  ) {
    return errorResponse("Некорректный зашифрованный снимок", 400);
  }

  const { error } = await supabase
    .from("vaults")
    .upsert({ user_id: userId, envelope, updated_at: new Date().toISOString() });

  if (error) throw error;
  return json({ ok: true, savedAt: new Date().toISOString() });
}

async function handleLogout(token: string): Promise<Response> {
  const tokenHash = await hashToken(token);
  await supabase.from("auth_sessions").delete().eq("token_hash", tokenHash);
  return json({ ok: true });
}

// ── Main handler ──

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const url = new URL(req.url);
    const path = url.pathname;
    const route = path.replace(/^\/session-vault/, "");

    if (req.method === "GET" && (route === "/health" || route === "/")) {
      return json({ ok: true, service: "session-workspace-api" });
    }

    if (req.method === "POST" && route === "/api/register") {
      const body = await readBody(req);
      return await handleRegister(body);
    }

    if (req.method === "POST" && route === "/api/login") {
      const body = await readBody(req);
      return await handleLogin(body);
    }

    const token = extractBearerToken(req);
    if (!token) return errorResponse("Сначала войди в личный кабинет", 401);

    const userId = await authenticate(token);
    if (!userId) return errorResponse("Сначала войди в личный кабинет", 401);

    if (req.method === "POST" && route === "/api/logout") {
      return await handleLogout(token);
    }

    if (req.method === "GET" && route === "/api/vault") {
      return await handleVaultGet(userId);
    }

    if (req.method === "PUT" && route === "/api/vault") {
      const body = await readBody(req);
      return await handleVaultPut(userId, body);
    }

    return errorResponse("Маршрут не найден", 404);
  } catch (err) {
    const status = (err as { status?: number }).status || 500;
    const message = status < 500 ? (err as Error).message : "Внутренняя ошибка сервера";
    if (status >= 500) console.error("Request failed:", err);
    return errorResponse(message, status);
  }
});
