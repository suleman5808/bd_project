import crypto from "node:crypto";
import mysql from "mysql2/promise";
import bcrypt from "bcryptjs";

const SESSION_COOKIE = "rgm_session";
const SESSION_SECONDS = 8 * 60 * 60;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

let pool;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}

function getPool() {
  const required = ["DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD"];
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length) throw new Error(`Missing environment variables: ${missing.join(", ")}`);

  if (!pool) {
    pool = mysql.createPool({
      host: process.env.DB_HOST,
      port: Number(process.env.DB_PORT || 3306),
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      waitForConnections: true,
      connectionLimit: 2,
      maxIdle: 2,
      idleTimeout: 60_000,
      queueLimit: 0,
      charset: "utf8mb4",
      supportBigNumbers: true,
      bigNumberStrings: true,
      ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: true } : undefined,
    });
  }
  return pool;
}

function getSessionSecret() {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("SESSION_SECRET must contain at least 32 characters");
  }
  return secret;
}

function signature(value, secret) {
  return crypto.createHmac("sha256", secret).update(value).digest("base64url");
}

function createSession(user) {
  const payload = Buffer.from(JSON.stringify({
    sub: String(user.id),
    name: user.full_name,
    email: user.email,
    exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS,
  })).toString("base64url");
  return `${payload}.${signature(payload, getSessionSecret())}`;
}

function readSession(request) {
  const cookieHeader = request.headers.get("cookie") || "";
  const cookie = cookieHeader.split(";").map((item) => item.trim())
    .find((item) => item.startsWith(`${SESSION_COOKIE}=`));
  if (!cookie) return null;

  try {
    const token = cookie.slice(SESSION_COOKIE.length + 1);
    const [payload, suppliedSignature, extra] = token.split(".");
    if (!payload || !suppliedSignature || extra) return null;

    const expected = Buffer.from(signature(payload, getSessionSecret()), "base64url");
    const supplied = Buffer.from(suppliedSignature, "base64url");
    if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) return null;

    const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!session.sub || !session.exp || session.exp <= Math.floor(Date.now() / 1000)) return null;
    return { id: session.sub, name: session.name, email: session.email };
  } catch {
    return null;
  }
}

function sessionCookie(request, token, maxAge = SESSION_SECONDS) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

async function readBody(request) {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

function validEmail(email) {
  return email.length <= 254 && EMAIL_PATTERN.test(email);
}

async function register(request) {
  const body = await readBody(request);
  if (!body) return json({ error: "Enter the registration details and try again." }, 400);

  const name = typeof body.name === "string" ? body.name.trim() : "";
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";
  const confirmPassword = typeof body.confirmPassword === "string" ? body.confirmPassword : "";

  if (!name || name.length > 80) return json({ error: "Enter a name with no more than 80 characters." }, 400);
  if (!validEmail(email)) return json({ error: "Enter a valid email address." }, 400);
  if (password.length < 8 || Buffer.byteLength(password, "utf8") > 72) {
    return json({ error: "Use a password of at least 8 characters (maximum 72 bytes)." }, 400);
  }
  if (password !== confirmPassword) return json({ error: "The passwords do not match." }, 400);

  try {
    getSessionSecret();
    const passwordHash = await bcrypt.hash(password, 10);
    const [result] = await getPool().execute(
      "INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)",
      [name, email, passwordHash],
    );
    const user = { id: result.insertId, full_name: name, email };
    return json({ ok: true, user: { name, email } }, 201, {
      "Set-Cookie": sessionCookie(request, createSession(user)),
    });
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return json({ error: "That email is already registered. Please sign in." }, 409);
    }
    throw error;
  }
}

async function login(request) {
  const body = await readBody(request);
  if (!body) return json({ error: "Enter your email and password." }, 400);
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";
  if (!validEmail(email) || !password || Buffer.byteLength(password, "utf8") > 72) {
    return json({ error: "Email or password is incorrect." }, 401);
  }

  getSessionSecret();
  const [rows] = await getPool().execute(
    "SELECT id, full_name, email, password_hash FROM users WHERE email = ? LIMIT 1",
    [email],
  );
  const user = rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return json({ error: "Email or password is incorrect." }, 401);
  }

  return json({ ok: true, user: { name: user.full_name, email: user.email } }, 200, {
    "Set-Cookie": sessionCookie(request, createSession(user)),
  });
}

export default async function handler(request) {
  const action = new URL(request.url).searchParams.get("action");
  try {
    if (action === "register" && request.method === "POST") return await register(request);
    if (action === "login" && request.method === "POST") return await login(request);

    if (action === "me" && request.method === "GET") {
      const user = readSession(request);
      return user ? json({ user }) : json({ error: "Please sign in." }, 401);
    }

    if (action === "logout" && request.method === "POST") {
      return json({ ok: true }, 200, {
        "Set-Cookie": sessionCookie(request, "", 0),
      });
    }

    return json({ error: "Route not found." }, 404);
  } catch (error) {
    console.error("Authentication function failed:", error);
    return json({ error: "The request could not be completed. Check the database connection and try again." }, 500);
  }
}
