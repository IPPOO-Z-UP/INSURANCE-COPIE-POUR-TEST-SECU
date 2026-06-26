import { Hono } from "npm:hono";
import { cors } from "npm:hono/cors";
import { logger } from "npm:hono/logger";
import { createClient } from "jsr:@supabase/supabase-js@2";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "npm:@simplewebauthn/server@10";
import * as kv from "./kv_store.tsx";
import {
  parseBody,
  SignupSchema, ProfileUpdateSchema, ClaimCreateSchema, PaymentLegacySchema,
  PaymentInitiateSchema, BeneficiaryCreateSchema, MessageCreateSchema, MessageEditSchema,
  SubscribeSchema, SettingsUpdateSchema, ChangePasswordSchema, RenewContractSchema,
} from "./validators.ts";

const app = new Hono();
app.use("*", logger(console.log));
app.use(
  "/*",
  cors({
    origin: "*",
    allowHeaders: ["Content-Type", "Authorization", "X-User-Token", "x-user-token", "X-Admin-Token", "x-admin-token", "X-Agent-2FA-Token", "x-agent-2fa-token"],
    allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    exposeHeaders: ["Content-Length"],
    maxAge: 600,
  }),
);

const PREFIX = "/make-server-752d1a39";

// F30 — Auto-scheduler "best effort" pour runRemindersCycle. Plutôt que
// d'exiger un Scheduler externe, on déclenche le cycle au plus toutes les
// 15 minutes lors d'une requête entrante. Le verrou KV (`reminders:auto:lock`)
// est positionné AVANT le run pour éviter le double-fire en cas de bursts,
// l'exécution est détachée de la requête (waitUntil ou fire-and-forget).
const AUTO_REMINDERS_INTERVAL_MS = 15 * 60_000;
let autoRemindersInflight = false;
async function maybeRunAutoReminders() {
  if (autoRemindersInflight) return;
  try {
    const last = ((await kv.get("reminders:auto:lock")) ?? 0) as number;
    const now = Date.now();
    if (typeof last === "number" && now - last < AUTO_REMINDERS_INTERVAL_MS) return;
    autoRemindersInflight = true;
    await kv.set("reminders:auto:lock", now);
    try {
      await runRemindersCycle("auto");
    } catch (err) {
      console.log("auto-reminders cycle error:", err);
    }
  } catch (err) {
    console.log("auto-reminders gate error:", err);
  } finally {
    autoRemindersInflight = false;
  }
}
app.use("*", async (c, next) => {
  await next();
  // Best-effort, ne bloque pas la réponse. EdgeRuntime.waitUntil prolonge la
  // durée de vie de la fonction Edge si dispo, sinon fire-and-forget.
  const er = (globalThis as any).EdgeRuntime;
  const promise = maybeRunAutoReminders();
  if (er && typeof er.waitUntil === "function") er.waitUntil(promise);
});
const BUCKET = "make-752d1a39-claims";
const MSG_BUCKET = "make-752d1a39-messages";
const AVATAR_BUCKET = "make-752d1a39-avatars";
const KYC_BUCKET = "make-752d1a39-kyc";
const MEDIA_BUCKET = "make-752d1a39-media";
const MSG_MAX_BYTES = 10 * 1024 * 1024;
const AVATAR_MAX_BYTES = 2 * 1024 * 1024;
const AVATAR_ALLOWED_MIME = /^image\/(png|jpe?g|webp)$/i;
const AVATAR_URL_TTL_SEC = 3600;
const MSG_ALLOWED_MIME = /^(image\/(png|jpe?g|gif|webp|heic|heif)|application\/pdf|audio\/(mpeg|mp4|webm|ogg|wav)|video\/(mp4|webm|quicktime)|text\/plain)$/i;

const admin = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

// Realtime broadcast helper (server -> client) via Supabase Broadcast REST.
// Used to push chat events instantly without client polling.
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
async function broadcast(topic: string, event: string, payload: unknown) {
  try {
    const res = await fetch(`${SUPABASE_URL}/realtime/v1/api/broadcast`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        apikey: SERVICE_ROLE,
        Authorization: `Bearer ${SERVICE_ROLE}`,
      },
      body: JSON.stringify({ messages: [{ topic, event, payload, private: false }] }),
    });
    if (!res.ok) console.log(`broadcast ${topic}/${event} failed: ${res.status}`);
  } catch (err) {
    console.log(`broadcast ${topic}/${event} error: ${err}`);
  }
}

// Idempotent bucket creation
(async () => {
  try {
    const { data: buckets } = await admin.storage.listBuckets();
    if (!buckets?.some((b) => b.name === BUCKET)) {
      await admin.storage.createBucket(BUCKET, { public: false });
      console.log(`Created storage bucket ${BUCKET}`);
    }
    if (!buckets?.some((b) => b.name === MSG_BUCKET)) {
      await admin.storage.createBucket(MSG_BUCKET, { public: false });
      console.log(`Created storage bucket ${MSG_BUCKET}`);
    }
    if (!buckets?.some((b) => b.name === AVATAR_BUCKET)) {
      await admin.storage.createBucket(AVATAR_BUCKET, { public: false });
      console.log(`Created storage bucket ${AVATAR_BUCKET}`);
    }
    if (!buckets?.some((b) => b.name === KYC_BUCKET)) {
      await admin.storage.createBucket(KYC_BUCKET, { public: false });
      console.log(`Created storage bucket ${KYC_BUCKET}`);
    }
    if (!buckets?.some((b) => b.name === MEDIA_BUCKET)) {
      await admin.storage.createBucket(MEDIA_BUCKET, { public: true });
      console.log(`Created storage bucket ${MEDIA_BUCKET}`);
    }
  } catch (err) {
    console.log(`Bucket init error: ${err}`);
  }
})();

// Admin auth is COMPLETELY SEPARATE from user auth. Credentials live in
// env vars (ADMIN_USERNAME / ADMIN_PASSWORD). Successful login returns an
// HMAC-signed token sent back in the X-Admin-Token header. Admin identity
// is NEVER tied to the Supabase users table — strict isolation by design.
const ADMIN_USERNAME = (Deno.env.get("ADMIN_USERNAME") ?? "").trim();
const ADMIN_PASSWORD = (Deno.env.get("ADMIN_PASSWORD") ?? "").trim();
const ADMIN_TOKEN_TTL_SEC = 60 * 60 * 8; // 8h

type AdminAccount = { username: string; password: string; role: "superadmin" | "operator" | "support"; totpSecret?: string };
function loadAdminAccounts(): AdminAccount[] {
  const raw = Deno.env.get("ADMIN_ACCOUNTS");
  if (raw) {
    try {
      const arr = JSON.parse(raw) as AdminAccount[];
      if (Array.isArray(arr) && arr.every((a) => a.username && a.password)) {
        return arr.map((a) => ({ ...a, role: a.role ?? "operator" }));
      }
    } catch (e) { console.log("ADMIN_ACCOUNTS parse error:", e); }
  }
  if (ADMIN_USERNAME && ADMIN_PASSWORD) {
    return [{
      username: ADMIN_USERNAME, password: ADMIN_PASSWORD, role: "superadmin",
      totpSecret: Deno.env.get("ADMIN_TOTP_SECRET") || undefined,
    }];
  }
  return [];
}
const ADMIN_ACCOUNTS = loadAdminAccounts();

// RFC 6238 TOTP — HMAC-SHA1, 30s step, 6 digits.
function base32Decode(s: string): Uint8Array {
  const alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = s.toUpperCase().replace(/[^A-Z2-7]/g, "");
  const out: number[] = [];
  let bits = 0, value = 0;
  for (const ch of clean) {
    const idx = alph.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { bits -= 8; out.push((value >> bits) & 0xff); }
  }
  return new Uint8Array(out);
}
async function totpCode(secret: string, t: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const counter = Math.floor(t / 30);
  const buf = new ArrayBuffer(8);
  const dv = new DataView(buf);
  dv.setUint32(4, counter, false);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
  const offset = sig[sig.length - 1] & 0x0f;
  const code = ((sig[offset] & 0x7f) << 24) | (sig[offset + 1] << 16) | (sig[offset + 2] << 8) | sig[offset + 3];
  return String(code % 1_000_000).padStart(6, "0");
}
async function verifyTotp(secret: string, code: string): Promise<boolean> {
  const t = Math.floor(Date.now() / 1000);
  for (const drift of [-1, 0, 1]) {
    if (await totpCode(secret, t + drift * 30) === code) return true;
  }
  return false;
}

async function requireAdminToken(c: any) {
  const token = c.req.header("X-Admin-Token") ?? c.req.header("x-admin-token");
  if (!token) return { admin: null, error: "missing-admin-token", status: 401 as const };
  const payload = await verifyToken<{ kind: string; username: string; role?: string; exp: number; jti?: string }>(token);
  if (!payload || payload.kind !== "admin") return { admin: null, error: "invalid-admin-token", status: 401 as const };
  if (Date.now() / 1000 > payload.exp) return { admin: null, error: "expired-admin-token", status: 401 as const };
  // D9 — Si le token porte un jti, la session doit exister (sinon = révoquée).
  // Les tokens pré-D9 sans jti restent acceptés pour ne pas déconnecter les
  // sessions en cours lors du déploiement.
  if (payload.jti) {
    const session = await kv.get(k.adminSession(payload.jti));
    if (!session) return { admin: null, error: "revoked-admin-session", status: 401 as const };
  }
  return { admin: { username: payload.username, role: (payload.role ?? "superadmin") as AdminAccount["role"], jti: payload.jti }, error: null, status: 200 as const };
}

function requireAdminRole(admin: { role: string } | null, ...allowed: AdminAccount["role"][]) {
  if (!admin) return false;
  return allowed.includes(admin.role as AdminAccount["role"]);
}

// Combine token + role check. Returns either { admin } on success or a JSON
// Response to short-circuit the handler. Usage:
//   const g = await requireAdmin(c, "superadmin"); if ("response" in g) return g.response;
//   ... use g.admin
async function requireAdmin(c: any, ...allowed: AdminAccount["role"][]) {
  const r = await requireAdminToken(c);
  if (!r.admin) return { response: c.json({ error: r.error }, r.status) };
  if (allowed.length && !requireAdminRole(r.admin, ...allowed)) {
    return { response: c.json({ error: "forbidden-role", required: allowed, role: r.admin.role }, 403) };
  }
  return { admin: r.admin };
}

// Agents are real Supabase users whose `user_metadata.role` (or
// `app_metadata.role`) equals "agent". As a bootstrap convenience the
// AGENT_EMAILS env var (comma-separated, lowercased) also grants the role —
// useful before we ship an admin UI to assign roles. Superadmins authenticated
// via Supabase (rare) also inherit the agent role so they can dogfood the app.
async function requireAgent(c: any) {
  const u = await requireUser(c);
  if (!u.user) return { user: null, agent: null, error: u.error, status: 401 as const };
  const meta = (u.user.user_metadata ?? {}) as Record<string, any>;
  const appMeta = (u.user.app_metadata ?? {}) as Record<string, any>;
  // app_metadata is server-controlled and the source of truth. user_metadata
  // is read for legacy agent accounts created before the migration to
  // app_metadata; new accounts only have the role in app_metadata.
  const role = (appMeta.role as string | undefined) ?? (meta.role as string | undefined);
  const allow = (Deno.env.get("AGENT_EMAILS") ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const email = (u.user.email ?? "").toLowerCase();
  const isAgent =
    role === "agent" ||
    role === "superadmin" ||
    (email && allow.includes(email));
  if (!isAgent) {
    return { user: u.user, agent: null, error: "forbidden", status: 403 as const };
  }
  // Lazy migration: if this agent's role only lives in user_metadata (legacy
  // accounts) or only comes from AGENT_EMAILS, copy it into app_metadata so
  // the client UI can trust app_metadata exclusively going forward.
  if (appMeta.role !== "agent" && appMeta.role !== "superadmin") {
    admin.auth.admin.updateUserById(u.user.id, {
      app_metadata: { ...appMeta, role: role ?? "agent" },
    }).catch((e) => console.log(`agent role backfill failed for ${u.user.id}: ${e}`));
  }
  const display = (meta.name as string | undefined) ?? u.user.email ?? "Agent";
  const matricule = await resolveAgentMatricule(u.user.id);
  return {
    user: u.user,
    agent: { id: u.user.id, username: display, email: u.user.email ?? "", matricule },
    error: null,
    status: 200 as const,
  };
}

// Resolve a stable IPPOO-A-XXXX matricule for a given Supabase user id, creating
// one on first call. We persist two keys:
//   agent:matricule:<userId>      -> matricule         (lookup direction A)
//   agent:matricule-claim:<mat>   -> userId            (uniqueness sentinel)
// A small bounded retry handles the unlikely random collision.
async function resolveAgentMatricule(userId: string): Promise<string> {
  const existing = await kv.get(`agent:matricule:${userId}`);
  if (existing && typeof existing === "string") return existing;
  for (let attempt = 0; attempt < 8; attempt++) {
    const n = Math.floor(1000 + Math.random() * 9000);
    const candidate = `IPPOO-A-${n}`;
    const claimKey = `agent:matricule-claim:${candidate}`;
    const claimed = await kv.get(claimKey);
    if (claimed) continue;
    await kv.set(claimKey, userId);
    await kv.set(`agent:matricule:${userId}`, candidate);
    return candidate;
  }
  // Extremely unlikely; fall back to a longer numeric tail to guarantee uniqueness.
  const fallback = `IPPOO-A-${Date.now().toString().slice(-6)}`;
  await kv.set(`agent:matricule-claim:${fallback}`, userId);
  await kv.set(`agent:matricule:${userId}`, fallback);
  return fallback;
}

async function requireUser(c: any) {
  // Prefer X-User-Token (set by client) so the platform-level Authorization
  // header can stay as the anon key (required when asymmetric JWTs are on).
  const userToken =
    c.req.header("X-User-Token") ??
    c.req.header("x-user-token") ??
    c.req.header("Authorization")?.split(" ")[1];
  if (!userToken) return { user: null, error: "missing-token" };
  const { data, error } = await admin.auth.getUser(userToken);
  if (error || !data.user) return { user: null, error: error?.message ?? "invalid-token" };
  return { user: data.user, error: null };
}

const k = {
  profile: (uid: string) => `profile:${uid}`,
  contracts: (uid: string) => `contracts:${uid}`,
  claims: (uid: string) => `claims:${uid}`,
  payments: (uid: string) => `payments:${uid}`,
  beneficiaries: (uid: string) => `beneficiaries:${uid}`,
  documents: (uid: string) => `documents:${uid}`,
  notifications: (uid: string) => `notifications:${uid}`,
  messages: (uid: string) => `messages:${uid}`,
  settings: (uid: string) => `settings:${uid}`,
  audit: (uid: string) => `audit:${uid}`,
  rate: (key: string) => `rate:${key}`,
  referralCode: (uid: string) => `referral:code:${uid}`,
  referralByCode: (code: string) => `referral:bycode:${code}`,
  referralRedemptions: (uid: string) => `referral:redemptions:${uid}`,
  accountDeletion: (uid: string) => `account:deletion:${uid}`,
  memberByNumber: (mn: string) => `member:bynum:${mn}`,
  conversationMeta: (uid: string) => `conv:meta:${uid}`,
  agentNotes: (uid: string) => `agent:notes:${uid}`,
  kyc: (uid: string) => `kyc:${uid}`,
  agentTemplates: (matricule: string) => `agent:templates:${matricule}`,
  agentTotp: (uid: string) => `agent:totp:${uid}`,
  kycLock: (uid: string, kycId: string) => `kyc:lock:${uid}:${kycId}`,
  agentTasks: (matricule: string) => `agent:tasks:${matricule}`,
  agentProfile: (matricule: string) => `agent:profile:${matricule}`,
  agentNotifs: (matricule: string) => `agent:notifs:${matricule}`,
  emailToUid: (email: string) => `email:${email.toLowerCase()}`,
  webauthnCreds: (uid: string) => `webauthn:creds:${uid}`,
  webauthnChallenge: (key: string) => `webauthn:chal:${key}`,
  hmacSecret: () => `system:hmac:secret`,
  promos: () => `system:promos`,
  partners: () => `system:partners`,
  site: () => `system:site`,
  pushSubs: (uid: string) => `push:subs:${uid}`,
  reminders: (uid: string) => `reminders:sent:${uid}`,
  broadcastHistory: () => `system:broadcast:history`,
  phoneOtp: (phone: string) => `otp:phone:${phone}`,
  consents: (uid: string) => `consents:${uid}`,
  // D1 PSP webhook log
  webhookEvent: (id: string) => `webhook:event:${id}`,
  webhookIndex: () => `webhook:index`,
  // D3 admin roles persistés
  adminRoles: () => `system:admin:roles`,
  // D8 incident ack
  incidentAck: (id: string) => `incident:ack:${id}`,
  incidentAcksIndex: () => `system:incident:acks`,
  // D9 admin sessions (jti)
  adminSession: (jti: string) => `admin:session:${jti}`,
  adminSessionsIndex: () => `system:admin:sessions:index`,
  // D11 audit chain tip
  auditChainTip: () => `system:audit:chain-tip`,
};

// --- External channel helpers (Email via Resend, SMS via Termii) ---
const RESEND_KEY = Deno.env.get("RESEND_API_KEY") ?? null;
const RESEND_FROM = Deno.env.get("RESEND_FROM") ?? "IPPOO <no-reply@ippoo.bj>";
const TERMII_KEY = Deno.env.get("TERMII_API_KEY") ?? null;
const TERMII_SENDER = Deno.env.get("TERMII_SENDER_ID") ?? "IPPOO";

async function sendEmail(to: string, subject: string, html: string): Promise<boolean> {
  if (!RESEND_KEY || !to) return false;
  try {
    // Force UTF-8 : certains clients mail (Outlook desktop) tombent sur Windows-1252
    // si le HTML ne déclare pas explicitement le charset → accents cassés.
    const wrappedHtml = /<meta\s+charset/i.test(html)
      ? html
      : `<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"></head><body>${html}</body></html>`;
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": `Bearer ${RESEND_KEY}`, "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify({ from: RESEND_FROM, to: [to], subject, html: wrappedHtml }),
    });
    return r.ok;
  } catch { return false; }
}

async function sendSms(to: string, text: string): Promise<boolean> {
  if (!TERMII_KEY || !to) return false;
  try {
    const phone = to.replace(/[^\d+]/g, "").replace(/^\+/, "");
    const r = await fetch("https://api.ng.termii.com/api/sms/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        to: phone, from: TERMII_SENDER, sms: text,
        type: "plain", channel: "generic", api_key: TERMII_KEY,
      }),
    });
    return r.ok;
  } catch { return false; }
}

// --- HMAC signing for QR tokens ---
const enc = new TextEncoder();
const dec = new TextDecoder();
function b64urlEncode(bytes: Uint8Array | ArrayBuffer): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (const b of arr) bin += String.fromCharCode(b);
  return btoa(bin).replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
// #12 — Rotation HMAC. La signature utilise toujours la clé primaire (KV
// `system:hmac:secret`). La vérification accepte aussi `system:hmac:secret:prev`
// pendant une fenêtre de rotation, ce qui permet de tourner la clé sans
// invalider d'un coup tous les jetons admin / QR / proof OTP émis. Pour
// déclencher une rotation : POST /admin/system/hmac/rotate (superadmin), qui
// déplace la clé courante vers `prev` et en génère une nouvelle.
let cachedHmacKey: CryptoKey | null = null;
let cachedHmacPrevKey: CryptoKey | null | undefined = undefined;
async function importHmac(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw", b64urlDecode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"],
  );
}
async function getHmacKey(): Promise<CryptoKey> {
  if (cachedHmacKey) return cachedHmacKey;
  let secret = await kv.get(k.hmacSecret());
  if (!secret) {
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    secret = b64urlEncode(buf);
    await kv.set(k.hmacSecret(), secret);
  }
  cachedHmacKey = await importHmac(secret);
  return cachedHmacKey;
}
async function getHmacPrevKey(): Promise<CryptoKey | null> {
  if (cachedHmacPrevKey !== undefined) return cachedHmacPrevKey;
  const secret = (await kv.get(`${k.hmacSecret()}:prev`)) as string | null;
  cachedHmacPrevKey = secret ? await importHmac(secret) : null;
  return cachedHmacPrevKey;
}
async function signToken(payload: Record<string, any>): Promise<string> {
  const key = await getHmacKey();
  const body = b64urlEncode(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(body));
  return `${body}.${b64urlEncode(sig)}`;
}
async function verifyToken<T = any>(token: string): Promise<T | null> {
  try {
    const [body, sig] = token.split(".");
    if (!body || !sig) return null;
    const sigBytes = b64urlDecode(sig);
    const bodyBytes = enc.encode(body);
    const key = await getHmacKey();
    let ok = await crypto.subtle.verify("HMAC", key, sigBytes, bodyBytes);
    if (!ok) {
      const prev = await getHmacPrevKey();
      if (prev) ok = await crypto.subtle.verify("HMAC", prev, sigBytes, bodyBytes);
    }
    if (!ok) return null;
    return JSON.parse(dec.decode(b64urlDecode(body))) as T;
  } catch {
    return null;
  }
}

// --- Unique immutable member number ---
function randomMemberNumber(): string {
  let n = "";
  const buf = new Uint8Array(10);
  crypto.getRandomValues(buf);
  for (const b of buf) n += String(b % 10);
  return `${n.slice(0, 4)}-${n.slice(4, 8)}-${n.slice(8, 10)}`;
}
async function assignMemberNumber(uid: string): Promise<string> {
  for (let i = 0; i < 12; i++) {
    const candidate = randomMemberNumber();
    if (!(await kv.get(k.memberByNumber(candidate)))) {
      await kv.set(k.memberByNumber(candidate), uid);
      return candidate;
    }
  }
  throw new Error("Impossible d'attribuer un numéro de membre unique");
}

const WEBAUTHN_RP_NAME = "IPPOO Assurance";
function webauthnContext(c: any) {
  const originHeader = c.req.header("origin") ?? c.req.header("Origin") ?? "";
  const envOrigin = Deno.env.get("WEBAUTHN_ORIGIN");
  const envRpId = Deno.env.get("WEBAUTHN_RP_ID");
  let origin = envOrigin || originHeader || "https://localhost";
  let rpID = envRpId || "localhost";
  try {
    const u = new URL(origin);
    if (!envRpId) rpID = u.hostname;
  } catch {}
  return { origin, rpID };
}

// Admin-side audit ring (séparé du journal client). On garde les 500 dernières
// actions admin pour permettre une lecture rapide « qui a fait quoi ». Tracé
// par :
//   - username (compte admin)
//   - role (au moment de l'action)
//   - ip / userAgent (forensique)
//   - action + meta arbitraire
async function sha256Hex(body: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// D11 — Chaîne de hash inviolable. Chaque entrée intègre prevHash + hash(prevHash|canonical).
// La pointe est conservée dans system:audit:chain-tip pour permettre la
// vérification ultérieure via /admin/audit/verify-chain.
async function adminAudit(c: any, admin: { username: string; role?: string }, action: string, meta: Record<string, any> = {}) {
  try {
    const ip = c?.req?.header("x-forwarded-for")?.split(",")[0]?.trim() ?? "anon";
    const ua = (c?.req?.header("user-agent") ?? "").slice(0, 200);
    const id = `aa_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;
    const at = new Date().toISOString();
    const prevHash = (((await kv.get(k.auditChainTip())) ?? "GENESIS") as string);
    const canonical = JSON.stringify({ id, username: admin.username, role: admin.role ?? "superadmin", action, meta, ip, ua, at });
    const hash = await sha256Hex(prevHash + "|" + canonical);
    const list = ((await kv.get("admin:audit")) ?? []) as any[];
    list.unshift({
      id, username: admin.username, role: admin.role ?? "superadmin",
      action, meta, ip, ua, at, prevHash, hash,
    });
    await kv.set("admin:audit", list.slice(0, 500));
    await kv.set(k.auditChainTip(), hash);
    broadcast(`admin:audit`, "admin:new", { id, action, username: admin.username, at }).catch(() => {});
  } catch (err) {
    console.log(`adminAudit error ${action}: ${err}`);
  }
}

async function audit(uid: string, action: string, meta: Record<string, any> = {}) {
  try {
    const list = (await kv.get(k.audit(uid))) ?? [];
    list.unshift({
      id: `a_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`,
      action,
      meta,
      at: new Date().toISOString(),
    });
    await kv.set(k.audit(uid), list.slice(0, 200));
    broadcast(`admin:audit`, "audit:new", { userId: uid, action, at: new Date().toISOString() }).catch(() => {});
    if (/payment|claim|signup|subscribe|profile.create/i.test(action)) {
      broadcast(`admin:stats`, "stats:dirty", { reason: action, at: Date.now() }).catch(() => {});
    }
  } catch (err) {
    console.log(`Audit log error for ${uid}/${action}: ${err}`);
  }
}

/** Sanitize 500 error responses to prevent internal info leakage. */
function safeError(c: any, err: any, message = "Une erreur interne est survenue") {
  console.log(`[error] ${message}:`, err);
  return c.json({ error: message }, 500);
}

/** Cryptographically secure random integer in [min, max] range. */
function secureRandomInt(min: number, max: number): number {
  const range = max - min + 1;
  const array = new Uint32Array(1);
  crypto.getRandomValues(array);
  return min + (array[0] % range);
}

// Returns true when allowed; false when over limit. Window is rolling N seconds.
async function rateLimit(key: string, max: number, windowSec: number): Promise<boolean> {
  const now = Date.now();
  const existing = (await kv.get(k.rate(key))) ?? { count: 0, resetAt: now + windowSec * 1000 };
  if (now > existing.resetAt) {
    await kv.set(k.rate(key), { count: 1, resetAt: now + windowSec * 1000 });
    return true;
  }
  if (existing.count >= max) return false;
  await kv.set(k.rate(key), { count: existing.count + 1, resetAt: existing.resetAt });
  return true;
}

// Inline guard used at the top of sensitive routes. Returns a Response when
// over limit (so callers do `const limited = await guardRate(...); if (limited) return limited;`)
// or null when allowed.
async function guardRate(
  c: any,
  scope: string,
  id: string,
  max: number,
  windowSec: number,
  message = "Trop de requêtes, réessayez plus tard.",
): Promise<Response | null> {
  const allowed = await rateLimit(`${scope}:${id}`, max, windowSec);
  if (allowed) return null;
  return c.json({ error: message }, 429);
}

function makeReferralCode(name: string) {
  const base = (name || "IPPOO").toUpperCase().replace(/[^A-Z]/g, "").slice(0, 4).padEnd(4, "X");
  const rand = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `${base}-${rand}`;
}

function notify(notifications: any[], title: string, body: string, type = "info", to?: string) {
  notifications.unshift({
    id: `n_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`,
    title,
    body,
    type,
    read: false,
    createdAt: new Date().toISOString(),
    ...(to ? { to } : {}),
  });
  return notifications.slice(0, 50);
}

// Persists the user's notification list AND broadcasts the freshest entry on
// the per-user realtime topic so connected clients can show a push-style toast
// instantly. Always use this instead of a raw `kv.set(k.notifications(uid), ...)`.
async function setNotifications(uid: string, list: any[]) {
  await kv.set(k.notifications(uid), list);
  const latest = list[0];
  if (latest) {
    // Fire-and-forget; broadcast() has its own internal try/catch so this can
    // never produce an unhandled rejection that would kill the worker.
    broadcast(`notifications:${uid}`, "notif:new", latest).catch(() => {});
  }
}

function formatXOFInt(n: number) {
  return `${Math.round(n).toLocaleString("fr-FR")} F CFA`;
}

// Apply payment-confirmation side effects based on the payment's `purpose`.
// Called exactly once per successful payment (from webhook or sandbox confirm).
async function applyPaymentSideEffects(userId: string, payment: any) {
  const purpose = payment?.purpose ?? "cotisation";
  const notifs = ((await kv.get(k.notifications(userId))) ?? []) as any[];
  try {
    if (purpose === "renewal" && payment.contractId) {
      const contracts = ((await kv.get(k.contracts(userId))) ?? []) as any[];
      const idx = contracts.findIndex((ct: any) => ct.id === payment.contractId);
      if (idx !== -1) {
        const ct = contracts[idx];
        const baseEnd = Math.max(Date.now(), new Date(ct.endDate).getTime());
        const newEnd = new Date(baseEnd + 365 * 86400000).toISOString();
        contracts[idx] = { ...ct, status: "active", endDate: newEnd, renewalNoticeSent: false, nextBillingDate: nextBillingFromNow(), pendingRenewalPaymentId: null, pendingRenewalAt: null };
        await kv.set(k.contracts(userId), contracts);
        await notifyAndDispatch(userId, notifs, {
          typeKey: "payment",
          title: "Contrat renouvelé",
          body: `« ${ct.product} » est prolongé jusqu'au ${new Date(newEnd).toLocaleDateString("fr-FR")}.`,
          severity: "success",
          to: "/espace-client/contrats",
        });
      }
    } else if (purpose === "card_activation") {
      let profile = (await kv.get(k.profile(userId))) ?? {};
      if (!profile.memberNumber) profile.memberNumber = await assignMemberNumber(userId);
      profile = { ...profile, cardActive: true, cardIssuedAt: new Date().toISOString() };
      await kv.set(k.profile(userId), profile);
      await notifyAndDispatch(userId, notifs, {
        typeKey: "payment",
        title: "Carte membre activée",
        body: `Votre carte IPPOO n° ${profile.memberNumber} est désormais active.`,
        severity: "success",
        to: "/espace-client/carte",
      });
    } else if (purpose === "monthly_premium" && payment.contractId) {
      const contracts = ((await kv.get(k.contracts(userId))) ?? []) as any[];
      const idx = contracts.findIndex((ct: any) => ct.id === payment.contractId);
      if (idx !== -1) {
        const wasSuspended = contracts[idx].status === "suspended";
        contracts[idx] = { ...contracts[idx], status: wasSuspended ? "active" : contracts[idx].status, suspendedAt: null, suspendedReason: null, lastPaidAt: new Date().toISOString(), nextBillingDate: nextBillingFromNow() };
        await kv.set(k.contracts(userId), contracts);
        await notifyAndDispatch(userId, notifs, {
          typeKey: "payment",
          title: "Cotisation mensuelle reçue",
          body: `Paiement de ${payment.amount} FCFA confirmé pour « ${contracts[idx].product} ».`,
          severity: "success",
          to: "/espace-client/cotisations",
        });
      }
    } else {
      await notifyAndDispatch(userId, notifs, {
        typeKey: "payment",
        title: "Cotisation reçue",
        body: `Paiement de ${payment.amount} FCFA confirmé.`,
        severity: "success",
        to: "/espace-client/cotisations",
      });
    }
  } catch (err) {
    console.log(`[side-effect] purpose=${purpose} user=${userId} payment=${payment?.id}: ${err}`);
  }
}

function nextBillingFromNow(): string {
  const d = new Date();
  d.setMonth(d.getMonth() + 1);
  d.setHours(9, 0, 0, 0);
  return d.toISOString();
}

async function sendInvoiceEmail(userId: string, payment: any) {
  try {
    const apiKey = Deno.env.get("RESEND_API_KEY");
    if (!apiKey) {
      console.log(`[email] RESEND_API_KEY not set, skipping invoice email for ${payment.id}`);
      return;
    }
    const profile = (await kv.get(k.profile(userId))) as any;
    const email = profile?.email;
    if (!email) {
      console.log(`[email] no email on profile for ${userId}, skipping`);
      return;
    }
    let contract: any = null;
    if (payment.contractId) {
      const contracts = ((await kv.get(k.contracts(userId))) ?? []) as any[];
      contract = contracts.find((c) => c.id === payment.contractId) ?? null;
    }
    const invoiceNumber = `INV-${String(payment.id).slice(-8).toUpperCase()}`;
    const dateStr = new Date(payment.createdAt).toLocaleDateString("fr-FR");
    const lineLabel = contract ? `Cotisation – ${contract.product}` : (payment.label ?? "Cotisation IPPOO");
    const total = formatXOFInt(payment.amount ?? 0);
    const from = Deno.env.get("RESEND_FROM") ?? "IPPOO Assurance <no-reply@ippoo.app>";

    const html = `<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"></head><body>
      <div style="font-family:Inter,Arial,sans-serif;max-width:560px;margin:0 auto;background:#fff;border-radius:18px;overflow:hidden;border:1px solid #eee">
        <div style="padding:28px 32px;background:linear-gradient(115deg,#6A1B9A 0%,#B71C7E 45%,#FF3B57 82%,#FF6A2D 100%);color:#fff">
          <div style="font-size:12px;letter-spacing:.08em;font-weight:700">IPPOO ASSURANCE</div>
          <div style="font-size:28px;font-weight:900;margin-top:6px">FACTURE</div>
          <div style="font-size:13px;opacity:.9;margin-top:4px">${invoiceNumber} · ${dateStr}</div>
        </div>
        <div style="padding:24px 32px;color:#0E1320">
          <p style="margin:0 0 6px;font-weight:700">Bonjour ${profile?.name ?? "membre IPPOO"},</p>
          <p style="margin:0 0 16px;color:#555;font-size:14px">Votre paiement a bien été confirmé. Voici le détail de votre facture.</p>
          <table style="width:100%;border-collapse:collapse;font-size:14px">
            <tr style="background:#0E1320;color:#fff">
              <td style="padding:10px 12px;text-align:left">Description</td>
              <td style="padding:10px 12px;text-align:right">Montant</td>
            </tr>
            <tr>
              <td style="padding:10px 12px;border-bottom:1px solid #eee">${lineLabel}</td>
              <td style="padding:10px 12px;border-bottom:1px solid #eee;text-align:right;font-weight:700">${total}</td>
            </tr>
            <tr>
              <td style="padding:14px 12px;font-weight:900">TOTAL</td>
              <td style="padding:14px 12px;font-weight:900;text-align:right;color:#FF3B57">${total}</td>
            </tr>
          </table>
          <p style="margin:18px 0 0;color:#666;font-size:13px">Référence paiement : ${payment.id}</p>
          <p style="margin:6px 0 0;color:#666;font-size:13px">Retrouvez votre facture dans votre espace client, onglet Documents.</p>
          <p style="margin:20px 0 0;color:#888;font-size:12px">IPPOO Assurance — La micro-assurance qui prend soin de vous au Bénin.</p>
        </div>
      </div></body></html>`;

    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        from,
        to: [email],
        subject: `Facture ${invoiceNumber} — ${total}`,
        html,
      }),
    });
    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      console.log(`[email] Resend error ${res.status} for ${payment.id}: ${txt}`);
    }
  } catch (err) {
    console.log(`[email] sendInvoiceEmail failed: ${err}`);
  }
}

// Public health probe — safe to expose. Reports liveness, a KV round-trip,
// and which optional integrations are configured (booleans only, never the
// secret values themselves). Consumed by uptime monitors AND by the admin
// Overview tile.
app.get(`${PREFIX}/health`, async (c) => {
  const startedAt = Date.now();
  let kvOk = false;
  try {
    await kv.get(k.site());
    kvOk = true;
  } catch (err) {
    console.log("[health] kv probe failed:", err);
  }
  const integrations = {
    kkiapay: !!Deno.env.get("KKIAPAY_PUBLIC_KEY") && !!Deno.env.get("KKIAPAY_PRIVATE_KEY"),
    kkiapaySandbox: (Deno.env.get("KKIAPAY_SANDBOX") ?? "true").toLowerCase() !== "false",
    resend: !!RESEND_KEY,
    termii: !!TERMII_KEY,
    vapid: !!(VAPID_PUBLIC && VAPID_PRIVATE),
    adminTotp: !!Deno.env.get("ADMIN_TOTP_SECRET") || ADMIN_ACCOUNTS.some((a) => !!a.totpSecret),
    agentSignup: !!Deno.env.get("AGENT_SIGNUP_CODE"),
  };
  let agentsOnline = 0;
  let lastBillingRun: string | null = null;
  try {
    const { data: presRows } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "agent:presence:%");
    const STALE_MS = 90_000;
    for (const row of presRows ?? []) {
      const p = (row.value ?? {}) as any;
      const age = p?.at ? Date.now() - new Date(p.at).getTime() : Infinity;
      if (p?.status === "online" && age <= STALE_MS) agentsOnline++;
    }
    const billingMeta = (await kv.get("billing:last")) as any;
    lastBillingRun = billingMeta?.at ?? null;
  } catch { /* probe failures don't fail health */ }
  return c.json({
    status: kvOk ? "ok" : "degraded",
    kv: kvOk,
    integrations,
    operations: {
      agentsOnline,
      lastBillingRun,
    },
    serverTime: new Date().toISOString(),
    latencyMs: Date.now() - startedAt,
    rev: "2026-05-29-20",
  });
});

// Liveness probe ultra-léger pour monitoring uptime externe (Pingdom, UptimeRobot).
// Pas d'auth, pas de KV probe, juste 200 OK rapide.
app.get(`${PREFIX}/ping`, (c) => c.text("pong", 200, { "Cache-Control": "no-store" }));

app.post(`${PREFIX}/signup`, async (c) => {
  try {
    const ip = c.req.header("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
    const allowed = await rateLimit(`signup:${ip}`, 20, 1800);
    if (!allowed) return c.json({ error: "Trop de tentatives, réessayez dans 30 min." }, 429);
    const parsed = await parseBody(c, SignupSchema);
    if (!parsed.ok) return c.json({ error: parsed.message }, parsed.status);
    const { email, password, name, phone, referralCode, enrollerMatricule, profile: profileDetails } = parsed.data;
    // Quota secondaire par email (anti-rotation d'IP). 3 tentatives / heure
    // pour le même email — bloque les attaques d'énumération distribuées.
    const emailKey = (email ?? "").toLowerCase().trim();
    if (emailKey) {
      const okEmail = await rateLimit(`signup-email:${emailKey}`, 10, 3600);
      if (!okEmail) return c.json({ error: "Trop de tentatives pour cet email, réessayez plus tard." }, 429);
    }
    // Résout le matricule conseiller en uid via la sentinelle ; ignore
    // silencieusement si le matricule est inconnu ou banni (le compte se
    // crée quand même — l'attribution est facultative).
    let enrolledBy: string | null = null;
    let enrolledByUid: string | null = null;
    if (enrollerMatricule && typeof enrollerMatricule === "string") {
      const mat = enrollerMatricule.toUpperCase().trim();
      const ownerUid = (await kv.get(`agent:matricule-claim:${mat}`)) as string | null;
      if (ownerUid) {
        const meta = ((await kv.get(`agent:matricule:${ownerUid}`)) ?? {}) as any;
        if (!meta?.banned) {
          enrolledBy = mat;
          enrolledByUid = ownerUid;
        }
      }
    }
    const profileType = profileDetails?.type ?? "particulier";
    const sousProfilList = Array.isArray(profileDetails?.sousProfil)
      ? profileDetails!.sousProfil!.filter((s) => typeof s === "string" && s.trim()).slice(0, 20)
      : [];
    const { data, error } = await admin.auth.admin.createUser({
      email,
      password,
      // user_metadata reste lisible côté client via la session Supabase — on y
      // duplique le type + sousProfil pour permettre une segmentation rapide
      // sans relire le KV (utilisé par l'admin search et les filtres broadcast).
      user_metadata: { name, phone, profileType, sousProfil: sousProfilList },
      // Email server not configured — confirm automatically
      email_confirm: true,
    });
    if (error) {
      console.log(`Signup error for ${email}: ${error.message}`);
      const msg = /already been registered|already registered|user already exists/i.test(error.message)
        ? "Cet email est déjà associé à un compte IPPOO."
        : error.message;
      return c.json({ error: msg, code: "email_taken" }, 400);
    }
    const uid = data.user!.id;
    const now = new Date().toISOString();
    const memberNumber = await assignMemberNumber(uid);
    await kv.set(k.emailToUid(email), uid);
    await kv.set(k.profile(uid), {
      id: uid,
      email,
      name,
      phone: phone ?? "",
      memberNumber,
      createdAt: now,
      type: profileType,
      sousProfil: sousProfilList,
      firstName: profileDetails?.firstName ?? null,
      lastName: profileDetails?.lastName ?? null,
      gender: profileDetails?.gender ?? null,
      birthDate: profileDetails?.birthDate ?? null,
      birthPlace: profileDetails?.birthPlace ?? null,
      nationality: profileDetails?.nationality ?? null,
      address: profileDetails?.address ?? null,
      profession: profileDetails?.profession ?? null,
      activite: profileDetails?.activite ?? null,
      secteur: profileDetails?.secteur ?? null,
      entreprise: profileDetails?.entreprise ?? null,
      statutPro: profileDetails?.statutPro ?? null,
      companyName: profileDetails?.companyName ?? profileDetails?.entreprise ?? null,
      ifu: profileDetails?.ifu ?? null,
      idType: profileDetails?.idType ?? null,
      idNumber: profileDetails?.idNumber ?? null,
      country: profileDetails?.country ?? "BJ",
      countryDial: profileDetails?.countryDial ?? "229",
      department: profileDetails?.department ?? null,
      city: profileDetails?.city ?? null,
      quartier: profileDetails?.quartier ?? null,
      // Besoins de couverture déclarés à l'inscription — utilisés ensuite par
      // l'outil de devis et la priorisation produits côté agent.
      couverture: Array.isArray(profileDetails?.couverture) ? profileDetails!.couverture : [],
      couvertureAutre: profileDetails?.couvertureAutre ?? null,
      formule: profileDetails?.formule ?? null,
      // Documents que le membre a déclaré pouvoir fournir (KYC futur). Sert
      // au pré-remplissage de la checklist KYC et au scoring de complétude.
      documentsDeclares: Array.isArray(profileDetails?.documents) ? profileDetails!.documents : [],
      documentAutre: profileDetails?.documentAutre ?? null,
      enrolledBy,
      enrolledByUid,
      enrolledAt: enrolledBy ? now : null,
      enrolledSource: enrolledBy ? "invite-link" : null,
    });
    await kv.set(k.contracts(uid), []);
    await kv.set(k.claims(uid), []);
    await kv.set(k.payments(uid), []);
    // Bénéficiaires saisis dans le wizard d'inscription : on les matérialise
    // pour qu'ils apparaissent dans la fiche membre et soient utilisables sans
    // ressaisie au moment d'une déclaration de sinistre.
    const seedBeneficiaries = Array.isArray(profileDetails?.beneficiaires)
      ? profileDetails!.beneficiaires!
          .filter((b) => b && (b.name || b.relation))
          .map((b) => ({
            id: crypto.randomUUID(),
            name: (b.name ?? "").toString().slice(0, 120),
            relation: (b.relation ?? "").toString().slice(0, 60),
            birthDate: b.birthDate ?? null,
            source: "signup",
            createdAt: now,
          }))
      : [];
    await kv.set(k.beneficiaries(uid), seedBeneficiaries);
    await kv.set(k.documents(uid), []);
    await setNotifications(uid, notify([], "Bienvenue chez IPPOO", "Votre espace est prêt. Souscrivez à une couverture pour démarrer.", "success"));
    await kv.set(k.messages(uid), []);
    await kv.set(k.settings(uid), { lang: "fr", notifySms: true, notifyEmail: true });
    // Referral: assign a unique code to the new user
    const code = makeReferralCode(name);
    await kv.set(k.referralCode(uid), code);
    await kv.set(k.referralByCode(code), uid);
    // Redeem incoming referral if provided
    if (referralCode && typeof referralCode === "string") {
      const refererUid = await kv.get(k.referralByCode(referralCode.toUpperCase().trim()));
      if (refererUid && refererUid !== uid) {
        const reds = (await kv.get(k.referralRedemptions(refererUid))) ?? [];
        reds.push({ uid, at: now });
        await kv.set(k.referralRedemptions(refererUid), reds);
        const refNotifs = (await kv.get(k.notifications(refererUid))) ?? [];
        await kv.set(
          k.notifications(refererUid),
          notify(refNotifs, "Parrainage validé", `Un nouveau filleul rejoint IPPOO grâce à votre code ${referralCode}.`, "success"),
        );
      }
    }
    await audit(uid, "signup", { email, ip, enrolledBy });
    if (enrolledBy) {
      await audit(uid, "enrollment.attributed", { matricule: enrolledBy, source: "invite-link" });
      await pushAgentNotif(enrolledBy, {
        type: "assignment",
        title: "Nouveau filleul",
        body: `${name} vient de s'inscrire via votre lien d'invitation.`,
        url: "/agent/portefeuille",
      }).catch(() => {});
    }
    return c.json({ ok: true });
  } catch (err) {
    return safeError(c, err, "Erreur serveur lors de l'inscription");
  }
});

// Signs the avatar storage path into a short-lived URL so the client can
// render the photo without leaking the bucket. Returns the profile unchanged
// when no avatarPath is set or signing fails.
async function withAvatarUrl<T extends { avatarPath?: string | null } | null | undefined>(
  profile: T,
): Promise<T extends null | undefined ? T : T & { avatarUrl: string | null }> {
  if (!profile) return profile as any;
  const path = (profile as any).avatarPath as string | undefined;
  if (!path) return { ...(profile as any), avatarUrl: null };
  try {
    const { data, error } = await admin.storage.from(AVATAR_BUCKET).createSignedUrl(path, AVATAR_URL_TTL_SEC);
    return { ...(profile as any), avatarUrl: error || !data ? null : data.signedUrl };
  } catch {
    return { ...(profile as any), avatarUrl: null };
  }
}
// Batch variant for list endpoints (agent inbox, admin customer scans, etc.).
async function withAvatarUrls<T extends { avatarPath?: string | null }>(profiles: T[]): Promise<(T & { avatarUrl: string | null })[]> {
  return Promise.all(profiles.map((p) => withAvatarUrl(p))) as any;
}

app.get(`${PREFIX}/me`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  let profile = await kv.get(k.profile(user.id));
  // Backfill memberNumber + email→uid mapping for legacy users
  if (profile && !profile.memberNumber) {
    profile = { ...profile, memberNumber: await assignMemberNumber(user.id) };
    await kv.set(k.profile(user.id), profile);
  }
  if (profile?.email) {
    const mapped = await kv.get(k.emailToUid(profile.email));
    if (!mapped) await kv.set(k.emailToUid(profile.email), user.id);
  }
  return c.json({ profile: await withAvatarUrl(profile) });
});

// === Phone OTP (Termii) — #4 ===
// `/phone/otp/send` génère un code 6 chiffres, hash stocké en KV avec TTL
// 10 min, envoi SMS via Termii. `/phone/otp/verify` consomme le code et
// retourne un jeton de preuve HMAC (5 min) que le client peut joindre à
// un signup ou à une mise à jour de profil. Tout est rate-limité par
// numéro et par IP pour bloquer l'enumeration.
function normalizePhone(raw: string): string {
  return (raw ?? "").replace(/[^\d+]/g, "").replace(/^\+/, "");
}
app.post(`${PREFIX}/phone/otp/send`, async (c) => {
  try {
    const body = await c.req.json().catch(() => ({}));
    const phone = normalizePhone(String(body?.phone ?? ""));
    if (!/^\d{8,15}$/.test(phone)) return c.json({ error: "Numéro invalide" }, 400);
    const ip = c.req.header("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
    if (!(await rateLimit(`otp-send-ip:${ip}`, 10, 3600))) return c.json({ error: "Trop de demandes, réessayez plus tard." }, 429);
    if (!(await rateLimit(`otp-send-ph:${phone}`, 3, 900))) return c.json({ error: "Trop de codes demandés pour ce numéro." }, 429);
    const code = String(secureRandomInt(100000, 999999));
    const hash = b64urlEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(`${phone}:${code}`))));
    await kv.set(k.phoneOtp(phone), { hash, attempts: 0, expiresAt: Date.now() + 10 * 60 * 1000 });
    const sent = await sendSms(phone, `IPPOO — votre code de vérification : ${code}. Valable 10 min. Ne le partagez jamais.`);
    return c.json({ ok: true, sent, gated: !TERMII_KEY }, 200);
  } catch (err) {
    console.log(`OTP send error: ${err}`);
    return c.json({ error: "Erreur lors de l'envoi du code" }, 500);
  }
});
app.post(`${PREFIX}/phone/otp/verify`, async (c) => {
  try {
    const body = await c.req.json().catch(() => ({}));
    const phone = normalizePhone(String(body?.phone ?? ""));
    const code = String(body?.code ?? "").trim();
    if (!/^\d{8,15}$/.test(phone) || !/^\d{6}$/.test(code)) return c.json({ error: "Données invalides" }, 400);
    const ip = c.req.header("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
    if (!(await rateLimit(`otp-verify-ip:${ip}`, 20, 3600))) return c.json({ error: "Trop de tentatives." }, 429);
    const rec = (await kv.get(k.phoneOtp(phone))) as { hash: string; attempts: number; expiresAt: number } | null;
    if (!rec) return c.json({ error: "Code expiré ou inconnu" }, 410);
    if (Date.now() > rec.expiresAt) { await kv.del(k.phoneOtp(phone)); return c.json({ error: "Code expiré" }, 410); }
    if (rec.attempts >= 5) { await kv.del(k.phoneOtp(phone)); return c.json({ error: "Trop de tentatives." }, 429); }
    const hash = b64urlEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(`${phone}:${code}`))));
    if (hash !== rec.hash) {
      await kv.set(k.phoneOtp(phone), { ...rec, attempts: rec.attempts + 1 });
      return c.json({ error: "Code incorrect" }, 400);
    }
    await kv.del(k.phoneOtp(phone));
    const payload = `${phone}.${Date.now()}`;
    const key = await getHmacKey();
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
    const proof = `${b64urlEncode(enc.encode(payload))}.${b64urlEncode(new Uint8Array(sig))}`;
    return c.json({ ok: true, verified: true, proof, ttlSec: 300 });
  } catch (err) {
    console.log(`OTP verify error: ${err}`);
    return c.json({ error: "Erreur de vérification" }, 500);
  }
});

// === Consents (P10) ===
// Stockage horodaté des consentements (CGU, confidentialité, traitement, ARS,
// marketing). Append-only : chaque appel pousse une nouvelle entrée, on garde
// l'historique pour preuve légale. La dernière entrée par type donne l'état
// courant.
app.post(`${PREFIX}/consents`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  try {
    const body = await c.req.json().catch(() => ({}));
    const items = Array.isArray(body?.items) ? body.items : [];
    const ALLOWED = new Set(["cgu", "confidentialite", "traitement", "ars", "marketing"]);
    const ip = c.req.header("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
    const userAgent = c.req.header("user-agent") ?? "unknown";
    const now = new Date().toISOString();
    const prev = ((await kv.get(k.consents(user.id))) ?? []) as any[];
    let stored = 0;
    for (const it of items) {
      if (!it || !ALLOWED.has(String(it.type))) continue;
      prev.push({
        type: String(it.type),
        version: String(it.version ?? "unknown"),
        granted: it.granted !== false,
        at: now,
        ip,
        userAgent,
      });
      stored++;
    }
    // Cap à 200 entrées pour éviter la croissance illimitée.
    const next = prev.slice(-200);
    await kv.set(k.consents(user.id), next);
    return c.json({ ok: true, stored, total: next.length });
  } catch (err) {
    console.log(`Consents save error: ${err}`);
    return c.json({ error: "Erreur enregistrement consentements" }, 500);
  }
});
app.get(`${PREFIX}/consents`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const consents = ((await kv.get(k.consents(user.id))) ?? []) as any[];
  return c.json({ consents });
});

// Upload / replace the user's profile photo. Stored at <uid>/avatar.<ext>
// (upsert) so old files are overwritten in-place — no orphans, no manual GC.
app.post(`${PREFIX}/profile/avatar`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const limited = await guardRate(c, "avatar-up", user.id, 20, 3600);
  if (limited) return limited;
  try {
    const form = await c.req.formData();
    const file = form.get("file");
    if (!(file instanceof File)) return c.json({ error: "Fichier manquant" }, 400);
    if (file.size > AVATAR_MAX_BYTES) return c.json({ error: "Image trop volumineuse (max 2 Mo)" }, 413);
    if (!AVATAR_ALLOWED_MIME.test(file.type)) return c.json({ error: `Format non autorisé : ${file.type}` }, 415);
    const ext = (file.type.split("/")[1] ?? "jpg").replace("jpeg", "jpg");
    const path = `${user.id}/avatar.${ext}`;
    // Delete sibling files (different extension) so we don't leave stragglers.
    try {
      const { data: existing } = await admin.storage.from(AVATAR_BUCKET).list(user.id, { limit: 50 });
      const toRemove = (existing ?? []).filter((f) => f.name && f.name !== `avatar.${ext}`).map((f) => `${user.id}/${f.name}`);
      if (toRemove.length) await admin.storage.from(AVATAR_BUCKET).remove(toRemove);
    } catch { /* best-effort */ }
    const { error: upErr } = await admin.storage.from(AVATAR_BUCKET).upload(path, file, {
      contentType: file.type,
      upsert: true,
    });
    if (upErr) return c.json({ error: `Upload échoué: ${upErr.message}` }, 500);
    const current = (await kv.get(k.profile(user.id))) ?? {};
    const next = { ...current, avatarPath: path, avatarUpdatedAt: new Date().toISOString(), id: user.id };
    await kv.set(k.profile(user.id), next);
    await audit(user.id, "profile.avatar.upload", { size: file.size, mime: file.type });
    return c.json({ profile: await withAvatarUrl(next) });
  } catch (err) {
    console.log(`Avatar upload error for ${user.id}: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

app.delete(`${PREFIX}/profile/avatar`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  try {
    const current = (await kv.get(k.profile(user.id))) ?? {};
    const path = current.avatarPath as string | undefined;
    if (path) {
      try { await admin.storage.from(AVATAR_BUCKET).remove([path]); } catch { /* ignore */ }
    }
    // Also list+sweep in case avatarPath drifted from the actual file.
    try {
      const { data: existing } = await admin.storage.from(AVATAR_BUCKET).list(user.id, { limit: 50 });
      const all = (existing ?? []).filter((f) => f.name).map((f) => `${user.id}/${f.name}`);
      if (all.length) await admin.storage.from(AVATAR_BUCKET).remove(all);
    } catch { /* ignore */ }
    const next = { ...current, avatarPath: null, avatarUpdatedAt: new Date().toISOString(), id: user.id };
    await kv.set(k.profile(user.id), next);
    await audit(user.id, "profile.avatar.delete", {});
    return c.json({ profile: await withAvatarUrl(next) });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.put(`${PREFIX}/me`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  try {
    const parsed = await parseBody(c, ProfileUpdateSchema);
    if (!parsed.ok) return c.json({ error: parsed.message }, parsed.status);
    const current = (await kv.get(k.profile(user.id))) ?? {};
    const next = { ...current, ...parsed.data, id: user.id };
    await kv.set(k.profile(user.id), next);
    return c.json({ profile: next });
  } catch (err) {
    console.log(`Profile update error for ${user.id}: ${err}`);
    return c.json({ error: `Erreur de mise à jour du profil: ${err}` }, 500);
  }
});

app.get(`${PREFIX}/contracts`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const contracts = (await kv.get(k.contracts(user.id))) ?? [];
  return c.json({ contracts });
});

// #6 — Attestation PDF générée côté serveur. Le client a déjà une version JS,
// mais elle casse sur certains Android anciens / hors-ligne. Ici on construit
// un PDF 1.4 manuel (5-6 objets, latin-1) — pas de dépendance externe.
function escapePdf(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}
// Helvetica Type1 base = encodage WinAnsi/Latin-1. Sans transliteration les
// accents UTF-8 multi-octets s'affichent comme mojibake dans le PDF.
function pdfAscii(s: string): string {
  return s.normalize("NFD").replace(/[̀-ͯ]/g, "")
    .replace(/[—–]/g, "-").replace(/[''‘’]/g, "'").replace(/[""“”]/g, '"')
    .replace(/[°]/g, "deg").replace(/[€]/g, "EUR")
    .replace(/[^\x20-\x7E]/g, "?");
}
function buildAttestationPdf(p: { memberNumber: string; name: string; product: string; effectiveDate: string; endDate: string; contractId: string }): Uint8Array {
  const lines = [
    "IPPOO ASSURANCE - ATTESTATION DE COUVERTURE",
    "",
    `Adherent      : ${pdfAscii(p.name)}`,
    `N adherent    : ${pdfAscii(p.memberNumber)}`,
    `Contrat       : ${pdfAscii(p.contractId)}`,
    `Produit       : ${pdfAscii(p.product)}`,
    `Effet         : ${pdfAscii(p.effectiveDate)}`,
    `Echeance      : ${pdfAscii(p.endDate)}`,
    "",
    "Le present document atteste de la couverture en cours.",
    `Edite le ${new Date().toISOString().slice(0, 10)} via espace client IPPOO.`,
  ];
  let stream = "BT\n/F1 12 Tf\n72 770 Td\n14 TL\n";
  for (const ln of lines) stream += `(${escapePdf(ln)}) Tj T*\n`;
  stream += "ET";
  const streamBytes = new TextEncoder().encode(stream);
  const objects: string[] = [];
  objects.push("<< /Type /Catalog /Pages 2 0 R >>");
  objects.push("<< /Type /Pages /Count 1 /Kids [3 0 R] >>");
  objects.push("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>");
  objects.push(`<< /Length ${streamBytes.length} >>\nstream\n${stream}\nendstream`);
  objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  let pdf = "%PDF-1.4\n";
  const offsets: number[] = [];
  for (let i = 0; i < objects.length; i++) {
    offsets.push(pdf.length);
    pdf += `${i + 1} 0 obj\n${objects[i]}\nendobj\n`;
  }
  const xrefOffset = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) pdf += `${String(off).padStart(10, "0")} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  void streamBytes;
  return new TextEncoder().encode(pdf);
}
app.get(`${PREFIX}/contracts/:id/attestation.pdf`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const id = c.req.param("id");
  const contracts = ((await kv.get(k.contracts(user.id))) ?? []) as any[];
  const ct = contracts.find((x) => x.id === id);
  if (!ct) return c.json({ error: "Contrat introuvable" }, 404);
  const profile = ((await kv.get(k.profile(user.id))) ?? {}) as any;
  const pdf = buildAttestationPdf({
    memberNumber: profile.memberNumber ?? "—",
    name: profile.name ?? user.email ?? "—",
    product: ct.product ?? "—",
    effectiveDate: (ct.effectiveDate ?? ct.startDate ?? ct.createdAt ?? "").slice(0, 10) || "—",
    endDate: (ct.endDate ?? ct.nextBillingDate ?? "").slice(0, 10) || "—",
    contractId: ct.id ?? "—",
  });
  await audit(user.id, "contract.attestation.pdf", { contractId: id });
  return new Response(pdf, {
    status: 200,
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": `attachment; filename="attestation-${ct.id}.pdf"`,
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Expose-Headers": "Content-Disposition",
    },
  });
});

app.get(`${PREFIX}/claims`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const claims = (await kv.get(k.claims(user.id))) ?? [];
  return c.json({ claims });
});

app.post(`${PREFIX}/claims`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const limited = await guardRate(c, "claims", user.id, 20, 3600);
  if (limited) return limited;
  try {
    const parsed = await parseBody(c, ClaimCreateSchema);
    if (!parsed.ok) return c.json({ error: parsed.message }, parsed.status);
    const { contractId, type, description, amount, beneficiaryId } = parsed.data;
    // Si un bénéficiaire est passé, on snapshot son nom au moment de la
    // déclaration (les bénéficiaires peuvent être renommés/supprimés plus tard
    // et les conseillers doivent voir l'identité d'origine pour l'instruction).
    let beneficiarySnapshot: { id: string; name: string; relation: string } | null = null;
    if (beneficiaryId) {
      const benefs = ((await kv.get(k.beneficiaries(user.id))) ?? []) as any[];
      const b = benefs.find((x: any) => x.id === beneficiaryId);
      if (b) beneficiarySnapshot = { id: b.id, name: b.name, relation: b.relation };
    }
    const autoMat = await pickOnlineAgentMatricule().catch(() => null);
    const claim = {
      id: `s_${Date.now()}`,
      contractId: contractId ?? null,
      type,
      description,
      amount: typeof amount === "number" ? amount : 0,
      status: "en_cours",
      createdAt: new Date().toISOString(),
      attachments: [] as { path: string; name: string; size: number }[],
      assignedTo: autoMat ?? null,
      assignedAt: autoMat ? new Date().toISOString() : null,
      assignedBy: autoMat ? "system:auto" : null,
      beneficiaryId: beneficiarySnapshot?.id ?? null,
      beneficiary: beneficiarySnapshot,
    };
    const claims = (await kv.get(k.claims(user.id))) ?? [];
    claims.unshift(claim);
    await kv.set(k.claims(user.id), claims);
    if (autoMat) {
      await pushAgentNotif(autoMat, {
        type: "assignment",
        title: "Nouveau sinistre",
        body: `Sinistre « ${type} » assigné automatiquement.`,
        url: "/agent/sinistres",
      }).catch(() => {});
    }
    const notifs = (await kv.get(k.notifications(user.id))) ?? [];
    await notifyAndDispatch(user.id, notifs, {
      typeKey: "claim",
      title: "Sinistre déclaré",
      body: `Votre déclaration « ${type} » est en cours d'instruction.`,
      severity: "info",
      to: "/espace-client/sinistres",
    });
    const profile = (await kv.get(k.profile(user.id))) ?? {};
    broadcast("agent:inbox", "claim:new", {
      userId: user.id,
      userName: profile.name ?? "",
      claimId: claim.id,
      claimType: type,
      at: claim.createdAt,
    }).catch(() => {});
    return c.json({ claim });
  } catch (err) {
    console.log(`Claim create error for ${user.id}: ${err}`);
    return c.json({ error: `Erreur de création du sinistre: ${err}` }, 500);
  }
});

app.get(`${PREFIX}/payments`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const all: any[] = (await kv.get(k.payments(user.id))) ?? [];
  // Pagination symétrique à /agent/payments : tri DESC createdAt + curseur `before`.
  const sorted = [...all].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  const url = new URL(c.req.url);
  const limitRaw = Number(url.searchParams.get("limit") ?? "0");
  const before = url.searchParams.get("before");
  // Sans `limit`, on conserve l'ancien contrat (liste complète) pour ne pas
  // casser les consommateurs existants. Avec `limit`, on pagine.
  if (!limitRaw) return c.json({ payments: sorted, nextBefore: null, total: sorted.length });
  const limit = Math.min(Math.max(limitRaw, 1), 500);
  const start = before ? sorted.findIndex((p) => String(p.createdAt) < before) : 0;
  const slice = start === -1 ? [] : sorted.slice(start, start + limit);
  const nextBefore = slice.length === limit ? String(slice[slice.length - 1].createdAt) : null;
  return c.json({ payments: slice, nextBefore, total: sorted.length });
});

// Initiate a Mobile Money payment via KkiaPay (Bénin). Returns a pending payment
// + the public key so the client can launch the widget. If no KKIAPAY_PUBLIC_KEY
// is configured, we fall back to a mock flow that can be confirmed by the client
// via /payments/confirm-mock (DEV/sandbox only).
app.post(`${PREFIX}/payments/initiate`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  try {
    const parsed = await parseBody(c, PaymentInitiateSchema);
    if (!parsed.ok) return c.json({ error: parsed.message }, parsed.status);
    const { contractId, amount, phone, purpose, paymentId } = parsed.data;
    const allowed = await rateLimit(`pay-init:${user.id}`, 10, 600);
    if (!allowed) return c.json({ error: "Trop de tentatives, réessayez plus tard." }, 429);
    const publicKey = Deno.env.get("KKIAPAY_PUBLIC_KEY") ?? "";
    const mode: "kkiapay" | "mock" = publicKey ? "kkiapay" : "mock";
    const now = new Date().toISOString();
    const payments = (await kv.get(k.payments(user.id))) ?? [];
    let payment: any;
    if (paymentId) {
      const idx = payments.findIndex((p: any) => p.id === paymentId);
      if (idx === -1) return c.json({ error: "Paiement introuvable" }, 404);
      if (payments[idx].status === "confirme") return c.json({ error: "Déjà confirmé" }, 400);
      payments[idx] = { ...payments[idx], phone: phone ?? payments[idx].phone ?? null, mode, status: "en_attente" };
      payment = payments[idx];
    } else {
      payment = {
        id: `p_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`,
        contractId: contractId ?? null,
        amount,
        currency: "XOF",
        method: "mobile_money",
        status: "en_attente" as const,
        phone: phone ?? null,
        mode,
        purpose: purpose ?? "cotisation",
        createdAt: now,
      };
      payments.unshift(payment);
    }
    await kv.set(k.payments(user.id), payments);
    await audit(user.id, "payment.initiated", { id: payment.id, amount, mode, purpose: payment.purpose });
    return c.json({
      payment,
      kkiapay: { publicKey, sandbox: !Deno.env.get("KKIAPAY_SECRET") },
    });
  } catch (err) {
    console.log(`Payment initiate error for ${user.id}: ${err}`);
    return c.json({ error: `Erreur initialisation paiement: ${err}` }, 500);
  }
});

// KkiaPay webhook. Production: verify the X-Kkiapay-Secret header against the
// shared secret stored in env, then mark the matching payment confirmed.
app.post(`${PREFIX}/payments/webhook`, async (c) => {
  const raw = await c.req.text().catch(() => "");
  try {
    const secret = Deno.env.get("KKIAPAY_SECRET");
    const provided = c.req.header("X-Kkiapay-Secret") ?? c.req.header("x-kkiapay-secret") ?? "";
    if (!secret || provided !== secret) {
      await logWebhookEvent({ provider: "kkiapay", c, status: "failed", reason: "signature", httpStatus: 401, rawBody: raw });
      return c.json({ error: "Signature invalide" }, 401);
    }
    const body = raw ? JSON.parse(raw) : {};
    const { state, data, amount } = body ?? {};
    const paymentId = data?.paymentId;
    const userId = data?.userId;
    if (!paymentId || !userId) {
      await logWebhookEvent({ provider: "kkiapay", c, status: "failed", reason: "missing-metadata", httpStatus: 400, rawBody: raw });
      return c.json({ error: "Données manquantes" }, 400);
    }
    const payments = ((await kv.get(k.payments(userId))) ?? []) as any[];
    const idx = payments.findIndex((p) => p.id === paymentId);
    if (idx === -1) {
      await logWebhookEvent({ provider: "kkiapay", c, status: "failed", reason: "payment-not-found", httpStatus: 404, rawBody: raw, metadata: { paymentId, userId } });
      return c.json({ error: "Paiement introuvable" }, 404);
    }
    const next = state === "SUCCESS" ? "confirme" : "echec";
    payments[idx] = { ...payments[idx], status: next, confirmedAt: new Date().toISOString() };
    await kv.set(k.payments(userId), payments);
    if (next === "confirme") {
      await applyPaymentSideEffects(userId, payments[idx]);
      sendInvoiceEmail(userId, payments[idx]);
    }
    await audit(userId, `payment.${next}`, { id: paymentId, amount, purpose: payments[idx].purpose });
    broadcast(`payments:live`, "payments:dirty", { userId, paymentId, status: next });
    broadcast(`payments:user:${userId}`, "payments:dirty", { paymentId, status: next });
    await logWebhookEvent({ provider: "kkiapay", c, status: "ok", httpStatus: 200, rawBody: raw, metadata: { paymentId, userId, next } });
    return c.json({ ok: true });
  } catch (err) {
    console.log(`Payment webhook error: ${err}`);
    await logWebhookEvent({ provider: "kkiapay", c, status: "failed", reason: `exception:${err}`, httpStatus: 500, rawBody: raw });
    return c.json({ error: "Erreur webhook" }, 500);
  }
});

// --- Unified payment confirmation adapter ---
// Used by every provider webhook to normalize state and run side-effects.
async function confirmPayment(userId: string, paymentId: string, success: boolean, providerTxnId?: string, provider?: string) {
  const payments = ((await kv.get(k.payments(userId))) ?? []) as any[];
  const idx = payments.findIndex((p) => p.id === paymentId);
  if (idx === -1) return { ok: false, reason: "not-found" };
  if (payments[idx].status === "confirme") return { ok: true, idempotent: true };
  const next = success ? "confirme" : "echec";
  payments[idx] = {
    ...payments[idx],
    status: next,
    confirmedAt: new Date().toISOString(),
    providerTxnId: providerTxnId ?? payments[idx].providerTxnId,
    provider: provider ?? payments[idx].provider,
  };
  await kv.set(k.payments(userId), payments);
  if (next === "confirme") {
    await applyPaymentSideEffects(userId, payments[idx]);
    sendInvoiceEmail(userId, payments[idx]);
  }
  await audit(userId, `payment.${next}`, { id: paymentId, provider, providerTxnId });
  // Realtime fan-out pour les calendriers admin / agent / espace-client. On
  // émet à la fois sur le canal global `payments:live` (admin/agent) et sur
  // un canal par utilisateur (CotisationsPage) pour éviter d'inonder tous
  // les clients d'événements qui ne les concernent pas.
  broadcast(`payments:live`, "payments:dirty", { userId, paymentId, status: next });
  broadcast(`payments:user:${userId}`, "payments:dirty", { paymentId, status: next });
  return { ok: true };
}

// CinetPay webhook (widely used in Bénin for MTN/Moov/Celtiis + cards).
// Verifies via HMAC SHA256 of body using CINETPAY_SECRET_KEY.
app.post(`${PREFIX}/payments/webhook/cinetpay`, async (c) => {
  const raw = await c.req.text().catch(() => "");
  try {
    const secret = Deno.env.get("CINETPAY_SECRET_KEY");
    if (!secret) { await logWebhookEvent({ provider: "cinetpay", c, status: "skipped", reason: "not-configured", httpStatus: 503, rawBody: raw }); return c.json({ error: "Provider non configuré" }, 503); }
    const sig = c.req.header("x-token") ?? "";
    const expected = await hmacHex(secret, raw);
    if (sig !== expected) { await logWebhookEvent({ provider: "cinetpay", c, status: "failed", reason: "signature", httpStatus: 401, rawBody: raw }); return c.json({ error: "Signature invalide" }, 401); }
    const body = raw ? JSON.parse(raw) : {};
    const paymentId = body?.cpm_custom ?? body?.metadata?.paymentId;
    const userId = body?.metadata?.userId;
    const txn = body?.cpm_trans_id ?? body?.transaction_id;
    const success = (body?.cpm_result === "00") || (body?.status === "ACCEPTED");
    if (!paymentId || !userId) { await logWebhookEvent({ provider: "cinetpay", c, status: "failed", reason: "missing-metadata", httpStatus: 400, rawBody: raw }); return c.json({ error: "Données manquantes" }, 400); }
    const res = await confirmPayment(userId, paymentId, success, txn, "cinetpay");
    if (!res.ok) { await logWebhookEvent({ provider: "cinetpay", c, status: "failed", reason: res.reason ?? "confirm-failed", httpStatus: 404, rawBody: raw, metadata: { paymentId, userId } }); return c.json({ error: res.reason }, 404); }
    await logWebhookEvent({ provider: "cinetpay", c, status: "ok", httpStatus: 200, rawBody: raw, metadata: { paymentId, userId, success } });
    return c.json({ ok: true });
  } catch (err) {
    console.log(`cinetpay webhook err: ${err}`);
    await logWebhookEvent({ provider: "cinetpay", c, status: "failed", reason: `exception:${err}`, httpStatus: 500, rawBody: raw });
    return c.json({ error: "Erreur webhook" }, 500);
  }
});

// FedaPay webhook (alternate aggregator).
app.post(`${PREFIX}/payments/webhook/fedapay`, async (c) => {
  const raw = await c.req.text().catch(() => "");
  try {
    const secret = Deno.env.get("FEDAPAY_WEBHOOK_SECRET");
    if (!secret) { await logWebhookEvent({ provider: "fedapay", c, status: "skipped", reason: "not-configured", httpStatus: 503, rawBody: raw }); return c.json({ error: "Provider non configuré" }, 503); }
    const sig = c.req.header("x-fedapay-signature") ?? "";
    const expected = await hmacHex(secret, raw);
    if (sig !== expected) { await logWebhookEvent({ provider: "fedapay", c, status: "failed", reason: "signature", httpStatus: 401, rawBody: raw }); return c.json({ error: "Signature invalide" }, 401); }
    const body = raw ? JSON.parse(raw) : {};
    const entity = body?.entity ?? body;
    const paymentId = entity?.custom_metadata?.paymentId;
    const userId = entity?.custom_metadata?.userId;
    const txn = entity?.reference ?? entity?.id;
    const success = entity?.status === "approved";
    if (!paymentId || !userId) { await logWebhookEvent({ provider: "fedapay", c, status: "failed", reason: "missing-metadata", httpStatus: 400, rawBody: raw }); return c.json({ error: "Métadonnées manquantes" }, 400); }
    const res = await confirmPayment(userId, paymentId, success, String(txn ?? ""), "fedapay");
    if (!res.ok) { await logWebhookEvent({ provider: "fedapay", c, status: "failed", reason: res.reason ?? "confirm-failed", httpStatus: 404, rawBody: raw, metadata: { paymentId, userId } }); return c.json({ error: res.reason }, 404); }
    await logWebhookEvent({ provider: "fedapay", c, status: "ok", httpStatus: 200, rawBody: raw, metadata: { paymentId, userId, success } });
    return c.json({ ok: true });
  } catch (err) {
    console.log(`fedapay webhook err: ${err}`);
    await logWebhookEvent({ provider: "fedapay", c, status: "failed", reason: `exception:${err}`, httpStatus: 500, rawBody: raw });
    return c.json({ error: "Erreur webhook" }, 500);
  }
});

// MTN MoMo Collections direct webhook (X-Callback-Key bearer).
app.post(`${PREFIX}/payments/webhook/mtn`, async (c) => {
  const raw = await c.req.text().catch(() => "");
  try {
    const key = Deno.env.get("MTN_MOMO_CALLBACK_KEY");
    if (!key) { await logWebhookEvent({ provider: "mtn-momo", c, status: "skipped", reason: "not-configured", httpStatus: 503, rawBody: raw }); return c.json({ error: "Provider non configuré" }, 503); }
    const provided = c.req.header("x-callback-key") ?? "";
    if (provided !== key) { await logWebhookEvent({ provider: "mtn-momo", c, status: "failed", reason: "signature", httpStatus: 401, rawBody: raw }); return c.json({ error: "Clé invalide" }, 401); }
    const body = raw ? JSON.parse(raw) : {};
    const paymentId = body?.externalId ?? body?.payerMessage;
    const userId = body?.payer?.partyId ? null : body?.metadata?.userId;
    const txn = body?.financialTransactionId ?? body?.referenceId;
    const success = body?.status === "SUCCESSFUL";
    if (!paymentId || !userId) { await logWebhookEvent({ provider: "mtn-momo", c, status: "failed", reason: "missing-metadata", httpStatus: 400, rawBody: raw }); return c.json({ error: "Métadonnées manquantes" }, 400); }
    const res = await confirmPayment(userId, paymentId, success, txn, "mtn-momo");
    if (!res.ok) { await logWebhookEvent({ provider: "mtn-momo", c, status: "failed", reason: res.reason ?? "confirm-failed", httpStatus: 404, rawBody: raw, metadata: { paymentId, userId } }); return c.json({ error: res.reason }, 404); }
    await logWebhookEvent({ provider: "mtn-momo", c, status: "ok", httpStatus: 200, rawBody: raw, metadata: { paymentId, userId, success } });
    return c.json({ ok: true });
  } catch (err) {
    console.log(`mtn webhook err: ${err}`);
    await logWebhookEvent({ provider: "mtn-momo", c, status: "failed", reason: `exception:${err}`, httpStatus: 500, rawBody: raw });
    return c.json({ error: "Erreur webhook" }, 500);
  }
});

// HMAC helper for webhook signatures.
async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Provider status (admin only): lists configured payment providers & test hints.
app.get(`${PREFIX}/admin/payments/providers`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  return c.json({
    providers: [
      { id: "kkiapay", name: "KkiaPay", configured: !!Deno.env.get("KKIAPAY_PUBLIC_KEY"), webhookConfigured: !!Deno.env.get("KKIAPAY_SECRET"), supports: ["mtn", "moov", "celtiis", "carte"] },
      { id: "cinetpay", name: "CinetPay", configured: !!Deno.env.get("CINETPAY_API_KEY"), webhookConfigured: !!Deno.env.get("CINETPAY_SECRET_KEY"), supports: ["mtn", "moov", "celtiis", "carte"] },
      { id: "fedapay", name: "FedaPay", configured: !!Deno.env.get("FEDAPAY_PUBLIC_KEY"), webhookConfigured: !!Deno.env.get("FEDAPAY_WEBHOOK_SECRET"), supports: ["mtn", "moov", "carte"] },
      { id: "mtn-momo", name: "MTN MoMo (direct)", configured: !!Deno.env.get("MTN_MOMO_SUBSCRIPTION_KEY"), webhookConfigured: !!Deno.env.get("MTN_MOMO_CALLBACK_KEY"), supports: ["mtn"] },
    ],
  });
});

// Sandbox/mock confirmation. Only allowed when no KKIAPAY_SECRET is set,
// because in production KkiaPay must call /payments/webhook directly.
app.post(`${PREFIX}/payments/:id/confirm-mock`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  if (Deno.env.get("KKIAPAY_SECRET") || Deno.env.get("APP_ENV") === "production" || Deno.env.get("KKIAPAY_PUBLIC_KEY")) {
    return c.json({ error: "Mode mock désactivé : passez par KkiaPay." }, 403);
  }
  const id = c.req.param("id");
  const payments = ((await kv.get(k.payments(user.id))) ?? []) as any[];
  const idx = payments.findIndex((p) => p.id === id);
  if (idx === -1) return c.json({ error: "Paiement introuvable" }, 404);
  if (payments[idx].status === "confirme") return c.json({ payment: payments[idx] });
  payments[idx] = { ...payments[idx], status: "confirme", confirmedAt: new Date().toISOString() };
  await kv.set(k.payments(user.id), payments);
  await applyPaymentSideEffects(user.id, payments[idx]);
  await audit(user.id, "payment.confirme", { id, mode: "mock", purpose: payments[idx].purpose });
  sendInvoiceEmail(user.id, payments[idx]);
  return c.json({ payment: payments[idx] });
});

app.get(`${PREFIX}/payments/:id`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const id = c.req.param("id");
  const payments = ((await kv.get(k.payments(user.id))) ?? []) as any[];
  const payment = payments.find((p) => p.id === id);
  if (!payment) return c.json({ error: "Paiement introuvable" }, 404);
  return c.json({ payment });
});

app.post(`${PREFIX}/payments`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const limited = await guardRate(c, "pay-legacy", user.id, 10, 600);
  if (limited) return limited;
  try {
    const parsed = await parseBody(c, PaymentLegacySchema);
    if (!parsed.ok) return c.json({ error: parsed.message }, parsed.status);
    const { contractId, amount, method } = parsed.data;
    const payment = {
      id: `p_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      contractId: contractId ?? null,
      amount,
      currency: "XOF",
      method: method ?? "mobile_money",
      status: "en_attente" as const,
      purpose: "cotisation" as const,
      createdAt: new Date().toISOString(),
    };
    const payments = (await kv.get(k.payments(user.id))) ?? [];
    payments.unshift(payment);
    await kv.set(k.payments(user.id), payments);
    return c.json({ payment });
  } catch (err) {
    console.log(`Payment create error for ${user.id}: ${err}`);
    return c.json({ error: `Erreur de cotisation: ${err}` }, 500);
  }
});

// ---- BENEFICIARIES ----
app.get(`${PREFIX}/beneficiaries`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const beneficiaries = (await kv.get(k.beneficiaries(user.id))) ?? [];
  return c.json({ beneficiaries });
});

app.post(`${PREFIX}/beneficiaries`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const limited = await guardRate(c, "ben", user.id, 20, 3600);
  if (limited) return limited;
  try {
    const parsed = await parseBody(c, BeneficiaryCreateSchema);
    if (!parsed.ok) return c.json({ error: parsed.message }, parsed.status);
    const { name, relation, birthDate } = parsed.data;
    const beneficiary = {
      id: `b_${Date.now()}`,
      name,
      relation,
      birthDate: birthDate ?? null,
      createdAt: new Date().toISOString(),
    };
    const list = (await kv.get(k.beneficiaries(user.id))) ?? [];
    list.push(beneficiary);
    await kv.set(k.beneficiaries(user.id), list);
    return c.json({ beneficiary });
  } catch (err) {
    console.log(`Beneficiary create error for ${user.id}: ${err}`);
    return c.json({ error: `Erreur d'ajout du bénéficiaire: ${err}` }, 500);
  }
});

// Upload an attachment for an existing claim (multipart form-data)
app.post(`${PREFIX}/claims/:id/attachments`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const limited = await guardRate(c, "att", user.id, 30, 3600);
  if (limited) return limited;
  const id = c.req.param("id");
  try {
    const form = await c.req.formData();
    const file = form.get("file");
    if (!(file instanceof File)) return c.json({ error: "Fichier manquant" }, 400);
    if (file.size > 10 * 1024 * 1024) return c.json({ error: "Fichier trop volumineux (10 Mo max)" }, 400);
    const path = `${user.id}/${id}/${Date.now()}-${file.name.replace(/[^a-zA-Z0-9_.-]/g, "_")}`;
    const { error: uploadErr } = await admin.storage.from(BUCKET).upload(path, file, { contentType: file.type, upsert: false });
    if (uploadErr) return c.json({ error: `Erreur d'upload: ${uploadErr.message}` }, 500);
    const claims = (await kv.get(k.claims(user.id))) ?? [];
    const idx = claims.findIndex((cl: any) => cl.id === id);
    if (idx === -1) return c.json({ error: "Sinistre introuvable" }, 404);
    claims[idx].attachments = [...(claims[idx].attachments ?? []), { path, name: file.name, size: file.size }];
    await kv.set(k.claims(user.id), claims);
    // A5 — Si le sinistre est déjà assigné à un conseiller, le prévenir tout
    // de suite : il a besoin de voir la nouvelle pièce sans recharger.
    const assignee = claims[idx].assignedTo as string | undefined;
    if (assignee) {
      broadcast("agent:inbox", "claim:attachment", {
        claimId: id, userId: user.id, to: assignee,
        attachment: { name: file.name, size: file.size },
        at: new Date().toISOString(),
      }).catch(() => { /* best-effort */ });
    }
    return c.json({ ok: true, attachment: { path, name: file.name, size: file.size } });
  } catch (err) {
    console.log(`Attachment upload error: ${err}`);
    return c.json({ error: `Erreur d'upload: ${err}` }, 500);
  }
});

// Signed URL for an attachment (5 min)
app.get(`${PREFIX}/claims/attachments/url`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const path = c.req.query("path");
  if (!path || !path.startsWith(`${user.id}/`)) return c.json({ error: "Chemin invalide" }, 400);
  const { data, error: signErr } = await admin.storage.from(BUCKET).createSignedUrl(path, 300);
  if (signErr) return c.json({ error: signErr.message }, 500);
  return c.json({ url: data.signedUrl });
});

app.delete(`${PREFIX}/beneficiaries/:id`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const id = c.req.param("id");
  const list = ((await kv.get(k.beneficiaries(user.id))) ?? []).filter((b: any) => b.id !== id);
  await kv.set(k.beneficiaries(user.id), list);
  return c.json({ ok: true });
});

// ---- DOCUMENTS ----
app.get(`${PREFIX}/documents`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const documents = (await kv.get(k.documents(user.id))) ?? [];
  return c.json({ documents });
});

// URL signée (5 min) pour consulter un document du client.
app.get(`${PREFIX}/documents/url`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const path = c.req.query("path");
  if (!path || !path.startsWith(`${user.id}/`)) return c.json({ error: "Chemin invalide" }, 400);
  const { data, error: signErr } = await admin.storage.from(BUCKET).createSignedUrl(path, 300);
  if (signErr) return c.json({ error: signErr.message }, 500);
  return c.json({ url: data.signedUrl });
});

// ---- NOTIFICATIONS ----
app.get(`${PREFIX}/notifications`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const notifications = (await kv.get(k.notifications(user.id))) ?? [];
  return c.json({ notifications });
});

app.post(`${PREFIX}/notifications/read`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const list = ((await kv.get(k.notifications(user.id))) ?? []).map((n: any) => ({ ...n, read: true }));
  await kv.set(k.notifications(user.id), list);
  return c.json({ ok: true });
});

// ---- MESSAGES ----
app.get(`${PREFIX}/messages`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const messages = (await kv.get(k.messages(user.id))) ?? [];
  return c.json({ messages });
});

const EDIT_WINDOW_MS = 5 * 60 * 1000;

// Edit own message (5 min window).
app.patch(`${PREFIX}/messages/:id`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const id = c.req.param("id");
  const parsed = await parseBody(c, MessageEditSchema);
  if (!parsed.ok) return c.json({ error: parsed.message }, parsed.status);
  const list = ((await kv.get(k.messages(user.id))) ?? []) as any[];
  const idx = list.findIndex((m) => m.id === id);
  if (idx < 0) return c.json({ error: "Message introuvable" }, 404);
  const m = list[idx];
  if (m.from !== "user") return c.json({ error: "Édition refusée" }, 403);
  if (m.deletedAt) return c.json({ error: "Message supprimé" }, 410);
  if (Date.now() - new Date(m.createdAt).getTime() > EDIT_WINDOW_MS) return c.json({ error: "Fenêtre d'édition expirée" }, 409);
  const updated = { ...m, body: parsed.data.content.trim(), editedAt: new Date().toISOString() };
  list[idx] = updated;
  await kv.set(k.messages(user.id), list);
  await Promise.all([
    broadcast(`chat:${user.id}`, "message:update", { message: updated }),
    broadcast(`admin:chat`, "message:update", { userId: user.id, message: updated }),
  ]);
  return c.json({ message: updated });
});

// Soft-delete own message. Body cleared, attachment hidden.
app.delete(`${PREFIX}/messages/:id`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const id = c.req.param("id");
  const list = ((await kv.get(k.messages(user.id))) ?? []) as any[];
  const idx = list.findIndex((m) => m.id === id);
  if (idx < 0) return c.json({ error: "Message introuvable" }, 404);
  if (list[idx].from !== "user") return c.json({ error: "Suppression refusée" }, 403);
  const updated = { ...list[idx], body: "", deletedAt: new Date().toISOString(), attachment: undefined };
  list[idx] = updated;
  await kv.set(k.messages(user.id), list);
  await Promise.all([
    broadcast(`chat:${user.id}`, "message:update", { message: updated }),
    broadcast(`admin:chat`, "message:update", { userId: user.id, message: updated }),
  ]);
  return c.json({ message: updated });
});

// Admin edit/delete on advisor messages.
app.patch(`${PREFIX}/admin/messages/:uid/:id`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  const id = c.req.param("id");
  const parsed = await parseBody(c, MessageEditSchema);
  if (!parsed.ok) return c.json({ error: parsed.message }, parsed.status);
  const list = ((await kv.get(k.messages(uid))) ?? []) as any[];
  const idx = list.findIndex((m) => m.id === id);
  if (idx < 0) return c.json({ error: "Message introuvable" }, 404);
  if (list[idx].from !== "conseiller") return c.json({ error: "Édition refusée" }, 403);
  if (list[idx].deletedAt) return c.json({ error: "Message supprimé" }, 410);
  const updated = { ...list[idx], body: parsed.data.content.trim(), editedAt: new Date().toISOString() };
  list[idx] = updated;
  await kv.set(k.messages(uid), list);
  await audit(uid, "message.admin_edit", { by: r.admin.username, id });
  await Promise.all([
    broadcast(`chat:${uid}`, "message:update", { message: updated }),
    broadcast(`admin:chat`, "message:update", { userId: uid, message: updated }),
  ]);
  return c.json({ message: updated });
});

app.delete(`${PREFIX}/admin/messages/:uid/:id`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  const id = c.req.param("id");
  const list = ((await kv.get(k.messages(uid))) ?? []) as any[];
  const idx = list.findIndex((m) => m.id === id);
  if (idx < 0) return c.json({ error: "Message introuvable" }, 404);
  if (list[idx].from !== "conseiller") return c.json({ error: "Suppression refusée" }, 403);
  const updated = { ...list[idx], body: "", deletedAt: new Date().toISOString(), attachment: undefined };
  list[idx] = updated;
  await kv.set(k.messages(uid), list);
  await audit(uid, "message.admin_delete", { by: r.admin.username, id });
  await Promise.all([
    broadcast(`chat:${uid}`, "message:update", { message: updated }),
    broadcast(`admin:chat`, "message:update", { userId: uid, message: updated }),
  ]);
  return c.json({ message: updated });
});

// Upload an attachment as a chat message. multipart/form-data: file=<File>, [caption]=string
app.post(`${PREFIX}/messages/attachment`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const limited = await guardRate(c, "msgatt", user.id, 20, 600);
  if (limited) return limited;
  try {
    const form = await c.req.formData();
    const file = form.get("file");
    const caption = String(form.get("caption") ?? "").trim();
    if (!(file instanceof File)) return c.json({ error: "Fichier manquant" }, 400);
    if (file.size > MSG_MAX_BYTES) return c.json({ error: "Fichier trop volumineux (max 10 Mo)" }, 413);
    if (!MSG_ALLOWED_MIME.test(file.type)) return c.json({ error: `Type non autorisé: ${file.type}` }, 415);
    const safeName = file.name.replace(/[^\w.\-]+/g, "_").slice(-80);
    const path = `${user.id}/${Date.now()}_${safeName}`;
    const { error: upErr } = await admin.storage.from(MSG_BUCKET).upload(path, file, { contentType: file.type, upsert: false });
    if (upErr) return c.json({ error: `Upload échoué: ${upErr.message}` }, 500);
    const profile = (await kv.get(k.profile(user.id))) ?? {};
    const userMsg = {
      id: `m_${Date.now()}`,
      from: "user",
      author: profile.name ?? "Vous",
      body: caption,
      createdAt: new Date().toISOString(),
      read: true,
      attachment: { name: file.name, mime: file.type, size: file.size, path },
    };
    const list = ((await kv.get(k.messages(user.id))) ?? []) as any[];
    list.push(userMsg);
    await kv.set(k.messages(user.id), list);
    await Promise.all([
      broadcast(`chat:${user.id}`, "message:new", { message: userMsg }),
      broadcast(`admin:chat`, "message:new", { userId: user.id, message: userMsg }),
      broadcast("agent:inbox", "message:new", {
        userId: user.id,
        userName: profile.name ?? "",
        preview: `📎 ${file.name}`,
        at: userMsg.createdAt,
      }),
    ]);
    return c.json({ message: userMsg });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.post(`${PREFIX}/admin/messages/:uid/attachment`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  try {
    const form = await c.req.formData();
    const file = form.get("file");
    const caption = String(form.get("caption") ?? "").trim();
    if (!(file instanceof File)) return c.json({ error: "Fichier manquant" }, 400);
    if (file.size > MSG_MAX_BYTES) return c.json({ error: "Fichier trop volumineux (max 10 Mo)" }, 413);
    if (!MSG_ALLOWED_MIME.test(file.type)) return c.json({ error: `Type non autorisé: ${file.type}` }, 415);
    const safeName = file.name.replace(/[^\w.\-]+/g, "_").slice(-80);
    const path = `${uid}/admin_${Date.now()}_${safeName}`;
    const { error: upErr } = await admin.storage.from(MSG_BUCKET).upload(path, file, { contentType: file.type, upsert: false });
    if (upErr) return c.json({ error: `Upload échoué: ${upErr.message}` }, 500);
    const msg = {
      id: `m_${Date.now()}`,
      from: "conseiller",
      author: `${r.admin.username} (IPPOO)`,
      body: caption,
      createdAt: new Date().toISOString(),
      read: false,
      attachment: { name: file.name, mime: file.type, size: file.size, path },
    };
    const list = ((await kv.get(k.messages(uid))) ?? []) as any[];
    list.push(msg);
    await kv.set(k.messages(uid), list);
    const notifs = ((await kv.get(k.notifications(uid))) ?? []) as any[];
    await notifyAndDispatch(uid, notifs, {
      typeKey: "system",
      title: "Nouveau message conseiller",
      body: `Pièce jointe : ${file.name}`,
      severity: "info",
      to: "/espace-client/messagerie",
      tag: `msg:${uid}`,
    });
    await audit(uid, "message.admin_attachment", { by: r.admin.username, name: file.name, size: file.size });
    await Promise.all([
      broadcast(`chat:${uid}`, "message:new", { message: msg }),
      broadcast(`admin:chat`, "message:new", { userId: uid, message: msg }),
    ]);
    return c.json({ message: msg });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Signed URL for a message attachment. User can fetch their own; admin can fetch any.
app.get(`${PREFIX}/messages/attachment-url`, async (c) => {
  const path = c.req.query("path") ?? "";
  if (!path) return c.json({ error: "path manquant" }, 400);
  const adminTok = c.req.header("X-Admin-Token") ?? c.req.header("x-admin-token");
  if (adminTok) {
    const r = await requireAdminToken(c);
    if (!r.admin) return c.json({ error: r.error }, r.status);
  } else {
    const { user, error } = await requireUser(c);
    if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
    if (!path.startsWith(`${user.id}/`)) return c.json({ error: "Accès refusé" }, 403);
  }
  const { data, error: sErr } = await admin.storage.from(MSG_BUCKET).createSignedUrl(path, 300);
  if (sErr || !data) return c.json({ error: sErr?.message ?? "Erreur signature" }, 500);
  return c.json({ url: data.signedUrl, expiresIn: 300 });
});

// Client marks all advisor messages as read. Broadcasts to admin so the
// unread badge drops instantly.
app.post(`${PREFIX}/messages/read`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const list = ((await kv.get(k.messages(user.id))) ?? []) as any[];
  let changed = 0;
  const marked = list.map((m) => {
    if (m.from === "conseiller" && !m.read) { changed++; return { ...m, read: true, readAt: new Date().toISOString() }; }
    return m;
  });
  if (changed > 0) {
    await kv.set(k.messages(user.id), marked);
    await broadcast(`admin:chat`, "message:read", { userId: user.id, count: changed, at: new Date().toISOString() });
  }
  return c.json({ ok: true, marked: changed });
});

// Admin marks the thread as read (or any single message). Broadcasts to the
// user's channel so the ✓✓ indicator lights up live on their messages.
app.post(`${PREFIX}/admin/messages/:uid/read`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  const list = ((await kv.get(k.messages(uid))) ?? []) as any[];
  let changed = 0;
  const marked = list.map((m) => {
    if (m.from === "user" && !m.read) { changed++; return { ...m, read: true, readAt: new Date().toISOString() }; }
    return m;
  });
  if (changed > 0) {
    await kv.set(k.messages(uid), marked);
    await broadcast(`chat:${uid}`, "message:read", { count: changed, at: new Date().toISOString() });
  }
  return c.json({ ok: true, marked: changed });
});

app.post(`${PREFIX}/messages`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const limited = await guardRate(c, "msg", user.id, 30, 600);
  if (limited) return limited;
  try {
    const parsed = await parseBody(c, MessageCreateSchema);
    if (!parsed.ok) return c.json({ error: parsed.message }, parsed.status);
    const content = parsed.data.content.trim();
    if (!content) return c.json({ error: "Message vide" }, 400);
    const profile = (await kv.get(k.profile(user.id))) ?? {};
    const now = new Date().toISOString();
    const replyToId = typeof (parsed.data as any).replyToId === "string" ? (parsed.data as any).replyToId : undefined;
    const userMsg: any = {
      id: `m_${Date.now()}`,
      from: "user",
      author: profile.name ?? "Vous",
      body: content.trim(),
      createdAt: now,
      read: true,
    };
    if (replyToId) userMsg.replyToId = replyToId;
    const list = (await kv.get(k.messages(user.id))) ?? [];
    list.push(userMsg);
    await kv.set(k.messages(user.id), list);
    // Auto-routage : si la conversation n'a pas encore d'assignee, on tente
    // de choisir un conseiller en ligne (round-robin). Si aucun n'est
    // disponible, la conversation reste non assignée — un admin / agent
    // pourra la prendre manuellement depuis l'inbox.
    try {
      const meta = (await kv.get(k.conversationMeta(user.id))) ?? { status: "ouvert", assignee: null, tags: [] };
      if (!meta.assignee) {
        const matricule = await pickOnlineAgentMatricule();
        if (matricule) {
          const next = { ...meta, assignee: matricule, updatedAt: new Date().toISOString() };
          await kv.set(k.conversationMeta(user.id), next);
          await audit(user.id, "conversation.autoroute", { assignee: matricule, reason: "online_round_robin" });
          await broadcast(`admin:chat`, "meta:update", { userId: user.id, meta: next });
        }
      }
    } catch (e) {
      console.log(`auto-router failed for ${user.id}: ${e}`);
    }
    // Push to the user's own channel (other client tabs) AND to the admin queue.
    await Promise.all([
      broadcast(`chat:${user.id}`, "message:new", { message: userMsg }),
      broadcast(`admin:chat`, "message:new", { userId: user.id, message: userMsg }),
      broadcast("agent:inbox", "message:new", {
        userId: user.id,
        userName: profile.name ?? "",
        preview: content.slice(0, 120),
        at: now,
      }),
    ]);
    return c.json({ messages: [userMsg] });
  } catch (err) {
    console.log(`Message create error for ${user.id}: ${err}`);
    return c.json({ error: `Erreur lors de l'envoi: ${err}` }, 500);
  }
});

// ---- SUBSCRIBE TO NEW CONTRACT ----
app.post(`${PREFIX}/subscribe`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const limited = await guardRate(c, "sub", user.id, 10, 3600);
  if (limited) return limited;
  try {
    const parsed = await parseBody(c, SubscribeSchema);
    if (!parsed.ok) return c.json({ error: parsed.message }, parsed.status);
    const { product, frequency } = parsed.data;
    const now = new Date().toISOString();
    const contract = {
      id: `c_${Date.now()}`,
      product,
      status: "active",
      startDate: now,
      endDate: new Date(Date.now() + 365 * 86400000).toISOString(),
      premium: BILLING.dailyPerProduct * BILLING.daysPerMonth,
      currency: "XOF",
      frequency: frequency ?? "mensuel",
      autoDebit: true,
      nextBillingDate: nextBillingFromNow(),
    };
    const contracts = (await kv.get(k.contracts(user.id))) ?? [];
    contracts.unshift(contract);
    await kv.set(k.contracts(user.id), contracts);
    const notifications = (await kv.get(k.notifications(user.id))) ?? [];
    await notifyAndDispatch(user.id, notifications, {
      typeKey: "system",
      title: "Souscription confirmée",
      body: `Votre contrat « ${product} » est actif.`,
      severity: "success",
      to: "/espace-client/contrats",
      tag: `contract:${contract.id}`,
    });
    return c.json({ contract });
  } catch (err) {
    console.log(`Subscribe error for ${user.id}: ${err}`);
    return c.json({ error: `Erreur de souscription: ${err}` }, 500);
  }
});

// ---- SETTINGS ----
app.get(`${PREFIX}/settings`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const settings = (await kv.get(k.settings(user.id))) ?? { lang: "fr", notifySms: true, notifyEmail: true };
  return c.json({ settings });
});

// Notification preferences — matrix view. Stored inside settings.notifPrefs.
app.get(`${PREFIX}/me/notif-prefs`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const prefs = await getNotifPrefs(user.id);
  return c.json({ prefs });
});

app.patch(`${PREFIX}/me/notif-prefs`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  try {
    const body = await c.req.json();
    const current = (await kv.get(k.settings(user.id))) ?? {};
    const previous = mergeNotifPrefs(current.notifPrefs);
    const merged: NotifPrefs = mergeNotifPrefs({
      channels: { ...(current.notifPrefs?.channels ?? {}), ...(body.channels ?? {}) },
      types: { ...(current.notifPrefs?.types ?? {}), ...(body.types ?? {}) },
    });
    await kv.set(k.settings(user.id), { ...current, notifPrefs: merged });

    // Diff and log only what actually changed so the audit trail stays
    // signal-heavy (one entry per real toggle, not per save).
    const channelDiff: Record<string, { from: boolean; to: boolean }> = {};
    for (const key of Object.keys(merged.channels) as NotifChannel[]) {
      if (previous.channels[key] !== merged.channels[key]) {
        channelDiff[key] = { from: previous.channels[key], to: merged.channels[key] };
      }
    }
    const typeDiff: Record<string, { from: boolean; to: boolean }> = {};
    for (const key of Object.keys(merged.types) as NotifTypeKey[]) {
      if (previous.types[key] !== merged.types[key]) {
        typeDiff[key] = { from: previous.types[key], to: merged.types[key] };
      }
    }
    if (Object.keys(channelDiff).length || Object.keys(typeDiff).length) {
      await audit(user.id, "notif_prefs.update", {
        ...(Object.keys(channelDiff).length ? { channels: channelDiff } : {}),
        ...(Object.keys(typeDiff).length ? { types: typeDiff } : {}),
      });
    }

    return c.json({ prefs: merged });
  } catch (err) {
    return c.json({ error: `Erreur sauvegarde préférences: ${err}` }, 500);
  }
});

app.put(`${PREFIX}/settings`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  try {
    const updates = await c.req.json();
    const current = (await kv.get(k.settings(user.id))) ?? {};
    const next = { ...current, ...updates };
    await kv.set(k.settings(user.id), next);
    return c.json({ settings: next });
  } catch (err) {
    console.log(`Settings update error for ${user.id}: ${err}`);
    return c.json({ error: `Erreur sauvegarde paramètres: ${err}` }, 500);
  }
});

// ---- CHANGE PASSWORD ----
app.post(`${PREFIX}/change-password`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  try {
    const allowed = await rateLimit(`pw:${user.id}`, 5, 3600);
    if (!allowed) return c.json({ error: "Trop de changements, réessayez dans 1 h." }, 429);
    const parsed = await parseBody(c, ChangePasswordSchema);
    if (!parsed.ok) return c.json({ error: parsed.message }, parsed.status);
    const { newPassword } = parsed.data;
    const { error: updateErr } = await admin.auth.admin.updateUserById(user.id, { password: newPassword });
    if (updateErr) {
      console.log(`Password change error for ${user.id}: ${updateErr.message}`);
      await audit(user.id, "password.change.failed", { reason: updateErr.message });
      return c.json({ error: updateErr.message }, 400);
    }
    await audit(user.id, "password.change", {});
    return c.json({ ok: true });
  } catch (err) {
    console.log(`Password change exception for ${user.id}: ${err}`);
    return c.json({ error: `Erreur changement mot de passe: ${err}` }, 500);
  }
});

// Check upcoming contract renewals and push notifications (idempotent via renewalNoticeSent flag)
app.post(`${PREFIX}/contracts/check-renewals`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  try {
    const contracts = (await kv.get(k.contracts(user.id))) ?? [];
    const notifs = (await kv.get(k.notifications(user.id))) ?? [];
    const now = Date.now();
    const WINDOW = 30 * 86400000;
    let changed = false;
    let pushed = 0;
    const updated = contracts.map((ct: any) => {
      if (ct.status !== "active" || !ct.endDate) return ct;
      const end = new Date(ct.endDate).getTime();
      const days = Math.ceil((end - now) / 86400000);
      if (days <= 30 && days >= 0 && !ct.renewalNoticeSent) {
        notify(
          notifs,
          "Échéance proche",
          `Votre contrat « ${ct.product} » arrive à échéance dans ${days} jour${days > 1 ? "s" : ""}.`,
          "warn",
        );
        pushed++;
        changed = true;
        return { ...ct, renewalNoticeSent: true };
      }
      if (days > WINDOW / 86400000 && ct.renewalNoticeSent) {
        return { ...ct, renewalNoticeSent: false };
      }
      return ct;
    });
    if (changed) {
      await kv.set(k.contracts(user.id), updated);
      await setNotifications(user.id, notifs.slice(0, 50));
    }
    return c.json({ pushed });
  } catch (err) {
    console.log(`Renewal check error for ${user.id}: ${err}`);
    return c.json({ error: `Erreur de vérification des échéances: ${err}` }, 500);
  }
});

// 1-click renewal: extends contract by 12 months + records payment
app.post(`${PREFIX}/contracts/:id/renew`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const limited = await guardRate(c, "renew", user.id, 10, 3600);
  if (limited) return limited;
  const id = c.req.param("id");
  try {
    const body = await c.req.json().catch(() => ({}));
    const phone = typeof body.phone === "string" ? body.phone : null;
    const contracts = (await kv.get(k.contracts(user.id))) ?? [];
    const ct = contracts.find((c: any) => c.id === id);
    if (!ct) return c.json({ error: "Contrat introuvable" }, 404);
    const publicKey = Deno.env.get("KKIAPAY_PUBLIC_KEY") ?? "";
    const mode: "kkiapay" | "mock" = publicKey ? "kkiapay" : "mock";
    const payment = {
      id: `p_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      contractId: ct.id,
      amount: ct.premium,
      currency: ct.currency ?? "XOF",
      method: "mobile_money",
      status: "en_attente" as const,
      purpose: "renewal" as const,
      phone,
      mode,
      createdAt: new Date().toISOString(),
    };
    const payments = (await kv.get(k.payments(user.id))) ?? [];
    payments.unshift(payment);
    await kv.set(k.payments(user.id), payments);
    // Marque le contrat « renouvellement en attente » → carte client affiche
    // un badge tant que le webhook KkiaPay n'a pas confirmé. Évite le double
    // déclenchement de paiement par un utilisateur impatient.
    const idx = contracts.findIndex((cx: any) => cx.id === ct.id);
    if (idx !== -1) {
      contracts[idx] = { ...contracts[idx], pendingRenewalPaymentId: payment.id, pendingRenewalAt: payment.createdAt };
      await kv.set(k.contracts(user.id), contracts);
    }
    await audit(user.id, "renewal.initiated", { id, premium: ct.premium, paymentId: payment.id });
    return c.json({
      payment,
      kkiapay: { publicKey, sandbox: !Deno.env.get("KKIAPAY_SECRET") },
    });
  } catch (err) {
    console.log(`Renewal error for ${user.id}/${id}: ${err}`);
    return c.json({ error: `Erreur de renouvellement: ${err}` }, 500);
  }
});

// ---- REFERRAL ----
app.get(`${PREFIX}/referral`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  let code = await kv.get(k.referralCode(user.id));
  if (!code) {
    const profile = (await kv.get(k.profile(user.id))) ?? {};
    code = makeReferralCode(profile.name ?? "IPPOO");
    await kv.set(k.referralCode(user.id), code);
    await kv.set(k.referralByCode(code), user.id);
  }
  const redemptions = (await kv.get(k.referralRedemptions(user.id))) ?? [];
  return c.json({ code, count: redemptions.length });
});

// ---- AUDIT LOG ----
app.get(`${PREFIX}/audit`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const entries = (await kv.get(k.audit(user.id))) ?? [];
  return c.json({ entries });
});

// ---- ACCOUNT DELETION (RGPD, soft-delete with 30-day grace) ----
app.post(`${PREFIX}/account/delete`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const limited = await guardRate(c, "acct-del", user.id, 5, 3600);
  if (limited) return limited;
  const scheduledFor = new Date(Date.now() + 30 * 86400000).toISOString();
  await kv.set(k.accountDeletion(user.id), { requestedAt: new Date().toISOString(), scheduledFor });
  await audit(user.id, "account.delete.request", { scheduledFor });
  const notifications = (await kv.get(k.notifications(user.id))) ?? [];
  await notifyAndDispatch(user.id, notifications, {
    typeKey: "system",
    title: "Suppression de compte programmée",
    body: `Votre compte sera supprimé le ${new Date(scheduledFor).toLocaleDateString("fr-FR")}. Connectez-vous pour annuler.`,
    severity: "warn",
    tag: `acct-del:${user.id}`,
  });
  return c.json({ ok: true, scheduledFor });
});

app.delete(`${PREFIX}/account/delete`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  await kv.del(k.accountDeletion(user.id));
  await audit(user.id, "account.delete.cancel", {});
  return c.json({ ok: true });
});

// RGPD data portability: returns a JSON dump of all user data so the user
// can keep a copy before requesting deletion.
app.get(`${PREFIX}/account/export`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const [profile, contracts, claims, payments, beneficiaries, documents, notifications, messages, settings, auditEntries, referralCode] =
    await Promise.all([
      kv.get(k.profile(user.id)),
      kv.get(k.contracts(user.id)),
      kv.get(k.claims(user.id)),
      kv.get(k.payments(user.id)),
      kv.get(k.beneficiaries(user.id)),
      kv.get(k.documents(user.id)),
      kv.get(k.notifications(user.id)),
      kv.get(k.messages(user.id)),
      kv.get(k.settings(user.id)),
      kv.get(k.audit(user.id)),
      kv.get(k.referralCode(user.id)),
    ]);
  // P11 — Inclure les binaires (KYC, pièces sinistre, pièces jointes
  // messagerie) sous forme d'URLs signées valables 7 jours. Le fichier JSON
  // d'export reste léger, et l'utilisateur peut télécharger chaque pièce
  // tant que l'URL est valide. Lecture récursive du préfixe `<uid>/` dans le
  // bucket privé.
  const consents = (await kv.get(`consents:${user.id}`)) ?? [];
  const files: Array<{ path: string; size: number; updatedAt: string | null; signedUrl: string | null }> = [];
  try {
    async function walk(prefix: string) {
      const { data, error: lerr } = await admin.storage.from(BUCKET).list(prefix, { limit: 1000 });
      if (lerr || !data) return;
      for (const entry of data) {
        if (!entry.name) continue;
        const full = prefix ? `${prefix}/${entry.name}` : entry.name;
        // Heuristique Supabase : "fichier" si id non nul OU metadata.size présent.
        const isFile = (entry as any).id || (entry.metadata && (entry.metadata as any).size != null);
        if (isFile) {
          const { data: signed } = await admin.storage.from(BUCKET).createSignedUrl(full, 60 * 60 * 24 * 7);
          files.push({
            path: full,
            size: ((entry.metadata as any)?.size ?? 0) as number,
            updatedAt: (entry as any).updated_at ?? null,
            signedUrl: signed?.signedUrl ?? null,
          });
        } else {
          await walk(full);
        }
      }
    }
    await walk(user.id);
  } catch (err) {
    console.log(`Account export storage walk failed for ${user.id}: ${err}`);
  }
  await audit(user.id, "account.export", { files: files.length });
  return c.json({
    exportedAt: new Date().toISOString(),
    user: { id: user.id, email: user.email },
    profile,
    contracts,
    claims,
    payments,
    beneficiaries,
    documents,
    notifications,
    messages,
    settings,
    audit: auditEntries,
    referralCode,
    consents,
    files,
    filesNote: "URLs signées valides 7 jours. Téléchargez les pièces avant expiration.",
  });
});

// Hard-delete: wipes all KV keys, storage files, and the auth user. Used by
// the admin sweep route (after the 30-day grace period) and the user-driven
// immediate-delete route.
async function hardDeleteUser(uid: string): Promise<void> {
  const profile = await kv.get(k.profile(uid));
  const keys = [
    k.profile(uid), k.contracts(uid), k.claims(uid), k.payments(uid),
    k.beneficiaries(uid), k.documents(uid), k.notifications(uid), k.messages(uid),
    k.settings(uid), k.audit(uid), k.referralCode(uid), k.accountDeletion(uid),
    k.webauthnCreds(uid), k.webauthnChallenge(`reg:${uid}`),
  ];
  if (profile?.email) keys.push(k.emailToUid(profile.email));
  if (profile?.memberNumber) keys.push(k.memberByNumber(profile.memberNumber));
  if (profile?.referralCode) keys.push(k.referralByCode(profile.referralCode));
  try { await kv.mdel(keys); } catch (err) { console.log(`hardDelete kv error ${uid}: ${err}`); }
  try {
    const { data: files } = await admin.storage.from(BUCKET).list(uid, { limit: 1000 });
    if (files && files.length) {
      const paths: string[] = [];
      for (const f of files) {
        if (f.name) {
          const { data: sub } = await admin.storage.from(BUCKET).list(`${uid}/${f.name}`, { limit: 1000 });
          for (const sf of sub ?? []) paths.push(`${uid}/${f.name}/${sf.name}`);
        }
      }
      if (paths.length) await admin.storage.from(BUCKET).remove(paths);
    }
  } catch (err) { console.log(`hardDelete storage error ${uid}: ${err}`); }
  try {
    const { data: av } = await admin.storage.from(AVATAR_BUCKET).list(uid, { limit: 50 });
    const avPaths = (av ?? []).filter((f) => f.name).map((f) => `${uid}/${f.name}`);
    if (avPaths.length) await admin.storage.from(AVATAR_BUCKET).remove(avPaths);
  } catch (err) { console.log(`hardDelete avatar storage error ${uid}: ${err}`); }
  try { await admin.auth.admin.deleteUser(uid); } catch (err) { console.log(`hardDelete auth error ${uid}: ${err}`); }
}

// User-driven immediate purge (skips the 30-day grace; consent already given).
app.post(`${PREFIX}/account/delete-now`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const limited = await guardRate(c, "acct-del-now", user.id, 2, 86400);
  if (limited) return limited;
  await hardDeleteUser(user.id);
  return c.json({ ok: true });
});

// Admin sweep: deletes accounts whose scheduledFor is past. Can be called by
// a cron job or manually by an admin from the admin portal.
app.post(`${PREFIX}/admin/account/sweep`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  const r = { admin: g.admin };
  try {
    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "account:deletion:%");
    if (error) return c.json({ error: error.message }, 500);
    const now = Date.now();
    const deleted: string[] = [];
    for (const row of data ?? []) {
      const uid = (row.key as string).slice("account:deletion:".length);
      const scheduledFor = (row.value as any)?.scheduledFor;
      if (!scheduledFor) continue;
      if (new Date(scheduledFor).getTime() <= now) {
        await hardDeleteUser(uid);
        deleted.push(uid);
      }
    }
    await adminAudit(c, r.admin, "account.sweep", { deleted: deleted.length });
    return c.json({ deleted: deleted.length, ids: deleted });
  } catch (err) {
    console.log(`Account sweep error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- BILLING & MEMBER CARD ----
const BILLING = {
  dailyPerProduct: 500,
  daysPerMonth: 31,
  accountFee: 1000,
  cardFee: 500,
};

function computeBilling(contracts: any[], profile: any) {
  const perProduct = BILLING.dailyPerProduct * BILLING.daysPerMonth;
  const active = (contracts ?? []).filter((c) => c.status === "active");
  const items: any[] = active.map((c) => ({
    kind: "insurance",
    label: `Assurance — ${c.product}`,
    contractId: c.id,
    perDay: BILLING.dailyPerProduct,
    days: BILLING.daysPerMonth,
    amount: perProduct,
  }));
  items.push({ kind: "account_fee", label: "Frais de gestion de compte", amount: BILLING.accountFee });
  if (profile?.cardActive) {
    items.push({ kind: "card_fee", label: "Carte membre IPPOO", amount: BILLING.cardFee });
  }
  const total = items.reduce((s, it) => s + it.amount, 0);
  return {
    items,
    total,
    perInsurance: perProduct,
    accountFee: BILLING.accountFee,
    cardFee: BILLING.cardFee,
    activeCount: active.length,
    cycle: "mensuel",
  };
}

app.get(`${PREFIX}/billing`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const contracts = (await kv.get(k.contracts(user.id))) ?? [];
  const profile = await kv.get(k.profile(user.id));
  return c.json(computeBilling(contracts, profile));
});

app.post(`${PREFIX}/member-card/activate`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const limited = await guardRate(c, "card", user.id, 5, 3600);
  if (limited) return limited;
  try {
    const contracts = (await kv.get(k.contracts(user.id))) ?? [];
    const hasActive = contracts.some((ct: any) => ct.status === "active");
    if (!hasActive) {
      return c.json({ error: "Vous devez d'abord souscrire à au moins une assurance." }, 400);
    }
    const profile = await kv.get(k.profile(user.id));
    if (!profile) return c.json({ error: "Profil introuvable" }, 404);
    if (profile.cardActive) return c.json({ profile, payment: null });
    const body = await c.req.json().catch(() => ({}));
    const phone = typeof body?.phone === "string" ? body.phone : null;
    const publicKey = Deno.env.get("KKIAPAY_PUBLIC_KEY") ?? "";
    const mode: "kkiapay" | "mock" = publicKey ? "kkiapay" : "mock";
    const payment = {
      id: `p_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      contractId: null,
      amount: BILLING.cardFee,
      currency: "XOF",
      method: "mobile_money",
      status: "en_attente" as const,
      purpose: "card_activation" as const,
      label: "Activation carte membre IPPOO",
      phone,
      mode,
      createdAt: new Date().toISOString(),
    };
    const payments = (await kv.get(k.payments(user.id))) ?? [];
    payments.unshift(payment);
    await kv.set(k.payments(user.id), payments);
    await audit(user.id, "member-card.activate.initiated", { paymentId: payment.id });
    return c.json({
      profile,
      payment,
      kkiapay: { publicKey, sandbox: !Deno.env.get("KKIAPAY_SECRET") },
    });
  } catch (err) {
    console.log(`Card activation error for ${user.id}: ${err}`);
    return c.json({ error: `Erreur d'activation: ${err}` }, 500);
  }
});

// ---- QR LOGIN: issue & verify signed QR tokens ----
app.get(`${PREFIX}/me/qr-token`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const profile = await kv.get(k.profile(user.id));
  if (!profile?.memberNumber) return c.json({ error: "Profil incomplet" }, 400);
  if (!profile.cardActive) return c.json({ error: "Carte membre non activée", code: "card_inactive" }, 403);
  const contracts = (await kv.get(k.contracts(user.id))) ?? [];
  if (!contracts.some((ct: any) => ct.status === "active")) {
    return c.json({ error: "Aucune souscription active", code: "no_subscription" }, 403);
  }
  const token = await signToken({
    v: 1,
    sub: user.id,
    mn: profile.memberNumber,
    iat: Math.floor(Date.now() / 1000),
  });
  return c.json({ token, memberNumber: profile.memberNumber });
});

// Exchange QR token → magic link (client completes via supabase.auth.verifyOtp)
app.post(`${PREFIX}/auth/qr-login`, async (c) => {
  try {
    const ip = c.req.header("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
    const allowed = await rateLimit(`qrlogin:${ip}`, 10, 600);
    if (!allowed) return c.json({ error: "Trop de tentatives, patientez." }, 429);
    const { token } = (await c.req.json()) ?? {};
    if (!token || typeof token !== "string") return c.json({ error: "Token manquant" }, 400);
    const payload = await verifyToken<{ sub: string; mn: string }>(token);
    if (!payload?.sub) return c.json({ error: "QR invalide ou falsifié" }, 401);
    const profile = await kv.get(k.profile(payload.sub));
    if (!profile?.email || profile.memberNumber !== payload.mn) {
      return c.json({ error: "Identifiants membres invalides" }, 401);
    }
    const { data, error: linkErr } = await admin.auth.admin.generateLink({
      type: "magiclink", email: profile.email,
    });
    if (linkErr) return c.json({ error: linkErr.message }, 500);
    await audit(payload.sub, "auth.qr.login", { ip });
    return c.json({
      email: profile.email,
      tokenHash: data.properties?.hashed_token,
      actionLink: data.properties?.action_link,
    });
  } catch (err) {
    console.log(`QR login error: ${err}`);
    return c.json({ error: `Erreur QR: ${err}` }, 500);
  }
});

// ---- WEBAUTHN (biometric) ----
app.post(`${PREFIX}/auth/webauthn/register/options`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const profile = await kv.get(k.profile(user.id));
  const existing = (await kv.get(k.webauthnCreds(user.id))) ?? [];
  const { rpID } = webauthnContext(c);
  const opts = await generateRegistrationOptions({
    rpName: WEBAUTHN_RP_NAME,
    rpID,
    userID: enc.encode(user.id),
    userName: profile?.email ?? user.email ?? user.id,
    userDisplayName: profile?.name ?? "Membre IPPOO",
    attestationType: "none",
    authenticatorSelection: { userVerification: "preferred", residentKey: "preferred" },
    excludeCredentials: existing.map((c: any) => ({ id: c.id, type: "public-key" })),
  });
  await kv.set(k.webauthnChallenge(`reg:${user.id}`), { challenge: opts.challenge, at: Date.now() });
  return c.json(opts);
});

app.post(`${PREFIX}/auth/webauthn/register/verify`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const limited = await guardRate(c, "biorev", user.id, 10, 600);
  if (limited) return limited;
  try {
    const body = await c.req.json();
    const stored = await kv.get(k.webauthnChallenge(`reg:${user.id}`));
    if (!stored?.challenge) return c.json({ error: "Aucun défi en cours" }, 400);
    const { origin, rpID } = webauthnContext(c);
    const verification = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: stored.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });
    if (!verification.verified || !verification.registrationInfo) {
      return c.json({ error: "Vérification échouée" }, 400);
    }
    const { credential } = verification.registrationInfo as any;
    const creds = (await kv.get(k.webauthnCreds(user.id))) ?? [];
    creds.push({
      id: credential.id,
      publicKey: b64urlEncode(credential.publicKey),
      counter: credential.counter ?? 0,
      transports: body.response?.response?.transports ?? [],
      createdAt: new Date().toISOString(),
    });
    await kv.set(k.webauthnCreds(user.id), creds);
    await audit(user.id, "auth.webauthn.register", {});
    return c.json({ ok: true });
  } catch (err) {
    console.log(`WebAuthn register verify error: ${err}`);
    return c.json({ error: `Erreur d'enregistrement biométrique: ${err}` }, 500);
  }
});

app.post(`${PREFIX}/auth/webauthn/login/options`, async (c) => {
  try {
    const { email } = (await c.req.json()) ?? {};
    if (!email) return c.json({ error: "Email requis" }, 400);
    const uid = await kv.get(k.emailToUid(email));
    if (!uid) return c.json({ error: "Aucun compte trouvé" }, 404);
    const creds = (await kv.get(k.webauthnCreds(uid))) ?? [];
    if (!creds.length) return c.json({ error: "Aucune empreinte enregistrée" }, 404);
    const { rpID } = webauthnContext(c);
    const opts = await generateAuthenticationOptions({
      rpID,
      allowCredentials: creds.map((c: any) => ({ id: c.id, type: "public-key", transports: c.transports })),
      userVerification: "preferred",
    });
    await kv.set(k.webauthnChallenge(`auth:${uid}`), { challenge: opts.challenge, at: Date.now() });
    return c.json({ ...opts, _uid: uid });
  } catch (err) {
    console.log(`WebAuthn auth options error: ${err}`);
    return c.json({ error: `Erreur: ${err}` }, 500);
  }
});

app.post(`${PREFIX}/auth/webauthn/login/verify`, async (c) => {
  try {
    const ip = c.req.header("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
    const allowed = await rateLimit(`biolog:${ip}`, 10, 600);
    if (!allowed) return c.json({ error: "Trop de tentatives, patientez." }, 429);
    const { email, response } = (await c.req.json()) ?? {};
    const uid = await kv.get(k.emailToUid(email));
    if (!uid) return c.json({ error: "Compte introuvable" }, 404);
    const stored = await kv.get(k.webauthnChallenge(`auth:${uid}`));
    if (!stored?.challenge) return c.json({ error: "Aucun défi en cours" }, 400);
    const creds = (await kv.get(k.webauthnCreds(uid))) ?? [];
    const cred = creds.find((c: any) => c.id === response.id);
    if (!cred) return c.json({ error: "Empreinte inconnue" }, 404);
    const { origin, rpID } = webauthnContext(c);
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: stored.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: cred.id,
        publicKey: b64urlDecode(cred.publicKey),
        counter: cred.counter,
        transports: cred.transports,
      },
      requireUserVerification: false,
    });
    if (!verification.verified) return c.json({ error: "Empreinte rejetée" }, 401);
    cred.counter = verification.authenticationInfo.newCounter;
    await kv.set(k.webauthnCreds(uid), creds);
    const profile = await kv.get(k.profile(uid));
    const { data, error: linkErr } = await admin.auth.admin.generateLink({
      type: "magiclink", email: profile.email,
    });
    if (linkErr) return c.json({ error: linkErr.message }, 500);
    await audit(uid, "auth.webauthn.login", { ip });
    return c.json({
      email: profile.email,
      tokenHash: data.properties?.hashed_token,
    });
  } catch (err) {
    console.log(`WebAuthn auth verify error: ${err}`);
    return c.json({ error: `Erreur de vérification biométrique: ${err}` }, 500);
  }
});

app.get(`${PREFIX}/auth/webauthn/status`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const creds = (await kv.get(k.webauthnCreds(user.id))) ?? [];
  return c.json({ count: creds.length, devices: creds.map((c: any) => ({ id: c.id, createdAt: c.createdAt })) });
});

app.delete(`${PREFIX}/auth/webauthn/:credId`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const credId = c.req.param("credId");
  const creds = ((await kv.get(k.webauthnCreds(user.id))) ?? []).filter((c: any) => c.id !== credId);
  await kv.set(k.webauthnCreds(user.id), creds);
  await audit(user.id, "auth.webauthn.remove", { credId });
  return c.json({ ok: true });
});

// ---- ADMIN ----
// Admin auth is fully isolated from user auth: credentials in env vars
// (ADMIN_USERNAME / ADMIN_PASSWORD), HMAC-signed session token, X-Admin-Token
// header. The Supabase users table is NEVER consulted for admin access.

app.post(`${PREFIX}/admin/login`, async (c) => {
  const ip = c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ?? "anon";
  const limited = await guardRate(c, `admin-login:${ip}`, 5, 600);
  if (limited) return limited;
  try {
    const body = await c.req.json().catch(() => ({}));
    const username = (body.username ?? "").toString().trim();
    const password = (body.password ?? "").toString();
    if (ADMIN_ACCOUNTS.length === 0) {
      return c.json({ error: "Back office non configuré: définissez ADMIN_USERNAME et ADMIN_PASSWORD (ou ADMIN_ACCOUNTS)." }, 503);
    }
    const acct = ADMIN_ACCOUNTS.find((a) => a.username === username && a.password === password);
    if (!acct) return c.json({ error: "Identifiants invalides" }, 401);

    if (acct.totpSecret) {
      const challengeExp = Math.floor(Date.now() / 1000) + 5 * 60;
      const challenge = await signToken({ kind: "admin-2fa", username: acct.username, role: acct.role, exp: challengeExp });
      return c.json({ requires2FA: true, challenge });
    }

    const exp = Math.floor(Date.now() / 1000) + ADMIN_TOKEN_TTL_SEC;
    const jti = crypto.randomUUID();
    const token = await signToken({ kind: "admin", username: acct.username, role: acct.role, iat: Math.floor(Date.now() / 1000), exp, jti });
    await persistAdminSession(c, jti, acct.username, acct.role, exp * 1000);
    await adminAudit(c, { username: acct.username, role: acct.role }, "login", { jti });
    return c.json({ token, username: acct.username, role: acct.role, expiresAt: exp * 1000 });
  } catch (err) {
    return safeError(c, err, "Erreur de connexion");
  }
});

app.post(`${PREFIX}/admin/login/2fa`, async (c) => {
  const ip = c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ?? "anon";
  const limited = await guardRate(c, `admin-2fa:${ip}`, 8, 600);
  if (limited) return limited;
  try {
    const body = await c.req.json().catch(() => ({}));
    const challenge = (body.challenge ?? "").toString();
    const code = (body.code ?? "").toString().trim();
    if (!challenge || !code) return c.json({ error: "Challenge ou code manquant" }, 400);
    const payload = await verifyToken<{ kind: string; username: string; role: string; exp: number }>(challenge);
    if (!payload || payload.kind !== "admin-2fa") return c.json({ error: "Challenge invalide" }, 401);
    if (Date.now() / 1000 > payload.exp) return c.json({ error: "Challenge expiré" }, 401);
    const acct = ADMIN_ACCOUNTS.find((a) => a.username === payload.username);
    if (!acct?.totpSecret) return c.json({ error: "Compte sans 2FA" }, 400);
    if (!(await verifyTotp(acct.totpSecret, code))) return c.json({ error: "Code invalide" }, 401);
    const exp = Math.floor(Date.now() / 1000) + ADMIN_TOKEN_TTL_SEC;
    const jti = crypto.randomUUID();
    const token = await signToken({ kind: "admin", username: acct.username, role: acct.role, iat: Math.floor(Date.now() / 1000), exp, jti });
    await persistAdminSession(c, jti, acct.username, acct.role, exp * 1000);
    await audit(`admin:${acct.username}`, "admin.login.2fa", { role: acct.role });
    await adminAudit(c, { username: acct.username, role: acct.role }, "login.2fa", { jti });
    return c.json({ token, username: acct.username, role: acct.role, expiresAt: exp * 1000 });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.get(`${PREFIX}/admin/check`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ admin: false, error: r.error }, r.status);
  return c.json({ admin: true, username: r.admin.username, role: r.admin.role });
});

app.get(`${PREFIX}/admin/claims`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "claims:%");
    if (error) return c.json({ error: error.message }, 500);
    const flat: any[] = [];
    for (const row of data ?? []) {
      const uid = (row.key as string).slice("claims:".length);
      const profile = (await kv.get(k.profile(uid))) ?? {};
      for (const cl of (row.value ?? []) as any[]) {
        const attachments = await Promise.all(
          (cl.attachments ?? []).map(async (a: any) => {
            if (!a?.path) return a;
            const { data: signed, error: sErr } = await admin.storage
              .from(BUCKET)
              .createSignedUrl(a.path, 300);
            return { ...a, url: sErr ? null : signed.signedUrl };
          }),
        );
        flat.push({
          ...cl,
          attachments,
          userId: uid,
          userEmail: profile.email ?? "",
          userName: profile.name ?? "",
          memberNumber: profile.memberNumber ?? "",
        });
      }
    }
    flat.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    return c.json({ claims: flat });
  } catch (err) {
    console.log(`Admin claims list error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

app.post(`${PREFIX}/admin/claims/bulk-status`, async (c) => {
  const g = await requireAdmin(c);
  if ("response" in g) return g.response;
  const r = { admin: g.admin };
  try {
    const body = await c.req.json().catch(() => ({}));
    const status = body.status as string;
    const note = ((body.note as string) ?? "").trim();
    const items = Array.isArray(body.items) ? body.items : [];
    if (!["en_cours", "valide", "rejete", "regle"].includes(status)) {
      return c.json({ error: "Statut invalide" }, 400);
    }
    if (status === "rejete" && note.length < 3) {
      return c.json({ error: "Un motif d'au moins 3 caractères est requis pour rejeter" }, 400);
    }
    if (items.length === 0) return c.json({ error: "Aucun sinistre sélectionné" }, 400);
    if (items.length > 200) return c.json({ error: "Trop de sinistres (max 200)" }, 400);

    const byUser = new Map<string, Set<string>>();
    for (const it of items) {
      if (!it?.userId || !it?.claimId) continue;
      if (!byUser.has(it.userId)) byUser.set(it.userId, new Set());
      byUser.get(it.userId)!.add(it.claimId);
    }

    let updated = 0;
    const errors: { userId: string; claimId: string; error: string }[] = [];
    const label = status === "valide" ? "validé" : status === "rejete" ? "rejeté" : status === "regle" ? "réglé" : "mis à jour";
    const decidedAt = new Date().toISOString();

    for (const [userId, claimIds] of byUser) {
      try {
        const claims = ((await kv.get(k.claims(userId))) ?? []) as any[];
        let touched = false;
        const changed: any[] = [];
        for (let i = 0; i < claims.length; i++) {
          if (claimIds.has(claims[i].id)) {
            claims[i] = { ...claims[i], status, adminNote: note || claims[i].adminNote, decidedAt, decidedBy: r.admin.username };
            changed.push(claims[i]);
            touched = true;
            updated++;
          }
        }
        if (!touched) continue;
        await kv.set(k.claims(userId), claims);
        const notifs = ((await kv.get(k.notifications(userId))) ?? []) as any[];
        for (const cl of changed) {
          await notifyAndDispatch(userId, notifs, {
            typeKey: "claim",
            title: "Sinistre " + label,
            body: `Votre sinistre « ${cl.type} » a été ${label}.`,
            severity: status === "rejete" ? "warn" : "success",
            to: "/espace-client/sinistres",
          });
          await audit(userId, "admin.claim.status", { claimId: cl.id, status, by: r.admin.username, bulk: true });
        }
      } catch (err) {
        errors.push({ userId, claimId: Array.from(claimIds).join(","), error: String(err) });
      }
    }
    await adminAudit(c, r.admin, "claim.bulk_status", { status, count: updated, errors: errors.length });
    return c.json({ updated, errors });
  } catch (err) {
    console.log(`Admin bulk claim status error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

app.post(`${PREFIX}/admin/claims/:userId/:claimId/status`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const userId = c.req.param("userId");
  const claimId = c.req.param("claimId");
  try {
    const body = await c.req.json().catch(() => ({}));
    const status = body.status as string;
    const note = (body.note as string) ?? "";
    if (!["en_cours", "valide", "rejete", "regle"].includes(status)) {
      return c.json({ error: "Statut invalide" }, 400);
    }
    if (status === "rejete" && note.trim().length < 3) {
      return c.json({ error: "Un motif d'au moins 3 caractères est requis pour rejeter un sinistre" }, 400);
    }
    const claims = (await kv.get(k.claims(userId))) ?? [];
    const idx = claims.findIndex((cl: any) => cl.id === claimId);
    if (idx === -1) return c.json({ error: "Sinistre introuvable" }, 404);
    claims[idx] = { ...claims[idx], status, adminNote: note, decidedAt: new Date().toISOString(), decidedBy: r.admin.username };
    await kv.set(k.claims(userId), claims);
    const notifs = (await kv.get(k.notifications(userId))) ?? [];
    const label = status === "valide" ? "validé" : status === "rejete" ? "rejeté" : status === "regle" ? "réglé" : "mis à jour";
    await notifyAndDispatch(userId, notifs, {
      typeKey: "claim",
      title: "Sinistre " + label,
      body: `Votre sinistre « ${claims[idx].type} » a été ${label}.`,
      severity: status === "rejete" ? "warn" : "success",
      to: "/espace-client/sinistres",
    });
    await audit(userId, "admin.claim.status", { claimId, status, by: r.admin.username });
    await adminAudit(c, r.admin, "claim.status", { userId, claimId, status });
    // A6 — Si le sinistre est porté par un conseiller, le prévenir aussi
    // (push + broadcast inbox) pour qu'il voie la décision admin sans
    // recharger sa console.
    const assignee = claims[idx].assignedTo as string | undefined;
    if (assignee) {
      const agentUid = await kv.get(`agent:matricule-claim:${assignee}`);
      if (typeof agentUid === "string") {
        const labelTxt = status === "valide" ? "validé" : status === "rejete" ? "rejeté" : status === "regle" ? "réglé" : "mis à jour";
        pushUsers([agentUid], {
          title: `Sinistre ${labelTxt}`,
          body: `Décision admin sur « ${claims[idx].type} ».`,
          url: `/agent/sinistres`,
          tag: `claim:${claimId}`,
        }).catch(() => { /* best-effort */ });
      }
      broadcast("agent:inbox", "claim:decision", {
        claimId, userId, to: assignee, status, by: r.admin.username,
        at: new Date().toISOString(),
      }).catch(() => { /* best-effort */ });
    }
    return c.json({ claim: claims[idx] });
  } catch (err) {
    console.log(`Admin claim update error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

app.get(`${PREFIX}/admin/stats`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const [profilesRes, claimsRes, paymentsRes, contractsRes, kycRes, presenceRes] = await Promise.all([
      admin.from("kv_store_752d1a39").select("key, value").like("key", "profile:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "claims:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "payments:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "contracts:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "kyc:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "agent:presence:%"),
    ]);

    const DAYS = 30;
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const dayKey = (d: Date) => d.toISOString().slice(0, 10);
    const dayList: string[] = [];
    for (let i = DAYS - 1; i >= 0; i--) {
      const d = new Date(today); d.setDate(today.getDate() - i);
      dayList.push(dayKey(d));
    }
    const revenueByDay: Record<string, number> = Object.fromEntries(dayList.map((k) => [k, 0]));
    const signupsByDay: Record<string, number> = Object.fromEntries(dayList.map((k) => [k, 0]));

    let totalUsers = 0;
    const membersByDept: Record<string, number> = {};
    for (const row of profilesRes.data ?? []) {
      const p = (row.value ?? {}) as any;
      totalUsers++;
      const dept = (p.department ?? "Non renseigné").toString();
      membersByDept[dept] = (membersByDept[dept] ?? 0) + 1;
      const ca = p.createdAt ?? p.signupAt;
      if (ca && typeof ca === "string") {
        const k = ca.slice(0, 10);
        if (k in signupsByDay) signupsByDay[k]++;
      }
    }

    const claimsByStatus: Record<string, number> = {};
    let totalClaims = 0, pendingClaims = 0;
    for (const row of claimsRes.data ?? []) for (const cl of (row.value ?? []) as any[]) {
      totalClaims++;
      const s = cl.status ?? "inconnu";
      claimsByStatus[s] = (claimsByStatus[s] ?? 0) + 1;
      if (s === "en_cours" || s === "soumis" || s === "en_examen") pendingClaims++;
    }

    let confirmedTotal = 0;
    let last24h = 0;
    const since24 = Date.now() - 24 * 3600 * 1000;
    const revenueByMethod: Record<string, number> = {};
    for (const row of paymentsRes.data ?? []) for (const p of (row.value ?? []) as any[]) {
      if (p.status !== "confirme") continue;
      const amt = p.amount ?? 0;
      confirmedTotal += amt;
      const m = (p.method ?? "autre").toString();
      revenueByMethod[m] = (revenueByMethod[m] ?? 0) + amt;
      const t = new Date(p.createdAt ?? Date.now()).getTime();
      if (t >= since24) last24h += amt;
      const k = (p.createdAt ?? "").slice(0, 10);
      if (k in revenueByDay) revenueByDay[k] += amt;
    }

    const productMix: Record<string, number> = {};
    let contractsActive = 0;
    for (const row of contractsRes.data ?? []) for (const ct of (row.value ?? []) as any[]) {
      if (ct.status === "active") contractsActive++;
      const p = (ct.product ?? "Autre").toString();
      productMix[p] = (productMix[p] ?? 0) + 1;
    }

    // ---- ALERTES OPÉRATIONNELLES (F26) ----
    const now = Date.now();
    let paymentsStale2d = 0;
    for (const row of paymentsRes.data ?? []) for (const p of (row.value ?? []) as any[]) {
      if (p.status !== "pending" && p.status !== "failed" && p.status !== "echec") continue;
      const t = new Date(p.createdAt ?? p.at ?? 0).getTime();
      if (!t) continue;
      if (now - t > 2 * 86400_000) paymentsStale2d++;
    }
    let claimsStale48h = 0;
    for (const row of claimsRes.data ?? []) for (const cl of (row.value ?? []) as any[]) {
      const s = cl.status ?? "";
      if (s !== "en_cours" && s !== "soumis" && s !== "en_examen") continue;
      const t = new Date(cl.createdAt ?? 0).getTime();
      if (!t) continue;
      if (now - t > 48 * 3600_000) claimsStale48h++;
    }
    let kycStale24h = 0;
    for (const row of kycRes.data ?? []) {
      const cur = (row.value ?? {} as any).current;
      if (!cur || cur.status !== "pending") continue;
      const t = new Date(cur.createdAt ?? 0).getTime();
      if (!t) continue;
      if (now - t > 24 * 3600_000) kycStale24h++;
    }
    let agentsOffline4h = 0;
    for (const row of presenceRes.data ?? []) {
      const p = (row.value ?? {}) as any;
      const status = p.status ?? "offline";
      if (status === "online") continue;
      const t = new Date(p.at ?? 0).getTime();
      if (!t) continue;
      if (now - t > 4 * 3600_000) agentsOffline4h++;
    }

    return c.json({
      users: totalUsers,
      contractsActive,
      claims: { total: totalClaims, pending: pendingClaims },
      revenue: confirmedTotal,
      revenueLast24h: last24h,
      timeseries: {
        days: dayList,
        revenue: dayList.map((k) => revenueByDay[k]),
        signups: dayList.map((k) => signupsByDay[k]),
      },
      breakdown: {
        claimsByStatus,
        revenueByMethod,
        productMix,
        membersByDept,
      },
      alerts: {
        paymentsStale2d,
        claimsStale48h,
        kycStale24h,
        agentsOffline4h,
      },
    });
  } catch (err) {
    console.log(`Admin stats error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: MEMBERS ----
app.get(`${PREFIX}/admin/members`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "profile:%");
    if (error) return c.json({ error: error.message }, 500);
    const members: any[] = [];
    for (const row of data ?? []) {
      const uid = (row.key as string).slice("profile:".length);
      const p = (row.value ?? {}) as any;
      const [contracts, claims, payments] = await Promise.all([
        kv.get(k.contracts(uid)).then((v) => (v ?? []) as any[]),
        kv.get(k.claims(uid)).then((v) => (v ?? []) as any[]),
        kv.get(k.payments(uid)).then((v) => (v ?? []) as any[]),
      ]);
      const activeContracts = contracts.filter((c: any) => c.status === "active").length;
      const pendingClaims = claims.filter((c: any) => c.status === "en_cours").length;
      const revenue = payments
        .filter((p: any) => p.status === "confirme")
        .reduce((s: number, p: any) => s + (p.amount ?? 0), 0);
      members.push({
        id: uid,
        email: p.email ?? "",
        name: p.name ?? "",
        phone: p.phone ?? "",
        memberNumber: p.memberNumber ?? "",
        createdAt: p.createdAt ?? null,
        suspended: !!p.suspended,
        activeContracts,
        pendingClaims,
        revenue,
        enrolledBy: p.enrolledBy ?? null,
        enrolledAt: p.enrolledAt ?? null,
        enrolledSource: p.enrolledSource ?? null,
      });
    }
    members.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    return c.json({ members });
  } catch (err) {
    console.log(`Admin members list error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

app.get(`${PREFIX}/admin/member/:uid`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  try {
    const [profile, contracts, claims, payments, beneficiaries, notifications, settings, auditLog, documents] = await Promise.all([
      kv.get(k.profile(uid)),
      kv.get(k.contracts(uid)),
      kv.get(k.claims(uid)),
      kv.get(k.payments(uid)),
      kv.get(k.beneficiaries(uid)),
      kv.get(k.notifications(uid)),
      kv.get(k.settings(uid)),
      kv.get(k.audit(uid)),
      kv.get(k.documents(uid)),
    ]);
    if (!profile) return c.json({ error: "Membre introuvable" }, 404);
    return c.json({
      profile,
      contracts: contracts ?? [],
      claims: claims ?? [],
      payments: payments ?? [],
      beneficiaries: beneficiaries ?? [],
      notifications: notifications ?? [],
      settings: settings ?? null,
      audit: (auditLog ?? []).slice(0, 50),
      documents: documents ?? [],
    });
  } catch (err) {
    console.log(`Admin member detail error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

app.get(`${PREFIX}/admin/member/:uid/export`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  try {
    const [profile, contracts, claims, payments, beneficiaries] = await Promise.all([
      kv.get(k.profile(uid)),
      kv.get(k.contracts(uid)),
      kv.get(k.claims(uid)),
      kv.get(k.payments(uid)),
      kv.get(k.beneficiaries(uid)),
    ]);
    if (!profile) return c.json({ error: "Membre introuvable" }, 404);
    const dump = { profile, contracts: contracts ?? [], claims: claims ?? [], payments: payments ?? [], beneficiaries: beneficiaries ?? [], exportedAt: new Date().toISOString(), exportedBy: r.admin.username };
    audit(uid, "admin.export_member", { by: r.admin.username });
    adminAudit(c, r.admin, "member.export", { uid });
    return new Response(JSON.stringify(dump, null, 2), {
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Disposition": `attachment; filename="ippoo-member-${uid}-${new Date().toISOString().slice(0, 10)}.json"`,
      },
    });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.post(`${PREFIX}/admin/member/:uid/suspend`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  try {
    const body = await c.req.json().catch(() => ({}));
    const suspended = !!body.suspended;
    const reason = String(body.reason ?? "").trim().slice(0, 400);
    // Suspension : motif obligatoire (audit/conformité). La réactivation peut
    // se faire sans motif — on conserve seulement l'historique.
    if (suspended && reason.length < 3) {
      return c.json({ error: "Motif requis pour suspendre un membre (3 caractères minimum)." }, 400);
    }
    const p = (await kv.get(k.profile(uid))) ?? {};
    p.suspended = suspended;
    p.suspension = suspended
      ? { reason, by: r.admin.username, at: new Date().toISOString() }
      : null;
    await kv.set(k.profile(uid), p);
    await audit(uid, "admin.member.suspend", { suspended, by: r.admin.username, reason: reason || undefined });
    await adminAudit(c, r.admin, "member.suspend", { uid, suspended, reason: reason || undefined });
    return c.json({ ok: true, suspended, suspension: p.suspension });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: CONTRACTS (flat) ----
app.get(`${PREFIX}/admin/contracts`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "contracts:%");
    if (error) return c.json({ error: error.message }, 500);
    const flat: any[] = [];
    for (const row of data ?? []) {
      const uid = (row.key as string).slice("contracts:".length);
      const profile = (await kv.get(k.profile(uid))) ?? {};
      for (const ct of (row.value ?? []) as any[]) {
        flat.push({
          ...ct,
          userId: uid,
          userEmail: profile.email ?? "",
          userName: profile.name ?? "",
        });
      }
    }
    flat.sort((a, b) => (a.startDate < b.startDate ? 1 : -1));
    return c.json({ contracts: flat });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: toggle autoDebit on a member contract (F29) ----
// Permet à l'admin de forcer (dés)activer le prélèvement automatique pour un
// contrat client — utile sur demande client (téléphone, e-mail) sans avoir à
// se connecter à son compte. Trace dans l'audit utilisateur + ring admin.
app.patch(`${PREFIX}/admin/contracts/:userId/:id/auto-debit`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const userId = c.req.param("userId");
  const id = c.req.param("id");
  try {
    const body = await c.req.json().catch(() => ({}));
    const enabled = !!body?.enabled;
    const contracts = ((await kv.get(k.contracts(userId))) ?? []) as any[];
    const idx = contracts.findIndex((ct: any) => ct.id === id);
    if (idx === -1) return c.json({ error: "Contrat introuvable" }, 404);
    const before = contracts[idx].autoDebit !== false;
    if (before === enabled) return c.json({ contract: contracts[idx], unchanged: true });
    contracts[idx] = {
      ...contracts[idx],
      autoDebit: enabled,
      nextBillingDate: enabled ? (contracts[idx].nextBillingDate ?? nextBillingFromNow()) : null,
    };
    await kv.set(k.contracts(userId), contracts);
    await audit(userId, "contract.autoDebit.adminToggle", { id, enabled, by: r.admin.username });
    await adminAudit(r.admin.username, "admin.contract.autoDebit", { userId, contractId: id, enabled });
    return c.json({ contract: contracts[idx] });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: PAYMENTS (flat) ----
// Paginated cross-user payments listing. Cursor is `before` = the createdAt
// of the last item from the previous page (exclusive). We flatten in-memory
// (no per-user payments index exists in the KV) but batch profile lookups
// via mget instead of one-per-user. Returns at most `limit` rows (default
// 100, max 500) and a `nextBefore` cursor when more are available.
async function listAllPaymentsPaginated(opts: { limit: number; before?: string; includeMemberNumber?: boolean; allowUids?: Set<string> }) {
  const limit = Math.min(Math.max(opts.limit, 1), 500);
  const { data: dataRaw, error } = await admin
    .from("kv_store_752d1a39")
    .select("key, value")
    .like("key", "payments:%");
  if (error) throw new Error(error.message);
  const data = opts.allowUids
    ? (dataRaw ?? []).filter((row) => opts.allowUids!.has((row.key as string).slice("payments:".length)))
    : (dataRaw ?? []);
  const uids = data.map((row) => (row.key as string).slice("payments:".length));
  const profiles = uids.length ? await kv.mget(uids.map((u) => k.profile(u))) : [];
  const profileByUid: Record<string, any> = {};
  uids.forEach((u, i) => (profileByUid[u] = profiles[i] ?? {}));
  const flat: any[] = [];
  for (const row of data) {
    const uid = (row.key as string).slice("payments:".length);
    const profile = profileByUid[uid] ?? {};
    for (const p of (row.value ?? []) as any[]) {
      flat.push({
        ...p,
        userId: uid,
        userEmail: profile.email ?? "",
        userName: profile.name ?? "",
        ...(opts.includeMemberNumber ? { memberNumber: profile.memberNumber ?? "" } : {}),
      });
    }
  }
  // Tie-safe cursor : `<createdAt>|<id>` (lexicographic). createdAt seul ne
  // suffit pas — deux paiements peuvent partager la même milliseconde, et un
  // filtre `< before` strict ferait sauter tout le groupe. On compare donc le
  // couple, ce qui garantit qu'on reprend exactement après le dernier item de
  // la page précédente, ni avant, ni après.
  const cursorOf = (p: any) => `${p.createdAt}|${p.id ?? ""}`;
  flat.sort((a, b) => {
    const ca = cursorOf(a), cb = cursorOf(b);
    return ca < cb ? 1 : ca > cb ? -1 : 0;
  });
  const filtered = opts.before ? flat.filter((p) => cursorOf(p) < opts.before!) : flat;
  const page = filtered.slice(0, limit);
  const nextBefore = filtered.length > limit ? cursorOf(page[page.length - 1]) : null;
  return { payments: page, nextBefore, total: flat.length };
}

app.get(`${PREFIX}/admin/payments`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const limit = parseInt(c.req.query("limit") ?? "100", 10);
    const before = c.req.query("before") ?? undefined;
    const withStats = c.req.query("stats") === "1";
    const res = await listAllPaymentsPaginated({ limit: isNaN(limit) ? 100 : limit, before });
    if (!withStats) return c.json(res);
    // Mini-stats par conseiller (matricule) : combien de paiements appartiennent
    // à chaque portefeuille. On joint conv:meta:* (assignee) avec payments:%.
    try {
      const [{ data: metaRows }, { data: payRows }] = await Promise.all([
        admin.from("kv_store_752d1a39").select("key, value").like("key", "conv:meta:%"),
        admin.from("kv_store_752d1a39").select("key, value").like("key", "payments:%"),
      ]);
      const uidToAssignee = new Map<string, string>();
      for (const row of metaRows ?? []) {
        const uid = (row.key as string).slice("conv:meta:".length);
        const ass = (row.value as any)?.assignee;
        if (ass) uidToAssignee.set(uid, ass);
      }
      const byAgent: Record<string, number> = {};
      let unassigned = 0;
      for (const row of payRows ?? []) {
        const uid = (row.key as string).slice("payments:".length);
        const cnt = ((row.value ?? []) as any[]).length;
        const ass = uidToAssignee.get(uid);
        if (ass) byAgent[ass] = (byAgent[ass] ?? 0) + cnt;
        else unassigned += cnt;
      }
      const perAgent = Object.entries(byAgent)
        .map(([matricule, count]) => ({ matricule, count }))
        .sort((a, b) => b.count - a.count);
      return c.json({ ...res, stats: { perAgent, unassigned } });
    } catch {
      return c.json(res);
    }
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: BROADCAST ----
app.post(`${PREFIX}/admin/broadcast`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  const r = { admin: g.admin };
  try {
    const body = await c.req.json();
    const title = (body.title ?? "").toString().trim();
    const text = (body.body ?? "").toString().trim();
    const type = ["info", "success", "warn"].includes(body.type) ? body.type : "info";
    const channels = Array.isArray(body.channels) && body.channels.length
      ? body.channels.filter((ch: string) => ["in_app", "push", "email", "sms"].includes(ch))
      : ["in_app"];
    const audience = body.audience ?? { kind: "all" };
    if (!title || !text) return c.json({ error: "Titre et message requis" }, 400);

    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key")
      .like("key", "profile:%");
    if (error) return c.json({ error: error.message }, 500);

    const targets: { uid: string; profile: any }[] = [];
    for (const row of data ?? []) {
      const uid = (row.key as string).slice("profile:".length);
      const p = (await kv.get(k.profile(uid))) as any;
      if (!p) continue;
      if (audience.kind === "department" && audience.value && p.department !== audience.value) continue;
      if (audience.kind === "profileType" && audience.value && p.type !== audience.value) continue;
      if (audience.kind === "sousProfil" && audience.value) {
        const list = Array.isArray(p.sousProfil) ? p.sousProfil : [];
        if (!list.includes(audience.value)) continue;
      }
      if (audience.kind === "couverture" && audience.value) {
        const list = Array.isArray(p.couverture) ? p.couverture : [];
        if (!list.includes(audience.value)) continue;
      }
      if (audience.kind === "active") {
        const contracts = ((await kv.get(k.contracts(uid))) ?? []) as any[];
        if (!contracts.some((c) => c.status === "actif")) continue;
      }
      targets.push({ uid, profile: p });
    }

    const stats = {
      in_app: 0, push: 0, email: 0, sms: 0,
      opted_out: 0,
      no_phone: 0, no_email: 0,
      sms_failed: 0, email_failed: 0, push_failed: 0,
    };
    const html = `<div style="font-family:system-ui,sans-serif;max-width:560px;margin:auto;padding:24px;"><h2 style="color:#0E1320">${title}</h2><p style="color:#333;line-height:1.55;white-space:pre-wrap">${text.replace(/[<>]/g, "")}</p><hr style="border:none;border-top:1px solid #eee;margin:24px 0"><p style="color:#888;font-size:12px">IPPOO ASSURANCE — Cotonou, Bénin · Gérez vos préférences depuis Paramètres &gt; Préférences avancées.</p></div>`;
    const sms = `${title}\n${text}`.slice(0, 320);
    const tag = `broadcast:${Date.now()}`;

    // Per-user fan-out so each user's notifPrefs (channel matrix + opt-out on
    // the "broadcast" type) is honoured. Admin choice in `channels` still
    // restricts the maximum reach, but a user can mute any of them.
    for (const { uid, profile } of targets) {
      const prefs = await getNotifPrefs(uid);
      if (prefs.types.broadcast === false) { stats.opted_out++; continue; }
      if (channels.includes("in_app") && prefs.channels.in_app !== false) {
        const notifs = (await kv.get(k.notifications(uid))) ?? [];
        await setNotifications(uid, notify(notifs, title, text, type));
        stats.in_app++;
      }
      if (channels.includes("push") && prefs.channels.push !== false) {
        const res = await pushUsers([uid], { title, body: text, url: "/espace-client/notifications", tag });
        const sent = (res as any)?.sent ?? 0;
        stats.push += sent;
        if (sent === 0) stats.push_failed++;
      }
      if (channels.includes("email") && prefs.channels.email !== false && RESEND_KEY) {
        if (!profile.email) stats.no_email++;
        else if (await sendEmail(profile.email, title, html)) stats.email++;
        else stats.email_failed++;
      }
      if (channels.includes("sms") && prefs.channels.sms !== false && TERMII_KEY) {
        if (!profile.phone) stats.no_phone++;
        else if (await sendSms(profile.phone, sms)) stats.sms++;
        else stats.sms_failed++;
      }
    }

    const history = ((await kv.get(k.broadcastHistory())) ?? []) as any[];
    const entry = {
      id: crypto.randomUUID(), title, body: text, type, channels, audience,
      stats, recipients: targets.length, at: new Date().toISOString(),
      by: r.admin.username,
    };
    await kv.set(k.broadcastHistory(), [entry, ...history].slice(0, 100));

    await audit(`admin:${r.admin.username}`, "admin.broadcast", { title, channels, recipients: targets.length, stats });
    await adminAudit(c, r.admin, "broadcast", { title, channels, recipients: targets.length, stats });
    return c.json({ ok: true, recipients: targets.length, stats });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.get(`${PREFIX}/admin/broadcast/history`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const history = ((await kv.get(k.broadcastHistory())) ?? []) as any[];
  return c.json({
    entries: history,
    channels: {
      in_app: true,
      push: !!(VAPID_PUBLIC && VAPID_PRIVATE),
      email: !!RESEND_KEY,
      sms: !!TERMII_KEY,
    },
  });
});

app.get(`${PREFIX}/admin/broadcast/audience`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const { data } = await admin.from("kv_store_752d1a39").select("key").like("key", "profile:%");
  const total = (data ?? []).length;
  const byDept: Record<string, number> = {};
  const byProfileType: Record<string, number> = {};
  const bySousProfil: Record<string, number> = {};
  const byCouverture: Record<string, number> = {};
  let active = 0;
  for (const row of data ?? []) {
    const uid = (row.key as string).slice("profile:".length);
    const p = (await kv.get(k.profile(uid))) as any;
    if (p?.department) byDept[p.department] = (byDept[p.department] ?? 0) + 1;
    if (p?.type) byProfileType[p.type] = (byProfileType[p.type] ?? 0) + 1;
    if (Array.isArray(p?.sousProfil)) {
      for (const sp of p.sousProfil) bySousProfil[sp] = (bySousProfil[sp] ?? 0) + 1;
    }
    if (Array.isArray(p?.couverture)) {
      for (const cv of p.couverture) byCouverture[cv] = (byCouverture[cv] ?? 0) + 1;
    }
    const contracts = ((await kv.get(k.contracts(uid))) ?? []) as any[];
    if (contracts.some((c) => c.status === "actif")) active++;
  }
  return c.json({ total, active, byDepartment: byDept, byProfileType, bySousProfil, byCouverture });
});

// ---- SITE CONTENT (public read + admin update) ----
const DEFAULT_SITE = {
  brandName: "IPPOO ASSURANCE",
  tagline: "La micro-assurance qui prend soin de vous au Bénin",
  heroTitle: "Protégez ce qui compte vraiment",
  heroSubtitle: "Souscrivez en 2 minutes à une couverture sur mesure, payable en Mobile Money à partir de 500 FCFA par jour.",
  aboutShort: "IPPOO ASSURANCE est une mutuelle de micro-assurance enregistrée au Bénin, dédiée aux familles, commerçants et professionnels.",
  contactEmail: "ippooz.up.2@gmail.com",
  contactPhone: "+229 01 41 52 10 92",
  contactAddress: "Parakou, Borgou, Bénin",
  whatsapp: "+229 01 41 52 10 92",
  facebook: "",
  instagram: "",
  linkedin: "",
};

app.get(`${PREFIX}/site`, async (c) => {
  const site = (await kv.get(k.site())) ?? DEFAULT_SITE;
  return c.json({ site: { ...DEFAULT_SITE, ...site } });
});

app.put(`${PREFIX}/admin/site`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  const r = { admin: g.admin };
  try {
    const body = await c.req.json();
    const current = (await kv.get(k.site())) ?? DEFAULT_SITE;
    const allow = [
      "brandName", "tagline", "heroTitle", "heroSubtitle", "aboutShort",
      "contactEmail", "contactPhone", "contactAddress", "whatsapp",
      "facebook", "instagram", "linkedin",
    ];
    const next: Record<string, string> = { ...current };
    for (const key of allow) {
      if (typeof body?.[key] === "string") next[key] = body[key].slice(0, 600);
    }
    await kv.set(k.site(), next);
    await audit(`admin:${r.admin.username}`, "admin.site.update", { count: Object.keys(body ?? {}).length });
    await adminAudit(c, r.admin, "site.update", { count: Object.keys(body ?? {}).length });
    return c.json({ ok: true, site: next });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- PARTNERS (public read + admin CRUD) ----
const DEFAULT_PARTNERS = [
  { id: "p1", name: "Clinique Atinkanmey", kind: "clinique", address: "Carré 1234, Atinkanmey", city: "Cotonou", phone: "+229 21 30 12 34", lat: 6.3654, lng: 2.4183, hours: "24/7" },
  { id: "p2", name: "Pharmacie Camp Guézo", kind: "pharmacie", address: "Boulevard Saint-Michel", city: "Cotonou", phone: "+229 21 31 45 67", lat: 6.3725, lng: 2.4248, hours: "8h–22h" },
  { id: "p3", name: "Hôpital de la Mère et de l'Enfant", kind: "hopital", address: "Lagune de Cotonou", city: "Cotonou", phone: "+229 21 33 22 11", lat: 6.3568, lng: 2.4290, hours: "24/7" },
  { id: "p4", name: "Pharmacie Sainte-Rita", kind: "pharmacie", address: "Avenue Steinmetz", city: "Cotonou", phone: "+229 21 32 78 90", lat: 6.3601, lng: 2.4079, hours: "7h–23h" },
  { id: "p5", name: "Clinique Mahouna", kind: "clinique", address: "Quartier Akpakpa", city: "Cotonou", phone: "+229 21 33 56 78", lat: 6.3712, lng: 2.4501, hours: "24/7" },
  { id: "p6", name: "Pharmacie Notre-Dame", kind: "pharmacie", address: "Place Catchi", city: "Porto-Novo", phone: "+229 20 21 33 44", lat: 6.4969, lng: 2.6289, hours: "8h–21h" },
  { id: "p7", name: "Centre Hospitalier Porto-Novo", kind: "hopital", address: "Avenue Jean-Bayol", city: "Porto-Novo", phone: "+229 20 21 56 78", lat: 6.4895, lng: 2.6080, hours: "24/7" },
  { id: "p8", name: "Pharmacie Jéricho", kind: "pharmacie", address: "Quartier Jéricho", city: "Cotonou", phone: "+229 21 30 88 99", lat: 6.3611, lng: 2.3950, hours: "7h–22h" },
  { id: "p9", name: "Clinique Bouge", kind: "clinique", address: "Route de l'aéroport", city: "Cotonou", phone: "+229 21 30 44 55", lat: 6.3528, lng: 2.3848, hours: "24/7" },
  { id: "p10", name: "Pharmacie Tokpa", kind: "pharmacie", address: "Marché Dantokpa", city: "Cotonou", phone: "+229 21 32 11 22", lat: 6.3680, lng: 2.4350, hours: "6h–20h" },
];

app.get(`${PREFIX}/partners`, async (c) => {
  const partners = (await kv.get(k.partners())) ?? DEFAULT_PARTNERS;
  return c.json({ partners });
});

app.put(`${PREFIX}/admin/partners`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  const r = { admin: g.admin };
  try {
    const body = await c.req.json();
    const raw = Array.isArray(body?.partners) ? body.partners : [];
    if (raw.length > 200) return c.json({ error: "Maximum 200 partenaires." }, 400);
    const errors: { index: number; field: string; message: string }[] = [];
    const seenIds = new Set<string>();
    const partners: any[] = [];
    raw.forEach((p: any, i: number) => {
      const name = String(p?.name ?? "").trim();
      const kind = String(p?.kind ?? "");
      const address = String(p?.address ?? "").trim();
      const city = String(p?.city ?? "").trim();
      const phone = String(p?.phone ?? "").trim();
      const lat = Number(p?.lat);
      const lng = Number(p?.lng);
      if (!name) errors.push({ index: i, field: "name", message: "Nom requis" });
      if (name.length > 160) errors.push({ index: i, field: "name", message: "Nom > 160 caractères" });
      if (!["clinique", "pharmacie", "hopital"].includes(kind)) errors.push({ index: i, field: "kind", message: "Type invalide (clinique | pharmacie | hopital)" });
      if (!city) errors.push({ index: i, field: "city", message: "Ville requise" });
      if (phone && !/^[+0-9 ().-]{6,30}$/.test(phone)) errors.push({ index: i, field: "phone", message: "Téléphone invalide" });
      if (!Number.isFinite(lat) || lat < -90 || lat > 90) errors.push({ index: i, field: "lat", message: "Latitude hors plage [-90, 90]" });
      if (!Number.isFinite(lng) || lng < -180 || lng > 180) errors.push({ index: i, field: "lng", message: "Longitude hors plage [-180, 180]" });
      const id = typeof p?.id === "string" && p.id ? p.id.slice(0, 40) : `pt_${Date.now()}_${i}`;
      if (seenIds.has(id)) errors.push({ index: i, field: "id", message: `Identifiant en doublon : ${id}` });
      seenIds.add(id);
      partners.push({
        id, name, kind, address: address.slice(0, 200), city: city.slice(0, 80), phone,
        lat: Number.isFinite(lat) ? lat : 0,
        lng: Number.isFinite(lng) ? lng : 0,
        hours: String(p?.hours ?? "").slice(0, 40),
      });
    });
    if (errors.length > 0) return c.json({ error: "Validation échouée", errors }, 400);
    await kv.set(k.partners(), partners);
    await audit(`admin:${r.admin.username}`, "admin.partners.update", { count: partners.length });
    await adminAudit(c, r.admin, "partners.update", { count: partners.length });
    return c.json({ ok: true, partners });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- PROMOS (public read + admin CRUD) ----
app.get(`${PREFIX}/promos`, async (c) => {
  const promos = (await kv.get(k.promos())) ?? [];
  return c.json({ promos });
});

app.put(`${PREFIX}/admin/promos`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  const r = { admin: g.admin };
  try {
    const body = await c.req.json();
    const raw = Array.isArray(body?.promos) ? body.promos : [];
    if (raw.length > 20) return c.json({ error: "Maximum 20 promos." }, 400);
    const errors: { index: number; field: string; message: string }[] = [];
    const seenIds = new Set<string>();
    const isHttpUrl = (s: string) => { try { const u = new URL(s); return u.protocol === "https:" || u.protocol === "http:"; } catch { return false; } };
    const isInternalPath = (s: string) => s.startsWith("/") && !s.startsWith("//");
    const promos: any[] = [];
    raw.forEach((p: any, i: number) => {
      const image = String(p?.image ?? "").trim();
      const alt = String(p?.alt ?? "").trim();
      const to = String(p?.to ?? "").trim();
      const title = String(p?.title ?? "").trim();
      const description = String(p?.description ?? "").trim();
      const ctaLabel = String(p?.ctaLabel ?? "").trim();
      const themeRaw = String(p?.theme ?? "dark").trim().toLowerCase();
      const theme = themeRaw === "light" ? "light" : "dark";
      if (!image) errors.push({ index: i, field: "image", message: "Image requise" });
      else if (image.length > 2000) errors.push({ index: i, field: "image", message: "URL image > 2000 caractères" });
      else if (!isHttpUrl(image) && !image.startsWith("data:image/") && !isInternalPath(image)) errors.push({ index: i, field: "image", message: "Image doit être une URL http(s), un chemin /asset ou data:image/" });
      if (!alt) errors.push({ index: i, field: "alt", message: "Texte alternatif requis (accessibilité)" });
      if (to && to.length > 200) errors.push({ index: i, field: "to", message: "URL > 200 caractères" });
      if (to && !isHttpUrl(to) && !isInternalPath(to)) errors.push({ index: i, field: "to", message: "Lien doit être une URL http(s) ou un chemin interne (/...)" });
      if (title.length > 120) errors.push({ index: i, field: "title", message: "Titre > 120 caractères" });
      if (description.length > 280) errors.push({ index: i, field: "description", message: "Description > 280 caractères" });
      if (ctaLabel.length > 40) errors.push({ index: i, field: "ctaLabel", message: "Libellé CTA > 40 caractères" });
      if (ctaLabel && !to) errors.push({ index: i, field: "ctaLabel", message: "CTA défini sans lien cible" });
      const id = typeof p?.id === "string" && p.id ? p.id.slice(0, 40) : `promo_${Date.now()}_${i}`;
      if (seenIds.has(id)) errors.push({ index: i, field: "id", message: `Identifiant en doublon : ${id}` });
      seenIds.add(id);
      promos.push({
        id, image: image.slice(0, 2000),
        alt: alt.slice(0, 160) || "Annonce IPPOO",
        to: to.slice(0, 200),
        title: title.slice(0, 120),
        description: description.slice(0, 280),
        ctaLabel: ctaLabel.slice(0, 40),
        theme,
        active: p?.active !== false,
      });
    });
    if (errors.length > 0) return c.json({ error: "Validation échouée", errors }, 400);
    await kv.set(k.promos(), promos);
    await audit(`admin:${r.admin.username}`, "admin.promos.update", { count: promos.length });
    await adminAudit(c, r.admin, "promos.update", { count: promos.length });
    return c.json({ ok: true, promos });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: AUDIT ADMIN (qui a fait quoi) ----
// Lit le ring `admin:audit` (max 500). Accessible à tous les rôles admin pour
// transparence interne ; les rôles support voient aussi qui agit.
app.get(`${PREFIX}/admin/audit/admins`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const entries = ((await kv.get("admin:audit")) ?? []) as any[];
  return c.json({ entries });
});

// A20 — Timeline audit par agent. Filtre admin:audit (actions admin) et
// audit:* (actions par utilisateur) sur un matricule ou agentId donné, pour
// que l'admin ou le manager puisse retracer ce que tel conseiller a fait
// (décisions sinistres, KYC, paiements, réassignations, etc.) sur une
// fenêtre temporelle courte. Recherche par matricule OU agentId; fenêtre
// par défaut 30 jours, max 1000 lignes.
app.get(`${PREFIX}/admin/audit/agent`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const matricule = (c.req.query("matricule") ?? "").trim();
  const agentId = (c.req.query("agentId") ?? "").trim();
  if (!matricule && !agentId) return c.json({ error: "matricule ou agentId requis" }, 400);
  try {
    const sinceMs = Date.now() - 30 * 24 * 3600_000;
    const match = (s: string) => (matricule && s.includes(matricule)) || (agentId && s.includes(agentId));
    // Actions admin (audits déclenchés via adminAudit).
    const adminEntries = ((await kv.get("admin:audit")) ?? []) as any[];
    const adminHits = adminEntries
      .filter((e) => new Date(e.at).getTime() >= sinceMs && (match(JSON.stringify(e?.meta ?? {})) || e?.admin === matricule))
      .map((e) => ({ ...e, _source: "admin" }));
    // Actions par-utilisateur où l'agent intervient (par ex. claim.reassign,
    // agent.claim.attachment, kyc.lock — tous stockent matricule dans meta).
    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "audit:%");
    if (error) return c.json({ error: error.message }, 500);
    const userHits: any[] = [];
    for (const row of data ?? []) {
      const uid = (row.key as string).slice("audit:".length);
      for (const e of (row.value ?? []) as any[]) {
        if (new Date(e.at).getTime() < sinceMs) continue;
        const metaStr = JSON.stringify(e.meta ?? {});
        if (match(metaStr)) {
          userHits.push({ ...e, userId: uid, _source: "user" });
        }
      }
    }
    const merged = [...adminHits, ...userHits]
      .sort((a, b) => (a.at < b.at ? 1 : -1))
      .slice(0, 1000);
    return c.json({ entries: merged });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: RECENT AUDIT ----
app.get(`${PREFIX}/admin/audit/recent`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "audit:%");
    if (error) return c.json({ error: error.message }, 500);
    const flat: any[] = [];
    for (const row of data ?? []) {
      const uid = (row.key as string).slice("audit:".length);
      const profile = (await kv.get(k.profile(uid))) ?? {};
      for (const e of (row.value ?? []) as any[]) {
        flat.push({ ...e, userId: uid, userEmail: profile.email ?? "", userName: profile.name ?? "" });
      }
    }
    flat.sort((a, b) => (a.at < b.at ? 1 : -1));
    return c.json({ entries: flat.slice(0, 200) });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- AUTO-DEBIT: monthly billing cycle ----
// Iterates over all users and, for every active contract whose nextBillingDate
// has elapsed and autoDebit is enabled, creates a pending monthly_premium
// payment and notifies the member to pay it via KkiaPay. Idempotent — won't
// re-create a payment for a cycle that already has one in en_attente or
// confirme for the current month.
async function runMonthlyBillingCycle(triggeredBy: string) {
  const { data, error } = await admin
    .from("kv_store_752d1a39")
    .select("key, value")
    .like("key", "contracts:%");
  if (error) throw new Error(error.message);
  const now = new Date();
  const monthKey = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
  let generated = 0;
  let skipped = 0;
  for (const row of data ?? []) {
    const uid = (row.key as string).slice("contracts:".length);
    const contracts = ((row.value ?? []) as any[]).slice();
    let changed = false;
    const payments = ((await kv.get(k.payments(uid))) ?? []) as any[];
    const notifs = ((await kv.get(k.notifications(uid))) ?? []) as any[];
    const toDispatch: Array<{ title: string; body: string; tag: string }> = [];
    for (let i = 0; i < contracts.length; i++) {
      const ct = contracts[i];
      if (ct.status !== "active") continue;
      if (ct.autoDebit === false) { skipped++; continue; }
      const due = ct.nextBillingDate ? new Date(ct.nextBillingDate).getTime() : 0;
      if (due > now.getTime()) continue;
      const already = payments.some((p) =>
        p.contractId === ct.id &&
        p.purpose === "monthly_premium" &&
        (p.cycleKey === monthKey || (p.status === "confirme" && (p.confirmedAt ?? p.createdAt ?? "").startsWith(monthKey)))
      );
      if (already) { skipped++; continue; }
      const payment = {
        id: `p_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
        contractId: ct.id,
        amount: ct.premium,
        currency: ct.currency ?? "XOF",
        method: "mobile_money",
        status: "en_attente" as const,
        purpose: "monthly_premium" as const,
        cycleKey: monthKey,
        mode: Deno.env.get("KKIAPAY_PUBLIC_KEY") ? "kkiapay" : "mock",
        createdAt: new Date().toISOString(),
      };
      payments.unshift(payment);
      const title = "Cotisation mensuelle à régler";
      const body = `Votre prélèvement de ${ct.premium} FCFA pour « ${ct.product} » est à régler.`;
      const prefs = await getNotifPrefs(uid);
      if (prefs.types.payment !== false && prefs.channels.in_app !== false) {
        notify(notifs, title, body, "warn", "/espace-client/cotisations");
      }
      if (prefs.types.payment !== false) {
        toDispatch.push({ title, body, tag: `billing:${payment.id}` });
      }
      contracts[i] = { ...ct, nextBillingDate: nextBillingFromNow() };
      changed = true;
      generated++;
    }
    if (changed) {
      await kv.set(k.payments(uid), payments);
      await setNotifications(uid, notifs.slice(0, 200));
      await kv.set(k.contracts(uid), contracts);
      for (const d of toDispatch) {
        await dispatchNotification(uid, { typeKey: "payment", title: d.title, body: d.body, url: "/espace-client/cotisations", tag: d.tag });
      }
    }
  }
  console.log(`[billing] cycle ${monthKey} by=${triggeredBy} generated=${generated} skipped=${skipped}`);
  return { cycleKey: monthKey, generated, skipped };
}

app.post(`${PREFIX}/admin/billing/run`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  const r = { admin: g.admin };
  try {
    const res = await runMonthlyBillingCycle(r.admin.username);
    await adminAudit(c, r.admin, "billing.run", res);
    return c.json({ ok: true, ...res });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Backfill idempotent : matérialise les bénéficiaires saisis au signup pour
// les comptes existants dont la liste `beneficiaries:<uid>` est vide. Permet
// de rattraper les inscriptions effectuées avant que la persistance du wizard
// soit complète. Re-jouable sans risque (skip si liste déjà peuplée).
app.post(`${PREFIX}/admin/maintenance/backfill-beneficiaries`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  const r = { admin: g.admin };
  try {
    const profiles = ((await kv.getByPrefix("profile:")) ?? []) as any[];
    let scanned = 0;
    let migrated = 0;
    let skipped = 0;
    const now = new Date().toISOString();
    for (const p of profiles) {
      scanned++;
      const uid = p?.id;
      if (!uid) { skipped++; continue; }
      const seed = Array.isArray(p?.beneficiaires) ? p.beneficiaires : [];
      const filtered = seed.filter((b: any) => b && (b.name || b.relation));
      if (filtered.length === 0) { skipped++; continue; }
      const existing = ((await kv.get(k.beneficiaries(uid))) ?? []) as any[];
      if (existing.length > 0) { skipped++; continue; }
      const list = filtered.map((b: any) => ({
        id: crypto.randomUUID(),
        name: (b.name ?? "").toString().slice(0, 120),
        relation: (b.relation ?? "").toString().slice(0, 60),
        birthDate: b.birthDate ?? null,
        source: "backfill",
        createdAt: now,
      }));
      await kv.set(k.beneficiaries(uid), list);
      migrated++;
    }
    const res = { scanned, migrated, skipped };
    await adminAudit(c, r.admin, "maintenance.backfill-beneficiaries", res);
    return c.json({ ok: true, ...res });
  } catch (err) {
    return c.json({ error: `backfill-beneficiaries: ${err}` }, 500);
  }
});

// Notification preferences — channel matrix + per-type opt-out. Stored on the
// user's settings record under `notifPrefs`. The reminders cycle and channel
// dispatch helpers consult this to honor user choices. Defaults are
// permissive: everything is on so a new user gets all critical reminders
// until they explicitly mute something.
type NotifChannel = "in_app" | "push" | "email" | "sms";
type NotifTypeKey = "upcoming" | "pending" | "failed" | "renewal" | "broadcast" | "claim" | "payment" | "system";
type NotifPrefs = {
  channels: Record<NotifChannel, boolean>;
  types: Record<NotifTypeKey, boolean>;
};
function defaultNotifPrefs(): NotifPrefs {
  return {
    channels: { in_app: true, push: true, email: true, sms: false },
    types: {
      upcoming: true,
      pending: true,
      failed: true,
      renewal: true,
      broadcast: true,
      claim: true,
      payment: true,
      system: true,
    },
  };
}
function mergeNotifPrefs(raw: any): NotifPrefs {
  const d = defaultNotifPrefs();
  if (!raw || typeof raw !== "object") return d;
  return {
    channels: { ...d.channels, ...(raw.channels ?? {}) },
    types: { ...d.types, ...(raw.types ?? {}) },
  };
}
async function getNotifPrefs(uid: string): Promise<NotifPrefs> {
  const s = (await kv.get(k.settings(uid))) ?? {};
  return mergeNotifPrefs(s.notifPrefs);
}

// Unified dispatcher used by reminders + ad-hoc server notifications. Respects
// the user's channel matrix and per-type opt-out. Caller owns persisting the
// in-app notification list (this dispatcher only fans out to push / email /
// sms when those channels are enabled). Returns counts for logging.
async function dispatchNotification(
  uid: string,
  args: {
    typeKey: NotifTypeKey;
    title: string;
    body: string;
    url?: string;
    tag?: string;
  },
) {
  const prefs = await getNotifPrefs(uid);
  const out = { push: 0, email: 0, sms: 0, skipped: false as boolean };
  if (prefs.types[args.typeKey] === false) { out.skipped = true; return out; }
  const profile = ((await kv.get(k.profile(uid))) ?? {}) as { email?: string; phone?: string };

  // Push (web-push, VAPID gated). pushUsers is no-op without VAPID env.
  if (prefs.channels.push !== false) {
    try {
      const pushFn = (globalThis as any).__ippoo_pushUsers;
      if (typeof pushFn === "function") {
        const res = await pushFn([uid], { title: args.title, body: args.body, url: args.url, tag: args.tag });
        out.push = res?.sent ?? 0;
      }
    } catch (err) {
      console.log(`[dispatch] push failed uid=${uid} type=${args.typeKey}: ${err}`);
    }
  }

  // Email (Resend gated)
  if (prefs.channels.email !== false && profile.email && RESEND_KEY) {
    const html = `<div style="font-family:system-ui,sans-serif;max-width:560px;margin:auto;padding:24px;color:#0E1320">
      <h2 style="margin:0 0 8px;font-size:18px">${args.title}</h2>
      <p style="margin:0;font-size:14px;line-height:1.5;color:#444">${args.body}</p>
      ${args.url ? `<p style="margin-top:16px"><a href="https://ippoo.app${args.url}" style="background:#FF3B57;color:#fff;text-decoration:none;padding:10px 16px;border-radius:10px;font-weight:700;font-size:13px">Ouvrir</a></p>` : ""}
      <hr style="border:none;border-top:1px solid #eee;margin:20px 0"/>
      <p style="font-size:11px;color:#888;margin:0">IPPOO Assurance · Vous pouvez gérer vos préférences depuis Paramètres &gt; Préférences avancées.</p>
    </div>`;
    try {
      if (await sendEmail(profile.email, args.title, html)) out.email = 1;
    } catch (err) {
      console.log(`[dispatch] email failed uid=${uid} type=${args.typeKey}: ${err}`);
    }
  }

  // SMS (Termii gated). Default off so this is rarely hit.
  if (prefs.channels.sms !== false && profile.phone && TERMII_KEY) {
    const text = `IPPOO: ${args.title}. ${args.body}`.slice(0, 320);
    try {
      if (await sendSms(profile.phone, text)) out.sms = 1;
    } catch (err) {
      console.log(`[dispatch] sms failed uid=${uid} type=${args.typeKey}: ${err}`);
    }
  }
  return out;
}

// Wrapper around notify() + setNotifications() + dispatchNotification(). Use
// this for any ad-hoc server-side notification so the channel matrix and
// per-type opt-out are honoured everywhere (not just in the reminders cycle).
// Caller still owns the `notifs` array (so it can mutate other contract /
// payment state in the same KV transaction window).
async function notifyAndDispatch(
  uid: string,
  notifs: any[],
  args: {
    typeKey: NotifTypeKey;
    title: string;
    body: string;
    severity?: "info" | "warn" | "success";
    to?: string;
    tag?: string;
  },
) {
  const prefs = await getNotifPrefs(uid);
  if (prefs.types[args.typeKey] === false) {
    return { inApp: false, dispatched: { push: 0, email: 0, sms: 0 } };
  }
  if (prefs.channels.in_app !== false) {
    const next = notify(notifs, args.title, args.body, args.severity ?? "info", args.to);
    notifs.length = 0;
    notifs.push(...next);
    await setNotifications(uid, notifs.slice(0, 200));
  }
  const out = await dispatchNotification(uid, {
    typeKey: args.typeKey,
    title: args.title,
    body: args.body,
    url: args.to,
    tag: args.tag,
  });
  return { inApp: prefs.channels.in_app !== false, dispatched: { push: out.push, email: out.email, sms: out.sms } };
}

// ---- AUTO-REMINDERS: payment + contract reminders ----
// Unified reminders cycle. Run several times a day (e.g. 08:00 / 14:00 / 20:00
// via Supabase Scheduled Functions or cron-job.org). Idempotent: each
// reminder is keyed and stored in `reminders:sent:<uid>` so a given reminder
// fires exactly once.
//
// Reminders generated:
//  - upcoming-3 / upcoming-1 / upcoming-0  -> active autoDebit contract whose
//    nextBillingDate is in 3 days / 1 day / today
//  - pending-24h                            -> en_attente payment older than 24h
//  - failed                                 -> echec payment, immediately
//  - renewal-7 / renewal-1                  -> contract endDate in 7/1 days
async function runRemindersCycle(triggeredBy: string) {
  const { data, error } = await admin
    .from("kv_store_752d1a39")
    .select("key, value")
    .like("key", "contracts:%");
  if (error) throw new Error(error.message);

  const now = Date.now();
  const DAY = 86_400_000;
  let sentCount = 0;
  let scanned = 0;
  const fanout = { push: 0, email: 0, sms: 0, opted_out_type: 0 };

  for (const row of data ?? []) {
    const uid = (row.key as string).slice("contracts:".length);
    scanned++;
    const contracts = ((row.value ?? []) as any[]) || [];
    const payments = ((await kv.get(k.payments(uid))) ?? []) as any[];
    const notifs = ((await kv.get(k.notifications(uid))) ?? []) as any[];
    const sent = new Set<string>(((await kv.get(k.reminders(uid))) ?? []) as string[]);
    const before = sent.size;
    const prefs = await getNotifPrefs(uid);

    // Pending out-of-band dispatches (push/email/sms). Executed after the
    // synchronous loop so the cycle stays fast and the persisted reminders
    // set / notifs list aren't blocked by network calls.
    const pendingDispatches: Array<{
      typeKey: NotifTypeKey; title: string; body: string; url?: string; tag: string;
    }> = [];

    const fire = (
      key: string,
      title: string,
      body: string,
      type: "info" | "warn" | "success",
      to: string | undefined,
      typeKey: NotifTypeKey,
    ) => {
      if (sent.has(key)) return;
      // Always record the key once a reminder *would* have fired so we don't
      // re-evaluate the same one tomorrow; opt-out is a "skip", not a "defer".
      sent.add(key);
      if (prefs.types[typeKey] === false) return;
      if (prefs.channels.in_app !== false) {
        const next = notify(notifs, title, body, type, to);
        notifs.length = 0;
        notifs.push(...next);
        sentCount++;
      }
      // Defer push/email/sms — dispatcher re-checks prefs and env gating.
      pendingDispatches.push({ typeKey, title, body, url: to, tag: key });
    };

    // Contract reminders
    for (const ct of contracts) {
      if (ct.status !== "active") continue;
      // Upcoming auto-debit
      if (ct.autoDebit !== false && ct.nextBillingDate) {
        const due = new Date(ct.nextBillingDate).getTime();
        const days = Math.floor((due - now) / DAY);
        const cycle = ct.nextBillingDate.slice(0, 10);
        if (days === 3) {
          fire(
            `upcoming:${ct.id}:${cycle}:d3`,
            "Prélèvement dans 3 jours",
            `Votre cotisation de ${ct.premium} FCFA pour « ${ct.product} » sera prélevée le ${new Date(due).toLocaleDateString("fr-FR")}.`,
            "info",
            "/espace-client/cotisations",
            "upcoming",
          );
        } else if (days === 1) {
          fire(
            `upcoming:${ct.id}:${cycle}:d1`,
            "Prélèvement demain",
            `Assurez-vous d'avoir le solde nécessaire pour ${ct.product} (${ct.premium} FCFA).`,
            "warn",
            "/espace-client/cotisations",
            "upcoming",
          );
        } else if (days === 0) {
          fire(
            `upcoming:${ct.id}:${cycle}:d0`,
            "Prélèvement aujourd'hui",
            `Votre cotisation ${ct.product} (${ct.premium} FCFA) est due aujourd'hui.`,
            "warn",
            "/espace-client/cotisations",
            "upcoming",
          );
        }
      }
      // Contract expiry / renewal
      if (ct.endDate) {
        const end = new Date(ct.endDate).getTime();
        const days = Math.floor((end - now) / DAY);
        const cycle = ct.endDate.slice(0, 10);
        if (days === 7) {
          fire(
            `renewal:${ct.id}:${cycle}:d7`,
            "Contrat à renouveler dans 7 jours",
            `« ${ct.product} » arrive à échéance le ${new Date(end).toLocaleDateString("fr-FR")}. Renouvelez-le en 1 clic.`,
            "info",
            "/espace-client/contrats",
            "renewal",
          );
        } else if (days === 1) {
          fire(
            `renewal:${ct.id}:${cycle}:d1`,
            "Contrat expire demain",
            `« ${ct.product} » expire demain. Renouvelez-le pour conserver votre couverture.`,
            "warn",
            "/espace-client/contrats",
            "renewal",
          );
        } else if (days === 0) {
          fire(
            `renewal:${ct.id}:${cycle}:d0`,
            "Contrat expirant aujourd'hui",
            `Dernier jour pour renouveler « ${ct.product} ».`,
            "warn",
            "/espace-client/contrats",
            "renewal",
          );
        }
      }
    }

    // Payment reminders + escalade « pending > 3j → SMS, pending > 5j → notif
    // pré-suspension, pending > 7j → suspension auto du contrat lié ».
    // Suspension : contract.status = "suspended" + flag suspendedAt. La
    // suspension est levée automatiquement au prochain paiement confirmé
    // (purpose monthly_premium / renewal — voir applyPaymentSideEffects).
    let suspensionsApplied = 0;
    for (const p of payments) {
      if (p.status === "en_attente") {
        const created = new Date(p.createdAt ?? 0).getTime();
        const ageMs = now - created;
        if (ageMs >= 24 * 3600_000) {
          fire(
            `pending24:${p.id}`,
            "Paiement en attente",
            `Un paiement de ${p.amount} FCFA est en attente depuis plus de 24h. Finalisez-le pour activer la couverture.`,
            "warn",
            "/espace-client/cotisations",
            "pending",
          );
        }
        if (ageMs >= 3 * DAY) {
          fire(
            `pending3d:${p.id}`,
            "Paiement non finalisé depuis 3 jours",
            `Votre paiement de ${p.amount} FCFA est toujours en attente. Sans régularisation sous 4 jours, votre contrat sera suspendu.`,
            "warn",
            "/espace-client/cotisations",
            "pending",
          );
        }
        if (ageMs >= 5 * DAY) {
          fire(
            `pending5d:${p.id}`,
            "Suspension imminente (48 h)",
            `Sans régularisation sous 48 h, votre contrat lié au paiement #${p.id.slice(-6)} sera suspendu automatiquement.`,
            "warn",
            "/espace-client/cotisations",
            "pending",
          );
        }
        if (ageMs >= 7 * DAY && p.contractId) {
          const idx = contracts.findIndex((cx: any) => cx.id === p.contractId);
          if (idx !== -1 && contracts[idx].status === "active") {
            contracts[idx] = {
              ...contracts[idx],
              status: "suspended",
              suspendedAt: new Date().toISOString(),
              suspendedReason: `payment-overdue:${p.id}`,
            };
            suspensionsApplied++;
            fire(
              `suspend:${p.id}`,
              "Contrat suspendu",
              `Votre contrat « ${contracts[idx].product} » est suspendu pour non-paiement. Régularisez ${p.amount} FCFA pour réactiver votre couverture.`,
              "warn",
              "/espace-client/contrats",
              "pending",
            );
            await audit(uid, "contract.suspended.auto", { contractId: contracts[idx].id, paymentId: p.id, ageDays: Math.floor(ageMs / DAY) });
          }
        }
      } else if (p.status === "echec") {
        fire(
          `failed:${p.id}`,
          "Paiement échoué",
          `Le paiement de ${p.amount} FCFA n'a pas abouti. Vous pouvez réessayer.`,
          "warn",
          "/espace-client/cotisations",
          "failed",
        );
      }
    }

    if (sent.size !== before) {
      // Bound the dedupe set so it doesn't grow forever. 500 last keys are
      // plenty — a user generates ~12 reminders/year per contract.
      const arr = Array.from(sent);
      const trimmed = arr.slice(Math.max(0, arr.length - 500));
      await kv.set(k.reminders(uid), trimmed);
      await setNotifications(uid, notifs.slice(0, 200));
    }
    if (suspensionsApplied > 0) {
      await kv.set(k.contracts(uid), contracts);
    }

    // Out-of-band channel fan-out (push / email / sms). Each call honours
    // the channel matrix and env-var gating internally. Errors are caught
    // inside dispatchNotification so one failing channel can't abort the
    // cycle for the next user.
    for (const d of pendingDispatches) {
      const res = await dispatchNotification(uid, d);
      if (res.skipped) fanout.opted_out_type++;
      fanout.push += res.push;
      fanout.email += res.email;
      fanout.sms += res.sms;
    }
  }
  console.log(
    `[reminders] by=${triggeredBy} scanned=${scanned} sent=${sentCount} push=${fanout.push} email=${fanout.email} sms=${fanout.sms} opted_out=${fanout.opted_out_type}`,
  );
  // Historique borné pour monitoring admin (vérifier que le cron tourne,
  // suivre le volume email/SMS pour les coûts). 100 cycles ≈ 33 jours à
  // 3 runs/j, suffisant pour repérer une dérive.
  try {
    const history = ((await kv.get("reminders:history")) ?? []) as any[];
    history.unshift({
      at: new Date().toISOString(),
      triggeredBy,
      scanned,
      sent: sentCount,
      fanout,
    });
    await kv.set("reminders:history", history.slice(0, 100));
  } catch (e) {
    console.log(`reminders history persist failed: ${e}`);
  }
  return { scanned, sent: sentCount, fanout };
}

app.get(`${PREFIX}/admin/reminders/history`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const history = ((await kv.get("reminders:history")) ?? []) as any[];
  return c.json({ history });
});

app.post(`${PREFIX}/admin/reminders/run`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  const r = { admin: g.admin };
  try {
    const res = await runRemindersCycle(r.admin.username);
    await adminAudit(c, r.admin, "reminders.run", res);
    return c.json({ ok: true, ...res });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.post(`${PREFIX}/reminders/cron`, async (c) => {
  const provided = c.req.header("X-Cron-Secret") ?? c.req.header("x-cron-secret") ?? "";
  const secret = Deno.env.get("CRON_SECRET") ?? "";
  if (!secret || provided !== secret) return c.json({ error: "Cron non autorisé" }, 401);
  try {
    const res = await runRemindersCycle("cron");
    return c.json({ ok: true, ...res });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// A14 — Cron rappel tâches conseiller. Itère sur agent:tasks:<matricule>,
// repère les tâches non-faites dont l'échéance est dans la fenêtre [now-5min,
// now+15min) ; envoie un push au conseiller via son agentId résolu depuis le
// matricule. Idempotence : marque `notifiedAt` sur la tâche pour ne pas
// renvoyer le même rappel à chaque tick.
app.post(`${PREFIX}/agent/tasks/remind/cron`, async (c) => {
  const provided = c.req.header("X-Cron-Secret") ?? c.req.header("x-cron-secret") ?? "";
  const secret = Deno.env.get("CRON_SECRET") ?? "";
  if (!secret || provided !== secret) return c.json({ error: "Cron non autorisé" }, 401);
  try {
    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "agent:tasks:%");
    if (error) return c.json({ error: error.message }, 500);
    const now = Date.now();
    let pushed = 0, scanned = 0;
    for (const row of data ?? []) {
      const matricule = (row.key as string).slice("agent:tasks:".length);
      const tasks = Array.isArray(row.value) ? (row.value as any[]) : [];
      let dirty = false;
      let needsPush: any[] = [];
      for (const t of tasks) {
        scanned++;
        if (t.done || !t.dueAt || t.notifiedAt) continue;
        const due = new Date(t.dueAt).getTime();
        if (isNaN(due)) continue;
        if (due > now - 5 * 60_000 && due < now + 15 * 60_000) {
          t.notifiedAt = new Date().toISOString();
          needsPush.push(t);
          dirty = true;
        }
      }
      if (dirty) await kv.set(row.key as string, tasks);
      if (needsPush.length === 0) continue;
      const agentUid = await kv.get(`agent:matricule-claim:${matricule}`);
      if (typeof agentUid !== "string") continue;
      for (const t of needsPush) {
        const due = new Date(t.dueAt).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
        await pushUsers([agentUid], {
          title: `Tâche à ${due}`,
          body: t.title ?? "Rappel d'une tâche",
          url: "/agent",
          tag: `agent-task:${t.id}`,
        });
        pushed++;
      }
    }
    return c.json({ ok: true, scanned, pushed });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// #8 — Cron sweep suppression 30j. Itère sur les demandes `account:deletion:*`
// et purge celles dont la grâce est écoulée. À planifier 1x/jour.
app.post(`${PREFIX}/account/sweep-deletions/cron`, async (c) => {
  const provided = c.req.header("X-Cron-Secret") ?? c.req.header("x-cron-secret") ?? "";
  const secret = Deno.env.get("CRON_SECRET") ?? "";
  if (!secret || provided !== secret) return c.json({ error: "Cron non autorisé" }, 401);
  try {
    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "account:deletion:%");
    if (error) return c.json({ error: error.message }, 500);
    const now = Date.now();
    let purged = 0;
    let pending = 0;
    for (const row of data ?? []) {
      const uid = (row.key as string).slice("account:deletion:".length);
      const rec = (row.value ?? {}) as { scheduledFor?: string };
      const due = rec.scheduledFor ? new Date(rec.scheduledFor).getTime() : 0;
      if (!due || due > now) { pending++; continue; }
      try { await hardDeleteUser(uid); purged++; }
      catch (err) { console.log(`sweep-deletions error ${uid}: ${err}`); }
    }
    console.log(`[sweep-deletions] purged=${purged} pending=${pending}`);
    return c.json({ ok: true, purged, pending, ranAt: new Date().toISOString() });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// #12 — Rotation HMAC. Déplace la clé courante vers `prev`, génère une
// nouvelle clé primaire. Les jetons émis sous l'ancienne clé restent valides
// jusqu'à la prochaine rotation (ou expiration naturelle). Strictement
// superadmin.
app.post(`${PREFIX}/admin/system/hmac/rotate`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if (!g.admin) return c.json({ error: g.error }, g.status);
  try {
    const current = (await kv.get(k.hmacSecret())) as string | null;
    if (!current) return c.json({ error: "Aucune clé primaire à tourner" }, 409);
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    const next = b64urlEncode(buf);
    await kv.set(`${k.hmacSecret()}:prev`, current);
    await kv.set(k.hmacSecret(), next);
    cachedHmacKey = null;
    cachedHmacPrevKey = undefined;
    console.log(`[hmac-rotate] by=${g.admin.username} at=${new Date().toISOString()}`);
    return c.json({ ok: true, rotatedAt: new Date().toISOString(), graceUntil: "next rotation" });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});
app.post(`${PREFIX}/admin/system/hmac/revoke-prev`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if (!g.admin) return c.json({ error: g.error }, g.status);
  await kv.del(`${k.hmacSecret()}:prev`);
  cachedHmacPrevKey = undefined;
  return c.json({ ok: true, revokedAt: new Date().toISOString() });
});

// #11 — Seed démo. Crée un client + 1 contrat + 1 paiement confirmé + 1
// sinistre + 1 conseiller pour les démos commerciales. Gated par superadmin
// uniquement. Idempotent : si l'email existe déjà, retourne les ids existants.
app.post(`${PREFIX}/admin/dev/seed-demo`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if (!g.admin) return c.json({ error: g.error }, g.status);
  try {
    const email = "demo.client@ippoo.local";
    const password = `Demo!${Math.random().toString(36).slice(2, 8)}`;
    const existingUid = await kv.get(k.emailToUid(email));
    let uid: string;
    if (existingUid) {
      uid = existingUid as string;
    } else {
      const { data, error } = await admin.auth.admin.createUser({
        email, password, email_confirm: true,
        user_metadata: { name: "Demo Client", phone: "22912345678" },
      });
      if (error) return c.json({ error: error.message }, 500);
      uid = data.user!.id;
      const memberNumber = await assignMemberNumber(uid);
      await kv.set(k.emailToUid(email), uid);
      await kv.set(k.profile(uid), {
        id: uid, email, name: "Demo Client", phone: "22912345678", memberNumber,
        createdAt: new Date().toISOString(), type: "particulier",
        firstName: "Demo", lastName: "Client", gender: "M",
        birthDate: "1990-01-01", country: "BJ", countryDial: "229",
        city: "Cotonou", kycVerified: true, kycVerifiedAt: new Date().toISOString(),
      });
    }
    const now = new Date();
    const contractId = `c_demo_${Date.now()}`;
    const contract = {
      id: contractId, product: "IPPOO Santé Essentiel", status: "active",
      premium: 5000, currency: "XOF", autoDebit: true,
      effectiveDate: now.toISOString(), startDate: now.toISOString(),
      endDate: new Date(now.getTime() + 365 * 86400000).toISOString(),
      nextBillingDate: new Date(now.getTime() + 30 * 86400000).toISOString(),
      createdAt: now.toISOString(),
    };
    await kv.set(k.contracts(uid), [contract]);
    const payment = {
      id: `p_demo_${Date.now()}`, contractId, amount: 5000, currency: "XOF",
      method: "mobile_money", status: "confirme", purpose: "monthly_premium",
      mode: "mock", createdAt: now.toISOString(), confirmedAt: now.toISOString(),
    };
    await kv.set(k.payments(uid), [payment]);
    const claim = {
      id: `cl_demo_${Date.now()}`, contractId, type: "consultation",
      amountRequested: 12000, status: "en_cours",
      description: "Consultation cardiologie",
      createdAt: now.toISOString(),
    };
    await kv.set(k.claims(uid), [claim]);
    await setNotifications(uid, [
      { id: `n_${Date.now()}`, title: "Compte démo prêt", body: "Toutes les données sont fictives.", type: "info", createdAt: now.toISOString(), read: false },
    ]);
    const agentEmail = "demo.agent@ippoo.local";
    const existingAgentUid = await kv.get(k.emailToUid(agentEmail));
    let agentMatricule: string | null = null;
    if (existingAgentUid) {
      const meta = (await kv.get(`agent:matricule:${existingAgentUid}`)) as any;
      agentMatricule = meta?.matricule ?? null;
    } else {
      const { data: ag } = await admin.auth.admin.createUser({
        email: agentEmail, password, email_confirm: true,
        user_metadata: { name: "Conseiller Démo", role: "conseiller" },
      });
      if (ag?.user) {
        const auid = ag.user.id;
        agentMatricule = "IPPOO-A-0099";
        await kv.set(k.emailToUid(agentEmail), auid);
        await kv.set(`agent:matricule:${auid}`, { matricule: agentMatricule, name: "Conseiller Démo", email: agentEmail, createdAt: now.toISOString() });
        await kv.set(`agent:matricule-claim:${agentMatricule}`, auid);
        await kv.set(k.agentProfile(agentMatricule), { matricule: agentMatricule, name: "Conseiller Démo", email: agentEmail });
      }
    }
    return c.json({
      ok: true, uid, email, password: existingUid ? "(unchanged)" : password,
      contractId: contract.id, paymentId: payment.id, claimId: claim.id,
      agentEmail, agentMatricule,
    });
  } catch (err) {
    console.log(`seed-demo error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

// #9 — Capture erreur frontend. Endpoint public (rate-limité) qui collecte
// les exceptions JS non gérées et les stocke dans `system:client-errors` (FIFO
// 500 entrées). Optionnellement forwardé à Sentry si SENTRY_DSN est défini.
app.post(`${PREFIX}/client-error`, async (c) => {
  try {
    const ip = c.req.header("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
    if (!(await rateLimit(`client-err:${ip}`, 30, 60))) return c.json({ ok: false, throttled: true }, 200);
    const body = await c.req.json().catch(() => ({}));
    const entry = {
      at: new Date().toISOString(),
      ip,
      ua: c.req.header("user-agent") ?? "",
      message: String(body?.message ?? "").slice(0, 500),
      stack: String(body?.stack ?? "").slice(0, 4000),
      url: String(body?.url ?? "").slice(0, 500),
      release: String(body?.release ?? "").slice(0, 64),
      userId: body?.userId ? String(body.userId).slice(0, 64) : null,
    };
    const prev = ((await kv.get("system:client-errors")) ?? []) as any[];
    await kv.set("system:client-errors", [entry, ...prev].slice(0, 500));
    const dsn = Deno.env.get("SENTRY_DSN");
    if (dsn) {
      try {
        const m = dsn.match(/^https?:\/\/([^@]+)@([^/]+)\/(\d+)$/);
        if (m) {
          const [, key, host, pid] = m;
          const url = `https://${host}/api/${pid}/store/?sentry_version=7&sentry_key=${key}`;
          await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              message: entry.message,
              exception: { values: [{ value: entry.message, stacktrace: { frames: [] } }] },
              level: "error",
              platform: "javascript",
              tags: { url: entry.url, release: entry.release, userId: entry.userId },
              extra: { stack: entry.stack, ua: entry.ua },
            }),
          });
        }
      } catch { /* non bloquant */ }
    }
    return c.json({ ok: true });
  } catch (err) {
    console.log(`client-error capture failed: ${err}`);
    return c.json({ ok: false }, 200);
  }
});

app.get(`${PREFIX}/admin/client-errors`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const errors = ((await kv.get("system:client-errors")) ?? []) as any[];
  return c.json({ errors: errors.slice(0, 200) });
});

// #13 — Backup KV quotidien. Dump tout le KV en JSON ndjson, upload dans le
// bucket avatars (chemin `__backup__/kv-YYYY-MM-DD.ndjson`). Compression
// gzip via TransformStream pour limiter la taille. À planifier 1x/jour.
app.post(`${PREFIX}/system/kv-backup/cron`, async (c) => {
  const provided = c.req.header("X-Cron-Secret") ?? c.req.header("x-cron-secret") ?? "";
  const secret = Deno.env.get("CRON_SECRET") ?? "";
  if (!secret || provided !== secret) return c.json({ error: "Cron non autorisé" }, 401);
  try {
    const day = new Date().toISOString().slice(0, 10);
    const path = `__backup__/kv-${day}.ndjson.gz`;
    let from = 0;
    const BATCH = 1000;
    const chunks: Uint8Array[] = [];
    const encoder = new TextEncoder();
    while (true) {
      const { data, error } = await admin
        .from("kv_store_752d1a39")
        .select("key, value")
        .range(from, from + BATCH - 1);
      if (error) return c.json({ error: error.message }, 500);
      if (!data || data.length === 0) break;
      for (const row of data) chunks.push(encoder.encode(JSON.stringify(row) + "\n"));
      if (data.length < BATCH) break;
      from += BATCH;
    }
    const raw = new Blob(chunks);
    const gz = raw.stream().pipeThrough(new CompressionStream("gzip"));
    const gzBuf = await new Response(gz).arrayBuffer();
    const { error: upErr } = await admin.storage.from(AVATAR_BUCKET).upload(path, gzBuf, {
      contentType: "application/gzip",
      upsert: true,
    });
    if (upErr) return c.json({ error: upErr.message }, 500);
    console.log(`[kv-backup] ${path} rows≈${chunks.length} size=${gzBuf.byteLength}B`);
    return c.json({ ok: true, path, rows: chunks.length, sizeBytes: gzBuf.byteLength });
  } catch (err) {
    console.log(`kv-backup error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

// Cron entrypoint protected by CRON_SECRET. Hook to Supabase Scheduled
// Functions / external cron to fire on the 1st of each month at 09:00 UTC+1.
app.post(`${PREFIX}/billing/cron`, async (c) => {
  const provided = c.req.header("X-Cron-Secret") ?? c.req.header("x-cron-secret") ?? "";
  const secret = Deno.env.get("CRON_SECRET") ?? "";
  if (!secret || provided !== secret) return c.json({ error: "Cron non autorisé" }, 401);
  try {
    const res = await runMonthlyBillingCycle("cron");
    return c.json({ ok: true, ...res });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- CONTRACT: toggle autoDebit ----
app.patch(`${PREFIX}/contracts/:id/auto-debit`, async (c) => {
  const { user, error } = await requireUser(c);
  if (!user) return c.json({ error: `Non autorisé: ${error}` }, 401);
  const id = c.req.param("id");
  try {
    const body = await c.req.json().catch(() => ({}));
    const enabled = !!body?.enabled;
    const contracts = ((await kv.get(k.contracts(user.id))) ?? []) as any[];
    const idx = contracts.findIndex((ct: any) => ct.id === id);
    if (idx === -1) return c.json({ error: "Contrat introuvable" }, 404);
    contracts[idx] = { ...contracts[idx], autoDebit: enabled, nextBillingDate: enabled ? (contracts[idx].nextBillingDate ?? nextBillingFromNow()) : null };
    await kv.set(k.contracts(user.id), contracts);
    await audit(user.id, "contract.autoDebit", { id, enabled });
    return c.json({ contract: contracts[idx] });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: MESSAGES (list conversations + reply) ----
app.get(`${PREFIX}/admin/messages`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const q = (c.req.query("q") ?? "").trim().toLowerCase();
  const statusFilter = (c.req.query("status") ?? "").trim();
  const mineOnly = c.req.query("mine") === "1";
  try {
    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "messages:%");
    if (error) return c.json({ error: error.message }, 500);
    const convos: any[] = [];
    for (const row of data ?? []) {
      const uid = (row.key as string).slice("messages:".length);
      const list = (row.value ?? []) as any[];
      if (list.length === 0) continue;
      const profile = (await kv.get(k.profile(uid))) ?? {};
      const meta = (await kv.get(k.conversationMeta(uid))) ?? { status: "ouvert", assignee: null };
      const last = list[list.length - 1];
      const unread = list.filter((m) => m.from === "user" && !m.read).length;
      const hay = `${profile.email ?? ""} ${profile.name ?? ""} ${profile.memberNumber ?? ""} ${last?.body ?? ""}`.toLowerCase();
      if (q && !hay.includes(q)) continue;
      if (statusFilter && (meta.status ?? "ouvert") !== statusFilter) continue;
      if (mineOnly && meta.assignee !== r.admin.username) continue;
      const signedAv = await withAvatarUrl(profile);
      convos.push({
        userId: uid,
        userEmail: profile.email ?? "",
        userName: profile.name ?? "",
        avatarUrl: signedAv.avatarUrl ?? null,
        memberNumber: profile.memberNumber ?? "",
        lastMessage: last?.body ?? (last?.attachment ? `📎 ${last.attachment.name}` : ""),
        lastAt: last?.createdAt ?? "",
        lastFrom: last?.from ?? "user",
        unread,
        total: list.length,
        status: meta.status ?? "ouvert",
        assignee: meta.assignee ?? null,
        tags: meta.tags ?? [],
      });
    }
    convos.sort((a, b) => (a.lastAt < b.lastAt ? 1 : -1));
    return c.json({ conversations: convos });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Update conversation meta (status / assignee / tags).
app.patch(`${PREFIX}/admin/messages/:uid/meta`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  try {
    const body = await c.req.json();
    const current = (await kv.get(k.conversationMeta(uid))) ?? { status: "ouvert", assignee: null, tags: [] };
    const next = { ...current };
    if (body?.status && ["ouvert", "en_cours", "resolu"].includes(body.status)) next.status = body.status;
    if (body?.assignee !== undefined) {
      if (body.assignee) {
        const candidate = String(body.assignee).slice(0, 80);
        // Validation stricte : l'assignee doit être un matricule conseiller
        // réellement émis (sentinelle agent:matricule-claim:<mat>). Empêche
        // d'injecter une chaîne arbitraire qui remonterait dans les dashboards.
        const owner = await kv.get(`agent:matricule-claim:${candidate}`);
        if (!owner) return c.json({ error: `Matricule inconnu : ${candidate}` }, 400);
        next.assignee = candidate;
      } else {
        next.assignee = null;
      }
    }
    if (Array.isArray(body?.tags)) next.tags = body.tags.slice(0, 8).map((t: any) => String(t).slice(0, 40));
    next.updatedAt = new Date().toISOString();
    await kv.set(k.conversationMeta(uid), next);
    await audit(uid, "conversation.meta", { by: r.admin.username, ...next });
    await broadcast(`admin:chat`, "meta:update", { userId: uid, meta: next });
    // Si l'assignee change, on prévient les portefeuilles des conseillers (côté
    // agent : page « Mon portefeuille » + Customer360) pour qu'ils se rechargent.
    if (current.assignee !== next.assignee) {
      await broadcast(`assignments:live`, "assignments:dirty", { userId: uid, from: current.assignee, to: next.assignee });
    }
    return c.json({ meta: next });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.get(`${PREFIX}/admin/messages/:uid`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  const list = (await kv.get(k.messages(uid))) ?? [];
  let changed = 0;
  const marked = (list as any[]).map((m) => {
    if (m.from === "user" && !m.read) { changed++; return { ...m, read: true, readAt: new Date().toISOString() }; }
    return m;
  });
  if (changed > 0) {
    await kv.set(k.messages(uid), marked);
    await broadcast(`chat:${uid}`, "message:read", { count: changed, at: new Date().toISOString() });
  }
  return c.json({ messages: marked });
});

app.post(`${PREFIX}/admin/messages/:uid`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  try {
    const body = await c.req.json();
    const content = String(body?.content ?? "").trim();
    if (!content) return c.json({ error: "Message vide" }, 400);
    const replyToId = typeof body?.replyToId === "string" ? body.replyToId : undefined;
    const msg: any = {
      id: `m_${Date.now()}`,
      from: "conseiller",
      author: `${r.admin.username} (IPPOO)`,
      body: content,
      createdAt: new Date().toISOString(),
      read: false,
    };
    if (replyToId) msg.replyToId = replyToId;
    const list = ((await kv.get(k.messages(uid))) ?? []) as any[];
    list.push(msg);
    await kv.set(k.messages(uid), list);
    const notifs = ((await kv.get(k.notifications(uid))) ?? []) as any[];
    await notifyAndDispatch(uid, notifs, {
      typeKey: "system",
      title: "Nouveau message conseiller",
      body: content.slice(0, 140),
      severity: "info",
      to: "/espace-client/messagerie",
      tag: `msg:${uid}`,
    });
    await audit(uid, "message.admin_reply", { by: r.admin.username, length: content.length });
    await Promise.all([
      broadcast(`chat:${uid}`, "message:new", { message: msg }),
      broadcast(`admin:chat`, "message:new", { userId: uid, message: msg }),
    ]);
    return c.json({ message: msg });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- AGENT: MESSAGES (list conversations + reply + meta) ----
// Mirrors /admin/messages* but the caller is a real Supabase user with
// `user_metadata.role === "agent"`. Broadcasts go to the same `admin:chat`
// topic so admins watching the back-office see live updates from agents too,
// and to the per-user `chat:<uid>` topic so the client sees the reply.
app.get(`${PREFIX}/agent/messages`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const q = (c.req.query("q") ?? "").trim().toLowerCase();
  const statusFilter = (c.req.query("status") ?? "").trim();
  const mineOnly = c.req.query("mine") === "1";
  try {
    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "messages:%");
    if (error) return c.json({ error: error.message }, 500);
    const convos: any[] = [];
    for (const row of data ?? []) {
      const uid = (row.key as string).slice("messages:".length);
      const list = (row.value ?? []) as any[];
      if (list.length === 0) continue;
      const profile = (await kv.get(k.profile(uid))) ?? {};
      const meta = (await kv.get(k.conversationMeta(uid))) ?? { status: "ouvert", assignee: null };
      const last = list[list.length - 1];
      const unread = list.filter((m) => m.from === "user" && !m.read).length;
      const hay = `${profile.email ?? ""} ${profile.name ?? ""} ${profile.memberNumber ?? ""} ${last?.body ?? ""}`.toLowerCase();
      if (q && !hay.includes(q)) continue;
      if (statusFilter && (meta.status ?? "ouvert") !== statusFilter) continue;
      // assignee est stocké en matricule (cf. /agent/messages/:uid/meta et
      // l'auto-router). On accepte aussi l'ancien username pour compat
      // avec les conversations assignées avant la migration.
      if (mineOnly && meta.assignee !== r.agent.matricule && meta.assignee !== r.agent.username) continue;
      const signedAv = await withAvatarUrl(profile);
      convos.push({
        userId: uid,
        userEmail: profile.email ?? "",
        userName: profile.name ?? "",
        avatarUrl: signedAv.avatarUrl ?? null,
        memberNumber: profile.memberNumber ?? "",
        lastMessage: last?.body ?? (last?.attachment ? `📎 ${last.attachment.name}` : ""),
        lastAt: last?.createdAt ?? "",
        lastFrom: last?.from ?? "user",
        unread,
        total: list.length,
        status: meta.status ?? "ouvert",
        assignee: meta.assignee ?? null,
        tags: meta.tags ?? [],
      });
    }
    convos.sort((a, b) => (a.lastAt < b.lastAt ? 1 : -1));
    return c.json({ conversations: convos, me: { id: r.agent.id, username: r.agent.username } });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.get(`${PREFIX}/agent/messages/:uid`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  const list = ((await kv.get(k.messages(uid))) ?? []) as any[];
  let changed = 0;
  const marked = list.map((m) => {
    if (m.from === "user" && !m.read) { changed++; return { ...m, read: true, readAt: new Date().toISOString() }; }
    return m;
  });
  if (changed > 0) {
    await kv.set(k.messages(uid), marked);
    await broadcast(`chat:${uid}`, "message:read", { count: changed, at: new Date().toISOString() });
  }
  return c.json({ messages: marked });
});

app.post(`${PREFIX}/agent/messages/:uid`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  try {
    const body = await c.req.json();
    const content = String(body?.content ?? "").trim();
    if (!content) return c.json({ error: "Message vide" }, 400);
    const replyToId = typeof body?.replyToId === "string" ? body.replyToId : undefined;
    const msg: any = {
      id: `m_${Date.now()}`,
      from: "conseiller",
      author: `${r.agent.username} · ${r.agent.matricule}`,
      body: content,
      createdAt: new Date().toISOString(),
      read: false,
    };
    if (replyToId) msg.replyToId = replyToId;
    const list = ((await kv.get(k.messages(uid))) ?? []) as any[];
    list.push(msg);
    await kv.set(k.messages(uid), list);
    const notifs = ((await kv.get(k.notifications(uid))) ?? []) as any[];
    await notifyAndDispatch(uid, notifs, {
      typeKey: "system",
      title: "Nouveau message conseiller",
      body: content.slice(0, 140),
      severity: "info",
      to: "/espace-client/messagerie",
      tag: `msg:${uid}`,
    });
    await audit(uid, "message.agent_reply", { by: r.agent.matricule, agentId: r.agent.id, length: content.length });
    await Promise.all([
      broadcast(`chat:${uid}`, "message:new", { message: msg }),
      broadcast(`admin:chat`, "message:new", { userId: uid, message: msg }),
    ]);
    return c.json({ message: msg });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.patch(`${PREFIX}/agent/messages/:uid/meta`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  try {
    const body = await c.req.json();
    const current = (await kv.get(k.conversationMeta(uid))) ?? { status: "ouvert", assignee: null, tags: [] };
    const next: any = { ...current };
    if (body?.status && ["ouvert", "en_cours", "resolu"].includes(body.status)) next.status = body.status;
    if (body?.assignee !== undefined) {
      if (body.assignee) {
        const candidate = String(body.assignee).slice(0, 80);
        // Validation stricte : l'assignee doit être un matricule conseiller
        // réellement émis (sentinelle agent:matricule-claim:<mat>). Empêche
        // d'injecter une chaîne arbitraire qui remonterait dans les dashboards.
        const owner = await kv.get(`agent:matricule-claim:${candidate}`);
        if (!owner) return c.json({ error: `Matricule inconnu : ${candidate}` }, 400);
        next.assignee = candidate;
      } else {
        next.assignee = null;
      }
    }
    // Convenience: ?claim=1 to assign to me, ?release=1 to clear.
    if (body?.claim === true) next.assignee = r.agent.matricule;
    if (body?.release === true) next.assignee = null;
    if (Array.isArray(body?.tags)) next.tags = body.tags.slice(0, 8).map((t: any) => String(t).slice(0, 40));
    next.updatedAt = new Date().toISOString();
    await kv.set(k.conversationMeta(uid), next);
    await audit(uid, "conversation.meta", { by: r.agent.matricule, agentId: r.agent.id, ...next });
    await broadcast(`admin:chat`, "meta:update", { userId: uid, meta: next });
    if (current.assignee !== next.assignee) {
      await broadcast(`assignments:live`, "assignments:dirty", { userId: uid, from: current.assignee, to: next.assignee });
      if (next.assignee && next.assignee !== r.agent.matricule) {
        const profile = ((await kv.get(k.profile(uid))) ?? {}) as any;
        await pushAgentNotif(next.assignee, {
          type: "assignment",
          title: "Nouveau client assigné",
          body: `${profile.name || profile.email || "Client"} — assigné par ${r.agent.matricule}`,
          url: `/agent/clients/${uid}`,
        });
      }
    }
    return c.json({ meta: next });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- AGENT SIGNUP (invite-coded) ----
// Conseillers ont leur propre flux d'inscription, séparé de /signup client.
// Gated par AGENT_SIGNUP_CODE (env var partagée par l'équipe RH/manager) pour
// éviter qu'un visiteur s'auto-promeuve. Crée un user Supabase avec
// `user_metadata.role = "agent"` directement, pré-résout son matricule.
app.post(`${PREFIX}/agent/signup`, async (c) => {
  try {
    const ip = c.req.header("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
    const allowed = await rateLimit(`agent-signup:${ip}`, 5, 600);
    if (!allowed) return c.json({ error: "Trop de tentatives, réessayez dans 10 min." }, 429);

    const expected = (Deno.env.get("AGENT_SIGNUP_CODE") ?? "").trim();
    if (!expected) {
      return c.json({ error: "Inscription conseiller désactivée (AGENT_SIGNUP_CODE non configuré côté serveur)." }, 503);
    }

    const body = await c.req.json().catch(() => ({}));
    const code = String(body?.code ?? "").trim();
    const email = String(body?.email ?? "").trim().toLowerCase();
    const password = String(body?.password ?? "");
    const name = String(body?.name ?? "").trim().slice(0, 80);
    const phone = String(body?.phone ?? "").trim().slice(0, 30);

    if (code !== expected) return c.json({ error: "Code d'invitation invalide." }, 403);
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) return c.json({ error: "Email invalide." }, 400);
    if (password.length < 8) return c.json({ error: "Mot de passe : 8 caractères minimum." }, 400);
    if (!name) return c.json({ error: "Nom requis." }, 400);

    // Pre-check: if this email is already a client account, refuse with a
    // crystal-clear message. `emailToUid` is only written by the client
    // signup flow, so a hit there is unambiguous. We also probe Supabase
    // auth to catch leftover users that predate the KV mapping.
    const existingClientUid = await kv.get(k.emailToUid(email));
    if (existingClientUid) {
      return c.json({
        error: "Cet email est déjà utilisé par un compte client IPPOO. Un identifiant ne peut pas servir à la fois pour l'espace client et l'espace conseiller — utilisez une autre adresse professionnelle.",
        code: "email_is_client",
      }, 409);
    }

    // `role` lives in app_metadata (server-controlled, immutable by the user
     // via the public Supabase API) — never in user_metadata, which the user
     // can self-edit and would let a client impersonate an agent client-side.
    const { data, error } = await admin.auth.admin.createUser({
      email,
      password,
      user_metadata: { name, phone },
      app_metadata: { role: "agent" },
      email_confirm: true,
    });
    if (error) {
      const taken = /already been registered|already registered|user already exists/i.test(error.message);
      let msg = error.message;
      let httpCode = 400;
      let errCode: string | undefined;
      if (taken) {
        // Disambiguate: client vs another agent already on this email.
        try {
          const list = await admin.auth.admin.listUsers({ page: 1, perPage: 200 });
          const existing = list.data.users.find((u) => (u.email ?? "").toLowerCase() === email);
          const appMeta = (existing?.app_metadata ?? {}) as Record<string, unknown>;
          const userMeta = (existing?.user_metadata ?? {}) as Record<string, unknown>;
          const role = (appMeta.role as string | undefined) ?? (userMeta.role as string | undefined);
          if (role === "agent" || role === "superadmin") {
            msg = "Un compte conseiller existe déjà pour cet email. Connectez-vous directement depuis /agent.";
            errCode = "email_is_agent";
          } else {
            msg = "Cet email est déjà utilisé par un compte client IPPOO. Un identifiant ne peut pas servir à la fois pour l'espace client et l'espace conseiller — utilisez une autre adresse professionnelle.";
            errCode = "email_is_client";
          }
          httpCode = 409;
        } catch {
          msg = "Cet email est déjà associé à un compte IPPOO. Utilisez une autre adresse.";
          errCode = "email_taken";
          httpCode = 409;
        }
      }
      console.log(`Agent signup error for ${email}: ${error.message}`);
      return c.json({ error: msg, ...(errCode ? { code: errCode } : {}) }, httpCode);
    }
    const uid = data.user!.id;
    const matricule = await resolveAgentMatricule(uid);
    await audit(uid, "agent.signup", { email, matricule });
    return c.json({
      agent: { id: uid, username: name, email, matricule },
    });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Returns the current agent identity / role flag so the frontend can gate the
// UI before issuing any /agent/* calls.
app.get(`${PREFIX}/agent/me`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error, isAgent: false }, r.status);
  const totp = (await kv.get(k.agentTotp(r.agent.id))) as { status?: string } | null;
  const enrolled = totp?.status === "active";
  // Verified for THIS session iff a valid X-Agent-2FA-Token is presented.
  let verified = !enrolled;
  if (enrolled) {
    const t = c.req.header("X-Agent-2FA-Token") ?? c.req.header("x-agent-2fa-token");
    if (t) {
      const payload = await verifyToken<{ kind: string; uid: string; exp: number }>(t);
      if (payload && payload.kind === "agent-2fa" && payload.uid === r.agent.id && Date.now() / 1000 < payload.exp) {
        verified = true;
      }
    }
  }
  const required = (Deno.env.get("AGENT_2FA_REQUIRED") ?? "0") === "1";
  return c.json({ isAgent: true, agent: r.agent, twoFactor: { enrolled, verified, required } });
});

// ---- AGENT: 2FA TOTP ----
// Conformité : protection des comptes conseillers à privilèges (décisions
// sinistres, KYC, encaissement). Secret TOTP base32 (RFC 6238) stocké en KV
// `agent:totp:<uid>` = { secret, status: "pending"|"active", enabledAt }.
// Le challenge `verify` renvoie un token HMAC court (8h) que le client renvoie
// dans `X-Agent-2FA-Token` pour franchir les endpoints sensibles.
function randomTotpSecret(): string {
  // 20 bytes (RFC 6238 §5.1) → 32 caractères base32.
  const alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const buf = new Uint8Array(20);
  crypto.getRandomValues(buf);
  let out = "";
  for (const b of buf) out += alph[b % 32];
  return out;
}

async function requireAgent2FA(c: any, agentId: string): Promise<{ ok: true } | { ok: false; response: Response }> {
  const totp = (await kv.get(k.agentTotp(agentId))) as { status?: string } | null;
  if (!totp || totp.status !== "active") return { ok: true };
  const t = c.req.header("X-Agent-2FA-Token") ?? c.req.header("x-agent-2fa-token");
  if (!t) return { ok: false, response: c.json({ error: "twofactor-required" }, 401) };
  const payload = await verifyToken<{ kind: string; uid: string; exp: number }>(t);
  if (!payload || payload.kind !== "agent-2fa" || payload.uid !== agentId || Date.now() / 1000 > payload.exp) {
    return { ok: false, response: c.json({ error: "twofactor-invalid" }, 401) };
  }
  return { ok: true };
}

app.get(`${PREFIX}/agent/2fa`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const totp = (await kv.get(k.agentTotp(r.agent.id))) as { status?: string; enabledAt?: string } | null;
  return c.json({
    enrolled: totp?.status === "active",
    pending: totp?.status === "pending",
    enabledAt: totp?.enabledAt ?? null,
  });
});

app.post(`${PREFIX}/agent/2fa/enroll`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const existing = (await kv.get(k.agentTotp(r.agent.id))) as { status?: string } | null;
  if (existing?.status === "active") return c.json({ error: "already-enrolled" }, 400);
  const secret = randomTotpSecret();
  await kv.set(k.agentTotp(r.agent.id), { secret, status: "pending", enabledAt: null });
  const issuer = encodeURIComponent("IPPOO Assurance");
  const label = encodeURIComponent(`${issuer}:${r.agent.email || r.agent.matricule}`);
  const otpauth = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
  await audit(r.agent.id, "agent.2fa.enroll.start", { matricule: r.agent.matricule });
  return c.json({ secret, otpauth });
});

app.post(`${PREFIX}/agent/2fa/activate`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const { code } = await c.req.json().catch(() => ({ code: "" }));
    const totp = (await kv.get(k.agentTotp(r.agent.id))) as { secret?: string; status?: string } | null;
    if (!totp?.secret || totp.status !== "pending") return c.json({ error: "no-enrollment" }, 400);
    if (!(await verifyTotp(totp.secret, String(code ?? "").trim()))) {
      return c.json({ error: "invalid-code" }, 400);
    }
    const now = new Date().toISOString();
    await kv.set(k.agentTotp(r.agent.id), { secret: totp.secret, status: "active", enabledAt: now });
    await audit(r.agent.id, "agent.2fa.activated", { matricule: r.agent.matricule });
    const token = await signToken({ kind: "agent-2fa", uid: r.agent.id, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 8 });
    return c.json({ ok: true, twoFactorToken: token });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.post(`${PREFIX}/agent/2fa/verify`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const { code } = await c.req.json().catch(() => ({ code: "" }));
    const totp = (await kv.get(k.agentTotp(r.agent.id))) as { secret?: string; status?: string } | null;
    if (!totp?.secret || totp.status !== "active") return c.json({ error: "not-enrolled" }, 400);
    if (!(await verifyTotp(totp.secret, String(code ?? "").trim()))) {
      await audit(r.agent.id, "agent.2fa.verify.failed", { matricule: r.agent.matricule });
      return c.json({ error: "invalid-code" }, 401);
    }
    const token = await signToken({ kind: "agent-2fa", uid: r.agent.id, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 8 });
    return c.json({ twoFactorToken: token });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.post(`${PREFIX}/agent/2fa/disable`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    // Désactivation : on exige un code TOTP courant pour éviter qu'un attaquant
    // ayant volé le cookie de session puisse couper le second facteur.
    const { code } = await c.req.json().catch(() => ({ code: "" }));
    const totp = (await kv.get(k.agentTotp(r.agent.id))) as { secret?: string; status?: string } | null;
    if (!totp?.secret) return c.json({ ok: true });
    if (totp.status === "active") {
      if (!(await verifyTotp(totp.secret, String(code ?? "").trim()))) {
        return c.json({ error: "invalid-code" }, 401);
      }
    }
    await kv.del(k.agentTotp(r.agent.id));
    await audit(r.agent.id, "agent.2fa.disabled", { matricule: r.agent.matricule });
    return c.json({ ok: true });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- AGENT: PRESENCE ----
// Persistance du statut "en ligne / en pause" du conseiller. Stocké en KV
// `agent:presence:<uid>` = { status, at }. Aucune TTL native côté KV : le
// frontend rafraîchit (heartbeat) toutes les 30s tant qu'il est en ligne, et
// les lecteurs considèrent une présence stale après 90s d'inactivité — c'est
// la responsabilité du consommateur (admin presence dashboard, futur router
// de tickets) de retraiter `at` pour décider qui peut recevoir un nouveau
// ticket.
type AgentPresence = { status: "online" | "paused"; at: string };

app.post(`${PREFIX}/agent/presence`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const body = await c.req.json().catch(() => ({}));
    const online = body?.online === true;
    const presence: AgentPresence = {
      status: online ? "online" : "paused",
      at: new Date().toISOString(),
    };
    await kv.set(`agent:presence:${r.agent.id}`, presence);
    // A8 — Publier la pause sur le bus realtime pour que le client (badge
    // « conseiller en ligne ») et les admins (dashboard) voient le changement
    // sans attendre le prochain refetch HTTP.
    broadcast("agent:presence", online ? "online" : "paused", {
      agentId: r.agent.id, matricule: r.agent.matricule,
      status: presence.status, at: presence.at,
    }).catch(() => { /* best-effort */ });
    return c.json({ presence });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Admin dashboard: liste de tous les conseillers ayant déjà publié une
// présence (online ou paused) avec leur statut courant. Le filtrage "stale"
// (>90s d'inactivité) est calculé côté serveur pour que les admins voient
// un statut effectif (online_stale) sans avoir à recoder la règle côté UI.
app.get(`${PREFIX}/admin/agents/presence`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "agent:presence:%");
    if (error) return c.json({ error: error.message }, 500);
    const STALE_MS = 90_000;
    const now = Date.now();
    // Préchargement des matricules en batch.
    const rows = data ?? [];
    const uids = rows.map((row) => (row.key as string).slice("agent:presence:".length));
    const matricules = uids.length ? await kv.mget(uids.map((u) => `agent:matricule:${u}`)) : [];
    // Une seule liste d'utilisateurs pour résoudre les emails/noms.
    let usersByUid = new Map<string, { email: string; name: string }>();
    try {
      const list = await admin.auth.admin.listUsers({ page: 1, perPage: 1000 });
      for (const u of list.data.users) {
        const meta = (u.user_metadata ?? {}) as Record<string, unknown>;
        usersByUid.set(u.id, {
          email: u.email ?? "",
          name: (meta.name as string | undefined) ?? u.email ?? "",
        });
      }
    } catch (e) {
      console.log(`agents presence listUsers failed: ${e}`);
    }
    const agents = rows.map((row, i) => {
      const uid = uids[i];
      const presence = (row.value ?? {}) as { status: string; at?: string };
      const at = presence.at ?? "";
      const ageMs = at ? now - new Date(at).getTime() : Number.POSITIVE_INFINITY;
      let effective: "online" | "online_stale" | "paused" | "offline";
      if (presence.status === "online" && ageMs <= STALE_MS) effective = "online";
      else if (presence.status === "online") effective = "online_stale";
      else if (presence.status === "paused") effective = "paused";
      else effective = "offline";
      const profile = usersByUid.get(uid) ?? { email: "", name: "" };
      return {
        userId: uid,
        matricule: (matricules[i] as string | undefined) ?? null,
        email: profile.email,
        name: profile.name,
        status: presence.status ?? "offline",
        effective,
        at,
        ageSec: Number.isFinite(ageMs) ? Math.round(ageMs / 1000) : null,
      };
    });
    agents.sort((a, b) => {
      const rank = (s: string) => (s === "online" ? 0 : s === "online_stale" ? 1 : s === "paused" ? 2 : 3);
      const dr = rank(a.effective) - rank(b.effective);
      if (dr !== 0) return dr;
      return (a.name || a.email).localeCompare(b.name || b.email);
    });
    return c.json({ agents, staleAfterSec: STALE_MS / 1000 });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// =========================================================================
// ADMIN: AGENTS CRUD
// =========================================================================

app.get(`${PREFIX}/admin/agents`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const list = await admin.auth.admin.listUsers({ page: 1, perPage: 1000 });
    const users = list.data.users.filter((u) => {
      const appMeta = (u.app_metadata ?? {}) as Record<string, unknown>;
      const userMeta = (u.user_metadata ?? {}) as Record<string, unknown>;
      const role = (appMeta.role as string | undefined) ?? (userMeta.role as string | undefined);
      return role === "agent";
    });
    const matricules = users.length ? await kv.mget(users.map((u) => `agent:matricule:${u.id}`)) : [];
    const presences = users.length ? await kv.mget(users.map((u) => `agent:presence:${u.id}`)) : [];
    const STALE_MS = 90_000;
    const now = Date.now();
    const agents = users.map((u, i) => {
      const meta = (u.user_metadata ?? {}) as Record<string, unknown>;
      const presence = (presences[i] ?? {}) as { status?: string; at?: string };
      const ageMs = presence.at ? now - new Date(presence.at).getTime() : Number.POSITIVE_INFINITY;
      let effective: "online" | "online_stale" | "paused" | "offline";
      if (presence.status === "online" && ageMs <= STALE_MS) effective = "online";
      else if (presence.status === "online") effective = "online_stale";
      else if (presence.status === "paused") effective = "paused";
      else effective = "offline";
      return {
        id: u.id,
        email: u.email ?? "",
        name: (meta.name as string | undefined) ?? "",
        phone: (meta.phone as string | undefined) ?? "",
        matricule: (matricules[i] as string | undefined) ?? null,
        createdAt: u.created_at,
        lastSignInAt: u.last_sign_in_at,
        banned: !!(u as any).banned_until && new Date((u as any).banned_until).getTime() > now,
        presence: effective,
      };
    });
    agents.sort((a, b) => (a.name || a.email).localeCompare(b.name || b.email));
    return c.json({ agents });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.post(`${PREFIX}/admin/agents`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  const r = { admin: g.admin };
  try {
    const body = await c.req.json().catch(() => ({}));
    const email = String(body?.email ?? "").trim().toLowerCase();
    const password = String(body?.password ?? "");
    const name = String(body?.name ?? "").trim().slice(0, 80);
    const phone = String(body?.phone ?? "").trim().slice(0, 30);
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) return c.json({ error: "Email invalide." }, 400);
    if (password.length < 8) return c.json({ error: "Mot de passe : 8 caractères minimum." }, 400);
    if (!name) return c.json({ error: "Nom requis." }, 400);
    const existingClientUid = await kv.get(k.emailToUid(email));
    if (existingClientUid) return c.json({ error: "Email déjà utilisé par un compte client." }, 409);
    const { data, error } = await admin.auth.admin.createUser({
      email, password,
      user_metadata: { name, phone },
      app_metadata: { role: "agent" },
      email_confirm: true,
    });
    if (error) return c.json({ error: error.message }, 400);
    const uid = data.user!.id;
    const matricule = await resolveAgentMatricule(uid);
    await audit(uid, "agent.created_by_admin", { email, by: r.admin.username });
    await adminAudit(c, r.admin, "agent.create", { agentId: uid, email, matricule });
    return c.json({ agent: { id: uid, email, name, phone, matricule } });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.patch(`${PREFIX}/admin/agents/:userId`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  const r = { admin: g.admin };
  const userId = c.req.param("userId");
  try {
    const body = await c.req.json().catch(() => ({}));
    const patch: any = {};
    if (typeof body?.name === "string" || typeof body?.phone === "string") {
      const { data: existing } = await admin.auth.admin.getUserById(userId);
      const prevMeta = (existing.user?.user_metadata ?? {}) as Record<string, unknown>;
      patch.user_metadata = {
        ...prevMeta,
        ...(typeof body.name === "string" ? { name: String(body.name).slice(0, 80) } : {}),
        ...(typeof body.phone === "string" ? { phone: String(body.phone).slice(0, 30) } : {}),
      };
    }
    if (typeof body?.banned === "boolean") {
      // 100 ans = ban permanent, "none" = lève le ban
      patch.ban_duration = body.banned ? "876000h" : "none";
    }
    if (typeof body?.password === "string" && body.password.length >= 8) {
      patch.password = body.password;
    }
    const { data, error } = await admin.auth.admin.updateUserById(userId, patch);
    if (error) return c.json({ error: error.message }, 400);
    await adminAudit(c, r.admin, "agent.update", { agentId: userId, fields: Object.keys(body ?? {}) });
    return c.json({ agent: { id: data.user!.id } });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// A16 — Révocation immédiate de toutes les sessions d'un conseiller.
// Invalide tous ses refresh tokens : il sera kické dès son prochain refresh
// (≤1h). Utile en cas de matériel volé / suspicion sans aller jusqu'au ban.
app.post(`${PREFIX}/admin/agents/:userId/sessions/revoke`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  const userId = c.req.param("userId");
  try {
    const { error } = await admin.auth.admin.signOut(userId, "global");
    if (error) return c.json({ error: error.message }, 400);
    await adminAudit(c, g.admin, "agent.sessions.revoke", { agentId: userId });
    return c.json({ ok: true });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.delete(`${PREFIX}/admin/agents/:userId`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  const r = { admin: g.admin };
  const userId = c.req.param("userId");
  try {
    // Libère la sentinelle matricule pour qu'elle puisse être réémise.
    const mat = await kv.get(`agent:matricule:${userId}`);
    if (mat) {
      await kv.del(`agent:matricule-claim:${mat}`);
      await kv.del(`agent:matricule:${userId}`);
    }
    await kv.del(`agent:presence:${userId}`);
    const { error } = await admin.auth.admin.deleteUser(userId);
    if (error) return c.json({ error: error.message }, 400);
    await adminAudit(c, r.admin, "agent.delete", { agentId: userId, matricule: mat });
    return c.json({ ok: true });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Round-robin auto-router: choisit un conseiller actuellement `online`
// (heartbeat <90s) pour assigner une nouvelle conversation. Le curseur est
// persisté en KV (`agent:router:cursor`) pour répartir équitablement entre
// connexions Edge Function. Retourne null si aucun agent éligible.
async function pickOnlineAgentMatricule(): Promise<string | null> {
  const { data, error } = await admin
    .from("kv_store_752d1a39")
    .select("key, value")
    .like("key", "agent:presence:%");
  if (error) {
    console.log(`router presence scan failed: ${error.message}`);
    return null;
  }
  const STALE_MS = 90_000;
  const now = Date.now();
  const onlineUids: string[] = [];
  for (const row of data ?? []) {
    const presence = (row.value ?? {}) as { status?: string; at?: string };
    if (presence.status !== "online") continue;
    const age = presence.at ? now - new Date(presence.at).getTime() : Infinity;
    if (age > STALE_MS) continue;
    onlineUids.push((row.key as string).slice("agent:presence:".length));
  }
  if (onlineUids.length === 0) return null;
  onlineUids.sort();
  const cursor = (await kv.get("agent:router:cursor")) as number | null;
  const idx = ((typeof cursor === "number" ? cursor : 0) + 1) % onlineUids.length;
  await kv.set("agent:router:cursor", idx);
  const matricule = (await kv.get(`agent:matricule:${onlineUids[idx]}`)) as string | null;
  return matricule ?? null;
}

app.get(`${PREFIX}/agent/presence`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const presence = (await kv.get(`agent:presence:${r.agent.id}`)) as AgentPresence | null;
  return c.json({ presence: presence ?? null });
});

// ---- AGENT: RESPONSE TEMPLATES (per-agent shortcuts) ----
// CRUD léger sur les templates de réponse personnels d'un conseiller (clé
// = matricule pour persister même si l'admin renomme/réassigne le compte).
type AgentTemplate = { id: string; title: string; body: string; updatedAt: string };

app.get(`${PREFIX}/agent/templates`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const list = ((await kv.get(k.agentTemplates(r.agent.matricule))) ?? []) as AgentTemplate[];
  return c.json({ templates: list });
});

app.post(`${PREFIX}/agent/templates`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const body = await c.req.json().catch(() => ({}));
    const title = String(body?.title ?? "").trim().slice(0, 80);
    const text = String(body?.body ?? "").trim().slice(0, 2000);
    if (!title || !text) return c.json({ error: "Titre et contenu requis" }, 400);
    const list = ((await kv.get(k.agentTemplates(r.agent.matricule))) ?? []) as AgentTemplate[];
    if (list.length >= 30) return c.json({ error: "Maximum 30 templates" }, 400);
    const tpl: AgentTemplate = { id: `tpl_${Date.now()}`, title, body: text, updatedAt: new Date().toISOString() };
    list.unshift(tpl);
    await kv.set(k.agentTemplates(r.agent.matricule), list);
    return c.json({ template: tpl });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.patch(`${PREFIX}/agent/templates/:id`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const id = c.req.param("id");
  try {
    const body = await c.req.json().catch(() => ({}));
    const list = ((await kv.get(k.agentTemplates(r.agent.matricule))) ?? []) as AgentTemplate[];
    const idx = list.findIndex((t) => t.id === id);
    if (idx === -1) return c.json({ error: "Introuvable" }, 404);
    if (typeof body?.title === "string") list[idx].title = body.title.trim().slice(0, 80) || list[idx].title;
    if (typeof body?.body === "string") list[idx].body = body.body.trim().slice(0, 2000) || list[idx].body;
    list[idx].updatedAt = new Date().toISOString();
    await kv.set(k.agentTemplates(r.agent.matricule), list);
    return c.json({ template: list[idx] });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.delete(`${PREFIX}/agent/templates/:id`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const id = c.req.param("id");
  const list = ((await kv.get(k.agentTemplates(r.agent.matricule))) ?? []) as AgentTemplate[];
  const next = list.filter((t) => t.id !== id);
  await kv.set(k.agentTemplates(r.agent.matricule), next);
  return c.json({ ok: true });
});

// ---- AGENT: CLAIMS (list + status change) ----
// Same shape as /admin/claims*. Status change writes the decider as
// `decidedBy = <agent username>` so the audit trail can distinguish agents
// from admins.
app.get(`${PREFIX}/agent/claims`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "claims:%");
    if (error) return c.json({ error: error.message }, 500);
    const flat: any[] = [];
    for (const row of data ?? []) {
      const uid = (row.key as string).slice("claims:".length);
      const profile = (await kv.get(k.profile(uid))) ?? {};
      for (const cl of (row.value ?? []) as any[]) {
        const attachments = await Promise.all(
          (cl.attachments ?? []).map(async (a: any) => {
            if (!a?.path) return a;
            const { data: signed, error: sErr } = await admin.storage
              .from(BUCKET)
              .createSignedUrl(a.path, 300);
            return { ...a, url: sErr ? null : signed.signedUrl };
          }),
        );
        flat.push({
          ...cl,
          attachments,
          userId: uid,
          userEmail: profile.email ?? "",
          userName: profile.name ?? "",
          memberNumber: profile.memberNumber ?? "",
        });
      }
    }
    flat.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    return c.json({ claims: flat });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: PORTFOLIOS (vue par conseiller) ----
// Pour chaque matricule émis, retourne : nom, charge (nb clients assignés),
// volume de paiements, dernière activité paiement. Utilisé par la vue admin
// « Conseillers » pour piloter la répartition de charge.
app.get(`${PREFIX}/admin/portfolios`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const [{ data: claimRows, error: e1 }, { data: metaRows, error: e2 }, { data: payRows, error: e3 }] =
      await Promise.all([
        admin.from("kv_store_752d1a39").select("key, value").like("key", "agent:matricule-claim:%"),
        admin.from("kv_store_752d1a39").select("key, value").like("key", "conv:meta:%"),
        admin.from("kv_store_752d1a39").select("key, value").like("key", "payments:%"),
      ]);
    if (e1 || e2 || e3) throw new Error(e1?.message || e2?.message || e3?.message);

    const matToUid = new Map<string, string>();
    for (const row of claimRows ?? []) {
      const mat = (row.key as string).slice("agent:matricule-claim:".length);
      matToUid.set(mat, String(row.value ?? ""));
    }
    const profiles = await kv.mget(Array.from(matToUid.values()).map((u) => k.profile(u)));
    const matToName = new Map<string, string>();
    let i = 0;
    for (const [mat] of matToUid) {
      matToName.set(mat, ((profiles[i] ?? {}) as any).name ?? "");
      i++;
    }
    const uidToAssignee = new Map<string, string>();
    for (const row of metaRows ?? []) {
      const uid = (row.key as string).slice("conv:meta:".length);
      const ass = (row.value as any)?.assignee;
      if (ass) uidToAssignee.set(uid, ass);
    }
    const stats = new Map<string, { clients: number; payments: number; lastPaymentAt: string | null }>();
    for (const mat of matToUid.keys()) stats.set(mat, { clients: 0, payments: 0, lastPaymentAt: null });
    for (const [uid, ass] of uidToAssignee) {
      const s = stats.get(ass);
      if (s) s.clients += 1;
    }
    let unassignedPayments = 0;
    for (const row of payRows ?? []) {
      const uid = (row.key as string).slice("payments:".length);
      const list = (row.value ?? []) as any[];
      const ass = uidToAssignee.get(uid);
      if (!ass) { unassignedPayments += list.length; continue; }
      const s = stats.get(ass);
      if (!s) continue;
      s.payments += list.length;
      for (const p of list) {
        if (!s.lastPaymentAt || String(p.createdAt) > s.lastPaymentAt) s.lastPaymentAt = String(p.createdAt);
      }
    }
    const portfolios = Array.from(stats.entries())
      .map(([matricule, s]) => ({
        matricule,
        name: matToName.get(matricule) ?? "",
        clients: s.clients,
        payments: s.payments,
        lastPaymentAt: s.lastPaymentAt,
      }))
      .sort((a, b) => b.clients - a.clients);
    return c.json({ portfolios, unassignedPayments });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- AGENT: ENCAISSEMENT MANUEL ----
// Le conseiller enregistre un paiement reçu en agence/espèces/virement pour un
// client. Statut « confirme » direct (déclencheurs side-effects identiques à
// un webhook KKiaPay). Tracé en audit avec matricule.
app.post(`${PREFIX}/agent/payments/:uid`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const g2 = await requireAgent2FA(c, r.agent.id);
  if (!g2.ok) return g2.response;
  const uid = c.req.param("uid");
  try {
    const body = await c.req.json();
    const amount = Number(body?.amount);
    const method = String(body?.method ?? "cash");
    const contractId = body?.contractId ? String(body.contractId) : undefined;
    const note = String(body?.note ?? "").slice(0, 200);
    if (!amount || amount <= 0) return c.json({ error: "Montant invalide" }, 400);
    if (!["cash", "agence", "virement", "carte"].includes(method)) {
      return c.json({ error: "Méthode invalide" }, 400);
    }
    const profile = (await kv.get(k.profile(uid))) as any;
    if (!profile) return c.json({ error: "Client introuvable" }, 404);
    const payments = ((await kv.get(k.payments(uid))) ?? []) as any[];
    const payment = {
      id: crypto.randomUUID(),
      amount,
      method,
      status: "confirme",
      currency: "XOF",
      contractId: contractId ?? null,
      createdAt: new Date().toISOString(),
      manual: true,
      collectedBy: r.agent.matricule,
      note,
    };
    payments.push(payment);
    await kv.set(k.payments(uid), payments);
    await applyPaymentSideEffects(uid, payment);
    await audit(uid, "agent.payment.manual", { amount, method, by: r.agent.matricule, paymentId: payment.id });
    await broadcast(`payments:live`, "payments:dirty", { reason: "agent_manual" });
    await broadcast(`payments:user:${uid}`, "payments:dirty", { reason: "agent_manual" });
    return c.json({ payment });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- AGENT: CYCLE DE VIE CONTRAT (F7) ----
// Renouvellement et résiliation assistés. Réutilise la même logique que
// /contracts/:id/renew et /contracts/:id/cancel côté client mais avec
// traçabilité conseiller (`actedBy`).
app.post(`${PREFIX}/agent/contracts/:uid/:contractId/:action`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  const contractId = c.req.param("contractId");
  const action = c.req.param("action");
  if (!["renew", "cancel"].includes(action)) return c.json({ error: "Action invalide" }, 400);
  try {
    const body = await c.req.json().catch(() => ({}));
    const reason = String(body?.reason ?? "").slice(0, 200);
    const contracts = ((await kv.get(k.contracts(uid))) ?? []) as any[];
    const idx = contracts.findIndex((c) => c.id === contractId);
    if (idx < 0) return c.json({ error: "Contrat introuvable" }, 404);
    const now = new Date().toISOString();
    if (action === "renew") {
      const newEnd = new Date(Date.now() + 365 * 86400000).toISOString();
      contracts[idx] = {
        ...contracts[idx],
        status: "active",
        endDate: newEnd,
        renewalNoticeSent: false,
        nextBillingDate: nextBillingFromNow(),
        lastRenewedAt: now,
        renewedBy: r.agent.matricule,
      };
    } else {
      contracts[idx] = {
        ...contracts[idx],
        status: "annule",
        cancelledAt: now,
        cancelledBy: r.agent.matricule,
        cancellationReason: reason,
        autoDebit: false,
        nextBillingDate: null,
      };
    }
    await kv.set(k.contracts(uid), contracts);
    const notifications = ((await kv.get(k.notifications(uid))) ?? []) as any[];
    await notifyAndDispatch(uid, notifications, {
      typeKey: "system",
      title: action === "renew" ? "Contrat renouvelé" : "Contrat résilié",
      body: action === "renew"
        ? `Votre conseiller a renouvelé « ${contracts[idx].product} » pour 12 mois.`
        : `Votre conseiller a résilié « ${contracts[idx].product} ». ${reason ? `Motif : ${reason}` : ""}`.trim(),
      severity: action === "renew" ? "success" : "info",
      to: "/espace-client/contrats",
      tag: `contract:${contractId}:${action}`,
    });
    await audit(uid, `agent.contract.${action}`, {
      contractId,
      by: r.agent.matricule,
      ...(action === "cancel" && reason ? { reason } : {}),
    });
    return c.json({ contract: contracts[idx] });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- AGENT: ÉDITION PROFIL CLIENT (F6) ----
// Permet à un conseiller de corriger les champs de contact d'un client (nom,
// téléphone, ville, adresse) — typiquement quand un client a fait une faute
// de frappe à l'inscription. Email + n° membre restent immuables (changements
// sensibles qui doivent passer par le client lui-même ou par l'admin).
app.patch(`${PREFIX}/agent/customer/:uid/profile`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  try {
    const body = await c.req.json();
    const current = (await kv.get(k.profile(uid))) as any;
    if (!current) return c.json({ error: "Client introuvable" }, 404);
    const allowed = ["name", "phone", "address", "city", "department", "country", "birthDate", "gender", "profession"];
    const patch: Record<string, any> = {};
    for (const f of allowed) {
      if (body[f] !== undefined) patch[f] = String(body[f] ?? "").slice(0, 200);
    }
    if (!Object.keys(patch).length) return c.json({ error: "Aucun champ à mettre à jour" }, 400);
    const next = { ...current, ...patch, updatedAt: new Date().toISOString() };
    await kv.set(k.profile(uid), next);
    await audit(uid, "agent.profile.update", { by: r.agent.matricule, fields: Object.keys(patch) });
    return c.json({ profile: next });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- AGENT: SOUSCRIPTION ASSISTÉE (T6) ----
// Le conseiller crée un contrat au nom d'un client (souscription en agence /
// téléphone). Même structure de contrat que /subscribe côté client, mais on
// trace `subscribedBy` (matricule) pour distinguer les souscriptions assistées
// dans le reporting et les audits.
app.post(`${PREFIX}/agent/subscribe/:uid`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const g2 = await requireAgent2FA(c, r.agent.id);
  if (!g2.ok) return g2.response;
  const uid = c.req.param("uid");
  try {
    const body = await c.req.json();
    const product = String(body?.product ?? "").trim().slice(0, 120);
    const frequency = String(body?.frequency ?? "mensuel").trim().slice(0, 20);
    const note = String(body?.note ?? "").trim().slice(0, 200);
    if (!product || product.length < 2) return c.json({ error: "Produit invalide" }, 400);
    if (!["mensuel", "trimestriel", "annuel"].includes(frequency)) {
      return c.json({ error: "Fréquence invalide" }, 400);
    }
    const profile = (await kv.get(k.profile(uid))) as any;
    if (!profile) return c.json({ error: "Client introuvable" }, 404);
    const now = new Date().toISOString();
    const contract = {
      id: `c_${Date.now()}`,
      product,
      status: "active",
      startDate: now,
      endDate: new Date(Date.now() + 365 * 86400000).toISOString(),
      premium: BILLING.dailyPerProduct * BILLING.daysPerMonth,
      currency: "XOF",
      frequency,
      autoDebit: true,
      nextBillingDate: nextBillingFromNow(),
      subscribedBy: r.agent.matricule,
      subscribedByName: r.agent.username,
      note: note || undefined,
    };
    const contracts = ((await kv.get(k.contracts(uid))) ?? []) as any[];
    contracts.unshift(contract);
    await kv.set(k.contracts(uid), contracts);
    const notifications = ((await kv.get(k.notifications(uid))) ?? []) as any[];
    await notifyAndDispatch(uid, notifications, {
      typeKey: "system",
      title: "Souscription confirmée",
      body: `Votre conseiller a activé le contrat « ${product} ».`,
      severity: "success",
      to: "/espace-client/contrats",
      tag: `contract:${contract.id}`,
    });
    await audit(uid, "agent.contract.subscribe", {
      product,
      frequency,
      contractId: contract.id,
      by: r.agent.matricule,
    });
    return c.json({ contract });
  } catch (err) {
    console.log(`Agent subscribe error for ${uid}: ${err}`);
    return c.json({ error: `Erreur de souscription: ${err}` }, 500);
  }
});

// ---- AGENT: UPLOAD DOCUMENT POUR LE CLIENT ----
// Le conseiller dépose un fichier (CNI, attestation, justificatif…) dans
// l'espace documents du client. Tracé `uploadedBy: matricule`, notifié au
// client, audité.
app.post(`${PREFIX}/agent/customer/:uid/documents`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  try {
    const profile = (await kv.get(k.profile(uid))) as any;
    if (!profile) return c.json({ error: "Client introuvable" }, 404);
    const form = await c.req.formData();
    const file = form.get("file");
    const label = String(form.get("label") ?? "").trim().slice(0, 120);
    const kind = String(form.get("kind") ?? "autre").trim().slice(0, 40);
    if (!(file instanceof File)) return c.json({ error: "Fichier manquant" }, 400);
    if (file.size > 10 * 1024 * 1024) return c.json({ error: "Fichier trop volumineux (10 Mo max)" }, 400);
    const id = crypto.randomUUID();
    const safeName = file.name.replace(/[^a-zA-Z0-9_.-]/g, "_");
    const path = `${uid}/docs/${id}/${Date.now()}-${safeName}`;
    const { error: uploadErr } = await admin.storage.from(BUCKET).upload(path, file, { contentType: file.type, upsert: false });
    if (uploadErr) return c.json({ error: `Erreur d'upload: ${uploadErr.message}` }, 500);
    const doc = {
      id,
      name: label || file.name,
      originalName: file.name,
      kind,
      path,
      size: file.size,
      contentType: file.type,
      createdAt: new Date().toISOString(),
      uploadedAt: new Date().toISOString(),
      uploadedBy: r.agent.matricule,
      uploadedByName: r.agent.username,
    };
    const documents = ((await kv.get(k.documents(uid))) ?? []) as any[];
    documents.unshift(doc);
    await kv.set(k.documents(uid), documents.slice(0, 500));
    const notifications = ((await kv.get(k.notifications(uid))) ?? []) as any[];
    await notifyAndDispatch(uid, notifications, {
      typeKey: "system",
      title: "Nouveau document disponible",
      body: `Votre conseiller a ajouté « ${doc.name} » à vos documents.`,
      severity: "info",
      to: "/espace-client/documents",
      tag: `doc:${id}`,
    });
    await audit(uid, "agent.document.upload", { docId: id, name: doc.name, kind, by: r.agent.matricule });
    return c.json({ document: doc });
  } catch (err) {
    console.log(`Agent doc upload error for ${uid}: ${err}`);
    return c.json({ error: `Erreur d'upload: ${err}` }, 500);
  }
});

app.get(`${PREFIX}/agent/customer/:uid/documents/url`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  const path = c.req.query("path");
  if (!path || !path.startsWith(`${uid}/`)) return c.json({ error: "Chemin invalide" }, 400);
  const { data, error: signErr } = await admin.storage.from(BUCKET).createSignedUrl(path, 300);
  if (signErr) return c.json({ error: signErr.message }, 500);
  return c.json({ url: data.signedUrl });
});

app.delete(`${PREFIX}/agent/customer/:uid/documents/:docId`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  const docId = c.req.param("docId");
  const documents = ((await kv.get(k.documents(uid))) ?? []) as any[];
  const doc = documents.find((d: any) => d.id === docId);
  if (!doc) return c.json({ error: "Document introuvable" }, 404);
  if (doc.path) {
    try { await admin.storage.from(BUCKET).remove([doc.path]); } catch { /* best effort */ }
  }
  const next = documents.filter((d: any) => d.id !== docId);
  await kv.set(k.documents(uid), next);
  await audit(uid, "agent.document.delete", { docId, name: doc.name, by: r.agent.matricule });
  return c.json({ ok: true });
});

// ---- AGENT: BÉNÉFICIAIRES (gestion depuis fiche client) ----
// Le conseiller peut ajouter / modifier / supprimer un bénéficiaire pour le
// compte du client. Toute action est notifiée au client, auditée et tracée
// au matricule du conseiller.
app.post(`${PREFIX}/agent/customer/:uid/beneficiaries`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  try {
    const profile = (await kv.get(k.profile(uid))) as any;
    if (!profile) return c.json({ error: "Client introuvable" }, 404);
    const body = await c.req.json();
    const name = String(body?.name ?? "").trim().slice(0, 120);
    const relation = String(body?.relation ?? "").trim().toLowerCase().slice(0, 30);
    const birthDate = body?.birthDate ? String(body.birthDate).slice(0, 10) : null;
    if (name.length < 2) return c.json({ error: "Nom invalide" }, 400);
    if (!relation) return c.json({ error: "Relation requise" }, 400);
    const beneficiary = {
      id: `b_${Date.now()}`,
      name,
      relation,
      birthDate,
      createdAt: new Date().toISOString(),
      createdBy: r.agent.matricule,
      createdByName: r.agent.username,
    };
    const list = ((await kv.get(k.beneficiaries(uid))) ?? []) as any[];
    list.push(beneficiary);
    await kv.set(k.beneficiaries(uid), list);
    const notifications = ((await kv.get(k.notifications(uid))) ?? []) as any[];
    await notifyAndDispatch(uid, notifications, {
      typeKey: "system",
      title: "Bénéficiaire ajouté",
      body: `Votre conseiller a ajouté ${name} (${relation}) à vos bénéficiaires.`,
      severity: "info",
      to: "/espace-client/beneficiaires",
      tag: `ben:${beneficiary.id}`,
    });
    await audit(uid, "agent.beneficiary.create", { id: beneficiary.id, name, relation, by: r.agent.matricule });
    return c.json({ beneficiary });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.patch(`${PREFIX}/agent/customer/:uid/beneficiaries/:id`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  const id = c.req.param("id");
  try {
    const body = await c.req.json();
    const list = ((await kv.get(k.beneficiaries(uid))) ?? []) as any[];
    const idx = list.findIndex((b: any) => b.id === id);
    if (idx === -1) return c.json({ error: "Bénéficiaire introuvable" }, 404);
    const patch: Record<string, unknown> = {};
    if (typeof body?.name === "string") patch.name = body.name.trim().slice(0, 120);
    if (typeof body?.relation === "string") patch.relation = body.relation.trim().toLowerCase().slice(0, 30);
    if (typeof body?.birthDate === "string" || body?.birthDate === null) {
      patch.birthDate = body.birthDate ? String(body.birthDate).slice(0, 10) : null;
    }
    if (Object.keys(patch).length === 0) return c.json({ error: "Aucun champ à modifier" }, 400);
    const updated = { ...list[idx], ...patch, updatedAt: new Date().toISOString(), updatedBy: r.agent.matricule };
    list[idx] = updated;
    await kv.set(k.beneficiaries(uid), list);
    const notifications = ((await kv.get(k.notifications(uid))) ?? []) as any[];
    await notifyAndDispatch(uid, notifications, {
      typeKey: "system",
      title: "Bénéficiaire mis à jour",
      body: `Votre conseiller a mis à jour le bénéficiaire ${updated.name}.`,
      severity: "info",
      to: "/espace-client/beneficiaires",
      tag: `ben:${id}`,
    });
    await audit(uid, "agent.beneficiary.update", { id, fields: Object.keys(patch), by: r.agent.matricule });
    return c.json({ beneficiary: updated });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.delete(`${PREFIX}/agent/customer/:uid/beneficiaries/:id`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  const id = c.req.param("id");
  const list = ((await kv.get(k.beneficiaries(uid))) ?? []) as any[];
  const removed = list.find((b: any) => b.id === id);
  if (!removed) return c.json({ error: "Bénéficiaire introuvable" }, 404);
  const next = list.filter((b: any) => b.id !== id);
  await kv.set(k.beneficiaries(uid), next);
  const notifications = ((await kv.get(k.notifications(uid))) ?? []) as any[];
  await notifyAndDispatch(uid, notifications, {
    typeKey: "system",
    title: "Bénéficiaire retiré",
    body: `Votre conseiller a retiré ${removed.name} de vos bénéficiaires.`,
    severity: "warning",
    to: "/espace-client/beneficiaires",
    tag: `ben:${id}`,
  });
  await audit(uid, "agent.beneficiary.delete", { id, name: removed.name, by: r.agent.matricule });
  return c.json({ ok: true });
});

// ---- AGENT: NOTES INTERNES (privées conseiller, invisibles client) ----
// Liste/ajout/suppression de notes sur la fiche d'un client. Stockées dans
// `agent:notes:<uid>` (jamais exposées par /me ou /customer côté client).
app.get(`${PREFIX}/agent/notes/:uid`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  const notes = ((await kv.get(k.agentNotes(uid))) ?? []) as any[];
  return c.json({ notes });
});
app.post(`${PREFIX}/agent/notes/:uid`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  try {
    const body = await c.req.json();
    const text = String(body?.text ?? "").trim().slice(0, 4000);
    if (!text) return c.json({ error: "Note vide" }, 400);
    const notes = ((await kv.get(k.agentNotes(uid))) ?? []) as any[];
    const note = {
      id: crypto.randomUUID(),
      text,
      authorMatricule: r.agent.matricule,
      authorName: r.agent.username,
      createdAt: new Date().toISOString(),
    };
    notes.push(note);
    await kv.set(k.agentNotes(uid), notes.slice(-200));
    return c.json({ note });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});
app.delete(`${PREFIX}/agent/notes/:uid/:noteId`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  const noteId = c.req.param("noteId");
  const notes = ((await kv.get(k.agentNotes(uid))) ?? []) as any[];
  const next = notes.filter((n: any) => n.id !== noteId);
  await kv.set(k.agentNotes(uid), next);
  return c.json({ ok: true });
});

// ---- AGENT: NOTIFICATIONS INTERNES (F5) ----
// File de notifications par conseiller (assignations, escalades, mentions).
// Stockée dans `agent:notifs:<matricule>`, bornée à 100 entrées. Broadcasts
// realtime via `agent:notifs:<matricule>` pour bip immédiat dans la console.
async function pushAgentNotif(matricule: string, notif: {
  type: "assignment" | "mention" | "escalation" | "system";
  title: string;
  body?: string;
  url?: string;
}) {
  if (!matricule) return;
  const key = k.agentNotifs(matricule);
  const list = ((await kv.get(key)) ?? []) as any[];
  const entry = {
    id: crypto.randomUUID(),
    ...notif,
    createdAt: new Date().toISOString(),
    read: false,
  };
  list.unshift(entry);
  await kv.set(key, list.slice(0, 100));
  await broadcast(`agent:notifs:${matricule}`, "notif:new", { id: entry.id, type: entry.type });
}

app.get(`${PREFIX}/agent/notifs`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const list = ((await kv.get(k.agentNotifs(r.agent.matricule))) ?? []) as any[];
  const unread = list.filter((n: any) => !n.read).length;
  return c.json({ notifs: list, unread });
});

app.post(`${PREFIX}/agent/notifs/read-all`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const list = ((await kv.get(k.agentNotifs(r.agent.matricule))) ?? []) as any[];
  const next = list.map((n: any) => ({ ...n, read: true }));
  await kv.set(k.agentNotifs(r.agent.matricule), next);
  return c.json({ ok: true });
});

app.post(`${PREFIX}/agent/notifs/:id/read`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const id = c.req.param("id");
  const list = ((await kv.get(k.agentNotifs(r.agent.matricule))) ?? []) as any[];
  const next = list.map((n: any) => n.id === id ? { ...n, read: true } : n);
  await kv.set(k.agentNotifs(r.agent.matricule), next);
  return c.json({ ok: true });
});

// ---- AGENT: PROFIL CONSEILLER (F4) ----
// Photo, signature mail/sms, téléphone direct, nom affiché. Stocké dans
// `agent:profile:<matricule>`. La signature est injectée par les pages
// d'envoi (mail Resend / SMS Termii) si elle est définie.
app.get(`${PREFIX}/agent/profile`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const profile = (await kv.get(k.agentProfile(r.agent.matricule))) ?? {
    displayName: r.agent.username,
    phone: "",
    avatarUrl: "",
    signature: "",
  };
  return c.json({ profile });
});

app.patch(`${PREFIX}/agent/profile`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const body = await c.req.json();
    const current = (await kv.get(k.agentProfile(r.agent.matricule))) ?? {};
    const next = {
      ...current,
      displayName: body.displayName !== undefined ? String(body.displayName).trim().slice(0, 80) : current.displayName,
      phone: body.phone !== undefined ? String(body.phone).trim().slice(0, 30) : current.phone,
      avatarUrl: body.avatarUrl !== undefined ? String(body.avatarUrl).trim().slice(0, 500) : current.avatarUrl,
      signature: body.signature !== undefined ? String(body.signature).slice(0, 1000) : current.signature,
      updatedAt: new Date().toISOString(),
    };
    await kv.set(k.agentProfile(r.agent.matricule), next);
    return c.json({ profile: next });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- AGENT: RECHERCHE GLOBALE TRANSVERSE (F3) ----
// Recherche un client par nom, email, téléphone, n° de membre. Renvoie au
// plus 20 résultats. Implémentation : scan des profiles + filtre en mémoire.
// Acceptable car la base reste de l'ordre du millier de clients ; au-delà,
// passer à une vue Postgres avec index trigram.
app.get(`${PREFIX}/agent/search`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const q = (c.req.query("q") ?? "").trim().toLowerCase();
  if (q.length < 2) return c.json({ results: [] });
  try {
    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "profile:%");
    if (error) return c.json({ error: error.message }, 500);
    const out: any[] = [];
    for (const row of data ?? []) {
      const uid = (row.key as string).slice("profile:".length);
      const p = (row.value ?? {}) as any;
      const hay = `${p.name ?? ""} ${p.email ?? ""} ${p.phone ?? ""} ${p.memberNumber ?? ""} ${p.city ?? ""}`.toLowerCase();
      if (!hay.includes(q)) continue;
      out.push({
        userId: uid,
        name: p.name ?? "",
        email: p.email ?? "",
        phone: p.phone ?? "",
        memberNumber: p.memberNumber ?? "",
        city: p.city ?? "",
      });
      if (out.length >= 20) break;
    }
    return c.json({ results: out });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- AGENT: TÂCHES & RAPPELS PERSONNELS (F2) ----
// To-do list privée par conseiller (ne sort jamais de sa session). Stockée
// dans `agent:tasks:<matricule>` sous forme de liste bornée à 200 entrées.
// Chaque tâche peut référencer un client (userId) pour deep-link vers la fiche.
app.get(`${PREFIX}/agent/tasks`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const tasks = ((await kv.get(k.agentTasks(r.agent.matricule))) ?? []) as any[];
  return c.json({ tasks });
});

app.post(`${PREFIX}/agent/tasks`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const body = await c.req.json();
    const title = String(body?.title ?? "").trim().slice(0, 200);
    const dueAt = body?.dueAt ? String(body.dueAt).slice(0, 40) : null;
    const userId = body?.userId ? String(body.userId).slice(0, 64) : null;
    if (!title) return c.json({ error: "Titre requis" }, 400);
    const task = {
      id: crypto.randomUUID(),
      title,
      dueAt,
      userId,
      done: false,
      createdAt: new Date().toISOString(),
      completedAt: null as string | null,
    };
    const tasks = ((await kv.get(k.agentTasks(r.agent.matricule))) ?? []) as any[];
    tasks.unshift(task);
    await kv.set(k.agentTasks(r.agent.matricule), tasks.slice(0, 200));
    return c.json({ task });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.patch(`${PREFIX}/agent/tasks/:id`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const id = c.req.param("id");
  try {
    const body = await c.req.json();
    const tasks = ((await kv.get(k.agentTasks(r.agent.matricule))) ?? []) as any[];
    const idx = tasks.findIndex((t) => t.id === id);
    if (idx < 0) return c.json({ error: "Tâche introuvable" }, 404);
    const patch: any = {};
    if (typeof body?.done === "boolean") {
      patch.done = body.done;
      patch.completedAt = body.done ? new Date().toISOString() : null;
    }
    if (typeof body?.title === "string") patch.title = String(body.title).trim().slice(0, 200);
    if (body?.dueAt !== undefined) patch.dueAt = body.dueAt ? String(body.dueAt).slice(0, 40) : null;
    tasks[idx] = { ...tasks[idx], ...patch };
    await kv.set(k.agentTasks(r.agent.matricule), tasks);
    return c.json({ task: tasks[idx] });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.delete(`${PREFIX}/agent/tasks/:id`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const id = c.req.param("id");
  const tasks = ((await kv.get(k.agentTasks(r.agent.matricule))) ?? []) as any[];
  const next = tasks.filter((t) => t.id !== id);
  await kv.set(k.agentTasks(r.agent.matricule), next);
  return c.json({ ok: true });
});

// ---- ADMIN: REBALANCE (round-robin des conversations non attribuées) ----
// Récupère toutes les conv:meta:* sans assignee et les distribue en round-robin
// parmi les conseillers actifs (présence online et non bannis). Idempotent au
// sens où relancer juste après n'a aucun effet (plus rien à attribuer).
// Admin : (ré)attribue manuellement un client à un conseiller (enrôleur).
// Cas typiques : client signé sans lien d'invitation et qu'on veut rattacher,
// transfert de portefeuille suite à un départ, correction d'une attribution
// erronée. Vide la valeur (matricule = "") pour détacher.
app.patch(`${PREFIX}/admin/members/:userId/enroller`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const userId = c.req.param("userId");
  try {
    const body = await c.req.json().catch(() => ({}));
    const raw = String(body.matricule ?? "").toUpperCase().trim();
    const profile = ((await kv.get(k.profile(userId))) ?? null) as any;
    if (!profile) return c.json({ error: "Client introuvable" }, 404);
    const prev = profile.enrolledBy ?? null;
    let nextMatricule: string | null = null;
    let nextUid: string | null = null;
    if (raw) {
      const ownerUid = (await kv.get(`agent:matricule-claim:${raw}`)) as string | null;
      if (!ownerUid) return c.json({ error: `Matricule ${raw} inconnu` }, 404);
      nextMatricule = raw;
      nextUid = ownerUid;
    }
    const now = new Date().toISOString();
    await kv.set(k.profile(userId), {
      ...profile,
      enrolledBy: nextMatricule,
      enrolledByUid: nextUid,
      enrolledAt: nextMatricule ? now : null,
      enrolledSource: nextMatricule ? "admin-manual" : null,
    });
    await audit(userId, "enrollment.reassigned", { from: prev, to: nextMatricule, by: `admin:${r.admin.username}` });
    if (nextMatricule) {
      await pushAgentNotif(nextMatricule, {
        type: "assignment",
        title: "Nouveau filleul (admin)",
        body: `Le client ${profile.name || profile.email} vous a été attribué par l'administration.`,
        url: "/agent/portefeuille",
      }).catch(() => {});
    }
    return c.json({ ok: true, enrolledBy: nextMatricule, previous: prev });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.post(`${PREFIX}/admin/portfolios/rebalance`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const dryRun = c.req.query("dryRun") === "1";
    const [{ data: claimRows }, { data: metaRows }] = await Promise.all([
      admin.from("kv_store_752d1a39").select("key, value").like("key", "agent:matricule-claim:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "conv:meta:%"),
    ]);
    // Conseillers candidats : matricule -> userId, filtré sur présence online et profil non banni
    const candidates: { matricule: string; userId: string }[] = [];
    for (const row of claimRows ?? []) {
      const mat = (row.key as string).slice("agent:matricule-claim:".length);
      const uid = String(row.value ?? "");
      if (!uid) continue;
      const presence = (await kv.get(`agent:presence:${uid}`)) as any;
      if (!presence || presence.status !== "online") continue;
      const profile = (await kv.get(k.profile(uid))) as any;
      if (profile?.banned) continue;
      candidates.push({ matricule: mat, userId: uid });
    }
    if (!candidates.length) return c.json({ error: "Aucun conseiller en ligne disponible pour le rebalance." }, 400);

    const unassigned = (metaRows ?? []).filter((row) => {
      const v = (row.value as any) ?? {};
      return !v.assignee;
    });
    let i = 0;
    const assignments: { userId: string; matricule: string }[] = [];
    for (const row of unassigned) {
      const uid = (row.key as string).slice("conv:meta:".length);
      const target = candidates[i % candidates.length];
      assignments.push({ userId: uid, matricule: target.matricule });
      if (!dryRun) {
        const next = { ...((row.value as any) ?? {}), assignee: target.matricule, updatedAt: new Date().toISOString() };
        await kv.set(k.conversationMeta(uid), next);
        await audit(uid, "conversation.rebalance", { by: r.admin.username, assignee: target.matricule });
      }
      i++;
    }
    if (!dryRun && assignments.length) {
      await broadcast(`assignments:live`, "assignments:dirty", { rebalance: true, count: assignments.length });
    }
    return c.json({ rebalanced: assignments.length, candidates: candidates.length, assignments, dryRun });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- AGENT: PEERS (liste des conseillers pour réassignation) ----
// Tous les matricules réellement émis (sentinelle agent:matricule-claim:*),
// hydratés avec le nom usuel. Utilisé par le sélecteur de réassignation pour
// éviter de saisir un matricule à la main.
app.get(`${PREFIX}/agent/peers`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const { data: rows, error: e } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "agent:matricule-claim:%");
    if (e) throw new Error(e.message);
    const out: { matricule: string; userId: string; name: string }[] = [];
    const uids: string[] = [];
    const mats: string[] = [];
    for (const row of rows ?? []) {
      const mat = (row.key as string).slice("agent:matricule-claim:".length);
      const uid = String(row.value ?? "");
      if (!uid) continue;
      mats.push(mat);
      uids.push(uid);
    }
    const profiles = uids.length ? await kv.mget(uids.map((u) => k.profile(u))) : [];
    for (let i = 0; i < uids.length; i++) {
      const profile = (profiles[i] ?? {}) as any;
      out.push({ matricule: mats[i], userId: uids[i], name: profile.name ?? "" });
    }
    out.sort((a, b) => a.matricule.localeCompare(b.matricule));
    return c.json({ peers: out });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- AGENT: PORTFOLIO (clients assignés au conseiller courant) ----
// Liste plate des uids dont la conversation a `meta.assignee === matricule`,
// hydratée avec profil + dernière activité, pour navigation directe depuis
// l'app conseiller (sans repasser par la liste globale des conversations).
// ---- AGENT: DASHBOARD (KPIs du jour) ----
// Agrégation en une seule requête de tout ce qu'un conseiller a besoin
// d'attaquer à la prise de poste : messages non lus (sur son portefeuille et
// global), sinistres ouverts, paiements en attente, KYC en file, contrats
// souscrits aujourd'hui, encaissements du jour. Conçu pour être appelé toutes
// les ~60 s par le shell agent — chaque sous-section utilise un préfixe KV
// dédié (4 scans) puis filtre en mémoire.
app.get(`${PREFIX}/agent/dashboard`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const mat = r.agent.matricule;
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const todayIso = today.toISOString();

    // 1) Conversations : portefeuille du conseiller = uids assignés à son matricule.
    const { data: metaRows } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "conv:meta:%");
    const mineUids = new Set<string>();
    let openConversations = 0;
    for (const row of metaRows ?? []) {
      const v = (row.value ?? {}) as any;
      if (v.assignee === mat) mineUids.add((row.key as string).slice("conv:meta:".length));
      if (v.status === "ouvert" || v.status === "en_cours") openConversations++;
    }

    // 2) Messages : on scanne les conversations et compte les unread (mine vs all).
    const { data: msgRows } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "messages:%");
    let unreadMine = 0, unreadAll = 0;
    for (const row of msgRows ?? []) {
      const uid = (row.key as string).slice("messages:".length);
      const list = (row.value ?? []) as any[];
      const u = list.filter((m) => m?.from === "user" && !m?.read).length;
      unreadAll += u;
      if (mineUids.has(uid)) unreadMine += u;
    }

    // 3) Sinistres en file (soumis / en_cours / en_examen) — global + mine.
    const { data: claimRows } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "claims:%");
    let claimsOpenAll = 0, claimsOpenMine = 0;
    const OPEN = new Set(["soumis", "en_cours", "en_examen"]);
    for (const row of claimRows ?? []) {
      const uid = (row.key as string).slice("claims:".length);
      const list = (row.value ?? []) as any[];
      const open = list.filter((cl) => OPEN.has(cl?.status)).length;
      claimsOpenAll += open;
      if (mineUids.has(uid)) claimsOpenMine += open;
    }

    // 4) KYC pending.
    const { data: kycRows } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "kyc:%");
    let kycPendingAll = 0, kycPendingMine = 0;
    for (const row of kycRows ?? []) {
      const uid = (row.key as string).slice("kyc:".length);
      const list = (row.value ?? []) as any[];
      const p = list.filter((kk) => kk?.status === "pending").length;
      kycPendingAll += p;
      if (mineUids.has(uid)) kycPendingMine += p;
    }

    // 5) Paiements : pending + confirmés du jour + contrats souscrits du jour.
    const { data: payRows } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "payments:%");
    let paymentsPendingAll = 0, paymentsPendingMine = 0;
    let paidTodayAll = 0, paidTodayMine = 0;
    for (const row of payRows ?? []) {
      const uid = (row.key as string).slice("payments:".length);
      const list = (row.value ?? []) as any[];
      for (const p of list) {
        if (p?.status === "en_attente") {
          paymentsPendingAll++;
          if (mineUids.has(uid)) paymentsPendingMine++;
        }
        if (p?.status === "confirme" && p?.createdAt >= todayIso) {
          const amt = Number(p.amount ?? 0);
          paidTodayAll += amt;
          if (mineUids.has(uid)) paidTodayMine += amt;
        }
      }
    }

    // 6) Contrats souscrits aujourd'hui (utile pour le rapport quotidien).
    const { data: ctRows } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "contracts:%");
    let contractsTodayAll = 0, contractsTodayMine = 0, contractsBySelfToday = 0;
    for (const row of ctRows ?? []) {
      const uid = (row.key as string).slice("contracts:".length);
      const list = (row.value ?? []) as any[];
      for (const ct of list) {
        if (ct?.startDate >= todayIso) {
          contractsTodayAll++;
          if (mineUids.has(uid)) contractsTodayMine++;
          if (ct?.subscribedBy === mat) contractsBySelfToday++;
        }
      }
    }

    return c.json({
      generatedAt: new Date().toISOString(),
      portfolioSize: mineUids.size,
      mine: {
        unreadMessages: unreadMine,
        claimsOpen: claimsOpenMine,
        kycPending: kycPendingMine,
        paymentsPending: paymentsPendingMine,
        paidTodayAmount: paidTodayMine,
        contractsToday: contractsTodayMine,
        contractsBySelfToday,
      },
      all: {
        unreadMessages: unreadAll,
        openConversations,
        claimsOpen: claimsOpenAll,
        kycPending: kycPendingAll,
        paymentsPending: paymentsPendingAll,
        paidTodayAmount: paidTodayAll,
        contractsToday: contractsTodayAll,
      },
    });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- AGENT: PERFORMANCE PERSONNELLE ----
// Compteurs sur fenêtre glissante (7/30/90 j) pour le matricule connecté :
// sinistres décidés, contrats souscrits, KYC tranchés, paiements encaissés
// manuellement, messages envoyés. Sert au tableau de performance.
app.get(`${PREFIX}/agent/me/performance`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const mat = r.agent.matricule;
    const days = Math.min(Math.max(Number(c.req.query("days") ?? 30) || 30, 1), 365);
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const [{ data: claimRows }, { data: ctRows }, { data: kycRows }, { data: payRows }, { data: msgRows }] = await Promise.all([
      admin.from("kv_store_752d1a39").select("key, value").like("key", "claims:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "contracts:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "kyc:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "payments:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "messages:%"),
    ]);

    let claimsDecided = 0, claimsValidated = 0, claimsRejected = 0, claimsSettled = 0;
    for (const row of claimRows ?? []) {
      const list = (row.value ?? []) as any[];
      for (const cl of list) {
        if (cl?.decidedBy === mat && cl?.decidedAt && cl.decidedAt >= since) {
          claimsDecided++;
          if (cl.status === "valide") claimsValidated++;
          else if (cl.status === "rejete") claimsRejected++;
          else if (cl.status === "regle") claimsSettled++;
        }
      }
    }

    let contractsSubscribed = 0, contractsRenewed = 0, contractsCancelled = 0;
    for (const row of ctRows ?? []) {
      const list = (row.value ?? []) as any[];
      for (const ct of list) {
        if (ct?.subscribedBy === mat && (ct?.startDate ?? "") >= since) contractsSubscribed++;
        if (ct?.renewedBy === mat && (ct?.lastRenewedAt ?? "") >= since) contractsRenewed++;
        if (ct?.cancelledBy === mat && (ct?.cancelledAt ?? "") >= since) contractsCancelled++;
      }
    }

    let kycDecided = 0, kycValidated = 0, kycRejected = 0;
    for (const row of kycRows ?? []) {
      const list = (row.value ?? []) as any[];
      for (const kk of list) {
        if (kk?.decidedByMatricule === mat && kk?.decidedAt && kk.decidedAt >= since) {
          kycDecided++;
          if (kk.status === "valide") kycValidated++;
          else if (kk.status === "rejete") kycRejected++;
        }
      }
    }

    let paymentsRecorded = 0, paymentsAmount = 0;
    for (const row of payRows ?? []) {
      const list = (row.value ?? []) as any[];
      for (const p of list) {
        if (p?.collectedBy === mat && (p?.createdAt ?? "") >= since && p?.status === "confirme") {
          paymentsRecorded++;
          paymentsAmount += Number(p.amount ?? 0);
        }
      }
    }

    let messagesSent = 0;
    let totalResponseMs = 0, responsePairs = 0;
    for (const row of msgRows ?? []) {
      const list = (row.value ?? []) as any[];
      let lastUserAt: number | null = null;
      for (const m of list) {
        if (m?.from === "user") {
          lastUserAt = new Date(m.createdAt).getTime();
        } else if (m?.from === "conseiller") {
          const matchesMe = m?.authorMatricule === mat || (!m?.authorMatricule && m?.author === r.agent.username);
          if (matchesMe && (m?.createdAt ?? "") >= since) {
            messagesSent++;
            if (lastUserAt) {
              const dt = new Date(m.createdAt).getTime() - lastUserAt;
              if (dt > 0 && dt < 7 * 86400000) { totalResponseMs += dt; responsePairs++; }
              lastUserAt = null;
            }
          } else {
            lastUserAt = null;
          }
        }
      }
    }
    const avgResponseSec = responsePairs > 0 ? Math.round(totalResponseMs / responsePairs / 1000) : null;

    return c.json({
      agent: { matricule: mat, name: r.agent.username },
      days,
      since,
      generatedAt: new Date().toISOString(),
      claims: { decided: claimsDecided, validated: claimsValidated, rejected: claimsRejected, settled: claimsSettled },
      contracts: { subscribed: contractsSubscribed, renewed: contractsRenewed, cancelled: contractsCancelled },
      kyc: { decided: kycDecided, validated: kycValidated, rejected: kycRejected },
      payments: { recorded: paymentsRecorded, amount: paymentsAmount },
      messages: { sent: messagesSent, avgResponseSec },
    });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Agent enrôle un client : crée un compte Supabase + profil, pose
// enrolledBy = matricule du conseiller appelant. Empêche les emails déjà
// existants (clients ou conseillers) avec un message désambiguïsé. Le mot
// de passe est temporaire ; le client peut le réinitialiser via le flow
// standard. Auto-confirme l'email (pas de serveur SMTP configuré).
app.post(`${PREFIX}/agent/clients`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const body = await c.req.json().catch(() => ({}));
    const email = String(body.email ?? "").trim().toLowerCase();
    const password = String(body.password ?? "").trim();
    const name = String(body.name ?? "").trim();
    const phone = String(body.phone ?? "").trim();
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return c.json({ error: "Email invalide" }, 400);
    if (!name || name.length < 2) return c.json({ error: "Nom requis (min. 2 caractères)" }, 400);
    if (!password || password.length < 8) return c.json({ error: "Mot de passe temporaire trop court (8 caractères min.)" }, 400);
    const existingUid = await kv.get(k.emailToUid(email));
    if (existingUid) {
      const isAgent = !!(await kv.get(`agent:matricule:${existingUid}`));
      return c.json({
        error: isAgent
          ? "Cet email correspond à un compte conseiller IPPOO — il ne peut pas être enrôlé comme client."
          : "Cet email a déjà un compte client IPPOO.",
      }, 409);
    }
    const { data, error } = await admin.auth.admin.createUser({
      email,
      password,
      user_metadata: { name, phone, profileType: "particulier", enrolledByMatricule: r.agent.matricule },
      email_confirm: true,
    });
    if (error) return c.json({ error: error.message }, 400);
    const uid = data.user!.id;
    const now = new Date().toISOString();
    const memberNumber = await assignMemberNumber(uid);
    await kv.set(k.emailToUid(email), uid);
    await kv.set(k.profile(uid), {
      id: uid,
      email,
      name,
      phone,
      memberNumber,
      createdAt: now,
      type: "particulier",
      country: "BJ",
      countryDial: "229",
      enrolledBy: r.agent.matricule,
      enrolledByUid: r.agent.id,
      enrolledAt: now,
      enrolledSource: "agent-console",
    });
    await kv.set(k.contracts(uid), []);
    await kv.set(k.claims(uid), []);
    await kv.set(k.payments(uid), []);
    await kv.set(k.beneficiaries(uid), []);
    await kv.set(k.documents(uid), []);
    await setNotifications(uid, notify([], "Bienvenue chez IPPOO", `Votre conseiller ${r.agent.matricule} a créé votre espace. Vous pouvez vous connecter dès maintenant.`, "success"));
    await kv.set(k.messages(uid), []);
    await kv.set(k.settings(uid), { lang: "fr", notifySms: true, notifyEmail: true });
    const code = makeReferralCode(name);
    await kv.set(k.referralCode(uid), code);
    await kv.set(k.referralByCode(code), uid);
    await audit(uid, "signup", { email, by: `agent:${r.agent.matricule}` });
    await audit(uid, "enrollment.attributed", { matricule: r.agent.matricule, source: "agent-console" });
    return c.json({ ok: true, userId: uid, memberNumber, email });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.get(`${PREFIX}/agent/portfolio`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const { data: metaRows, error: metaErr } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "conv:meta:%");
    if (metaErr) throw new Error(metaErr.message);
    const mat = r.agent.matricule;
    const assignedUids = (metaRows ?? [])
      .filter((row) => (row.value as any)?.assignee === mat)
      .map((row) => (row.key as string).slice("conv:meta:".length));
    // Union avec les filleuls (profile.enrolledBy === mat). Permet au toggle
    // « Mes filleuls » de voir les comptes qu'on a enrôlés même si la conv n'a
    // pas encore été assignée (auto-dispatch ou silence du client).
    const { data: profileRows } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "profile:%");
    const enrolledUids = (profileRows ?? [])
      .filter((row) => (row.value as any)?.enrolledBy === mat)
      .map((row) => (row.key as string).slice("profile:".length));
    const uids = Array.from(new Set([...assignedUids, ...enrolledUids]));
    if (!uids.length) return c.json({ clients: [] });
    const assignedSet = new Set(assignedUids);
    const profiles = await kv.mget(uids.map((u) => k.profile(u)));
    const convos = await kv.mget(uids.map((u) => k.messages(u)));
    const clients = uids.map((uid, i) => {
      const profile = (profiles[i] ?? {}) as any;
      const conv = (convos[i] ?? []) as any[];
      const last = conv[conv.length - 1];
      return {
        userId: uid,
        userEmail: profile.email ?? "",
        userName: profile.name ?? "",
        memberNumber: profile.memberNumber ?? "",
        lastMessageAt: last?.createdAt ?? null,
        lastMessagePreview: last?.body ? String(last.body).slice(0, 80) : "",
        enrolledBy: profile.enrolledBy ?? null,
        enrolledAt: profile.enrolledAt ?? null,
        enrolledSource: profile.enrolledSource ?? null,
        assigned: assignedSet.has(uid),
      };
    });
    clients.sort((a, b) => String(b.lastMessageAt ?? "").localeCompare(String(a.lastMessageAt ?? "")));
    return c.json({ clients });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- AGENT: PAYMENTS (read-only, all users) ----
// Used by the agent calendar / payment tracking view. Same flat shape as
// /admin/payments but agent-scoped (requireAgent) so conseillers can monitor
// daily collections across their portfolio without needing admin rights.
app.get(`${PREFIX}/agent/payments`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const limit = parseInt(c.req.query("limit") ?? "100", 10);
    const before = c.req.query("before") ?? undefined;
    const mine = c.req.query("mine") === "1";
    let allowUids: Set<string> | undefined;
    if (mine) {
      // Portefeuille du conseiller : on collecte les conversations dont le
      // meta.assignee correspond au matricule du conseiller courant, puis
      // on filtre les paiements aux uids ainsi obtenus.
      const { data: metaRows, error: metaErr } = await admin
        .from("kv_store_752d1a39")
        .select("key, value")
        .like("key", "conv:meta:%");
      if (metaErr) throw new Error(metaErr.message);
      const mat = r.agent.matricule;
      allowUids = new Set(
        (metaRows ?? [])
          .filter((row) => (row.value as any)?.assignee === mat)
          .map((row) => (row.key as string).slice("conv:meta:".length)),
      );
    }
    const res = await listAllPaymentsPaginated({ limit: isNaN(limit) ? 100 : limit, before, includeMemberNumber: true, allowUids });
    // Marquer chaque paiement comme appartenant ou non au portefeuille du
    // conseiller courant (pour badge UI). Quand `mine=1`, tout est in.
    if (mine) {
      for (const p of res.payments as any[]) p.inPortfolio = true;
    } else {
      try {
        const { data: metaRows } = await admin
          .from("kv_store_752d1a39")
          .select("key, value")
          .like("key", "conv:meta:%");
        const mat = r.agent.matricule;
        const portfolioUids = new Set(
          (metaRows ?? [])
            .filter((row) => (row.value as any)?.assignee === mat)
            .map((row) => (row.key as string).slice("conv:meta:".length)),
        );
        for (const p of res.payments as any[]) p.inPortfolio = portfolioUids.has(p.userId);
      } catch { /* best-effort */ }
    }
    // Mini-stats portefeuille : on calcule combien de paiements totaux
    // appartiennent au portefeuille du conseiller courant vs hors portefeuille.
    // On fait toujours le scan conv:meta:* (même si !mine) pour pré-remplir le
    // toggle UI côté agent.
    let inPortfolio = 0;
    let outPortfolio = 0;
    try {
      const { data: metaRows } = await admin
        .from("kv_store_752d1a39")
        .select("key, value")
        .like("key", "conv:meta:%");
      const mat = r.agent.matricule;
      const portfolioUids = new Set(
        (metaRows ?? [])
          .filter((row) => (row.value as any)?.assignee === mat)
          .map((row) => (row.key as string).slice("conv:meta:".length)),
      );
      // Si `mine` est actif on a déjà filtré : tout dans `total` est portefeuille.
      // Sinon, on compte sur l'ensemble (re-scan payments:%) pour donner le vrai total.
      if (mine) {
        inPortfolio = res.total;
        const { data: allPay } = await admin
          .from("kv_store_752d1a39")
          .select("key, value")
          .like("key", "payments:%");
        for (const row of allPay ?? []) {
          const uid = (row.key as string).slice("payments:".length);
          if (!portfolioUids.has(uid)) outPortfolio += ((row.value ?? []) as any[]).length;
        }
      } else {
        for (const row of metaRows ?? []) { /* noop, kept for symmetry */ }
        const { data: allPay } = await admin
          .from("kv_store_752d1a39")
          .select("key, value")
          .like("key", "payments:%");
        for (const row of allPay ?? []) {
          const uid = (row.key as string).slice("payments:".length);
          const cnt = ((row.value ?? []) as any[]).length;
          if (portfolioUids.has(uid)) inPortfolio += cnt;
          else outPortfolio += cnt;
        }
      }
    } catch { /* mini-stats best-effort, ne pas casser la réponse */ }
    return c.json({ ...res, portfolio: { in: inPortfolio, out: outPortfolio } });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.post(`${PREFIX}/agent/claims/:userId/:claimId/status`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const g2 = await requireAgent2FA(c, r.agent.id);
  if (!g2.ok) return g2.response;
  const userId = c.req.param("userId");
  const claimId = c.req.param("claimId");
  try {
    const body = await c.req.json().catch(() => ({}));
    const status = body.status as string;
    const note = (body.note as string) ?? "";
    if (!["en_cours", "valide", "rejete", "regle"].includes(status)) {
      return c.json({ error: "Statut invalide" }, 400);
    }
    if (status === "rejete" && note.trim().length < 3) {
      return c.json({ error: "Un motif d'au moins 3 caractères est requis pour rejeter un sinistre" }, 400);
    }
    const claims = ((await kv.get(k.claims(userId))) ?? []) as any[];
    const idx = claims.findIndex((cl: any) => cl.id === claimId);
    if (idx === -1) return c.json({ error: "Sinistre introuvable" }, 404);
    claims[idx] = {
      ...claims[idx],
      status,
      adminNote: note,
      decidedAt: new Date().toISOString(),
      decidedBy: `${r.agent.username} · ${r.agent.matricule}`,
      decidedByMatricule: r.agent.matricule,
    };
    await kv.set(k.claims(userId), claims);
    const notifs = ((await kv.get(k.notifications(userId))) ?? []) as any[];
    const label = status === "valide" ? "validé" : status === "rejete" ? "rejeté" : status === "regle" ? "réglé" : "mis à jour";
    await notifyAndDispatch(userId, notifs, {
      typeKey: "claim",
      title: "Sinistre " + label,
      body: `Votre sinistre « ${claims[idx].type} » a été ${label}.`,
      severity: status === "rejete" ? "warn" : "success",
      to: "/espace-client/sinistres",
    });
    await audit(userId, "agent.claim.status", { claimId, status, by: r.agent.matricule, agentId: r.agent.id });
    return c.json({ claim: claims[idx] });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Agent : upload d'une pièce justificative supplémentaire sur un sinistre client.
// Utile quand le client envoie un document par WhatsApp / en agence : l'agent
// le rattache au dossier au lieu de demander au client de le re-soumettre depuis
// l'app. L'attachement est marqué `addedBy` pour traçabilité (audit + UI).
app.post(`${PREFIX}/agent/claims/:userId/:claimId/attachment`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const g2 = await requireAgent2FA(c, r.agent.id);
  if (!g2.ok) return g2.response;
  const limited = await guardRate(c, "agent-att", r.agent.id, 60, 3600);
  if (limited) return limited;
  const userId = c.req.param("userId");
  const claimId = c.req.param("claimId");
  try {
    const form = await c.req.formData();
    const file = form.get("file");
    if (!(file instanceof File)) return c.json({ error: "Fichier manquant" }, 400);
    if (file.size > 10 * 1024 * 1024) return c.json({ error: "Fichier trop volumineux (10 Mo max)" }, 400);
    const claims = ((await kv.get(k.claims(userId))) ?? []) as any[];
    const idx = claims.findIndex((cl: any) => cl.id === claimId);
    if (idx === -1) return c.json({ error: "Sinistre introuvable" }, 404);
    const path = `${userId}/${claimId}/${Date.now()}-agent-${file.name.replace(/[^a-zA-Z0-9_.-]/g, "_")}`;
    const { error: uploadErr } = await admin.storage.from(BUCKET).upload(path, file, { contentType: file.type, upsert: false });
    if (uploadErr) return c.json({ error: `Erreur d'upload: ${uploadErr.message}` }, 500);
    const att = { path, name: file.name, size: file.size, addedBy: `agent:${r.agent.matricule}`, addedAt: new Date().toISOString() };
    claims[idx].attachments = [...(claims[idx].attachments ?? []), att];
    await kv.set(k.claims(userId), claims);
    await audit(userId, "agent.claim.attachment", { claimId, path, by: r.agent.matricule, agentId: r.agent.id });
    // A5 — Si le sinistre est assigné à un autre conseiller, le prévenir.
    const assignee = claims[idx].assignedTo as string | undefined;
    if (assignee && assignee !== r.agent.matricule) {
      broadcast("agent:inbox", "claim:attachment", {
        claimId, userId, to: assignee, by: r.agent.matricule,
        attachment: { name: file.name, size: file.size },
        at: new Date().toISOString(),
      }).catch(() => { /* best-effort */ });
    }
    return c.json({ ok: true, attachment: att });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Agent : URL signée (5 min) pour télécharger une pièce d'un sinistre client.
app.get(`${PREFIX}/agent/claims/attachment-url`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const path = c.req.query("path");
  const userId = c.req.query("userId");
  if (!path || !userId || !path.startsWith(`${userId}/`)) return c.json({ error: "Chemin invalide" }, 400);
  const { data, error: signErr } = await admin.storage.from(BUCKET).createSignedUrl(path, 300);
  if (signErr) return c.json({ error: signErr.message }, 500);
  return c.json({ url: data.signedUrl });
});

// ---- AGENT: CUSTOMER 360° ----
// One round-trip giving the agent everything they need on a client : profile,
// contracts, claims, payments (last 20), beneficiaries, documents, last 10
// messages, conversation meta, settings (so the agent can see push prefs etc).
app.get(`${PREFIX}/agent/customer/:uid`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  // Anti-énumération : un agent ne doit pas pouvoir scanner les UUIDs
  // Supabase pour mapper des comptes existants. 200 req/min par agent reste
  // confortable pour un usage normal (ouverture de fiches client).
  const limited = await guardRate(c, "agent-customer", r.agent.id, 200, 60);
  if (limited) return limited;
  try {
    const profile = await kv.get(k.profile(uid));
    if (!profile) {
      await audit(`agent:${r.agent.matricule}`, "agent.customer.notfound", { uid });
      return c.json({ error: "Client introuvable" }, 404);
    }
    const [contracts, claims, payments, beneficiaries, documents, messages, convMeta, settings, notifications] = await Promise.all([
      kv.get(k.contracts(uid)),
      kv.get(k.claims(uid)),
      kv.get(k.payments(uid)),
      kv.get(k.beneficiaries(uid)),
      kv.get(k.documents(uid)),
      kv.get(k.messages(uid)),
      kv.get(k.conversationMeta(uid)),
      kv.get(k.settings(uid)),
      kv.get(k.notifications(uid)),
    ]);
    const msgList = (messages ?? []) as any[];
    const payList = (payments ?? []) as any[];
    return c.json({
      profile: await withAvatarUrl(profile),
      contracts: contracts ?? [],
      claims: claims ?? [],
      payments: payList.slice(-20).reverse(),
      beneficiaries: beneficiaries ?? [],
      documents: documents ?? [],
      lastMessages: msgList.slice(-10),
      conversationMeta: convMeta ?? { status: "ouvert", assignee: null, tags: [] },
      settings: settings ?? null,
      unreadNotifications: ((notifications ?? []) as any[]).filter((n) => !n.read).length,
    });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- KYC / VALIDATION SOUSCRIPTIONS ----
// Vérification identité du client. La 1ʳᵉ étape de souscription d'un produit
// d'assurance impose la conformité réglementaire (CIMA) : un conseiller doit
// valider les pièces d'identité avant que le contrat soit activé pour de bon.
// Modèle KV : kyc:<userId> -> { current, history[] } où current est la demande
// active (pending|valide|rejete). Un seul KYC actif par client à la fois.

type KycRequest = {
  id: string;
  type: "identite" | "adresse" | "revenu" | string;
  status: "pending" | "valide" | "rejete";
  fields: Record<string, string>;
  docs: { name: string; url?: string }[];
  createdAt: string;
  decidedAt?: string;
  decidedBy?: string;
  decidedByMatricule?: string;
  note?: string;
};

async function getKycBundle(uid: string): Promise<{ current: KycRequest | null; history: KycRequest[] }> {
  const raw = await kv.get(k.kyc(uid));
  if (!raw || typeof raw !== "object") return { current: null, history: [] };
  return {
    current: (raw as any).current ?? null,
    history: Array.isArray((raw as any).history) ? (raw as any).history : [],
  };
}

// Client : upload d'une pièce KYC (jusqu'à 10 Mo). Retourne {path,name,size}
// à intégrer dans le tableau `docs` du POST /kyc.
// Admin : upload d'une image publique (bannière promo, logo partenaire, etc).
// Retourne l'URL publique directement, exploitable dans n'importe quel <img>.
// Bucket dédié `make-752d1a39-media` (public). 5 Mo max, types images uniquement.
app.post(`${PREFIX}/admin/media/upload`, async (c) => {
  const a = await requireAdmin(c);
  if (!a.admin) return a.response;
  try {
    const form = await c.req.formData();
    const file = form.get("file");
    if (!(file instanceof File)) return c.json({ error: "Fichier manquant" }, 400);
    if (file.size > 5 * 1024 * 1024) return c.json({ error: "Image trop volumineuse (5 Mo max)" }, 400);
    if (!/^image\//.test(file.type)) return c.json({ error: "Format non supporté (image uniquement)" }, 400);
    const safe = file.name.replace(/[^a-zA-Z0-9_.-]/g, "_");
    const folder = (form.get("folder") as string | null)?.replace(/[^a-zA-Z0-9_-]/g, "") || "misc";
    const path = `${folder}/${Date.now()}-${safe}`;
    const { error: upErr } = await admin.storage.from(MEDIA_BUCKET).upload(path, file, { contentType: file.type, upsert: false });
    if (upErr) return c.json({ error: `Erreur d'upload: ${upErr.message}` }, 500);
    const { data: pub } = admin.storage.from(MEDIA_BUCKET).getPublicUrl(path);
    return c.json({ url: pub.publicUrl, path, name: file.name, size: file.size });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.post(`${PREFIX}/kyc/upload`, async (c) => {
  const r = await requireUser(c);
  if (!r.user) return c.json({ error: r.error }, 401);
  try {
    const form = await c.req.formData();
    const file = form.get("file");
    if (!(file instanceof File)) return c.json({ error: "Fichier manquant" }, 400);
    if (file.size > 10 * 1024 * 1024) return c.json({ error: "Fichier trop volumineux (10 Mo max)" }, 400);
    const safe = file.name.replace(/[^a-zA-Z0-9_.-]/g, "_");
    const path = `${r.user.id}/${Date.now()}-${safe}`;
    const { error: upErr } = await admin.storage.from(KYC_BUCKET).upload(path, file, { contentType: file.type, upsert: false });
    if (upErr) return c.json({ error: `Erreur d'upload: ${upErr.message}` }, 500);
    await audit(r.user.id, "kyc.upload", { name: file.name, size: file.size });
    return c.json({ path, name: file.name, size: file.size });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// URL signée (5 min) pour consulter une pièce KYC. Le client n'accède qu'à ses
// propres fichiers ; les conseillers (et le back-office) passent par leur
// propre endpoint qui s'autorise via requireAgent/requireAdmin.
app.get(`${PREFIX}/kyc/url`, async (c) => {
  const r = await requireUser(c);
  if (!r.user) return c.json({ error: r.error }, 401);
  const path = c.req.query("path");
  if (!path || !path.startsWith(`${r.user.id}/`)) return c.json({ error: "Chemin invalide" }, 400);
  const { data, error: sErr } = await admin.storage.from(KYC_BUCKET).createSignedUrl(path, 300);
  if (sErr) return c.json({ error: sErr.message }, 500);
  return c.json({ url: data.signedUrl });
});

// Client : soumet une demande KYC (remplace toute demande pending existante).
app.post(`${PREFIX}/kyc`, async (c) => {
  const r = await requireUser(c);
  if (!r.user) return c.json({ error: r.error }, 401);
  try {
    const body = await c.req.json().catch(() => ({}));
    const fields = (body?.fields && typeof body.fields === "object") ? body.fields as Record<string, string> : {};
    const docs = Array.isArray(body?.docs) ? body.docs.slice(0, 6) : [];
    const type = ["identite", "adresse", "revenu"].includes(body?.type) ? body.type : "identite";
    const bundle = await getKycBundle(r.user.id);
    const next: KycRequest = {
      id: `kyc_${Date.now()}`,
      type,
      status: "pending",
      fields,
      docs,
      createdAt: new Date().toISOString(),
    };
    const history = bundle.current && bundle.current.status !== "pending"
      ? [bundle.current, ...bundle.history].slice(0, 10)
      : bundle.history;
    await kv.set(k.kyc(r.user.id), { current: next, history });
    await audit(r.user.id, "kyc.submit", { id: next.id, type });
    const profile = (await kv.get(k.profile(r.user.id))) ?? {};
    await Promise.all([
      broadcast(`admin:chat`, "kyc:new", { userId: r.user.id, kycId: next.id }),
      broadcast("agent:inbox", "kyc:new", {
        userId: r.user.id,
        userName: profile.name ?? "",
        kycId: next.id,
        kycType: type,
        at: next.createdAt,
      }),
    ]);
    return c.json({ kyc: next });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Client : lit son propre KYC.
app.get(`${PREFIX}/kyc`, async (c) => {
  const r = await requireUser(c);
  if (!r.user) return c.json({ error: r.error }, 401);
  const bundle = await getKycBundle(r.user.id);
  return c.json(bundle);
});

// Client : « relancer » une demande KYC en cours. Push notification sur le
// canal agent + flag remindedAt sur la demande pour permettre l'affichage
// d'un compteur côté conseiller. Rate-limité à 1 relance / 24 h pour ne pas
// spammer.
app.post(`${PREFIX}/kyc/remind`, async (c) => {
  const r = await requireUser(c);
  if (!r.user) return c.json({ error: r.error }, 401);
  const limited = await guardRate(c, "kyc-remind", r.user.id, 1, 24 * 3600);
  if (limited) return limited;
  const bundle = await getKycBundle(r.user.id);
  const cur = bundle.current;
  if (!cur || cur.status !== "pending") return c.json({ error: "Aucune demande en attente" }, 400);
  const updated = { ...cur, remindedAt: new Date().toISOString(), remindCount: (cur as any).remindCount ? (cur as any).remindCount + 1 : 1 };
  await kv.set(k.kyc(r.user.id), { current: updated, history: bundle.history });
  const profile = (await kv.get(k.profile(r.user.id))) ?? {};
  const ageDays = Math.floor((Date.now() - new Date(cur.createdAt).getTime()) / 86_400_000);
  await broadcast("agent:inbox", "kyc:remind", {
    userId: r.user.id,
    userName: profile.name ?? profile.fullName ?? "",
    kycId: cur.id,
    kycType: cur.type,
    ageDays,
    at: updated.remindedAt,
  });
  await audit(r.user.id, "kyc.remind", { id: cur.id, ageDays });
  return c.json({ kyc: updated });
});

// Agent : file d'attente — toutes les demandes pending + 30 dernières décidées.
app.get(`${PREFIX}/agent/kyc`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "kyc:%");
    if (error) return c.json({ error: error.message }, 500);
    const rows = (data ?? []) as { key: string; value: any }[];
    const pending: any[] = [];
    const decided: any[] = [];
    for (const row of rows) {
      const userId = row.key.slice("kyc:".length);
      const profile = (await kv.get(k.profile(userId))) as any;
      const enrich = async (req: KycRequest) => {
        const docs = await Promise.all(
          (req.docs ?? []).map(async (d: any) => {
            if (!d?.path) return d;
            const { data, error: sErr } = await admin.storage
              .from(KYC_BUCKET)
              .createSignedUrl(d.path, 300);
            return { ...d, url: sErr ? null : data.signedUrl };
          }),
        );
        let lock: any = null;
        if (req.status === "pending") {
          const raw = (await kv.get(k.kycLock(userId, req.id))) as any;
          if (raw?.expiresAt && raw.expiresAt > new Date().toISOString()) {
            lock = {
              agentId: raw.agentId,
              agentMatricule: raw.agentMatricule,
              agentName: raw.agentName ?? raw.agentMatricule,
              lockedAt: raw.lockedAt,
              expiresAt: raw.expiresAt,
              lockedByMe: raw.agentId === r.agent.id,
            };
          }
        }
        return {
          ...req,
          docs,
          lock,
          userId,
          userEmail: profile?.email ?? "",
          userName: profile?.fullName ?? profile?.name ?? "Client",
          memberNumber: profile?.memberNumber ?? "",
        };
      };
      const cur: KycRequest | null = row.value?.current ?? null;
      if (cur?.status === "pending") pending.push(await enrich(cur));
      else if (cur) decided.push(await enrich(cur));
      const hist: KycRequest[] = Array.isArray(row.value?.history) ? row.value.history : [];
      for (const h of hist) decided.push(await enrich(h));
    }
    pending.sort((a, b) => (a.createdAt < b.createdAt ? -1 : 1));
    decided.sort((a, b) => ((b.decidedAt ?? "") < (a.decidedAt ?? "") ? -1 : 1));
    return c.json({ pending, decided: decided.slice(0, 30) });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Agent : lock 15 min sur une demande KYC (évite collision conseillers).
const KYC_LOCK_TTL_MS = 15 * 60_000;
app.post(`${PREFIX}/agent/kyc/:userId/:kycId/lock`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const userId = c.req.param("userId");
  const kycId = c.req.param("kycId");
  try {
    const body = await c.req.json().catch(() => ({} as any));
    const force = body?.force === true;
    const release = body?.release === true;
    const lockKey = k.kycLock(userId, kycId);
    const existing = (await kv.get(lockKey)) as any;
    const now = Date.now();
    const stillValid = existing?.expiresAt && new Date(existing.expiresAt).getTime() > now;
    if (release) {
      if (stillValid && existing.agentId !== r.agent.id && !force) {
        return c.json({ error: "Verrou détenu par un autre conseiller." }, 409);
      }
      await kv.del(lockKey);
      await audit(userId, "kyc.lock.release", { kycId, by: r.agent.matricule });
      return c.json({ lock: null });
    }
    if (stillValid && existing.agentId !== r.agent.id && !force) {
      return c.json({
        error: "verrou-occupe",
        lock: {
          agentMatricule: existing.agentMatricule,
          agentName: existing.agentName ?? existing.agentMatricule,
          expiresAt: existing.expiresAt,
        },
      }, 409);
    }
    const lock = {
      agentId: r.agent.id,
      agentMatricule: r.agent.matricule,
      agentName: r.agent.username,
      lockedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + KYC_LOCK_TTL_MS).toISOString(),
    };
    await kv.set(lockKey, lock);
    await audit(userId, force && stillValid ? "kyc.lock.force" : "kyc.lock.acquire", {
      kycId, by: r.agent.matricule, takenFrom: stillValid ? existing.agentMatricule : null,
    });
    return c.json({ lock: { ...lock, lockedByMe: true } });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Agent : décide.
app.post(`${PREFIX}/agent/kyc/:userId/:kycId/decision`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const g2 = await requireAgent2FA(c, r.agent.id);
  if (!g2.ok) return g2.response;
  const userId = c.req.param("userId");
  const kycId = c.req.param("kycId");
  try {
    const body = await c.req.json().catch(() => ({}));
    const decision = body.decision as string;
    const note = (body.note as string) ?? "";
    if (!["valide", "rejete"].includes(decision)) return c.json({ error: "Décision invalide" }, 400);
    const bundle = await getKycBundle(userId);
    if (!bundle.current || bundle.current.id !== kycId) return c.json({ error: "Demande introuvable" }, 404);
    if (bundle.current.status !== "pending") return c.json({ error: "Déjà décidée" }, 409);
    const existingLock = (await kv.get(k.kycLock(userId, kycId))) as any;
    if (
      existingLock?.expiresAt &&
      new Date(existingLock.expiresAt).getTime() > Date.now() &&
      existingLock.agentId !== r.agent.id
    ) {
      return c.json({
        error: `Demande verrouillée par ${existingLock.agentName ?? existingLock.agentMatricule}. Forcez le verrou pour reprendre la main.`,
      }, 409);
    }
    const decided: KycRequest = {
      ...bundle.current,
      status: decision as "valide" | "rejete",
      note,
      decidedAt: new Date().toISOString(),
      decidedBy: `${r.agent.username} · ${r.agent.matricule}`,
      decidedByMatricule: r.agent.matricule,
    };
    await kv.set(k.kyc(userId), { current: decided, history: bundle.history });
    await kv.del(k.kycLock(userId, kycId)).catch(() => {});
    if (decision === "valide") {
      const profile = ((await kv.get(k.profile(userId))) ?? {}) as any;
      await kv.set(k.profile(userId), { ...profile, kycVerified: true, kycVerifiedAt: decided.decidedAt });
    }
    const notifs = ((await kv.get(k.notifications(userId))) ?? []) as any[];
    const label = decision === "valide" ? "validée" : "rejetée";
    await setNotifications(
      userId,
      notify(
        notifs,
        `Vérification ${label}`,
        decision === "valide"
          ? "Votre identité a été vérifiée par un conseiller. Bienvenue !"
          : `Votre vérification a été rejetée${note ? ` : ${note}` : ""}. Vous pouvez resoumettre.`,
        decision === "valide" ? "success" : "warn",
        "/espace-client/profil",
      ),
    );
    await audit(userId, "kyc.decision", { kycId, decision, by: r.agent.matricule, agentId: r.agent.id });
    pushUsers([userId], {
      title: `Vérification ${label}`,
      body: decision === "valide" ? "Votre identité a été validée." : "Votre vérification a été rejetée.",
      url: "/espace-client/profil",
      tag: `kyc:${kycId}`,
    }).catch((e) => console.log(`push kyc err: ${e}`));
    return c.json({ kyc: decided });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Admin : file KYC globale (même payload que /agent/kyc, mais auth HMAC admin).
app.get(`${PREFIX}/admin/kyc`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const { data, error } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "kyc:%");
    if (error) return c.json({ error: error.message }, 500);
    const rows = (data ?? []) as { key: string; value: any }[];
    const pending: any[] = [];
    const decided: any[] = [];
    for (const row of rows) {
      const userId = row.key.slice("kyc:".length);
      const profile = (await kv.get(k.profile(userId))) as any;
      const enrich = async (req: KycRequest) => {
        const docs = await Promise.all(
          (req.docs ?? []).map(async (d: any) => {
            if (!d?.path) return d;
            const { data, error: sErr } = await admin.storage
              .from(KYC_BUCKET)
              .createSignedUrl(d.path, 300);
            return { ...d, url: sErr ? null : data.signedUrl };
          }),
        );
        return {
          ...req,
          docs,
          userId,
          userEmail: profile?.email ?? "",
          userName: profile?.fullName ?? profile?.name ?? "Client",
          memberNumber: profile?.memberNumber ?? "",
        };
      };
      const cur: KycRequest | null = row.value?.current ?? null;
      if (cur?.status === "pending") pending.push(await enrich(cur));
      else if (cur) decided.push(await enrich(cur));
      const hist: KycRequest[] = Array.isArray(row.value?.history) ? row.value.history : [];
      for (const h of hist) decided.push(await enrich(h));
    }
    pending.sort((a, b) => (a.createdAt < b.createdAt ? -1 : 1));
    decided.sort((a, b) => ((b.decidedAt ?? "") < (a.decidedAt ?? "") ? -1 : 1));
    return c.json({ pending, decided: decided.slice(0, 50) });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Admin : décide d'une demande KYC.
app.post(`${PREFIX}/admin/kyc/:userId/:kycId/decision`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const userId = c.req.param("userId");
  const kycId = c.req.param("kycId");
  try {
    const body = await c.req.json().catch(() => ({}));
    const decision = body.decision as string;
    const note = (body.note as string) ?? "";
    if (!["valide", "rejete"].includes(decision)) return c.json({ error: "Décision invalide" }, 400);
    const bundle = await getKycBundle(userId);
    if (!bundle.current || bundle.current.id !== kycId) return c.json({ error: "Demande introuvable" }, 404);
    if (bundle.current.status !== "pending") return c.json({ error: "Déjà décidée" }, 409);
    const decided: KycRequest = {
      ...bundle.current,
      status: decision as "valide" | "rejete",
      note,
      decidedAt: new Date().toISOString(),
      decidedBy: `Admin · ${r.admin.username}`,
    };
    await kv.set(k.kyc(userId), { current: decided, history: bundle.history });
    if (decision === "valide") {
      const profile = ((await kv.get(k.profile(userId))) ?? {}) as any;
      await kv.set(k.profile(userId), { ...profile, kycVerified: true, kycVerifiedAt: decided.decidedAt });
    }
    const notifs = ((await kv.get(k.notifications(userId))) ?? []) as any[];
    const label = decision === "valide" ? "validée" : "rejetée";
    await setNotifications(
      userId,
      notify(
        notifs,
        `Vérification ${label}`,
        decision === "valide"
          ? "Votre identité a été vérifiée. Bienvenue !"
          : `Votre vérification a été rejetée${note ? ` : ${note}` : ""}. Vous pouvez resoumettre.`,
        decision === "valide" ? "success" : "warn",
        "/espace-client/profil",
      ),
    );
    await audit(userId, "kyc.decision", { kycId, decision, by: `admin:${r.admin.username}` });
    // #7 — Lien magique de reprise KYC sur refus. Email transactionnel
    // contenant un deep-link `/espace-client/kyc?reprise=1` (l'user doit être
    // connecté, mais le lien le pousse direct sur l'écran de re-soumission).
    if (decision === "rejete") {
      const profile = ((await kv.get(k.profile(userId))) ?? {}) as any;
      if (profile?.email) {
        const APP_URL = Deno.env.get("APP_URL") ?? "https://app.ippoo.bj";
        const link = `${APP_URL}/espace-client/kyc?reprise=1&ref=${encodeURIComponent(kycId)}`;
        const esc = (s: string) => String(s).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch] as string));
        const safeNote = esc(note || "Pièces non lisibles ou incomplètes.");
        const html = `<div style="font-family:system-ui,sans-serif;max-width:520px;margin:auto">
          <h2 style="color:#FF3B57">Vérification d'identité à refaire</h2>
          <p>Bonjour ${esc(profile.name ?? "")},</p>
          <p>Votre vérification a malheureusement été <b>rejetée</b>.<br/>Motif : <i>${safeNote}</i></p>
          <p>Vous pouvez la reprendre en 1 clic :</p>
          <p style="margin:24px 0"><a href="${link}" style="background:#FF3B57;color:#fff;padding:12px 20px;border-radius:10px;text-decoration:none;font-weight:700">Reprendre ma vérification</a></p>
          <p style="color:#666;font-size:13px">Lien valide tant que vous restez connecté à votre espace IPPOO.</p>
        </div>`;
        await sendEmail(profile.email, "IPPOO — Reprenez votre vérification d'identité", html);
      }
    }
    // A6 — Si la KYC avait été pré-validée / verrouillée par un conseiller,
    // le prévenir aussi (broadcast + push) du verdict admin.
    const lock = (bundle.current as any)?.lock as { agentMatricule?: string; agentId?: string } | undefined;
    if (lock?.agentId) {
      pushUsers([lock.agentId], {
        title: `Vérification ${label}`,
        body: `Décision admin sur la KYC ${bundle.current.type ?? ""}.`,
        url: `/agent/kyc`,
        tag: `kyc:${kycId}`,
      }).catch(() => { /* best-effort */ });
    }
    if (lock?.agentMatricule) {
      broadcast("agent:inbox", "kyc:decision", {
        kycId, userId, to: lock.agentMatricule, decision, by: r.admin.username,
        at: new Date().toISOString(),
      }).catch(() => { /* best-effort */ });
    }
    return c.json({ kyc: decided });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Admin : réassigne un sinistre à un autre conseiller (par matricule).
app.post(`${PREFIX}/admin/claims/:userId/:claimId/reassign`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const userId = c.req.param("userId");
  const claimId = c.req.param("claimId");
  try {
    const body = await c.req.json().catch(() => ({}));
    const matricule = String(body.matricule ?? "").trim();
    if (!matricule) return c.json({ error: "Matricule requis" }, 400);
    const list = ((await kv.get(k.claims(userId))) ?? []) as any[];
    const idx = list.findIndex((cl: any) => cl.id === claimId);
    if (idx < 0) return c.json({ error: "Sinistre introuvable" }, 404);
    const prev = list[idx].assignedTo ?? null;
    list[idx] = {
      ...list[idx],
      assignedTo: matricule,
      reassignedAt: new Date().toISOString(),
      reassignedBy: `admin:${r.admin.username}`,
    };
    await kv.set(k.claims(userId), list);
    await audit(userId, "claim.reassign", { claimId, from: prev, to: matricule, by: `admin:${r.admin.username}` });
    await pushAgentNotif(matricule, {
      type: "assignment",
      title: "Sinistre réassigné",
      body: `Vous êtes désormais en charge du sinistre ${claimId}.`,
      url: "/agent/sinistres",
    });
    broadcast("agent:inbox", "claim:reassign", {
      claimId,
      userId,
      from: prev,
      to: matricule,
      by: `admin:${r.admin.username}`,
      at: new Date().toISOString(),
    });
    return c.json({ claim: list[idx] });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Agent : s'assigne un sinistre orphelin (assignedTo vide ou conseiller hors ligne).
// Refuse 409 si déjà détenu par un autre conseiller actif (l'admin a /reassign pour ça).
app.post(`${PREFIX}/agent/claims/:userId/:claimId/assign-me`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const userId = c.req.param("userId");
  const claimId = c.req.param("claimId");
  try {
    const list = ((await kv.get(k.claims(userId))) ?? []) as any[];
    const idx = list.findIndex((cl: any) => cl.id === claimId);
    if (idx < 0) return c.json({ error: "Sinistre introuvable" }, 404);
    const prev = list[idx].assignedTo ?? null;
    if (prev && prev !== r.agent.matricule) {
      return c.json({
        error: `Sinistre déjà assigné à ${prev}. Demandez à l'admin une réassignation.`,
      }, 409);
    }
    list[idx] = {
      ...list[idx],
      assignedTo: r.agent.matricule,
      assignedAt: new Date().toISOString(),
      assignedBy: `self:${r.agent.matricule}`,
    };
    await kv.set(k.claims(userId), list);
    await audit(userId, "claim.assign.self", { claimId, to: r.agent.matricule });
    broadcast("agent:inbox", "claim:assign", {
      claimId, userId, to: r.agent.matricule, by: "self", at: new Date().toISOString(),
    });
    return c.json({ claim: list[idx] });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// Agent : transfère un sinistre qu'il détient vers un autre conseiller. Pratique
// quand un dossier sort du périmètre du conseiller (spécialisation auto/santé,
// agence locale) sans devoir solliciter l'admin. Seul le titulaire actuel peut
// passer la main; cible doit être un matricule existant.
app.post(`${PREFIX}/agent/claims/:userId/:claimId/reassign-to`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const userId = c.req.param("userId");
  const claimId = c.req.param("claimId");
  try {
    const body = await c.req.json().catch(() => ({}));
    const matricule = String(body.matricule ?? "").trim();
    const reason = String(body.reason ?? "").trim().slice(0, 200);
    if (!matricule) return c.json({ error: "Matricule cible requis" }, 400);
    if (matricule === r.agent.matricule) return c.json({ error: "Cible identique à l'actuel" }, 400);
    if (!/^IPPOO-A-\d{4}$/.test(matricule)) return c.json({ error: "Format matricule invalide (attendu IPPOO-A-XXXX)" }, 400);
    const list = ((await kv.get(k.claims(userId))) ?? []) as any[];
    const idx = list.findIndex((cl: any) => cl.id === claimId);
    if (idx < 0) return c.json({ error: "Sinistre introuvable" }, 404);
    const prev = list[idx].assignedTo ?? null;
    if (prev !== r.agent.matricule) {
      return c.json({ error: "Vous n'êtes pas le titulaire de ce sinistre" }, 403);
    }
    list[idx] = {
      ...list[idx],
      assignedTo: matricule,
      reassignedAt: new Date().toISOString(),
      reassignedBy: `agent:${r.agent.matricule}`,
      reassignedReason: reason || null,
    };
    await kv.set(k.claims(userId), list);
    await audit(userId, "claim.reassign.agent", { claimId, from: prev, to: matricule, by: r.agent.matricule, reason });
    await pushAgentNotif(matricule, {
      type: "assignment",
      title: "Sinistre transféré",
      body: `${r.agent.matricule} vous transfère le sinistre ${claimId}${reason ? ` — ${reason}` : ""}.`,
      url: "/agent/sinistres",
    });
    broadcast("agent:inbox", "claim:reassign", {
      claimId, userId, from: prev, to: matricule, by: `agent:${r.agent.matricule}`, at: new Date().toISOString(),
    });
    return c.json({ claim: list[idx] });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: ROTATE HMAC SECRET (F14) ----
// Régénère le secret HMAC qui signe les jetons admin. Toutes les sessions
// admin existantes sont invalidées (next request retournera 401 → login).
// L'audit retient `from`/`to` (préfixes seulement, jamais le secret complet).
app.post(`${PREFIX}/admin/security/rotate-hmac`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const previous = (await kv.get(k.hmacSecret())) as string | null;
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    const next = b64urlEncode(buf);
    await kv.set(k.hmacSecret(), next);
    cachedHmacKey = null;
    await audit(`admin:${r.admin.username}`, "admin.security.rotate-hmac", {
      previousPrefix: previous ? previous.slice(0, 6) + "…" : null,
      nextPrefix: next.slice(0, 6) + "…",
      at: new Date().toISOString(),
    }).catch(() => {});
    return c.json({
      ok: true,
      rotated: true,
      sessionsInvalidated: true,
      message: "Secret HMAC régénéré. Toutes les sessions admin doivent se reconnecter.",
    });
  } catch (err) {
    console.log(`HMAC rotate error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: DISPATCH SWEEP (réassigne ce qui est resté chez un agent offline > X heures) ----
// Détecte les conversations et sinistres assignés à un matricule dont la présence
// n'est plus "online" (ou stale > 90s) depuis au moins `hours` (défaut 4 h). Les
// réassigne au round-robin vers un agent online et notifie le nouveau matricule.
app.post(`${PREFIX}/admin/dispatch/sweep`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const body = await c.req.json().catch(() => ({}));
    const hours = Math.min(Math.max(Number(body.hours ?? 4), 1), 168);
    const STALE_MS = 90_000;
    const cutoff = Date.now() - hours * 3600_000;

    const [{ data: presRows }, { data: matRows }] = await Promise.all([
      admin.from("kv_store_752d1a39").select("key, value").like("key", "agent:presence:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "agent:matricule:%"),
    ]);
    const matByUid = new Map<string, string>();
    for (const row of matRows ?? []) {
      const key = row.key as string;
      if (key.startsWith("agent:matricule-claim:")) continue;
      const uid = key.slice("agent:matricule:".length);
      const v = row.value as any;
      const mat = typeof v === "string" ? v : v?.matricule;
      if (mat) matByUid.set(uid, mat);
    }
    const allMatricules = new Set(matByUid.values());

    const offlineMatricules = new Set<string>();
    const onlineMatricules: string[] = [];
    const presByMat = new Map<string, { status?: string; at?: string }>();
    for (const row of presRows ?? []) {
      const uid = (row.key as string).slice("agent:presence:".length);
      const mat = matByUid.get(uid);
      if (!mat) continue;
      const p = (row.value ?? {}) as any;
      presByMat.set(mat, p);
      const age = p.at ? Date.now() - new Date(p.at).getTime() : Infinity;
      if (p.status === "online" && age <= STALE_MS) onlineMatricules.push(mat);
    }
    for (const mat of allMatricules) {
      const p = presByMat.get(mat);
      const lastSeen = p?.at ? new Date(p.at).getTime() : 0;
      if (p?.status === "online" && Date.now() - lastSeen <= STALE_MS) continue;
      if (lastSeen >= cutoff) continue;
      offlineMatricules.add(mat);
    }

    if (onlineMatricules.length === 0) {
      return c.json({ ok: true, reassigned: 0, reason: "no-online-agent", offlineMatricules: [...offlineMatricules] });
    }
    onlineMatricules.sort();
    let cursor = ((await kv.get("agent:router:cursor")) as number | null) ?? 0;
    const nextMat = () => { cursor = (cursor + 1) % onlineMatricules.length; return onlineMatricules[cursor]; };

    let convReassigned = 0, claimReassigned = 0;
    const { data: metaRows } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "conv:meta:%");
    for (const row of metaRows ?? []) {
      const meta = (row.value ?? {}) as any;
      const assignee = meta.assignee;
      if (!assignee || !offlineMatricules.has(assignee)) continue;
      const uid = (row.key as string).slice("conv:meta:".length);
      const newMat = nextMat();
      await kv.set(`conv:meta:${uid}`, { ...meta, assignee: newMat, reassignedAt: new Date().toISOString(), reassignedFrom: assignee, reassignedBy: `admin-sweep:${r.admin.username}` });
      await pushAgentNotif(newMat, { type: "assignment", title: "Conversation réassignée", body: `Reprise d'une conversation laissée par ${assignee}.`, url: "/agent/inbox" }).catch(() => {});
      broadcast("agent:inbox", "conv:reassign", { userId: uid, from: assignee, to: newMat, by: `admin-sweep:${r.admin.username}`, at: new Date().toISOString() });
      convReassigned++;
    }

    const { data: claimRows } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "claims:%");
    for (const row of claimRows ?? []) {
      const list = (row.value ?? []) as any[];
      const uid = (row.key as string).slice("claims:".length);
      let changed = false;
      for (let i = 0; i < list.length; i++) {
        const cl = list[i];
        if (!cl?.assignedTo || !offlineMatricules.has(cl.assignedTo)) continue;
        if (cl.status === "regle" || cl.status === "rejete") continue;
        const newMat = nextMat();
        list[i] = { ...cl, assignedTo: newMat, reassignedAt: new Date().toISOString(), reassignedFrom: cl.assignedTo, reassignedBy: `admin-sweep:${r.admin.username}` };
        await pushAgentNotif(newMat, { type: "assignment", title: "Sinistre réassigné", body: `Reprise du sinistre ${cl.id} (ex-${cl.assignedTo}).`, url: "/agent/sinistres" }).catch(() => {});
        await audit(uid, "claim.reassign", { claimId: cl.id, from: cl.assignedTo, to: newMat, by: `admin-sweep:${r.admin.username}` }).catch(() => {});
        broadcast("agent:inbox", "claim:reassign", { claimId: cl.id, userId: uid, from: cl.assignedTo, to: newMat, by: `admin-sweep:${r.admin.username}`, at: new Date().toISOString() });
        claimReassigned++;
        changed = true;
      }
      if (changed) await kv.set(`claims:${uid}`, list);
    }

    await kv.set("agent:router:cursor", cursor);
    return c.json({
      ok: true,
      hours,
      onlineCount: onlineMatricules.length,
      offlineMatricules: [...offlineMatricules],
      reassigned: convReassigned + claimReassigned,
      conversations: convReassigned,
      claims: claimReassigned,
    });
  } catch (err) {
    console.log(`Dispatch sweep error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: EXPORT COMPTABLE CSV MENSUEL (F12) ----
// Renvoie un CSV (text/csv) de tous les paiements confirmés du mois `month`
// (format `YYYY-MM`) avec colonnes : date, userId, email, produit, méthode,
// montant XOF, statut, agent collecteur, matricule agent, taux commission,
// montant commission. Le taux est lu via env `COMMISSION_RATE_AGENT` (défaut 0.05).
app.get(`${PREFIX}/admin/export/accounting`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const month = String(c.req.query("month") ?? new Date().toISOString().slice(0, 7));
    const from = c.req.query("from") ? String(c.req.query("from")) : month;
    const to = c.req.query("to") ? String(c.req.query("to")) : month;
    if (!/^\d{4}-\d{2}$/.test(from) || !/^\d{4}-\d{2}$/.test(to)) return c.json({ error: "Paramètres `from`/`to` invalides (YYYY-MM)" }, 400);
    if (from > to) return c.json({ error: "`from` doit être ≤ `to`" }, 400);
    const inRange = (m: string) => m >= from && m <= to;
    const rangeLabel = from === to ? from : `${from}_${to}`;
    const commissionRate = Math.max(0, Math.min(1, Number(Deno.env.get("COMMISSION_RATE_AGENT") ?? "0.05")));

    const [{ data: payRows }, { data: profRows }] = await Promise.all([
      admin.from("kv_store_752d1a39").select("key, value").like("key", "payments:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "profile:%"),
    ]);
    const emailByUid = new Map<string, string>();
    for (const row of profRows ?? []) {
      const uid = (row.key as string).slice("profile:".length);
      const p = (row.value ?? {}) as any;
      if (p?.email) emailByUid.set(uid, p.email);
    }

    const escape = (v: unknown): string => {
      const s = v == null ? "" : String(v);
      return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const header = [
      "date", "userId", "email", "paymentId", "produit", "methode",
      "montant_xof", "statut", "agent_username", "agent_matricule",
      "taux_commission", "commission_xof",
    ];
    const lines: string[] = [header.join(",")];
    let totalRevenue = 0, totalCommission = 0, lineCount = 0;

    for (const row of payRows ?? []) {
      const uid = (row.key as string).slice("payments:".length);
      const list = (row.value ?? []) as any[];
      for (const p of list) {
        if (p?.status !== "confirme") continue;
        const date = String(p?.createdAt ?? "");
        if (!inRange(date.slice(0, 7))) continue;
        const amount = Number(p?.amount ?? 0);
        const collected = p?.collectedBy ? String(p.collectedBy) : "";
        const commission = collected ? Math.round(amount * commissionRate) : 0;
        totalRevenue += amount;
        totalCommission += commission;
        lineCount++;
        lines.push([
          date,
          uid,
          emailByUid.get(uid) ?? "",
          p?.id ?? "",
          p?.product ?? p?.label ?? "",
          p?.method ?? "",
          amount,
          p?.status ?? "",
          p?.collectedByName ?? "",
          collected,
          commissionRate,
          commission,
        ].map(escape).join(","));
      }
    }

    const periodLabel = from === to ? `mois ${from}` : `période ${from} → ${to}`;
    const summary = `# Export comptable IPPOO · ${periodLabel}\n# ${lineCount} paiements · CA ${totalRevenue} XOF · commissions ${totalCommission} XOF (taux ${commissionRate})\n# Généré le ${new Date().toISOString()} par admin:${r.admin.username}\n`;
    // BOM UTF-8 : Excel Windows interprète sinon le CSV en Latin-1 → mojibake sur accents.
    const body = "﻿" + summary + lines.join("\n") + "\n";
    const sha256 = await sha256Hex(body);
    const filename = `ippoo-comptable-${rangeLabel}.csv`;
    await audit(`admin:${r.admin.username}`, "admin.export.accounting", {
      from, to, lineCount, totalRevenue, totalCommission, sha256, bytes: body.length, filename,
    }).catch(() => {});
    await adminAudit(c, r.admin, "admin.export.accounting", {
      from, to, lineCount, totalRevenue, totalCommission, sha256, bytes: body.length, filename,
    }).catch(() => {});
    return new Response(body, {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "X-Export-Sha256": sha256,
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Expose-Headers": "X-Export-Sha256, Content-Disposition",
      },
    });
  } catch (err) {
    console.log(`Accounting export error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: EXPORT COMMISSIONS PAR AGENT (F12) ----
// CSV agrégé par matricule pour le mois `month` : nombre de paiements collectés,
// CA collecté, commission due. Pour la paye / virement bancaire des conseillers.
app.get(`${PREFIX}/admin/export/commissions`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const month = String(c.req.query("month") ?? new Date().toISOString().slice(0, 7));
    const from = c.req.query("from") ? String(c.req.query("from")) : month;
    const to = c.req.query("to") ? String(c.req.query("to")) : month;
    if (!/^\d{4}-\d{2}$/.test(from) || !/^\d{4}-\d{2}$/.test(to)) return c.json({ error: "Paramètres `from`/`to` invalides (YYYY-MM)" }, 400);
    if (from > to) return c.json({ error: "`from` doit être ≤ `to`" }, 400);
    const inRange = (m: string) => m >= from && m <= to;
    const rangeLabel = from === to ? from : `${from}_${to}`;
    const commissionRate = Math.max(0, Math.min(1, Number(Deno.env.get("COMMISSION_RATE_AGENT") ?? "0.05")));

    const [{ data: payRows }, { data: matRows }, { data: profRows }] = await Promise.all([
      admin.from("kv_store_752d1a39").select("key, value").like("key", "payments:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "agent:matricule:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "profile:%"),
    ]);

    const profileByUid = new Map<string, any>();
    for (const row of profRows ?? []) profileByUid.set((row.key as string).slice("profile:".length), row.value);
    const agentProfileByMat = new Map<string, { name?: string; email?: string; phone?: string }>();
    for (const row of matRows ?? []) {
      const key = row.key as string;
      if (key.startsWith("agent:matricule-claim:")) continue;
      const uid = key.slice("agent:matricule:".length);
      const v = row.value as any;
      const mat = typeof v === "string" ? v : v?.matricule;
      if (!mat) continue;
      const p = profileByUid.get(uid) as any;
      agentProfileByMat.set(mat, { name: p?.name, email: p?.email, phone: p?.phone });
    }

    type Agg = { matricule: string; count: number; revenue: number };
    const byMat = new Map<string, Agg>();
    for (const row of payRows ?? []) for (const p of (row.value ?? []) as any[]) {
      if (p?.status !== "confirme") continue;
      const mat = p?.collectedBy;
      if (!mat) continue;
      const date = String(p?.createdAt ?? "");
      if (!inRange(date.slice(0, 7))) continue;
      const a = byMat.get(mat) ?? { matricule: mat, count: 0, revenue: 0 };
      a.count++; a.revenue += Number(p?.amount ?? 0);
      byMat.set(mat, a);
    }

    const escape = (v: unknown): string => {
      const s = v == null ? "" : String(v);
      return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const header = ["matricule", "nom", "email", "telephone", "paiements_count", "ca_collecte_xof", "taux_commission", "commission_due_xof"];
    const rows = [...byMat.values()].sort((a, b) => b.revenue - a.revenue);
    const lines: string[] = [header.join(",")];
    let totalCa = 0, totalCom = 0;
    for (const a of rows) {
      const meta = agentProfileByMat.get(a.matricule) ?? {};
      const com = Math.round(a.revenue * commissionRate);
      totalCa += a.revenue; totalCom += com;
      lines.push([a.matricule, meta.name ?? "", meta.email ?? "", meta.phone ?? "", a.count, a.revenue, commissionRate, com].map(escape).join(","));
    }
    const periodLabel = from === to ? `mois ${from}` : `période ${from} → ${to}`;
    const summary = `# Commissions conseillers IPPOO · ${periodLabel}\n# ${rows.length} matricules · CA total ${totalCa} XOF · commissions à verser ${totalCom} XOF (taux ${commissionRate})\n# Généré le ${new Date().toISOString()} par admin:${r.admin.username}\n`;
    const body = "﻿" + summary + lines.join("\n") + "\n";
    const sha256 = await sha256Hex(body);
    const filename = `ippoo-commissions-${rangeLabel}.csv`;
    await audit(`admin:${r.admin.username}`, "admin.export.commissions", {
      from, to, agents: rows.length, totalCa, totalCom, sha256, bytes: body.length, filename,
    }).catch(() => {});
    await adminAudit(c, r.admin, "admin.export.commissions", {
      from, to, agents: rows.length, totalCa, totalCom, sha256, bytes: body.length, filename,
    }).catch(() => {});
    return new Response(body, {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "X-Export-Sha256": sha256,
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Expose-Headers": "X-Export-Sha256, Content-Disposition",
      },
    });
  } catch (err) {
    console.log(`Commissions export error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: EXPORT CSV FILLEULS PAR CONSEILLER ----
// Liste tous les comptes clients avec leur enrôleur (matricule conseiller).
// Filtres : `matricule=IPPOO-A-XXXX` (un seul conseiller) ou `since=YYYY-MM-DD`.
// Sortie : 1 ligne par filleul (uid, email, nom, n° membre, créé le, enrolledBy,
// enrolledAt, source, nb contrats, CA confirmé), triée par enrôleur puis date.
app.get(`${PREFIX}/admin/export/enrollments`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const filterMat = (c.req.query("matricule") ?? "").trim().toUpperCase();
    const sinceRaw = (c.req.query("since") ?? "").trim();
    const sinceTs = sinceRaw ? Date.parse(sinceRaw) : NaN;
    const [{ data: profRows }, { data: payRows }, { data: ctRows }] = await Promise.all([
      admin.from("kv_store_752d1a39").select("key, value").like("key", "profile:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "payments:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "contracts:%"),
    ]);
    const revenueByUid = new Map<string, number>();
    const paysByUid = new Map<string, number>();
    for (const row of payRows ?? []) {
      const uid = (row.key as string).slice("payments:".length);
      let rev = 0, n = 0;
      for (const p of (row.value ?? []) as any[]) {
        if (p?.status !== "confirme") continue;
        rev += Number(p?.amount ?? 0); n++;
      }
      revenueByUid.set(uid, rev); paysByUid.set(uid, n);
    }
    const ctCountByUid = new Map<string, number>();
    for (const row of ctRows ?? []) {
      const uid = (row.key as string).slice("contracts:".length);
      ctCountByUid.set(uid, ((row.value ?? []) as any[]).length);
    }
    type R = { uid: string; email: string; name: string; memberNumber: string; createdAt: string; enrolledBy: string; enrolledAt: string; enrolledSource: string; contracts: number; payments: number; revenue: number };
    const rows: R[] = [];
    for (const row of profRows ?? []) {
      const p = row.value as any;
      if (!p) continue;
      const enrolledBy = String(p.enrolledBy ?? "");
      if (!enrolledBy) continue;
      if (filterMat && enrolledBy.toUpperCase() !== filterMat) continue;
      const enrolledAt = String(p.enrolledAt ?? "");
      if (!isNaN(sinceTs) && enrolledAt) {
        const ts = Date.parse(enrolledAt);
        if (isNaN(ts) || ts < sinceTs) continue;
      }
      const uid = (row.key as string).slice("profile:".length);
      rows.push({
        uid,
        email: p.email ?? "",
        name: p.name ?? "",
        memberNumber: p.memberNumber ?? "",
        createdAt: p.createdAt ?? "",
        enrolledBy,
        enrolledAt,
        enrolledSource: p.enrolledSource ?? "",
        contracts: ctCountByUid.get(uid) ?? 0,
        payments: paysByUid.get(uid) ?? 0,
        revenue: revenueByUid.get(uid) ?? 0,
      });
    }
    rows.sort((a, b) => a.enrolledBy.localeCompare(b.enrolledBy) || String(b.enrolledAt).localeCompare(String(a.enrolledAt)));
    const escape = (v: unknown): string => {
      const s = v == null ? "" : String(v);
      return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const header = ["enrolledBy", "enrolledAt", "source", "memberNumber", "name", "email", "createdAt", "contracts", "payments_count", "revenue_xof"];
    const lines = [header.join(",")];
    let totalRev = 0;
    const matCount = new Map<string, number>();
    for (const r2 of rows) {
      totalRev += r2.revenue;
      matCount.set(r2.enrolledBy, (matCount.get(r2.enrolledBy) ?? 0) + 1);
      lines.push([r2.enrolledBy, r2.enrolledAt, r2.enrolledSource, r2.memberNumber, r2.name, r2.email, r2.createdAt, r2.contracts, r2.payments, r2.revenue].map(escape).join(","));
    }
    const summary = `# Filleuls IPPOO · ${filterMat || "tous conseillers"}${sinceRaw ? ` · depuis ${sinceRaw}` : ""}\n# ${rows.length} filleul(s) · ${matCount.size} conseiller(s) · CA cumulé ${totalRev} XOF\n# Généré le ${new Date().toISOString()} par admin:${r.admin.username}\n`;
    const fname = `ippoo-filleuls-${filterMat || "all"}-${new Date().toISOString().slice(0, 10)}.csv`;
    const body = "﻿" + summary + lines.join("\n") + "\n";
    const sha256 = await sha256Hex(body);
    await audit(`admin:${r.admin.username}`, "admin.export.enrollments", {
      matricule: filterMat || null, since: sinceRaw || null, count: rows.length, totalRev,
      sha256, bytes: body.length, filename: fname,
    }).catch(() => {});
    await adminAudit(c, r.admin, "admin.export.enrollments", {
      matricule: filterMat || null, since: sinceRaw || null, count: rows.length, totalRev,
      sha256, bytes: body.length, filename: fname,
    }).catch(() => {});
    return new Response(body, {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="${fname}"`,
        "X-Export-Sha256": sha256,
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Expose-Headers": "X-Export-Sha256, Content-Disposition",
      },
    });
  } catch (err) {
    console.log(`Enrollments export error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: KPIs BUSINESS (CA mensuel, churn, conversion, top produits) ----
app.get(`${PREFIX}/admin/kpi`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const [{ data: payRows }, { data: ctRows }, { data: profRows }, { data: quoteRows }] = await Promise.all([
      admin.from("kv_store_752d1a39").select("key, value").like("key", "payments:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "contracts:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "profile:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "quotes:%"),
    ]);

    const now = new Date();
    const ym = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
    const months: string[] = [];
    for (let i = 11; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      months.push(ym(d));
    }
    const monthIdx = new Map(months.map((m, i) => [m, i]));
    const revenueByMonth = new Array(12).fill(0);
    const subsByMonth = new Array(12).fill(0);
    const churnByMonth = new Array(12).fill(0);
    const revenueByProduct: Record<string, number> = {};

    for (const row of payRows ?? []) for (const p of (row.value ?? []) as any[]) {
      if (p?.status !== "confirme") continue;
      const m = (p.createdAt ?? "").slice(0, 7);
      const i = monthIdx.get(m);
      if (i !== undefined) revenueByMonth[i] += Number(p.amount ?? 0);
      const prod = String(p?.product ?? p?.label ?? "Autre");
      revenueByProduct[prod] = (revenueByProduct[prod] ?? 0) + Number(p.amount ?? 0);
    }

    let activeContracts = 0, cancelledTotal = 0, assistedSubs = 0;
    for (const row of ctRows ?? []) for (const ct of (row.value ?? []) as any[]) {
      if (ct?.status === "active") activeContracts++;
      if (ct?.subscribedBy) assistedSubs++;
      const sm = (ct?.startDate ?? "").slice(0, 7);
      const si = monthIdx.get(sm);
      if (si !== undefined) subsByMonth[si]++;
      if (ct?.cancelledAt) {
        const cm = (ct.cancelledAt ?? "").slice(0, 7);
        const ci = monthIdx.get(cm);
        if (ci !== undefined) churnByMonth[ci]++;
        cancelledTotal++;
      }
    }

    let totalUsers = 0, usersWithContract = 0;
    const usersWithContractSet = new Set<string>();
    for (const row of ctRows ?? []) {
      const uid = (row.key as string).slice("contracts:".length);
      const list = (row.value ?? []) as any[];
      if (list.some((c: any) => c?.status === "active")) usersWithContractSet.add(uid);
    }
    usersWithContract = usersWithContractSet.size;
    for (const _ of profRows ?? []) totalUsers++;

    let totalQuotes = 0;
    for (const row of quoteRows ?? []) {
      const list = Array.isArray(row.value) ? (row.value as any[]) : [row.value];
      totalQuotes += list.filter(Boolean).length;
    }
    const conversionRate = totalQuotes > 0 ? activeContracts / totalQuotes : null;
    const churnRate = (cancelledTotal + activeContracts) > 0
      ? cancelledTotal / (cancelledTotal + activeContracts)
      : 0;

    const topProducts = Object.entries(revenueByProduct)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8)
      .map(([product, revenue]) => ({ product, revenue }));

    const currentMonth = revenueByMonth[11] ?? 0;
    const previousMonth = revenueByMonth[10] ?? 0;
    const momGrowth = previousMonth > 0 ? (currentMonth - previousMonth) / previousMonth : null;

    return c.json({
      generatedAt: new Date().toISOString(),
      months,
      revenueByMonth,
      subsByMonth,
      churnByMonth,
      topProducts,
      summary: {
        currentMonthRevenue: currentMonth,
        previousMonthRevenue: previousMonth,
        momGrowth,
        activeContracts,
        cancelledTotal,
        churnRate,
        totalUsers,
        usersWithContract,
        totalQuotes,
        conversionRate,
        assistedSubscriptions: assistedSubs,
      },
    });
  } catch (err) {
    console.log(`Admin KPI error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

// ---- ADMIN: PERFORMANCE PAR AGENT ----
// A13 — Géo-tag visite terrain. Quand un conseiller rend visite à un client
// (souscription papier, signature physique, livraison de carte), il pousse
// sa position GPS + matricule + uid. On stocke un ring borné 200 par client
// pour traçabilité ; les admins peuvent ensuite faire des contrôles.
app.post(`${PREFIX}/agent/visits/:uid`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  const uid = c.req.param("uid");
  try {
    const body = await c.req.json().catch(() => ({}));
    const lat = Number(body?.lat);
    const lng = Number(body?.lng);
    const accuracy = Number(body?.accuracy ?? 0);
    const note = String(body?.note ?? "").slice(0, 500);
    if (!isFinite(lat) || !isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180) {
      return c.json({ error: "Coordonnées invalides" }, 400);
    }
    const key = `agent:visits:${uid}`;
    const list = ((await kv.get(key)) ?? []) as any[];
    const entry = {
      id: `v_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      agentId: r.agent.id, matricule: r.agent.matricule,
      lat, lng, accuracy, note,
      at: new Date().toISOString(),
    };
    list.unshift(entry);
    await kv.set(key, list.slice(0, 200));
    await audit(uid, "agent.visit", { matricule: r.agent.matricule, lat, lng });
    return c.json({ ok: true, visit: entry });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// A11 — Dashboard commissions agent. Pour le conseiller connecté, retourne
// les paiements confirmés qu'il a encaissés (collectedBy === matricule)
// ventilés par mois sur les 6 derniers mois + total période + taux de
// commission appliqué (par défaut 5%, surchargeable via AGENT_COMMISSION_PCT).
app.get(`${PREFIX}/agent/commissions`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const pct = Number(Deno.env.get("AGENT_COMMISSION_PCT") ?? "5");
    const months: string[] = [];
    const now = new Date();
    for (let i = 5; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      months.push(`${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`);
    }
    const monthIdx = new Map(months.map((m, i) => [m, i]));
    const byMonth = new Array(6).fill(0);
    const { data, error } = await admin.from("kv_store_752d1a39").select("key, value").like("key", "payments:%");
    if (error) return c.json({ error: error.message }, 500);
    let total = 0, count = 0;
    for (const row of data ?? []) for (const p of (row.value ?? []) as any[]) {
      if (p?.status !== "confirme") continue;
      if (p?.collectedBy !== r.agent.matricule) continue;
      const m = (p.createdAt ?? "").slice(0, 7);
      const i = monthIdx.get(m);
      if (i === undefined) continue;
      const amt = Number(p.amount ?? 0);
      byMonth[i] += amt;
      total += amt;
      count++;
    }
    const commissionByMonth = byMonth.map((a) => Math.round(a * pct) / 100);
    const totalCommission = Math.round(total * pct) / 100;
    return c.json({
      pct, months,
      collectedByMonth: byMonth,
      commissionByMonth,
      totalCollected: total,
      totalCommission,
      paymentsCount: count,
    });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

// A17 — Leaderboard agent. Le conseiller voit son propre matricule en clair
// et son rang ; les autres sont anonymisés (A1, A2, …) pour ne pas exposer
// la performance individuelle des collègues. Métriques 30j : sinistres décidés
// + montants encaissés. Léger : agrège payments + claims uniquement.
app.get(`${PREFIX}/agent/leaderboard`, async (c) => {
  const r = await requireAgent(c);
  if (!r.agent) return c.json({ error: r.error }, r.status);
  try {
    const since = new Date(Date.now() - 30 * 86400000).toISOString();
    const [{ data: claimRows }, { data: payRows }, { data: matRows }] = await Promise.all([
      admin.from("kv_store_752d1a39").select("key, value").like("key", "claims:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "payments:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "agent:matricule:%"),
    ]);
    const matSet = new Set<string>();
    for (const row of matRows ?? []) {
      const k0 = row.key as string;
      if (k0.startsWith("agent:matricule-claim:")) continue;
      const v = row.value as any;
      const m = typeof v === "string" ? v : v?.matricule;
      if (m) matSet.add(m);
    }
    type Row = { matricule: string; claimsDecided: number; paymentsAmount: number; score: number };
    const stats: Record<string, Row> = {};
    for (const m of matSet) stats[m] = { matricule: m, claimsDecided: 0, paymentsAmount: 0, score: 0 };
    for (const row of claimRows ?? []) for (const cl of (row.value ?? []) as any[]) {
      const m = cl?.decidedBy;
      if (!m || !matSet.has(m) || (cl?.decidedAt ?? "") < since) continue;
      stats[m].claimsDecided++;
    }
    for (const row of payRows ?? []) for (const p of (row.value ?? []) as any[]) {
      const m = p?.collectedBy;
      if (!m || !matSet.has(m) || p?.status !== "confirme" || (p?.createdAt ?? "") < since) continue;
      stats[m].paymentsAmount += Number(p.amount ?? 0);
    }
    // Score composite simple : 1 décision = 1pt, 10 000 FCFA encaissés = 1pt.
    const ranked = Object.values(stats)
      .map((s) => ({ ...s, score: s.claimsDecided + s.paymentsAmount / 10000 }))
      .sort((a, b) => b.score - a.score);
    const meIdx = ranked.findIndex((s) => s.matricule === r.agent.matricule);
    const anonymized = ranked.map((s, i) => ({
      rank: i + 1,
      isMe: s.matricule === r.agent.matricule,
      label: s.matricule === r.agent.matricule ? s.matricule : `A${i + 1}`,
      claimsDecided: s.claimsDecided,
      paymentsAmount: Math.round(s.paymentsAmount),
      score: Math.round(s.score * 10) / 10,
    }));
    return c.json({ rank: meIdx + 1, total: ranked.length, leaderboard: anonymized });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.get(`${PREFIX}/admin/agents/performance`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const days = Math.min(Math.max(Number(c.req.query("days") ?? 30) || 30, 1), 365);
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const [{ data: matRows }, { data: claimRows }, { data: ctRows }, { data: kycRows }, { data: payRows }, { data: msgRows }, { data: profileRows }] = await Promise.all([
      admin.from("kv_store_752d1a39").select("key, value").like("key", "agent:matricule:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "claims:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "contracts:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "kyc:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "payments:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "messages:%"),
      admin.from("kv_store_752d1a39").select("key, value").like("key", "profile:%"),
    ]);

    type AgentInfo = { matricule: string; userId: string; email?: string; name?: string };
    const agents: AgentInfo[] = [];
    for (const row of matRows ?? []) {
      const key = row.key as string;
      if (key.startsWith("agent:matricule-claim:")) continue;
      const uid = key.slice("agent:matricule:".length);
      const v = row.value as any;
      const matricule = typeof v === "string" ? v : v?.matricule;
      if (!matricule) continue;
      agents.push({ matricule, userId: uid });
    }
    await Promise.all(agents.map(async (a) => {
      const p = await kv.get(k.profile(a.userId)) as any;
      if (p) { a.email = p.email; a.name = p.name; }
    }));

    const matSet = new Set(agents.map((a) => a.matricule));
    const initStats = () => ({
      claimsDecided: 0, claimsValidated: 0, claimsRejected: 0, claimsSettled: 0,
      contractsSubscribed: 0, contractsRenewed: 0, contractsCancelled: 0,
      kycDecided: 0, kycValidated: 0, kycRejected: 0,
      paymentsAmount: 0, paymentsCount: 0,
      messagesSent: 0,
      totalResponseMs: 0, responsePairs: 0, responsesUnder1h: 0,
      enrollmentsTotal: 0, enrollmentsWindow: 0,
    });
    const stats: Record<string, ReturnType<typeof initStats>> = {};
    for (const m of matSet) stats[m] = initStats();

    for (const row of claimRows ?? []) for (const cl of (row.value ?? []) as any[]) {
      const m = cl?.decidedBy;
      if (!m || !matSet.has(m)) continue;
      if (!cl?.decidedAt || cl.decidedAt < since) continue;
      const s = stats[m];
      s.claimsDecided++;
      if (cl.status === "valide") s.claimsValidated++;
      else if (cl.status === "rejete") s.claimsRejected++;
      else if (cl.status === "regle") s.claimsSettled++;
    }
    for (const row of ctRows ?? []) for (const ct of (row.value ?? []) as any[]) {
      if (ct?.subscribedBy && matSet.has(ct.subscribedBy) && (ct?.startDate ?? "") >= since) stats[ct.subscribedBy].contractsSubscribed++;
      if (ct?.renewedBy && matSet.has(ct.renewedBy) && (ct?.lastRenewedAt ?? "") >= since) stats[ct.renewedBy].contractsRenewed++;
      if (ct?.cancelledBy && matSet.has(ct.cancelledBy) && (ct?.cancelledAt ?? "") >= since) stats[ct.cancelledBy].contractsCancelled++;
    }
    for (const row of kycRows ?? []) for (const kk of (row.value ?? []) as any[]) {
      const m = kk?.decidedByMatricule;
      if (!m || !matSet.has(m)) continue;
      if (!kk?.decidedAt || kk.decidedAt < since) continue;
      const s = stats[m];
      s.kycDecided++;
      if (kk.status === "valide") s.kycValidated++;
      else if (kk.status === "rejete") s.kycRejected++;
    }
    for (const row of payRows ?? []) for (const p of (row.value ?? []) as any[]) {
      const m = p?.collectedBy;
      if (!m || !matSet.has(m)) continue;
      if (p?.status !== "confirme" || (p?.createdAt ?? "") < since) continue;
      const s = stats[m];
      s.paymentsCount++;
      s.paymentsAmount += Number(p.amount ?? 0);
    }
    for (const row of profileRows ?? []) {
      const p = (row.value ?? {}) as any;
      const m = p?.enrolledBy;
      if (!m || !matSet.has(m)) continue;
      const s = stats[m];
      s.enrollmentsTotal++;
      const at = p?.enrolledAt ?? p?.createdAt;
      if (at && at >= since) s.enrollmentsWindow++;
    }
    for (const row of msgRows ?? []) {
      const list = (row.value ?? []) as any[];
      let lastUserAt: number | null = null;
      for (const m of list) {
        if (m?.from === "user") {
          lastUserAt = new Date(m.createdAt).getTime();
        } else if (m?.from === "conseiller") {
          const mat = m?.authorMatricule;
          if (mat && matSet.has(mat) && (m?.createdAt ?? "") >= since) {
            const s = stats[mat];
            s.messagesSent++;
            if (lastUserAt) {
              const dt = new Date(m.createdAt).getTime() - lastUserAt;
              if (dt > 0 && dt < 7 * 86400000) {
                s.totalResponseMs += dt; s.responsePairs++;
                if (dt <= 3_600_000) s.responsesUnder1h++;
              }
              lastUserAt = null;
            }
          } else {
            lastUserAt = null;
          }
        }
      }
    }

    const result = agents.map((a) => {
      const s = stats[a.matricule];
      const avgResponseSec = s.responsePairs > 0 ? Math.round(s.totalResponseMs / s.responsePairs / 1000) : null;
      const slaUnder1hPct = s.responsePairs > 0 ? Math.round((s.responsesUnder1h * 100) / s.responsePairs) : null;
      return {
        matricule: a.matricule,
        userId: a.userId,
        name: a.name ?? "",
        email: a.email ?? "",
        claims: { decided: s.claimsDecided, validated: s.claimsValidated, rejected: s.claimsRejected, settled: s.claimsSettled },
        contracts: { subscribed: s.contractsSubscribed, renewed: s.contractsRenewed, cancelled: s.contractsCancelled },
        kyc: { decided: s.kycDecided, validated: s.kycValidated, rejected: s.kycRejected },
        payments: { amount: s.paymentsAmount, count: s.paymentsCount },
        messages: { sent: s.messagesSent, avgResponseSec, responsePairs: s.responsePairs, responsesUnder1h: s.responsesUnder1h, slaUnder1hPct },
        enrollments: { total: s.enrollmentsTotal, window: s.enrollmentsWindow },
      };
    }).sort((a, b) => (b.enrollments.window + b.contracts.subscribed + b.claims.decided + b.kyc.decided) - (a.enrollments.window + a.contracts.subscribed + a.claims.decided + a.kyc.decided));

    // CSV variant pour pilotage RH/coach : ?format=csv renvoie le même payload
    // en CSV avec les colonnes principales (SLA inclus). Pas de séparation
    // d'endpoint pour éviter de dupliquer toute la collecte amont.
    if (c.req.query("format") === "csv") {
      const escape = (v: unknown): string => {
        const s = v == null ? "" : String(v);
        return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
      };
      const header = [
        "matricule", "nom", "email",
        "filleuls_fenetre", "filleuls_total",
        "contrats_souscrits", "contrats_renouveles", "contrats_annules",
        "sinistres_decides", "sinistres_valides", "sinistres_rejetes", "sinistres_regles",
        "kyc_decides", "kyc_valides", "kyc_rejetes",
        "paiements_count", "paiements_montant_xof",
        "messages_envoyes", "reponses_paires", "reponses_sous_1h", "sla_sous_1h_pct", "delai_moyen_sec",
      ];
      const lines = [header.join(",")];
      for (const a of result) {
        lines.push([
          a.matricule, a.name, a.email,
          a.enrollments.window, a.enrollments.total,
          a.contracts.subscribed, a.contracts.renewed, a.contracts.cancelled,
          a.claims.decided, a.claims.validated, a.claims.rejected, a.claims.settled,
          a.kyc.decided, a.kyc.validated, a.kyc.rejected,
          a.payments.count, a.payments.amount,
          a.messages.sent, a.messages.responsePairs, a.messages.responsesUnder1h, a.messages.slaUnder1hPct ?? "", a.messages.avgResponseSec ?? "",
        ].map(escape).join(","));
      }
      const summary = `# Performance conseillers IPPOO · ${days}j (depuis ${since.slice(0,10)})\n# ${result.length} matricules · généré le ${new Date().toISOString()} par admin:${r.admin.username}\n`;
      const body = "﻿" + summary + lines.join("\n") + "\n";
      const filename = `ippoo-perf-agents-${days}j.csv`;
      await adminAudit(c, r.admin, "admin.export.agentsPerf", { days, agents: result.length, bytes: body.length, filename }).catch(() => {});
      return new Response(body, {
        status: 200,
        headers: {
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": `attachment; filename="${filename}"`,
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Expose-Headers": "Content-Disposition",
        },
      });
    }

    return c.json({ generatedAt: new Date().toISOString(), days, since, agents: result });
  } catch (err) {
    console.log(`Admin agents perf error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

// P10 — Consentements horodatés (CGU / confidentialité / traitement données).
// Stockage append-only : on garde l'historique complet pour preuve. Schéma :
//   consents:<uid> = [{ type, version, at, ip, userAgent }]
// Le frontend POST juste après le signup ou lors d'une mise à jour des CGU.
app.post(`${PREFIX}/consents`, async (c) => {
  const r = await requireUser(c);
  if (!r.user) return c.json({ error: r.error }, r.status);
  try {
    const body = await c.req.json();
    const items = Array.isArray(body?.items) ? body.items : [];
    if (items.length === 0) return c.json({ error: "Aucun consentement fourni" }, 400);
    const ip = c.req.header("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
    const ua = c.req.header("user-agent") ?? "";
    const at = new Date().toISOString();
    const accepted = ["cgu", "confidentialite", "traitement", "ars", "marketing"];
    const valid = items
      .filter((it: any) => it && typeof it.type === "string" && accepted.includes(it.type))
      .map((it: any) => ({
        type: it.type,
        version: String(it.version ?? "1"),
        granted: it.granted !== false,
        at,
        ip,
        userAgent: ua.slice(0, 200),
      }));
    if (valid.length === 0) return c.json({ error: "Types de consentement invalides" }, 400);
    const key = `consents:${r.user.id}`;
    const existing = ((await kv.get(key)) ?? []) as any[];
    const merged = [...existing, ...valid].slice(-100);
    await kv.set(key, merged);
    return c.json({ ok: true, stored: valid.length, total: merged.length });
  } catch (err) {
    return c.json({ error: `Consents store error: ${err}` }, 500);
  }
});

app.get(`${PREFIX}/consents`, async (c) => {
  const r = await requireUser(c);
  if (!r.user) return c.json({ error: r.error }, r.status);
  const list = ((await kv.get(`consents:${r.user.id}`)) ?? []) as any[];
  return c.json({ consents: list });
});

// SLA public côté client (C7) : retourne le nombre de conseillers actuellement
// en ligne et un délai estimé de réponse, pour rassurer l'utilisateur dans la
// messagerie. Lecture rapide de `agent:presence:*` ; aucune auth requise au-
// delà du publicAnonKey (l'info exposée est volontairement agrégée).
app.get(`${PREFIX}/sla/public`, async (c) => {
  try {
    const { data } = await admin
      .from("kv_store_752d1a39")
      .select("key, value")
      .like("key", "agent:presence:%");
    const STALE_MS = 90_000;
    const now = Date.now();
    let online = 0;
    for (const row of data ?? []) {
      const p = (row.value ?? {}) as { status?: string; at?: string };
      if (p.status !== "online") continue;
      const at = p.at ? new Date(p.at).getTime() : 0;
      if (now - at <= STALE_MS) online++;
    }
    let etaLabel: string;
    let etaMinutes: number;
    if (online >= 3) { etaLabel = "Réponse sous 5 min"; etaMinutes = 5; }
    else if (online >= 1) { etaLabel = "Réponse sous 15 min"; etaMinutes = 15; }
    else { etaLabel = "Réponse sous 24h ouvrées"; etaMinutes = 24 * 60; }
    return c.json({
      online,
      etaLabel,
      etaMinutes,
      generatedAt: new Date().toISOString(),
    }, 200, { "Cache-Control": "public, max-age=30" });
  } catch (err) {
    console.log(`SLA public error: ${err}`);
    return c.json({ online: 0, etaLabel: "Réponse sous 24h ouvrées", etaMinutes: 24 * 60 }, 200);
  }
});

// === Web Push (VAPID) ===
// Configure VAPID_PUBLIC, VAPID_PRIVATE, VAPID_SUBJECT (mailto:contact@…)
// env vars to enable real push delivery. Without them, /push/vapid-public
// returns null and subscribe routes still store subscriptions (so the UI
// state stays correct), but pushUsers() will short-circuit.
const VAPID_PUBLIC = Deno.env.get("VAPID_PUBLIC") ?? null;
const VAPID_PRIVATE = Deno.env.get("VAPID_PRIVATE") ?? null;
const VAPID_SUBJECT = Deno.env.get("VAPID_SUBJECT") ?? "mailto:contact@ippoo.example";

app.get(`${PREFIX}/push/vapid-public`, (c) => c.json({ publicKey: VAPID_PUBLIC }));

app.post(`${PREFIX}/push/subscribe`, async (c) => {
  const r = await requireUser(c);
  if (!r.user) return c.json({ error: r.error }, 401);
  try {
    const body = await c.req.json();
    const sub = body?.subscription;
    if (!sub?.endpoint) return c.json({ error: "subscription invalide" }, 400);
    const list = ((await kv.get(k.pushSubs(r.user.id))) ?? []) as any[];
    const next = list.filter((s) => s.endpoint !== sub.endpoint).concat([{ ...sub, createdAt: new Date().toISOString() }]);
    await kv.set(k.pushSubs(r.user.id), next.slice(-5));
    return c.json({ ok: true });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

app.post(`${PREFIX}/push/unsubscribe`, async (c) => {
  const r = await requireUser(c);
  if (!r.user) return c.json({ error: r.error }, 401);
  try {
    const body = await c.req.json();
    const endpoint = String(body?.endpoint ?? "");
    const list = ((await kv.get(k.pushSubs(r.user.id))) ?? []) as any[];
    await kv.set(k.pushSubs(r.user.id), list.filter((s) => s.endpoint !== endpoint));
    return c.json({ ok: true });
  } catch (err) {
    return c.json({ error: `${err}` }, 500);
  }
});

/** Send a push notification to one or many users. No-op when VAPID env unset. */
async function pushUsers(uids: string[], payload: { title: string; body: string; url?: string; tag?: string }) {
  if (!VAPID_PUBLIC || !VAPID_PRIVATE) return { sent: 0, skipped: uids.length, reason: "no-vapid" };
  let webpush: any;
  try {
    webpush = await import("npm:web-push@3.6.7");
    webpush.default.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC, VAPID_PRIVATE);
  } catch (err) {
    console.error("web-push import failed", err);
    return { sent: 0, skipped: uids.length, reason: "import-failed" };
  }
  let sent = 0;
  let failed = 0;
  for (const uid of uids) {
    const subs = ((await kv.get(k.pushSubs(uid))) ?? []) as any[];
    for (const s of subs) {
      try {
        await webpush.default.sendNotification(s, JSON.stringify(payload));
        sent++;
      } catch (err: any) {
        failed++;
        // Stale subscription — drop on 404/410
        if (err?.statusCode === 404 || err?.statusCode === 410) {
          const cur = ((await kv.get(k.pushSubs(uid))) ?? []) as any[];
          await kv.set(k.pushSubs(uid), cur.filter((x) => x.endpoint !== s.endpoint));
        }
      }
    }
  }
  return { sent, failed };
}
// Expose for callers within this module (notify helpers etc.)
(globalThis as any).__ippoo_pushUsers = pushUsers;

// === Wallet integrations ===
// Google Wallet — issues a signed JWT Save-to-Wallet link.
// Requires: GOOGLE_WALLET_ISSUER_ID, GOOGLE_WALLET_CLASS_ID,
// GOOGLE_WALLET_SA_EMAIL, GOOGLE_WALLET_SA_KEY (PEM private key).
const GW_ISSUER = Deno.env.get("GOOGLE_WALLET_ISSUER_ID") ?? null;
const GW_CLASS = Deno.env.get("GOOGLE_WALLET_CLASS_ID") ?? null;
const GW_SA_EMAIL = Deno.env.get("GOOGLE_WALLET_SA_EMAIL") ?? null;
const GW_SA_KEY = Deno.env.get("GOOGLE_WALLET_SA_KEY") ?? null;

async function importPemRsaKey(pem: string): Promise<CryptoKey> {
  const body = pem.replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const der = b64urlDecode(body.replace(/\+/g, "-").replace(/\//g, "_"));
  return crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
}

app.get(`${PREFIX}/wallet/google`, async (c) => {
  const r = await requireUser(c);
  if (!r.user) return c.json({ error: r.error }, 401);
  const configured = !!(GW_ISSUER && GW_CLASS && GW_SA_EMAIL && GW_SA_KEY);
  if (!configured) return c.json({ saveUrl: null, configured: false });
  try {
    const profile = (await kv.get(k.profile(r.user.id))) as any;
    const objectId = `${GW_ISSUER}.member-${r.user.id}`;
    const payload = {
      iss: GW_SA_EMAIL,
      aud: "google",
      typ: "savetowallet",
      iat: Math.floor(Date.now() / 1000),
      payload: {
        genericObjects: [{
          id: objectId,
          classId: GW_CLASS,
          state: "ACTIVE",
          cardTitle: { defaultValue: { language: "fr", value: "IPPOO Assurance" } },
          header: { defaultValue: { language: "fr", value: profile?.name ?? "Membre IPPOO" } },
          subheader: { defaultValue: { language: "fr", value: "Carte Membre" } },
          textModulesData: [{ header: "N° Membre", body: profile?.memberNumber ?? "—" }],
          barcode: { type: "QR_CODE", value: profile?.memberNumber ?? r.user.id, alternateText: profile?.memberNumber ?? "" },
        }],
      },
    };
    const header = { alg: "RS256", typ: "JWT" };
    const h64 = b64urlEncode(enc.encode(JSON.stringify(header)));
    const p64 = b64urlEncode(enc.encode(JSON.stringify(payload)));
    const signingInput = `${h64}.${p64}`;
    const key = await importPemRsaKey(GW_SA_KEY!);
    const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(signingInput));
    const jwt = `${signingInput}.${b64urlEncode(sig)}`;
    return c.json({ saveUrl: `https://pay.google.com/gp/v/save/${jwt}`, configured: true });
  } catch (err) {
    return c.json({ saveUrl: null, configured: true, error: `${err}` }, 500);
  }
});

// Apple Wallet — signed .pkpass requires Apple Developer Pass Type ID cert.
// Without APPLE_PASS_CERT + APPLE_PASS_KEY, we return 503 with a clear msg.
// Admin: resend invoice for a specific payment via email (uses Resend).
app.post(`${PREFIX}/admin/payments/:userId/:paymentId/refund`, async (c) => {
  const g = await requireAdmin(c);
  if ("response" in g) return g.response;
  const r = { admin: g.admin };
  const userId = c.req.param("userId");
  const paymentId = c.req.param("paymentId");
  try {
    const body = await c.req.json().catch(() => ({}));
    const action = body.action as string;
    const reason = ((body.reason as string) ?? "").trim();
    if (!["rembourse", "annule"].includes(action)) {
      return c.json({ error: "Action invalide (rembourse | annule)" }, 400);
    }
    if (reason.length < 3) {
      return c.json({ error: "Un motif d'au moins 3 caractères est requis" }, 400);
    }
    const payments = ((await kv.get(k.payments(userId))) ?? []) as any[];
    const idx = payments.findIndex((p: any) => p.id === paymentId);
    if (idx === -1) return c.json({ error: "Paiement introuvable" }, 404);
    const pay = payments[idx];
    if (action === "rembourse" && pay.status !== "confirme") {
      return c.json({ error: "Seul un paiement confirmé peut être remboursé" }, 400);
    }
    if (action === "annule" && pay.status === "confirme") {
      return c.json({ error: "Impossible d'annuler un paiement confirmé (utiliser remboursement)" }, 400);
    }
    payments[idx] = {
      ...pay,
      status: action,
      refundedAt: new Date().toISOString(),
      refundReason: reason,
      refundedBy: r.admin.username,
    };
    await kv.set(k.payments(userId), payments);
    const notifs = ((await kv.get(k.notifications(userId))) ?? []) as any[];
    const label = action === "rembourse" ? "remboursé" : "annulé";
    await notifyAndDispatch(userId, notifs, {
      typeKey: "payment",
      title: `Paiement ${label}`,
      body: `Votre paiement de ${pay.amount} FCFA a été ${label}. Motif : ${reason}`,
      severity: "warn",
      to: "/espace-client/cotisations",
    });
    await audit(userId, `admin.payment.${action}`, { paymentId, reason, by: r.admin.username });
    await adminAudit(c, r.admin, `payment.${action}`, { userId, paymentId, amount: pay.amount, reason });
    broadcast(`payments:live`, "payments:dirty", { userId, paymentId, status: action });
    broadcast(`payments:user:${userId}`, "payments:dirty", { paymentId, status: action });
    return c.json({ payment: payments[idx] });
  } catch (err) {
    console.log(`Admin payment refund error: ${err}`);
    return c.json({ error: `${err}` }, 500);
  }
});

app.post(`${PREFIX}/admin/payments/:userId/:paymentId/send-invoice`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  const userId = c.req.param("userId");
  const paymentId = c.req.param("paymentId");
  const payments = ((await kv.get(k.payments(userId))) ?? []) as any[];
  const payment = payments.find((p) => p.id === paymentId);
  if (!payment) return c.json({ error: "Paiement introuvable" }, 404);
  if (payment.status !== "confirme") return c.json({ error: "Paiement non confirmé" }, 400);
  const profile = (await kv.get(k.profile(userId))) as any;
  if (!profile?.email) return c.json({ error: "Membre sans e-mail" }, 400);
  if (!RESEND_KEY) return c.json({ error: "Resend non configuré" }, 503);
  const invNo = `INV-${payment.id.slice(-8).toUpperCase()}`;
  const dateStr = new Date(payment.createdAt).toLocaleDateString("fr-FR");
  const amount = new Intl.NumberFormat("fr-FR").format(payment.amount) + " FCFA";
  const html = `<div style="font-family:system-ui,sans-serif;max-width:600px;margin:auto;padding:24px;color:#191923">
    <h1 style="color:#D84332;letter-spacing:-0.02em">FACTURE ${invNo}</h1>
    <p>Bonjour ${profile.name || profile.firstName || "membre"},</p>
    <p>Veuillez trouver le récapitulatif de votre paiement IPPOO ASSURANCE :</p>
    <table style="width:100%;border-collapse:collapse;margin:16px 0">
      <tr><td style="padding:8px;border-bottom:1px solid #eee"><b>Date</b></td><td style="padding:8px;border-bottom:1px solid #eee">${dateStr}</td></tr>
      <tr><td style="padding:8px;border-bottom:1px solid #eee"><b>Méthode</b></td><td style="padding:8px;border-bottom:1px solid #eee">${payment.method}</td></tr>
      <tr><td style="padding:8px;border-bottom:1px solid #eee"><b>Référence</b></td><td style="padding:8px;border-bottom:1px solid #eee">${payment.id}</td></tr>
      <tr><td style="padding:8px"><b>Total</b></td><td style="padding:8px;color:#D84332;font-size:18px;font-weight:900">${amount}</td></tr>
    </table>
    <p style="color:#777;font-size:13px">Une copie complète est disponible dans votre espace client.</p>
    <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
    <p style="color:#888;font-size:12px">IPPOO ASSURANCE · Parakou, Bénin · +229 01 41 52 10 92</p>
  </div>`;
  const ok = await sendEmail(profile.email, `Facture IPPOO ${invNo} — ${amount}`, html);
  if (!ok) return c.json({ error: "Échec d'envoi" }, 502);
  await audit(`admin:${r.admin.username}`, "admin.invoice.email", { paymentId, to: profile.email });
  await adminAudit(c, r.admin, "invoice.email", { userId, paymentId });
  return c.json({ ok: true });
});

// Wallet status (admin diagnostics).
app.get(`${PREFIX}/admin/wallet/status`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  return c.json({
    google: { configured: !!(GW_ISSUER && GW_CLASS && GW_SA_EMAIL && GW_SA_KEY) },
    apple: { configured: false, reason: "Pass Type ID requis (Apple Developer)" },
  });
});

app.get(`${PREFIX}/wallet/apple`, (c) => {
  return c.json(
    { error: "Apple Wallet non configuré (Pass Type ID requis)", configured: false },
    503,
  );
});

// =====================================================================
// ====  Bloc D1-D12 — back-office admin (helpers + endpoints)        ===
// =====================================================================

// ---- D1 — Journal des webhooks PSP ----------------------------------
// Pour chaque webhook PSP entrant, on persiste un événement complet
// (provider, status, raison, headers, body brut tronqué) dans un ring
// borné à 500. Permet la replay/diagnostic depuis le back-office.
async function logWebhookEvent(opts: {
  provider: string;
  c: any;
  status: "ok" | "failed" | "skipped";
  reason?: string;
  httpStatus?: number;
  rawBody?: string;
  metadata?: Record<string, any>;
}) {
  try {
    const id = `wh_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
    const headers: Record<string, string> = {};
    try {
      const raw = (opts.c?.req?.raw?.headers ?? opts.c?.req?.header) as any;
      if (raw && typeof raw.forEach === "function") {
        raw.forEach((v: string, k: string) => { headers[k] = v.slice(0, 500); });
      } else if (opts.c?.req?.header) {
        for (const h of ["content-type", "user-agent", "x-forwarded-for", "x-kkiapay-secret", "x-fedapay-signature", "x-callback-key", "x-cinetpay-signature"]) {
          const v = opts.c.req.header(h);
          if (v) headers[h] = String(v).slice(0, 500);
        }
      }
    } catch { /* ignore */ }
    const body = (opts.rawBody ?? "").slice(0, 64_000);
    const event = {
      id,
      provider: opts.provider,
      status: opts.status,
      reason: opts.reason ?? "",
      path: opts.c?.req?.path ?? "",
      method: opts.c?.req?.method ?? "POST",
      receivedAt: new Date().toISOString(),
      bytes: body.length,
      httpStatus: opts.httpStatus ?? 0,
      headers,
      body,
      metadata: opts.metadata ?? {},
    };
    await kv.set(k.webhookEvent(id), event);
    const index = ((await kv.get(k.webhookIndex())) ?? []) as { id: string; provider: string; status: string; reason: string; receivedAt: string; httpStatus: number; bytes: number; path: string; method: string; replayedAt?: string; replayedBy?: string }[];
    index.unshift({
      id, provider: event.provider, status: event.status, reason: event.reason,
      receivedAt: event.receivedAt, httpStatus: event.httpStatus, bytes: event.bytes,
      path: event.path, method: event.method,
    });
    await kv.set(k.webhookIndex(), index.slice(0, 500));
    if (opts.status === "failed") {
      broadcast(`admin:webhooks`, "webhook:failed", { provider: opts.provider, reason: opts.reason, at: event.receivedAt }).catch(() => {});
    }
  } catch (err) {
    console.log(`logWebhookEvent error: ${err}`);
  }
}

// ---- D9 — Persistance des sessions admin ----------------------------
async function persistAdminSession(c: any, jti: string, username: string, role: string, expiresAtMs: number) {
  try {
    const ip = c?.req?.header("x-forwarded-for")?.split(",")[0]?.trim() ?? "anon";
    const ua = (c?.req?.header("user-agent") ?? "").slice(0, 200);
    const session = {
      jti, username, role, ip, ua,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(expiresAtMs).toISOString(),
    };
    await kv.set(k.adminSession(jti), session);
    const idx = ((await kv.get(k.adminSessionsIndex())) ?? []) as string[];
    if (!idx.includes(jti)) idx.unshift(jti);
    await kv.set(k.adminSessionsIndex(), idx.slice(0, 200));
  } catch (err) {
    console.log(`persistAdminSession error: ${err}`);
  }
}

// ---- D1 — Liste webhooks --------------------------------------------
app.get(`${PREFIX}/admin/webhooks`, async (c) => {
  const g = await requireAdmin(c, "superadmin", "operator", "support");
  if ("response" in g) return g.response;
  try {
    const url = new URL(c.req.url);
    const filter = url.searchParams.get("filter") ?? "all";
    const limit = Math.max(1, Math.min(500, Number(url.searchParams.get("limit") ?? "100")));
    let index = ((await kv.get(k.webhookIndex())) ?? []) as any[];
    if (filter === "failed") index = index.filter((e) => e.status === "failed");
    else if (filter === "ok") index = index.filter((e) => e.status === "ok");
    return c.json({ events: index.slice(0, limit) });
  } catch (err) {
    return c.json({ error: `webhooks list: ${err}` }, 500);
  }
});

app.get(`${PREFIX}/admin/webhooks/:id`, async (c) => {
  const g = await requireAdmin(c, "superadmin", "operator", "support");
  if ("response" in g) return g.response;
  try {
    const id = c.req.param("id");
    const event = await kv.get(k.webhookEvent(id));
    if (!event) return c.json({ error: "not-found" }, 404);
    return c.json({ event });
  } catch (err) {
    return c.json({ error: `webhook detail: ${err}` }, 500);
  }
});

// Replay un webhook PSP en re-postant le body brut sur la même route, avec
// les headers d'origine (signature comprise). Audité.
app.post(`${PREFIX}/admin/webhooks/:id/replay`, async (c) => {
  const g = await requireAdmin(c, "superadmin", "operator");
  if ("response" in g) return g.response;
  try {
    const id = c.req.param("id");
    const event = (await kv.get(k.webhookEvent(id))) as any;
    if (!event) return c.json({ error: "not-found" }, 404);
    const origin = new URL(c.req.url).origin;
    const replayUrl = `${origin}${event.path}`;
    const headers: Record<string, string> = { "Content-Type": event.headers?.["content-type"] ?? "application/json" };
    for (const [hk, hv] of Object.entries(event.headers ?? {})) {
      if (typeof hv === "string" && /^x-/i.test(hk)) headers[hk] = hv;
    }
    const r = await fetch(replayUrl, { method: event.method ?? "POST", headers, body: event.body ?? "" });
    const updatedIndex = ((await kv.get(k.webhookIndex())) ?? []) as any[];
    const at = new Date().toISOString();
    const i = updatedIndex.findIndex((e) => e.id === id);
    if (i >= 0) { updatedIndex[i].replayedAt = at; updatedIndex[i].replayedBy = g.admin.username; await kv.set(k.webhookIndex(), updatedIndex); }
    event.replayedAt = at; event.replayedBy = g.admin.username; await kv.set(k.webhookEvent(id), event);
    await adminAudit(c, g.admin, "webhook.replay", { id, provider: event.provider, httpStatus: r.status });
    return c.json({ ok: true, httpStatus: r.status });
  } catch (err) {
    return c.json({ error: `webhook replay: ${err}` }, 500);
  }
});

// ---- D2 — Réconciliation paiements ---------------------------------
app.get(`${PREFIX}/admin/payments/reconcile`, async (c) => {
  const g = await requireAdmin(c, "superadmin", "operator");
  if ("response" in g) return g.response;
  try {
    const url = new URL(c.req.url);
    const olderMin = Math.max(1, Math.min(1440, Number(url.searchParams.get("olderMin") ?? "10")));
    const cutoff = Date.now() - olderMin * 60_000;
    const all = (await kv.getByPrefix("payments:")) ?? [];
    const pending: { userId: string; userEmail: string; userName: string; payment: any }[] = [];
    for (const arr of all as any[][]) {
      if (!Array.isArray(arr)) continue;
      for (const p of arr) {
        if (p?.status !== "en_attente") continue;
        const created = new Date(p.createdAt ?? 0).getTime();
        if (!Number.isFinite(created) || created > cutoff) continue;
        const uid = p.userId ?? p.uid ?? "";
        let email = ""; let name = "";
        if (uid) {
          const prof = await kv.get(k.profile(uid));
          email = (prof as any)?.email ?? ""; name = (prof as any)?.name ?? "";
        }
        pending.push({ userId: uid, userEmail: email, userName: name, payment: p });
      }
    }
    pending.sort((a, b) => +new Date(a.payment.createdAt) - +new Date(b.payment.createdAt));
    return c.json({ pending });
  } catch (err) {
    return c.json({ error: `reconcile: ${err}` }, 500);
  }
});

app.post(`${PREFIX}/admin/payments/:userId/:paymentId/force-confirm`, async (c) => {
  const g = await requireAdmin(c, "superadmin", "operator");
  if ("response" in g) return g.response;
  try {
    const userId = c.req.param("userId");
    const paymentId = c.req.param("paymentId");
    const body = await c.req.json().catch(() => ({}));
    const motif = (body.motif ?? "").toString().trim();
    if (motif.length < 5) return c.json({ error: "Motif obligatoire (5 caractères min)" }, 400);
    const list = ((await kv.get(k.payments(userId))) ?? []) as any[];
    const i = list.findIndex((p) => p.id === paymentId);
    if (i < 0) return c.json({ error: "not-found" }, 404);
    if (list[i].status === "confirme") return c.json({ payment: list[i] });
    list[i] = { ...list[i], status: "confirme", confirmedAt: new Date().toISOString(), forceConfirmed: true, forceConfirmMotif: motif, forceConfirmBy: g.admin.username };
    await kv.set(k.payments(userId), list);
    await audit(userId, "payment.force_confirm", { paymentId, motif, by: g.admin.username });
    await adminAudit(c, g.admin, "payment.force_confirm", { userId, paymentId, motif });
    broadcast(`admin:stats`, "stats:dirty", { reason: "force-confirm", at: Date.now() }).catch(() => {});
    return c.json({ payment: list[i] });
  } catch (err) {
    return c.json({ error: `force-confirm: ${err}` }, 500);
  }
});

// ---- D3 — Rôles admin (superadmin seulement) -----------------------
app.get(`${PREFIX}/admin/roles`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  try {
    const roles = ((await kv.get(k.adminRoles())) ?? []) as any[];
    return c.json({ roles });
  } catch (err) {
    return c.json({ error: `roles: ${err}` }, 500);
  }
});

app.post(`${PREFIX}/admin/roles`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  try {
    const body = await c.req.json().catch(() => ({}));
    const username = (body.username ?? "").toString().trim();
    const role = (body.role ?? "").toString().trim();
    const password = (body.password ?? "").toString();
    if (!username || !["superadmin", "operator", "support"].includes(role) || password.length < 12) {
      return c.json({ error: "username, role (superadmin|operator|support), password (≥12) requis" }, 400);
    }
    const roles = ((await kv.get(k.adminRoles())) ?? []) as any[];
    if (roles.some((r) => r.username === username)) return c.json({ error: "Identifiant déjà utilisé" }, 409);
    const pwHash = await sha256Hex(password + ":" + username);
    roles.push({ username, role, pwHash, createdAt: new Date().toISOString(), createdBy: g.admin.username });
    await kv.set(k.adminRoles(), roles);
    await adminAudit(c, g.admin, "role.create", { username, role });
    return c.json({ ok: true });
  } catch (err) {
    return c.json({ error: `roles add: ${err}` }, 500);
  }
});

app.delete(`${PREFIX}/admin/roles/:username`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  try {
    const username = decodeURIComponent(c.req.param("username"));
    const roles = ((await kv.get(k.adminRoles())) ?? []) as any[];
    const next = roles.filter((r) => r.username !== username);
    if (next.length === roles.length) return c.json({ error: "not-found" }, 404);
    await kv.set(k.adminRoles(), next);
    await adminAudit(c, g.admin, "role.delete", { username });
    return c.json({ ok: true });
  } catch (err) {
    return c.json({ error: `roles del: ${err}` }, 500);
  }
});

// ---- D4 — Santé système agrégée ------------------------------------
app.get(`${PREFIX}/admin/system/health`, async (c) => {
  const g = await requireAdmin(c, "superadmin", "operator", "support");
  if ("response" in g) return g.response;
  try {
    const t0 = Date.now();
    let dbOk = true;
    try { await kv.get(k.hmacSecret()); } catch { dbOk = false; }
    const latencyMs = Date.now() - t0;
    const integrations = {
      resend: !!Deno.env.get("RESEND_API_KEY"),
      termii: !!Deno.env.get("TERMII_API_KEY"),
      vapid: !!Deno.env.get("VAPID_PRIVATE_KEY") && !!Deno.env.get("VAPID_PUBLIC_KEY"),
      adminTotp: ADMIN_ACCOUNTS.some((a) => !!a.totpSecret),
    };
    const psp = {
      kkiapay: !!Deno.env.get("KKIAPAY_PUBLIC_KEY") && !!Deno.env.get("KKIAPAY_SECRET"),
      cinetpay: !!Deno.env.get("CINETPAY_API_KEY") && !!Deno.env.get("CINETPAY_SECRET_KEY"),
      fedapay: !!Deno.env.get("FEDAPAY_PUBLIC_KEY") && !!Deno.env.get("FEDAPAY_WEBHOOK_SECRET"),
      momo: !!Deno.env.get("MOMO_SUBSCRIPTION_KEY") && !!Deno.env.get("MOMO_CALLBACK_KEY"),
    };
    const cronNames = ["reminders:auto", "billing:auto", "sweep:deletion", "kv:backup"];
    const crons = await Promise.all(cronNames.map(async (name) => {
      const last = (await kv.get(`${name}:lock`)) as number | null;
      const ok = (await kv.get(`${name}:last-ok`)) as boolean | null;
      return { name, lastRunAt: last ? new Date(last).toISOString() : null, lastOk: ok };
    }));
    const webhookIndex = ((await kv.get(k.webhookIndex())) ?? []) as any[];
    const day = Date.now() - 86_400_000;
    let failed24h = 0, ok24h = 0;
    for (const e of webhookIndex) {
      const t = +new Date(e.receivedAt);
      if (!Number.isFinite(t) || t < day) continue;
      if (e.status === "failed") failed24h++;
      else if (e.status === "ok") ok24h++;
    }
    return c.json({
      generatedAt: new Date().toISOString(),
      db: { ok: dbOk, latencyMs },
      integrations, psp, crons,
      webhooks: { total: webhookIndex.length, failed24h, ok24h },
    });
  } catch (err) {
    return c.json({ error: `system health: ${err}` }, 500);
  }
});

// ---- D5 — Badge counts ---------------------------------------------
app.get(`${PREFIX}/admin/badges/counts`, async (c) => {
  const g = await requireAdmin(c, "superadmin", "operator", "support");
  if ("response" in g) return g.response;
  try {
    const [allClaims, allKyc, allConv, webhookIndex] = await Promise.all([
      kv.getByPrefix("claims:"),
      kv.getByPrefix("kyc:"),
      kv.getByPrefix("conv:meta:"),
      kv.get(k.webhookIndex()),
    ]);
    let openClaims = 0;
    for (const arr of (allClaims ?? []) as any[][]) {
      if (!Array.isArray(arr)) continue;
      for (const cl of arr) if (cl?.status === "en_cours") openClaims++;
    }
    let pendingKyc = 0;
    for (const arr of (allKyc ?? []) as any[][]) {
      if (!Array.isArray(arr)) continue;
      for (const k2 of arr) if (k2?.status === "pending") pendingKyc++;
    }
    let openConversations = 0;
    for (const meta of (allConv ?? []) as any[]) {
      if (meta && meta.status && meta.status !== "resolu") openConversations++;
    }
    const day = Date.now() - 86_400_000;
    let failedWebhooks = 0;
    for (const e of (webhookIndex ?? []) as any[]) {
      if (e?.status !== "failed") continue;
      const t = +new Date(e.receivedAt);
      if (Number.isFinite(t) && t >= day) failedWebhooks++;
    }
    return c.json({ openClaims, pendingKyc, openConversations, failedWebhooks });
  } catch (err) {
    return c.json({ error: `badges: ${err}` }, 500);
  }
});

// ---- D6 — Recherche globale ----------------------------------------
app.get(`${PREFIX}/admin/search`, async (c) => {
  const g = await requireAdmin(c, "superadmin", "operator", "support");
  if ("response" in g) return g.response;
  try {
    const q = (new URL(c.req.url).searchParams.get("q") ?? "").trim();
    if (q.length < 2) return c.json({ results: [] });
    const lower = q.toLowerCase();
    const isMatricule = /^IPPOO-A-\d{4,}$/i.test(q);
    const results: { kind: string; id: string; label: string; sub?: string; href: string }[] = [];

    // Matricule strict
    if (isMatricule) {
      const userId = (await kv.get(`agent:matricule-claim:${q.toUpperCase()}`)) as string | null;
      if (userId) results.push({ kind: "agent", id: userId, label: q.toUpperCase(), sub: "Agent", href: `/admin/membres?uid=${userId}` });
    }
    // Membres (limite scan)
    const profiles = ((await kv.getByPrefix("profile:")) ?? []) as any[];
    let added = 0;
    for (const p of profiles) {
      if (added >= 20) break;
      if (!p) continue;
      const hay = `${p.email ?? ""} ${p.name ?? ""} ${p.firstName ?? ""} ${p.lastName ?? ""} ${p.memberNumber ?? ""} ${p.phone ?? ""}`.toLowerCase();
      if (hay.includes(lower)) {
        results.push({
          kind: "member", id: p.id ?? "",
          label: p.name || p.email || (p.memberNumber ?? "Membre"),
          sub: [p.memberNumber, p.email].filter(Boolean).join(" · "),
          href: `/admin/membres?uid=${p.id}`,
        });
        added++;
      }
    }
    return c.json({ results });
  } catch (err) {
    return c.json({ error: `search: ${err}` }, 500);
  }
});

// ---- D8 — Acquittement incidents -----------------------------------
app.post(`${PREFIX}/admin/incidents/:id/ack`, async (c) => {
  const g = await requireAdmin(c, "superadmin", "operator", "support");
  if ("response" in g) return g.response;
  try {
    const id = c.req.param("id");
    const body = await c.req.json().catch(() => ({}));
    const note = (body.note ?? "").toString().slice(0, 500);
    const ack = { by: g.admin.username, at: new Date().toISOString(), note };
    await kv.set(k.incidentAck(id), ack);
    const idx = ((await kv.get(k.incidentAcksIndex())) ?? {}) as Record<string, any>;
    idx[id] = ack;
    await kv.set(k.incidentAcksIndex(), idx);
    await adminAudit(c, g.admin, "incident.ack", { id, note });
    return c.json({ ok: true, ack });
  } catch (err) {
    return c.json({ error: `incident ack: ${err}` }, 500);
  }
});

app.get(`${PREFIX}/admin/incidents/acks`, async (c) => {
  const g = await requireAdmin(c, "superadmin", "operator", "support");
  if ("response" in g) return g.response;
  try {
    const acks = ((await kv.get(k.incidentAcksIndex())) ?? {}) as Record<string, any>;
    return c.json({ acks });
  } catch (err) {
    return c.json({ error: `incident acks: ${err}` }, 500);
  }
});

// ---- D9 — Sessions admin -------------------------------------------
app.get(`${PREFIX}/admin/sessions`, async (c) => {
  const g = await requireAdmin(c, "superadmin", "operator", "support");
  if ("response" in g) return g.response;
  try {
    const r = await requireAdminToken(c);
    const currentJti = (r.admin as any)?.jti ?? null;
    const idx = ((await kv.get(k.adminSessionsIndex())) ?? []) as string[];
    const sessions: any[] = [];
    for (const jti of idx) {
      const s = await kv.get(k.adminSession(jti));
      if (s) sessions.push({ ...s, current: jti === currentJti });
    }
    return c.json({ sessions });
  } catch (err) {
    return c.json({ error: `sessions: ${err}` }, 500);
  }
});

app.post(`${PREFIX}/admin/sessions/:jti/revoke`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  try {
    const jti = decodeURIComponent(c.req.param("jti"));
    await kv.del(k.adminSession(jti));
    const idx = ((await kv.get(k.adminSessionsIndex())) ?? []) as string[];
    await kv.set(k.adminSessionsIndex(), idx.filter((x) => x !== jti));
    await adminAudit(c, g.admin, "session.revoke", { jti });
    return c.json({ ok: true });
  } catch (err) {
    return c.json({ error: `session revoke: ${err}` }, 500);
  }
});

app.post(`${PREFIX}/admin/logout`, async (c) => {
  const r = await requireAdminToken(c);
  if (!r.admin) return c.json({ error: r.error }, r.status);
  try {
    const jti = (r.admin as any)?.jti;
    if (jti) {
      await kv.del(k.adminSession(jti));
      const idx = ((await kv.get(k.adminSessionsIndex())) ?? []) as string[];
      await kv.set(k.adminSessionsIndex(), idx.filter((x) => x !== jti));
    }
    await adminAudit(c, r.admin, "logout", { jti });
    return c.json({ ok: true });
  } catch (err) {
    return c.json({ error: `logout: ${err}` }, 500);
  }
});

// ---- D10 — Rate-limit visible --------------------------------------
app.get(`${PREFIX}/admin/rate-limit/status`, async (c) => {
  const g = await requireAdmin(c, "superadmin", "operator", "support");
  if ("response" in g) return g.response;
  try {
    const all = ((await kv.getByPrefix("rate:")) ?? []) as any[];
    const buckets = (all || []).filter(Boolean).map((b: any) => ({
      key: b.key ?? "?",
      hits: b.count ?? b.hits ?? 0,
      windowSec: b.windowSec ?? 0,
      remaining: Math.max(0, (b.limit ?? 0) - (b.count ?? 0)),
      resetAt: b.resetAt ? new Date(b.resetAt).toISOString() : "",
    })).slice(0, 200);
    return c.json({ buckets });
  } catch (err) {
    return c.json({ error: `rate status: ${err}` }, 500);
  }
});

app.post(`${PREFIX}/admin/rate-limit/clear`, async (c) => {
  const g = await requireAdmin(c, "superadmin", "operator");
  if ("response" in g) return g.response;
  try {
    const body = await c.req.json().catch(() => ({}));
    const key = (body.key ?? "").toString().trim();
    if (!key) return c.json({ error: "key requise" }, 400);
    await kv.del(k.rate(key));
    await adminAudit(c, g.admin, "rate.clear", { key });
    return c.json({ ok: true });
  } catch (err) {
    return c.json({ error: `rate clear: ${err}` }, 500);
  }
});

// ---- D11 — Vérification chaîne audit -------------------------------
app.get(`${PREFIX}/admin/audit/verify-chain`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  try {
    const list = ((await kv.get("admin:audit")) ?? []) as any[];
    // list est unshift-ordered ⇒ remettre dans l'ordre chronologique
    const chrono = [...list].reverse();
    let prev = "GENESIS";
    let brokenAt: number | null = null;
    for (let i = 0; i < chrono.length; i++) {
      const e = chrono[i];
      const canonical = JSON.stringify({ id: e.id, username: e.username, role: e.role, action: e.action, meta: e.meta, ip: e.ip, ua: e.ua, at: e.at });
      const expected = await sha256Hex(prev + "|" + canonical);
      if (e.prevHash !== prev || e.hash !== expected) { brokenAt = i; break; }
      prev = e.hash;
    }
    const tip = ((await kv.get(k.auditChainTip())) ?? "GENESIS") as string;
    return c.json({ ok: brokenAt === null, total: chrono.length, brokenAt, tip });
  } catch (err) {
    return c.json({ error: `verify-chain: ${err}` }, 500);
  }
});

// ---- D12 — Effacement RGPD ------------------------------------------
app.post(`${PREFIX}/admin/users/:userId/erase`, async (c) => {
  const g = await requireAdmin(c, "superadmin");
  if ("response" in g) return g.response;
  try {
    const userId = c.req.param("userId");
    const prefix = userId.slice(0, 8);
    const body = await c.req.json().catch(() => ({}));
    const confirm = (body.confirm ?? "").toString().trim();
    if (confirm !== `EFFACER ${prefix}`) return c.json({ error: `Confirmation requise: 'EFFACER ${prefix}'` }, 400);
    const prefixes = [
      `profile:${userId}`, `contracts:${userId}`, `claims:${userId}`,
      `payments:${userId}`, `beneficiaries:${userId}`, `documents:${userId}`,
      `notifications:${userId}`, `messages:${userId}`, `settings:${userId}`,
      `audit:${userId}`, `kyc:${userId}`, `referral:code:${userId}`,
      `referral:redemptions:${userId}`, `account:deletion:${userId}`,
      `conv:meta:${userId}`, `agent:notes:${userId}`, `push:subs:${userId}`,
      `reminders:sent:${userId}`, `consents:${userId}`, `webauthn:creds:${userId}`,
    ];
    let erased = 0;
    for (const p of prefixes) {
      try { await kv.del(p); erased++; } catch { /* continue */ }
    }
    try { await admin.auth.admin.deleteUser(userId); } catch (e) { console.log(`erase auth delete err: ${e}`); }
    await adminAudit(c, g.admin, "user.erase", { userId, erased });
    return c.json({ ok: true, erased });
  } catch (err) {
    return c.json({ error: `erase: ${err}` }, 500);
  }
});

// =====================================================================
// ====  Fin bloc D1-D12                                              ===
// =====================================================================

// Catch-all to surface unmatched paths with helpful detail (instead of bare 404)
app.all("*", (c) => {
  return c.json(
    { error: `Route inconnue: ${c.req.method} ${new URL(c.req.url).pathname}` },
    404,
  );
});

// rev: 2026-05-29-14 (/agent/signup: pré-check emailToUid + désambiguïsation client/agent dans le message d'erreur — symétrie complète des deux espaces)
// rev: 2026-05-29-15 (KYC client : POST /kyc/upload + GET /kyc/url ; bucket make-752d1a39-kyc ; agent /agent/kyc enrichit docs avec URLs signées 5 min)
// rev: 2026-05-29-16 (T6 agent : POST /agent/subscribe/:uid — souscription assistée traçant subscribedBy matricule + notif client)
// rev: 2026-05-29-17 (F9 admin : GET /admin/kpi — CA mensuel 12 mois, top produits, churn, conversion ; GET /admin/agents/performance — perf par matricule fenêtre glissante)
// rev: 2026-05-29-18 (F10 dispatch : POST /claims auto-assign via pickOnlineAgentMatricule ; POST /admin/dispatch/sweep — réassigne conv. & sinistres laissés par agents offline > 4 h)
// rev: 2026-05-29-19 (F12 export : GET /admin/export/accounting?month=YYYY-MM (CSV paiements + commission) + GET /admin/export/commissions (CSV agrégé par matricule). Taux commission via env COMMISSION_RATE_AGENT, défaut 5%.)
// rev: 2026-05-30-01 (S4 agent attachments : POST /agent/claims/:userId/:claimId/attachment + GET /agent/claims/attachment-url. Permet à l'agent d'ajouter une pièce justificative au dossier sinistre du client, avec traçabilité addedBy.)
// rev: 2026-05-30-02 (S7 transfert agent→agent : POST /agent/claims/:userId/:claimId/reassign-to (titulaire seul, format matricule strict).)
// rev: 2026-05-30-03 (S8 export comptable plage : /admin/export/accounting et /admin/export/commissions acceptent désormais ?from=YYYY-MM&to=YYYY-MM (inclusif) en plus de ?month=. Filename et résumé adaptés.)
// rev: 2026-05-30-04 (S9 SLA + export perf : /admin/agents/performance ajoute responsePairs/responsesUnder1h/slaUnder1hPct (réponses en moins d'1h ouvré-ish, fenêtre glissante). format=csv pour télécharger.)
// rev: 2026-05-29-20 (F13 health : /health enrichi { agentSignup, operations.agentsOnline, lastBillingRun } + /ping pong)
// rev: 2026-05-29-21 (F14 sécurité : POST /admin/security/rotate-hmac — rotation atomique du secret HMAC, invalide tokens admin, audit prefix-only)
// rev: 2026-05-29-22 (F16 2FA agent : agent:totp:<uid>, GET/POST /agent/2fa{,/enroll,/activate,/verify,/disable} ; gating requireAgent2FA sur /agent/payments,/subscribe,/claims/:/status,/kyc/:/decision)
Deno.serve(app.fetch);
