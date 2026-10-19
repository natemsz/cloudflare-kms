// EveSynapse key-wrap service.
//
// A two-endpoint Cloudflare Worker that holds one key-encryption
// key (the KEK, a Worker secret) and wraps / unwraps an EveSynapse
// instance's token-encryption key with it:
//
//   POST /v1/wrap    {"secret": "…"}  -> {"wrapped": "…"}
//   POST /v1/unwrap  {"wrapped": "…"} -> {"secret": "…"}
//
// An instance stores only the wrapped blob and calls /v1/unwrap
// once at startup, so the usable key never sits in the instance's
// files: a stolen copy of the machine (database, .env and all)
// cannot open the tokens EveSynapse sealed with that key.
//
// Both calls require a per-instance bearer credential; the Worker
// stores only its SHA-256 hash. An instance may also pin the
// source IPs it calls from. Every call is logged as one JSON line.
// Nothing else is stored: no wrapped blobs, no secrets, no state
// beyond configuration (the rate limiter below is best-effort,
// per-isolate memory).

const IV_BYTES = 12; // AES-GCM nonce, fresh per wrap
const MAX_BODY_BYTES = 16384;
const SECRET_MIN = 32; // mirrors EveSynapse's own key rule
const SECRET_MAX = 1024;
const WRAPPED_MAX = 8192;
const RATE_LIMIT = 60; // calls per instance per window
const RATE_WINDOW_MS = 60_000;

const rateBuckets = new Map(); // instance id -> {start, count}
const kekCache = new WeakMap(); // env object -> Promise<CryptoKey>

function json(status, value) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function fail(status, message) {
  return json(status, { error: message });
}

function log(entry) {
  console.log(JSON.stringify({ service: "evesynapse-keywrap", ...entry }));
}

// --- base64url -------------------------------------------------

function b64urlEncode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function b64urlDecode(text) {
  const b64 = text.replaceAll("-", "+").replaceAll("_", "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Compares two hex strings without an early exit on the first
// difference (lengths are not secret: hashes are fixed-size).
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// --- configuration ----------------------------------------------

function kekKey(env) {
  let pending = kekCache.get(env);
  if (!pending) {
    pending = (async () => {
      if (typeof env.KEK !== "string" || env.KEK === "") {
        throw new Error("KEK secret is not set");
      }
      // Accept standard or URL-safe base64, padded or not
      // (openssl rand -base64 32 writes the standard, padded form).
      const compact = env.KEK.replace(/\s+/g, "").replaceAll("-", "+").replaceAll("_", "/");
      const padded = compact + "=".repeat((4 - (compact.length % 4)) % 4);
      const bin = atob(padded);
      const raw = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) raw[i] = bin.charCodeAt(i);
      if (raw.length !== 32) throw new Error("KEK must decode to 32 bytes");
      return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    })();
    kekCache.set(env, pending);
  }
  return pending;
}

function parseInstances(env) {
  if (typeof env.INSTANCES !== "string" || env.INSTANCES === "") {
    throw new Error("INSTANCES secret is not set");
  }
  const list = JSON.parse(env.INSTANCES);
  if (!Array.isArray(list)) throw new Error("INSTANCES must be a JSON array");
  for (const inst of list) {
    if (typeof inst?.id !== "string" || typeof inst?.credentialSha256 !== "string") {
      throw new Error("each instance needs an id and a credentialSha256");
    }
  }
  return list;
}

// authenticate resolves the caller to its configured instance, or
// returns the HTTP status to refuse it with.
async function authenticate(request, env) {
  const header = request.headers.get("Authorization") || "";
  const match = /^Bearer (.+)$/.exec(header);
  if (!match) return { status: 401 };
  const presented = await sha256Hex(match[1]);
  const instances = parseInstances(env);
  const instance = instances.find((inst) => timingSafeEqual(presented, inst.credentialSha256.toLowerCase()));
  if (!instance) return { status: 401 };
  if (Array.isArray(instance.ips) && instance.ips.length > 0) {
    const ip = request.headers.get("CF-Connecting-IP") || "";
    if (!instance.ips.includes(ip)) return { status: 403 };
  }
  return { instance };
}

function rateLimited(id) {
  const now = Date.now();
  let bucket = rateBuckets.get(id);
  if (!bucket || now - bucket.start >= RATE_WINDOW_MS) {
    bucket = { start: now, count: 0 };
    rateBuckets.set(id, bucket);
  }
  bucket.count += 1;
  return bucket.count > RATE_LIMIT;
}

async function readJSON(request) {
  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) throw new Error("body too large");
  return JSON.parse(raw);
}

// --- endpoints ----------------------------------------------------

async function handleWrap(request, env) {
  const body = await readJSON(request);
  const secret = body?.secret;
  if (typeof secret !== "string" || secret.length < SECRET_MIN || secret.length > SECRET_MAX) {
    return fail(400, `secret must be a string of ${SECRET_MIN} to ${SECRET_MAX} characters`);
  }
  const key = await kekKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(secret)),
  );
  const blob = new Uint8Array(iv.length + sealed.length);
  blob.set(iv, 0);
  blob.set(sealed, iv.length);
  return json(200, { wrapped: b64urlEncode(blob) });
}

async function handleUnwrap(request, env) {
  const body = await readJSON(request);
  const wrapped = body?.wrapped;
  if (typeof wrapped !== "string" || wrapped.length === 0 || wrapped.length > WRAPPED_MAX) {
    return fail(400, "wrapped must be a non-empty string");
  }
  let blob;
  try {
    blob = b64urlDecode(wrapped);
  } catch {
    return fail(400, "wrapped is not valid base64url");
  }
  if (blob.length <= IV_BYTES) return fail(400, "wrapped is too short");
  const key = await kekKey(env);
  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: blob.subarray(0, IV_BYTES) },
      key,
      blob.subarray(IV_BYTES),
    );
  } catch {
    return fail(400, "wrapped does not open under this service's key");
  }
  const secret = new TextDecoder().decode(plain);
  if (secret.length === 0 || secret.length > SECRET_MAX) {
    return fail(400, "wrapped does not hold a usable secret");
  }
  return json(200, { secret });
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    const endpoint = pathname === "/v1/wrap" ? "wrap" : pathname === "/v1/unwrap" ? "unwrap" : null;
    const ip = request.headers.get("CF-Connecting-IP") || "";
    if (endpoint === null) {
      log({ endpoint: pathname, result: "not-found", ip });
      return fail(404, "no such route; this service only wraps and unwraps");
    }
    if (request.method !== "POST") {
      log({ endpoint, result: "method-not-allowed", ip });
      return fail(405, "POST only");
    }
    let instance = null;
    try {
      const auth = await authenticate(request, env);
      if (auth.status) {
        log({ endpoint, result: auth.status === 403 ? "ip-refused" : "unauthorized", ip });
        return fail(auth.status, auth.status === 403 ? "source address not allowed for this instance" : "missing or unknown credential");
      }
      instance = auth.instance;
      if (rateLimited(instance.id)) {
        log({ endpoint, instance: instance.id, result: "rate-limited", ip });
        return fail(429, "too many calls; try again in a minute");
      }
      const response = endpoint === "wrap" ? await handleWrap(request, env) : await handleUnwrap(request, env);
      log({ endpoint, instance: instance.id, result: response.status === 200 ? "ok" : `http-${response.status}`, ip });
      return response;
    } catch (err) {
      // Configuration and body errors land here. Messages are ours
      // or the JSON parser's; neither can carry a secret value.
      log({ endpoint, instance: instance?.id ?? "unknown", result: "error", error: String(err?.message ?? err), ip });
      return fail(500, "the key service is misconfigured or the request was malformed");
    }
  },
};

// Exported for the protocol tests (test/worker.test.mjs).
export const _internals = { b64urlEncode, b64urlDecode, sha256Hex, timingSafeEqual };
