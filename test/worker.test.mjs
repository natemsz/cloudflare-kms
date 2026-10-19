// Protocol tests for the key-wrap Worker. Run with: npm test
// (Node's built-in test runner; the Worker uses only WebCrypto,
// Request and Response, all of which Node provides.)

import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import test from "node:test";

import worker, { _internals } from "../src/index.js";

const CREDENTIAL = "test-credential-0123456789abcdef";
const SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef"; // 48 chars

function sha256Hex(text) {
  return createHash("sha256").update(text).digest("hex");
}

function makeEnv(instances) {
  return {
    KEK: randomBytes(32).toString("base64"),
    INSTANCES: JSON.stringify(
      instances ?? [{ id: "inst", credentialSha256: sha256Hex(CREDENTIAL), ips: [] }],
    ),
  };
}

function call(env, path, { method = "POST", credential = CREDENTIAL, ip, body } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (credential !== null) headers.Authorization = `Bearer ${credential}`;
  if (ip) headers["CF-Connecting-IP"] = ip;
  return worker.fetch(
    new Request(`https://keywrap.test${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
    env,
  );
}

test("wrap then unwrap returns the secret, and wraps differ", async () => {
  const env = makeEnv();
  const first = await call(env, "/v1/wrap", { body: { secret: SECRET } });
  assert.equal(first.status, 200);
  const { wrapped } = await first.json();
  assert.equal(typeof wrapped, "string");

  const second = await call(env, "/v1/wrap", { body: { secret: SECRET } });
  const { wrapped: wrappedAgain } = await second.json();
  assert.notEqual(wrappedAgain, wrapped); // fresh IV per wrap

  const opened = await call(env, "/v1/unwrap", { body: { wrapped } });
  assert.equal(opened.status, 200);
  assert.deepEqual(await opened.json(), { secret: SECRET });
});

test("a tampered or foreign wrapped blob does not open", async () => {
  const env = makeEnv();
  const res = await call(env, "/v1/wrap", { body: { secret: SECRET } });
  const { wrapped } = await res.json();
  const tampered = wrapped.slice(0, -2) + (wrapped.endsWith("AA") ? "BB" : "AA");
  const opened = await call(env, "/v1/unwrap", { body: { wrapped: tampered } });
  assert.equal(opened.status, 400);

  // A second deployment (different KEK) cannot open it either.
  const other = await call(makeEnv(), "/v1/unwrap", { body: { wrapped } });
  assert.equal(other.status, 400);
});

test("missing and wrong credentials are refused", async () => {
  const env = makeEnv();
  assert.equal((await call(env, "/v1/wrap", { credential: null, body: { secret: SECRET } })).status, 401);
  assert.equal((await call(env, "/v1/wrap", { credential: "nope", body: { secret: SECRET } })).status, 401);
});

test("the source-IP allowlist is enforced when configured", async () => {
  const env = makeEnv([
    { id: "pinned", credentialSha256: sha256Hex(CREDENTIAL), ips: ["203.0.113.7"] },
  ]);
  assert.equal((await call(env, "/v1/wrap", { body: { secret: SECRET } })).status, 403);
  assert.equal((await call(env, "/v1/wrap", { ip: "198.51.100.9", body: { secret: SECRET } })).status, 403);
  assert.equal((await call(env, "/v1/wrap", { ip: "203.0.113.7", body: { secret: SECRET } })).status, 200);
});

test("routes, methods and secret shape are validated", async () => {
  const env = makeEnv();
  assert.equal((await call(env, "/v1/other", { body: {} })).status, 404);
  assert.equal((await call(env, "/", { body: {} })).status, 404);
  assert.equal((await call(env, "/v1/wrap", { method: "GET" })).status, 405);
  assert.equal((await call(env, "/v1/wrap", { body: { secret: "too-short" } })).status, 400);
  assert.equal((await call(env, "/v1/unwrap", { body: { wrapped: "" } })).status, 400);
  assert.equal((await call(env, "/v1/unwrap", { body: { wrapped: "!!!not-base64!!!" } })).status, 400);
});

test("calls past the rate limit are refused", async () => {
  const env = makeEnv();
  let last;
  for (let i = 0; i < 61; i++) {
    last = await call(env, "/v1/wrap", { body: { secret: SECRET } });
  }
  assert.equal(last.status, 429);
});

test("base64url and hash helpers round-trip", async () => {
  const bytes = randomBytes(33);
  assert.deepEqual(
    Buffer.from(_internals.b64urlDecode(_internals.b64urlEncode(bytes))),
    Buffer.from(bytes),
  );
  assert.equal(await _internals.sha256Hex("abc"), sha256Hex("abc"));
  assert.equal(_internals.timingSafeEqual("abcd", "abcd"), true);
  assert.equal(_internals.timingSafeEqual("abcd", "abce"), false);
  assert.equal(_internals.timingSafeEqual("abc", "abcd"), false);
});
