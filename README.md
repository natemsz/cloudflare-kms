# cloudflare-kms

A tiny key service for [EveSynapse](https://github.com/natemsz/evesynapse)
self-hosters: it keeps your instance's token-encryption key wrapped
in a KMS instead of sitting in a file on the same machine as the
database it protects. This is intended for ES, but can theoretically be used
to encrypt any arbitrary token as well.

EveSynapse encrypts the EVE login tokens it stores (AES-256-GCM).
With the key in `.env`, a copy of the machine's files, database
and `.env` together, opens every token. With this service, the
key is wrapped by a key **this Worker alone holds**; the instance
stores only the wrapped blob and calls the Worker once at startup
to unwrap it. The usable key then lives in the app's memory only.

You run this Worker in **your own Cloudflare account** (the free
tier is far more than a once-per-start call needs).

## The protocol

Two endpoints, nothing else. Both take and answer JSON, both need
an `Authorization: Bearer <credential>` header, and both are
rate-limited (60 calls/minute/instance) and logged.

| Call | Request | Answer |
|------|---------|--------|
| `POST /v1/wrap` | `{"secret": "…"}` | `{"wrapped": "…"}` |
| `POST /v1/unwrap` | `{"wrapped": "…"}` | `{"secret": "…"}` |

Wrapping is AES-256-GCM under the Worker's KEK, with a fresh
random IV per wrap; the blob is that IV and ciphertext,
base64url-encoded. The protocol is deliberately plain HTTPS and
JSON: any function on any platform that answers these two calls
can serve an EveSynapse instance instead of this Worker. For details
on a secure setup in OCI, see the [ES.app](https://github.com/natemsz/evesynapse) README
for instructions. Other cloud providers like Azure, Google, etc almost certainly would need
additional code to make it work properly, which is not provided.

## Deploy yours

You need: a Cloudflare account (free), `npx` (from Node 18+), and
your EveSynapse token key (the `TOKEN_ENCRYPTION_KEY` value you
already have, or a fresh `openssl rand -hex 32`).

```sh
git clone https://github.com/natemsz/cloudflare-kms
cd cloudflare-kms
npx wrangler login
```

**1. Set the wrapping key (the KEK).** Generate it and hand it to
the Worker as a secret. It is never written to this repo or to
your instance.

```sh
openssl rand -base64 32          # copy the output
npx wrangler secret put KEK      # paste it when asked
```

Keep a copy of that value in your password manager. If the KEK is
lost, nothing can be unwrapped (see "If something goes wrong").

**2. Choose the credential your instance will present.** Pick one,
keep it for step 4, and give the Worker only its SHA-256 hash:

```sh
openssl rand -hex 32                                  # the credential
printf %s 'THE-CREDENTIAL' | sha256sum                # its hash
```

Then store the instance list as a secret. Replace the hash with
yours, and put your server's public IP in `ips` so only your
server can call (recommended; leave `[]` to skip the pin):

```sh
npx wrangler secret put INSTANCES
# paste: [{"id":"my-instance","credentialSha256":"THE-HASH","ips":["203.0.113.7"]}]
```

**3. Deploy.**

```sh
npx wrangler deploy
```

Note the address it prints, e.g.
`https://evesynapse-keywrap.<your-subdomain>.workers.dev`.

**4. Wrap your token key once.**

```sh
curl -s -X POST https://evesynapse-keywrap.<your-subdomain>.workers.dev/v1/wrap \
  -H 'Authorization: Bearer THE-CREDENTIAL' \
  -H 'Content-Type: application/json' \
  -d '{"secret":"YOUR-TOKEN-ENCRYPTION-KEY"}'
# -> {"wrapped":"..."}
```

**5. Point the instance at it.** In the instance's `.env`:

```sh
TOKEN_KEY_PROVIDER=http
TOKEN_KEY_WRAPPED=<the wrapped value from step 4>
TOKEN_KEY_UNWRAP_URL=https://evesynapse-keywrap.<your-subdomain>.workers.dev/v1/unwrap
TOKEN_KEY_UNWRAP_CREDENTIAL=<the credential from step 2>
```

Restart EveSynapse. Its log shows
`token encryption key loaded from the unwrap endpoint` once the
key arrives. The app serves normally while the endpoint is
unreachable — it retries in the background — so a Cloudflare
outage never takes your instance down; token-dependent work waits
for the unlock. Once a start has unlocked cleanly, you can remove
`TOKEN_ENCRYPTION_KEY` from `.env` (keep it in your backups until
then). From then on, a copy of the machine's files cannot open
the stored tokens.

## Revoking access

- **One instance stops working, right now:** change or remove its
  entry in `INSTANCES` (a new credential hash) — its old credential
  is refused from that moment. Re-wrap for the new credential only
  if you also rotate the token key itself.
- **Everything stops:** delete the Worker (or replace the KEK and
  re-wrap). Instances keep serving their public pages and retry;
  no stored token can be opened anywhere.
- **Rotate the token key:** generate a new key, wrap it, update
  `TOKEN_KEY_WRAPPED`, and restart; the instance re-seals stored
  tokens under the new key at that start, as with an env key. The
  old wrapped blob is then useless.

## Logs

Every call writes one JSON line (timestamped by the platform):
endpoint, instance id, source IP, result. Watch them with
`npx wrangler tail` or in the Cloudflare dashboard under
Workers → evesynapse-keywrap → Logs. An `unwrap` result of `ok`
outside your instance's restarts is worth a look.

## If something goes wrong

- **App logs "token key unwrap failed (will retry)"** — the
  endpoint is unreachable, the credential's hash doesn't match, or
  the source IP is pinned and the call comes from elsewhere. The
  app keeps serving and retrying.
- **"the unwrapped token key does not open the stored tokens"** —
  the blob unwraps to a different key than the tokens were sealed
  with (usually the wrong blob for this instance). The app refuses
  to use it and keeps retrying with what it's given.
- **KEK lost** — wrapped blobs cannot be opened, by design. Treat
  it like losing `TOKEN_ENCRYPTION_KEY`: the stored tokens are
  unrecoverable and every character signs in once more. This is
  why step 1 says to keep a copy in your password manager.

## Development

No dependencies. `npm test` runs the protocol tests on Node's
built-in runner (WebCrypto only). `npm run dev` serves locally
through wrangler; put throwaway `KEK`/`INSTANCES` values in a
`.dev.vars` file (never commit it).
