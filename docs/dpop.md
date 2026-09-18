---
draft: false
title: 'DPoP Integration'
weight: 8
---

# DPoP integration

DPoP protects access and refresh tokens if they are copied. The SPA or BFF keeps a
private signing key and sends a new signed proof with every protected request. Truster
validates proofs only for requests to its own endpoints, including `/par`, `/token`,
`/revoke`, and `/userinfo`. Each application API must independently validate the access
token and the DPoP proof for requests it receives.

DPoP still requires TLS, PKCE, and normal token validation. It does not encrypt tokens
or stop malicious code already running inside the SPA or BFF from using the key.

## Configure a client

```jsonc
"dpop": {
  "mode": "required",
  "signing_algorithm": "ES256"
},
"require_par": true
```

`mode` is `disabled` by default. When it is `required`, the signing algorithm defaults
to `ES256`. ES256 is normally the best choice because it provides strong security with
smaller, faster proofs. Use `ES512` only when your security policy requires its stronger
P-521 profile and accepts larger signatures and more CPU work.

Give Bearer and DPoP clients different client IDs. If you need to change a client's DPoP
mode or signing algorithm, create a new client ID instead; existing logins may otherwise
stop working. Losing the private key also requires a new login.

Browser clients should set `require_par: true`. PAR saves the authorization request in
Truster before the browser redirect, so the redirect cannot change its PKCE or DPoP
values.

## The flow at a glance

1. **SPA or BFF:** Create a signing key and keep it for the login and all later token
   refreshes.
2. **SPA or BFF:** Send the login request to `/par` with the key's thumbprint, a DPoP
   proof, or both.
3. **Browser:** Open `/authorize` with the returned one-use `request_uri` and complete
   login.
4. **SPA or BFF:** Exchange the authorization code at `/token` with a fresh proof from
   the same key.
5. **SPA or BFF:** Present the access token with a new proof on every API request.
6. **SPA or BFF:** Use that key again when refreshing tokens or revoking the refresh
   grant.

Truster receives the public key and its thumbprint, never the private key.

## Create the key and thumbprint

For a direct SPA, create a non-extractable ECDSA `CryptoKey` with Web Crypto. Use P-256
for ES256 or P-521 for ES512. A BFF creates the same kind of key on the server. Give each
saved account or login its own key instead of sharing one key across users.

Export only the public key as a JWK. To calculate `dpop_jkt`, serialize its required
members in this exact order, hash the UTF-8 JSON with SHA-256, then encode the hash with
URL-safe base64 and omit the trailing `=` padding:

```json
{"crv":"P-256","kty":"EC","x":"...","y":"..."}
```

Use `P-521` in `crv` for ES512; the thumbprint still uses SHA-256. Keep the private key,
thumbprint, PKCE verifier, `state`, and expected ID-token `nonce` together until the
login callback is complete. Keep the key afterward for refresh and revocation.

## Create a proof

A DPoP proof is a short-lived signed JWT describing the HTTP request you are about to
send. Put the compact JWT in exactly one `DPoP` header. Its JWT header contains:

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
}
```

Its payload contains:

- `jti`: a new unpredictable ID; generate another one for every retry;
- `htm`: the request's uppercase HTTP method, such as `POST`;
- `htu`: the exact public URL being called, without its query or fragment;
- `iat`: the current Unix timestamp in seconds; and
- `ath`: only when calling an API, the SHA-256 hash of the exact access-token text,
  encoded with URL-safe base64 without trailing `=` padding.

Truster accepts `iat` from ten seconds in the past through five seconds in the future.
Proofs are limited to 8 KiB. Create a new proof for every request and retry. For `htu`,
use the public URL advertised to clients, not an internal address behind a proxy.

## Start authorization with PAR

POST the normal Authorization Code + PKCE form fields and `client_id` to `/par`. Also
send `dpop_jkt`, a proof whose `htu` is the public `/par` URL, or both. If you send both,
they must identify the same key.

Truster returns a `request_uri` that expires after 60 seconds and works once. Open
`/authorize` in the browser with only that value and `client_id`. With `require_par`
enabled, Truster rejects login requests that skip `/par`. After consuming the pushed
request, Truster redirects the browser to an opaque continuation URL so refreshing a
sign-in or consent page does not attempt to reuse the `request_uri`.

The continuation URL contains live authorization state. Reverse proxies, ingress
controllers, access loggers, and APM agents must redact the `state` query parameter.
If response headers are recorded, they must also redact `state` from `Location`. The
supplied Caddy configurations redact request state and omit logged `Location` response
headers by default; this filtering does not alter the HTTP redirect sent to the browser.

## Exchange, refresh, and revoke

When exchanging the code or using a refresh token, send a new proof whose `htu` is the
public `/token` URL. Sign it with the same key used during login. A successful response
contains `token_type: DPoP`, and the access token contains the key's thumbprint in its
`cnf.jkt` field.

To revoke the refresh grant—the server-side session behind the refresh token—POST the
token and `client_id` to `/revoke` with a new proof for the public `/revoke` URL. This
proof does not need `ath`. Even if this network request fails, mark the local session
logged out and delete its local tokens and key.

## Call an API

```http
Authorization: DPoP <access-token>
DPoP: <fresh-proof-with-ath>
```

Truster does not validate requests sent to an application API. The API must
independently validate the access token and proof before handling the request:

1. Validate the token's signature, issuer, audience, expiry, and authorization claims.
2. Require `Authorization: DPoP <access-token>`; never accept a token containing
   `cnf.jkt` as `Authorization: Bearer <access-token>`.
3. Validate the proof signature, supported algorithm, matching key curve, and embedded
   public key. Check `htm`, exact public `htu`, `iat`, and `ath` against the request and
   token.
4. Require the proof key's thumbprint to equal the token's `cnf.jkt`.
5. Require a short proof lifetime. A bounded in-memory replay cache can additionally
   reject reuse seen by the same API replica during that window.

Reject private or symmetric embedded keys and JWT headers that refer to keys on another
server. Truster does not use the optional DPoP nonce feature.

## Replay protection and failures

RFC 9449 requires a short proof lifetime; strict global single-use tracking is optional
and can be impractical across replicas. Truster retains replay hashes in a bounded
in-memory cache for its 15-second acceptance window. A replay reaching the same process
is always rejected without a database write or database availability dependency. The
cache stores only a hash of the thumbprint, `jti`, method, and URL—not proofs, tokens,
public keys, or raw `jti` values.

Each replica has an independent cache, so cross-replica replay detection is best-effort
rather than guaranteed. This is intentional and permitted by RFC 9449. Kubernetes
client-IP affinity does not reliably keep one DPoP key on one replica, so Truster does
not require or enable it. A gateway that supports consistent hashing by the complete
`DPoP` header can route an exact replay to the same backend, but that is an optional,
provider-specific mitigation. Losing a replay cache does not require an outage or a
15-second HTTP 503 recovery period.

Truster limits PAR, token, and revocation separately to 100 requests per second per
process, with a burst of 200, before request parsing or database access. Keep per-user or
per-IP limits at your reverse proxy or API gateway. Monitor replay attempts, rate-limit
rejections, request latency, and server clock accuracy.

`/par` returns `invalid_request` when a required client sends neither `dpop_jkt` nor a
proof. Token, revocation, and API calls report `invalid_dpop_proof` when a required proof
is missing, too old, reused, or created for another method or URL. API errors use the
`WWW-Authenticate` response header; token and revocation errors use JSON.

For complete SPA and backend-for-frontend designs, see the
[app integration guide](/docs/app-integration/).
