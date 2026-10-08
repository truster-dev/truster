---
draft: false
title: 'App Integration Guide For Developers'
linkTitle: 'App Integration'
weight: 7
---

# App Integration Guide For Developers

This page describes a recommended way for developers to use Truster with their
apps, using an SPA backed by a Go HTTP API as a reference example. It also
explains when a direct SPA or backend for frontend (BFF) is a better fit. See
[Concepts](/docs/concepts/) for terminology and [DPoP integration](/docs/dpop/)
for proof construction.

## Choosing an architecture

For most first-party web applications, the choice depends on which component
needs to call the API:

1. **SPA and API with token cookies (recommended):** If the SPA and its API are same-site, and
   that API is the resource server, use `HttpOnly` token cookies with a
   browser-held DPoP key. This is the recommended design.
2. **Direct SPA with DPoP:** If browser JavaScript must call Truster or
   independent APIs itself, use `Authorization: DPoP`.
3. **Backend For Frontend (BFF):** If the backend must call downstream APIs, or
   the browser cannot keep a persistent Web Crypto key, let the BFF own the
   tokens and key.

The first design depends on all of the protections below. If the application
cannot provide them, use a BFF rather than an incomplete version of the design.

## Option 1: SPA and API with token cookies (recommended)

In this design, JavaScript owns a non-extractable DPoP key but cannot read the
OAuth tokens. The tokens travel in `HttpOnly` cookies, and the API handles the
calls to Truster for login, refresh, and revocation. The access token remains
the credential. The API also keeps a session record containing metadata and the
current refresh-token hash (and not raw tokens), so that it can coordinate refreshes
and revoke access immediately.

In this option, the browser sends the access token in an `HttpOnly` cookie rather
than an `Authorization` header. Most DPoP middleware follows RFC 9449 and expects
`Authorization: DPoP`, so the API must explicitly support this cookie-based form.

```diagram
┌ Browser ────────────────────────────────────┐
│ ┌ SPA ──────────────┐  ┌ IndexedDB ───────┐ │
│ │ Application code  │  │ DPoP CryptoKey   │ │
│ │ Signs requests    │  │ Public JWK, hash │ │
│ │                   │  │ and expiry       │ │
│ └───────────────────┘  └──────────────────┘ │
│ ┌ HttpOnly cookie jar ────────────────────┐ │
│ │ Access and refresh tokens               │ │
│ └─────────────────────────────────────────┘ │
└──────────────┬───────────────▲──────────────┘
               │ proofs +      │ cookies +
               │ cookies       │ hash/expiry
               ▼               │
┌ API ────────────────────────────────────────┐           ┌ Truster ────────────┐
│ Resource server and OAuth flow              │── OAuth ─▶│ Authorization server  │
│                                             │◀─ tokens ─│                       │
└──────────────────────┬──────────────────────┘           └───────────────────────┘
                       │ session metadata,
                       │ refresh-token hash
                       ▼
             ┌ API Database ─────────────────┐
             │ - sessions table              │
             └───────────────────────────────┘
```

In **Truster**, configure a dedicated public client with required ES256/P-256
DPoP, PAR, PKCE, and rotating refresh tokens. Pin its issuer, client ID, callback,
and provider endpoints. Prefer a same-origin SPA and API. The relevant part of the Truster configuration looks like this; replace the
client ID and callback URL, and add the service, state, secrets, and login
connector settings described in [Configuration](/docs/config/):

```jsonc
{
  "$schema": "https://truster.dev/schema/v3/config.schema.json",
  "static_policy": {
    "clients": {
      "example-web": {
        "redirect_uris": ["https://api.example.com/auth/callback"],
        "require_user_groups_from_policy": false,
        "dpop": {
          "mode": "required",
          "signing_algorithm": "ES256"
        },
        "require_par": true,
        "refresh_tokens": {
          "enabled": true,
          "allow_offline_access": false
        }
      }
    }
  }
}
```

If Truster should restrict access by group, configure a
`user_group_mapping` and change `require_user_groups_from_policy` to `true`.

The reference design uses numbered slots so one browser can stay signed in as
more than one user. A slot is only a small local identifier that ties together
one DPoP key, token cookies, server session, and cached data; it does not prove
the user's identity. An app that supports one login can use a single fixed slot.

### Login

1. **Browser:** Create a non-extractable P-256 Web Crypto key for the new login
   and save the `CryptoKey` in pending IndexedDB state for its slot.
2. **API:** Generate random `state`, an ID-token `nonce`, and an S256 PKCE
   verifier. Store them with the slot and key thumbprint in short-lived,
   single-use server state.
3. **API:** Bind the initiating browser with a separate `Secure`, `HttpOnly`,
   `SameSite=Lax` transaction cookie. Allow only local redirect destinations.
4. **Browser and API:** The SPA sends `dpop_jkt` and one fresh proof targeted at
   Truster's public `/par` URL. The API constructs the fixed PAR request and
   forwards the proof.
5. **API and Browser:** The API callback validates the transaction cookie and
   `state`, records the code once, and redirects to the SPA. The SPA then posts a
   fresh `/token` proof; the API consumes the flow and exchanges the code with
   the stored verifier.
6. **API:** Validate `token_type: DPoP`; both JWT signatures, issuer, audience,
   expiry, and purpose; ID-token `nonce`; subject continuity; required `sid`;
   and access-token `cnf.jkt` against the pending key.
7. **API:** Commit the session, then set the exact tokens in separate
   slot-numbered `Secure`, `HttpOnly` cookies with no `Domain`. Access uses
   `Path=/`; refresh is restricted to the authentication path; both are normally
   `SameSite=Strict`.
8. **API and Browser:** The API returns only the access-token hash and expiry.
   The browser then replaces the pending slot with active state containing only
   the key, public JWK, hash, and expiry.

Apart from the fixed flow values above, the API must choose the provider URL,
client ID, redirect URI, and OAuth parameters itself rather than accepting them
from the browser. Authentication responses must use `Cache-Control: no-store`
and must never expose a raw token, code, or PKCE verifier.

### Authenticated API requests

- **Browser:** Use the slot's access-token hash as `ath` and create a fresh proof
  for every request and retry. The browser sends the matching access cookie
  automatically.
- **Browser and API:** If the slot's key is missing or does not match, the browser
  asks the API to expire the slot's cookies, clears its local state, and requires
  a new login. Do not attach a replacement key to an existing grant.
- **API:** Require the access cookie and exactly one proof on every protected
  browser request. Reject conflicting cookie and `Authorization` credentials.
- **API:** Reject ambiguous duplicate cookies.
- **API and Infrastructure:** Do not log or trace cookies, proofs, codes, or
  tokens.

For every cookie-authenticated request that changes data, the **API** must verify
the exact `Origin` and require a custom CSRF header. Do not change data through
`GET` or `HEAD`. `SameSite` and DPoP do not replace CSRF protection.

### API validation

Before trusting information from a token:

1. **API:** Verify the access JWT signature with an algorithm allowlist, then
   issuer, audience, expiry, purpose, scopes, and other authorization claims.
   Cache JWKS and rate-limit refreshes for unknown key IDs.
2. **API:** Require `cnf.jkt`. Validate proof type, ES256/P-256 public JWK,
   signature, exact method and externally visible query-free `htu`, bounded
   `iat`, nonempty `jti`, and `ath`. Match the proof thumbprint to `cnf.jkt`.
3. **API:** Require a short proof lifetime and reject duplicates seen by the same process
   with a bounded in-memory cache of `(jkt, jti, htm, htu)` hashes. Detection across
   replicas is best-effort and strict shared replay storage is optional. Do not make every
   resource request perform a SQL write or return `503` merely because a replay cache was
   lost.
4. **API:** Require an unrevoked, unexpired session keyed by trusted issuer,
   client ID, `sid`, and subject. Never create or reactivate it from a presented
   token.
5. **API:** Enforce resource-level authorization; no valid token, slot, session,
   scope, or group alone grants resource access.

DPoP does not guarantee that a request will run only once. Design important operations,
such as creating an order or charging a payment, so that receiving the same request twice
does not perform the action twice.

The **API** must build `htu` from trusted external configuration, not forwarding
headers. If the SPA and API have different origins but remain same-site, allow
credentials only from the exact SPA origin. If they are cross-site, use direct
SPA DPoP or put a same-site BFF in front of the API.

### Refresh and logout

- **Browser:** Create refresh and revocation proofs with the same slot key and the
  real Truster endpoint URL; these proofs do not include `ath`.
- **API:** Serialize refresh-token rotation per `sid` in durable server state and
  store only a refresh-token hash.
- **Browser:** Use the browser's
  [Web Locks API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Locks_API)
  to coordinate refreshes between tabs; the API remains responsible for durable
  serialization.
- **API:** During refresh, verify the current access JWT and every binding claim
  except expiry before using its `sid`, subject, or `cnf.jkt` to locate the
  session. Never authorize a resource with an expired token.
- **API:** Validate every replacement token and require continuity of issuer,
  client, `sid`, subject, and `cnf.jkt` before rotating cookies or browser
  metadata.
- **Browser and API:** Prevent stale requests or late responses from overwriting
  a newer token, key, or cleared slot. If it is unclear whether rotation
  succeeded, require a new login rather than falling back to weaker
  authentication.
- **API:** On logout, revoke the local `sid` first, then ask Truster to revoke the
  grant. Always clear the token cookies, even if remote revocation fails.
- **Browser:** Always clear the slot's key on logout. Do not refresh or reactivate
  a revoked `sid`.

## Option 2: Direct SPA with DPoP

Use direct SPA DPoP when JavaScript must call resource servers itself. Send
`Authorization: DPoP <access-token>` with a fresh proof. Keep access tokens in
memory where possible and avoid persistent refresh tokens. If persistence is
necessary, bind the refresh token with DPoP and use a short lifetime, because
browser storage is not secret storage.

If Truster is cross-origin, a controlled proxy must provide exact-origin CORS
for `/par`, `/token`, and `/revoke` without changing their public URLs.

## Option 3: Backend For Frontend (BFF)

Use a BFF when the backend must call downstream APIs or the browser cannot keep a
durable key. The BFF protects the tokens and DPoP key, while the browser receives
a random `Secure`, `HttpOnly`, `SameSite` session cookie. The BFF creates proofs
for Truster and downstream APIs. Apply the same validation, rotation,
revocation, and cookie-CSRF protections. Multiple BFF replicas must share token
and key state or route each session to the same replica.

## CLIs and XSS

Register CLIs and automation under separate client IDs. Prefer DPoP with
Authorization Code + PKCE and a loopback callback; store credentials in the OS
credential store. Keep Bearer-only clients separate and accept their greater
token-theft risk.

DPoP limits credential theft; it does not stop malicious same-origin code from
using a key while present. Maintain a strict CSP, escape untrusted content,
minimize third-party scripts, and use Trusted Types where practical.
