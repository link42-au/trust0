# Architecture

## System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                     trust0.app                                  │
│                                                                 │
│  API Worker (Hono + D1)              SvelteKit Frontend         │
│  ├── ASPE endpoints                  ├── Landing page           │
│  ├── Sigchain endpoints              ├── Identity dashboard     │
│  ├── Attestation endpoints           ├── 20 proof pages         │
│  ├── Export/import                   ├── Profile viewer         │
│  └── Better Auth (GitHub OAuth)      ├── Document signing       │
│                                      └── Key management         │
│                                                                 │
│  CORS Proxy Worker                   Bots                       │
│  └── HTTP, DNS, ActivityPub,         ├── Discord (Worker)       │
│      GraphQL, ASPE proxying          └── Telegram (Worker)      │
│                                                                 │
│  Cloudflare D1 (SQLite)                                         │
│  ├── user, session, account (Better Auth)                       │
│  ├── crypto_profile (fingerprint → profile JWS)                 │
│  ├── sigchain_link (identity_id, seqno → link JWS)              │
│  ├── username (username → fingerprint)                          │
│  └── attestation (fingerprint → platform attestation)           │
└─────────────────────────────────────────────────────────────────┘
```

## Packages

### @trust0/identity (Apache-2.0)

Pure TypeScript crypto library. No I/O, no network. Works in browser and Node.js.

| Module | Purpose |
|--------|---------|
| `keys.ts` | Ed25519 keygen via WebCrypto, fingerprint computation |
| `profile.ts` | ASP profile creation, parsing, request signing |
| `chain.ts` | Sigchain link creation, parsing, hash computation, chain verification |
| `signing.ts` | Document signing (JWS detached), Rekor timestamping, multi-party |
| `ssh.ts` | JWK → SSH public key conversion |
| `mnemonic.ts` | BIP39 24-word paper key backup |

Dependencies: `jose` v6, `rfc4648`, `@scure/bip39`

### @trust0/verify (Apache-2.0)

Forked from [doipjs](https://codeberg.org/keyoxide/doipjs) v2.1.0. Proof verification engine with 31 service providers.

Used client-side in the browser to verify claims. The CORS proxy handles cross-origin requests.

## Verification Flow

```
Viewer's Browser
  │
  ├── Fetch profile from trust0.app/.well-known/aspe/id/{fp}
  │   └── Verify JWS signature (jose library)
  │
  ├── Fetch sigchain from trust0.app/api/identity/chain/{fp}
  │   └── Replay chain, verify all signatures and hashes
  │
  ├── For each claim:
  │   ├── GitHub: fetch gist via GitHub API
  │   ├── DNS: query via CORS proxy → DNS-over-HTTPS
  │   ├── Mastodon: fetch profile via CORS proxy → ActivityPub
  │   ├── Email: check server attestation endpoint
  │   └── ... (31 providers via @trust0/verify)
  │
  └── Render results: VERIFIED / FAILED / UNSUPPORTED
```

The server cannot forge verification results. The viewer computed everything.

## Data Portability

Every row in D1 is a signed JWS blob. The server adds convenience (indexing, auth, nice URLs) but the data doesn't depend on the server.

**Export**: `GET /api/identity/export` returns complete identity as JSON (profile + chain + attestations)

**Import**: `POST /api/identity/import` registers the signed profile and verified
sigchain on any Trust0 instance. Before import, the authenticated client requests
a five-minute challenge and signs it with the private key for the imported
profile. The challenge binds the proof to the authenticated user, exact session,
configured ASPE authority, deterministic bundle digest, and a one-time nonce.
Submitting a new challenge replaces the previous challenge for that user.

The API verifies the profile, the proof-of-possession signature, and the complete
sigchain before writing. Imports are limited to 40 links and chain rows are
written in bounded chunks so the operation stays below D1 query and parameter
limits. A guarded D1 batch claims and consumes the challenge while inserting the
profile and chain; a replay, replacement challenge, ownership conflict, or
concurrent import cannot commit a partial identity. Exported server attestations
are deliberately ignored and excluded from the signed import digest because
they are statements made by the source server, not portable cryptographic proof.
The user must re-attest email, Discord, Telegram, and any other server-attested
claims on the destination instance.

**Self-host**: Export files can be served as static files on GitHub Pages, any domain, or any ASPE-compatible server

## Identity State and Write Safety

The API treats a verified sigchain as the authority for an identity's active
keys and current profile fingerprint. Profile updates and chain appends must be
owned by the authenticated user and signed by an active key. A chain transition
may temporarily advance the current profile fingerprint only through the signed
`profile_update` step of a key rotation; unrelated appends and same-key profile
writes are rejected while that rotation is pending.

Profile creation, sigchain initialization, profile-key rotation, identity
import, and one-time email challenge consumption use guarded D1 statements. The
guards re-check ownership, absence of conflicts, the expected chain head, or the
unconsumed challenge at write time. Multi-row state changes use D1 batches so a
failed or stale operation rolls back instead of leaving partial state. Sigchain
append races are rejected by the unique identity/sequence constraint and require
the caller to refetch before retrying.

Browser key rotation orders its durable steps as `key_rotate`, local storage of
the new usable key, `profile_update`, then public ASPE profile replacement. If a
reload or network failure interrupts the sequence, recovery derives the missing
step from the locally stored key and the cryptographically verified server chain;
it resumes only the pending transition and does not depend on an unverified local
progress flag.

## ASPE Authority and Outbound Fetch Safety

ASPE URIs are parsed using the final colon as the fingerprint separator, so a
canonical authority may include an explicit development or self-hosted port.
Signed update and delete requests must name the configured `ASPE_DOMAIN`
authority exactly after case normalization, including its port when present.

The CORS proxy requires HTTPS, rejects literal loopback/private targets, handles
redirects manually, validates every redirect target, rejects loops and more than
five hops, and removes credentials when the origin changes. The Node verifier
applies the same HTTPS, redirect, loop, and hop constraints and additionally
resolves every hostname address before connecting. It rejects any non-global
answer and pins an approved address into the request lookup, preventing DNS
rebinding between validation and the socket connection. Localhost verification
is available only through its explicit development option.

## Compatibility

trust0 implements the Ariadne specification:
- [Ariadne Core v0](spec/ariadne-core-v0.md) — bidirectional proof protocol
- [Ariadne Signature Profile v0](spec/ariadne-asp-v0.md) — Ed25519 signed profiles
- [ASPE Protocol](spec/ariadne-asp-v0.md#aspe-protocol-exchange) — HTTP API for profiles

trust0 profiles are verifiable by Keyoxide. Keyoxide profiles are verifiable by trust0.

## Testing with Keyoxide

You can verify interoperability by:

1. Create a trust0 profile with at least one proof (e.g., GitHub)
2. Visit `https://keyoxide.org/aspe:trust0.app:YOUR_FINGERPRINT`
3. Keyoxide should fetch and verify your profile

Conversely:
1. Find a Keyoxide user's ASPE URI
2. trust0's profile viewer fetches and verifies it using @trust0/verify (doipjs fork)

This works because both implement the same Ariadne/ASPE specifications.
