# CLAUDE.md — oid-fed-demo

## What this project is

Visual demo of OpenID Federation 1.0. One Cloudflare Worker (TypeScript) + one Cloudflare Pages SPA (static HTML). No backend infrastructure cost.

## Quick reference

### Worker local dev
```bash
cd worker && npm run dev    # http://localhost:8787
```

### Tests
```bash
cd worker && npm test       # vitest, 16 tests
cd worker && npm run typecheck
```

### SPA local dev
Open `spa/index.html?worker=http://localhost:8787` directly in browser, or:
```bash
npx serve spa   # http://localhost:3000
```

## Key Worker endpoints

| Endpoint | Returns |
|---|---|
| `/ta/.well-known/openid-federation` | Trust Anchor Entity Config JWT (`application/entity-statement+jwt`) |
| `/idp/{keycloak,okta,entra}/.well-known/openid-federation` | IdP Entity Config JWT |
| `/rp/portal/.well-known/openid-federation` | RP Entity Config JWT |
| `/ta/federation/fetch?sub=<id>` | Subordinate Statement JWT |
| `/ta/federation/list` | JSON list of member entity IDs |
| `/api/chain?entity=keycloak\|okta\|entra` | Full trust chain (3 decoded JWTs) — single call, self-consistent |
| `/api/state` | Federation snapshot + N×M vs O(N+M) stats |

## Key design decisions

- **Module-level `_state`** — keys generated once per isolate cold-start (`getState()` in `index.ts`). All `/api/chain` calls within the same isolate are key-consistent. Isolate recycling is acceptable for a demo.
- **Single-call chain** (`/api/chain`) — all three JWTs (EC + SubStmt + TA EC) built and decoded atomically in one request. Avoids cross-request key inconsistency.
- **Entity IDs are URL prefixes** — `${BASE_URL}/ta`, `${BASE_URL}/idp/keycloak`, etc. `BASE_URL` is a Worker env var: `http://localhost:8787` (dev) or `https://oid-fed-demo-worker.workers.dev` (production).
- **`wrangler.jsonc`** — two environments: default (dev) with `BASE_URL = "http://localhost:8787"`, `production` with `BASE_URL = "https://oid-fed-demo-worker.workers.dev"`.

## File map

```
worker/
  src/
    crypto.ts       — generateKeyPair, signJWT, verifyJWT, decodeJWT (Web Crypto)
    entities.ts     — buildTAEntityConfig, buildKeycloakEntityConfig, ..., buildTrustChain
    index.ts        — Worker fetch handler, router, getState()
    index.test.ts   — 16 vitest tests
  package.json
  tsconfig.json
  wrangler.jsonc
  vitest.config.ts
spa/
  index.html        — full SPA (no deps, inline CSS+JS)
.github/workflows/
  ci.yml            — test → deploy-worker → deploy-spa
```

## Git workflow

**Never commit to `main` directly.** Use `feat/`, `fix/`, `chore/` branches + PRs. See global CLAUDE.md for the full workflow.

## Deployment

- **Worker**: `npx wrangler deploy --env production` (from `worker/`)
- **SPA**: `npx wrangler pages deploy spa --project-name=oid-fed-demo --branch=main` (from repo root)
- CI does both automatically on merge to `main`; GitHub environment `ci` holds `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.

## OID-FED spec quick ref

- **Entity Configuration** — self-signed JWT at `/.well-known/openid-federation`. Fields: `iss`, `sub` (=self), `iat`, `exp`, `jwks`, `metadata`, `authority_hints` (leaf entities only).
- **Subordinate Statement** — JWT issued by a Superior (`iss`=TA) about a Subordinate (`sub`=leaf). Contains `jwks` the TA vouches for, optional `metadata_policy`.
- **Trust chain** — EC (leaf) → SubStmt (TA→leaf) → EC (TA). Verified top-down: TA EC key → signs SubStmt → SubStmt `jwks` key must match leaf EC key.
- **Signing algorithm**: ES256 (P-256) throughout.
