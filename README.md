# oid-fed-demo

Visual, interactive demo of [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) — showing how a Trust Anchor reduces N×M bilateral IdP ↔ RP configurations to O(N+M) Entity Configurations.

**Live demo**: https://oid-fed-demo.pages.dev  
**Worker API**: https://oid-fed-demo-worker-production.jralmaraz1.workers.dev

## Narrative

**FinClear** operates a federation with one Trust Anchor federating three identity providers (Keycloak, Okta, Entra) and one relying party (FinClear Portal). The demo makes the trust chain tangible: click through each step to see the real JWTs — Entity Configurations, Subordinate Statements — being resolved and decoded live.

## Architecture

```
spa/index.html              ← Cloudflare Pages (static)
        │
        │  /api/chain?entity=keycloak   (single-call trust chain)
        │  /api/state                   (federation overview)
        ▼
worker/src/index.ts         ← Cloudflare Worker (TypeScript)
  ├── crypto.ts             ← Web Crypto API — ES256 sign/verify/decode
  └── entities.ts           ← OID-FED 1.0 builders (EC, SubStmt, chain)
```

All state lives in a single Cloudflare Worker isolate — keys are generated once per cold-start, so every trust chain call within the same isolate is self-consistent.

## Local development

```bash
cd worker
npm install
npm run dev          # Worker at http://localhost:8787
```

Open `spa/index.html` in your browser with `?worker=http://localhost:8787` to point the SPA at your local Worker.

## Running tests

```bash
cd worker
npm test             # vitest — 16 tests
npm run typecheck    # tsc --noEmit
```

## Deploying

Deployment is automated via GitHub Actions on push to `main`:

1. `test` — typecheck + vitest
2. `deploy-worker` — `wrangler deploy --env production`
3. `deploy-spa` — `wrangler pages deploy spa --project-name=oid-fed-demo`

### Required GitHub secrets (environment: `ci`)

| Secret | Description |
|---|---|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token with Workers + Pages deploy permissions |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account ID |

### Manual deploy

```bash
cd worker
npx wrangler deploy --env production          # Worker
npx wrangler pages deploy ../spa \
    --project-name=oid-fed-demo \
    --branch=main                             # SPA
```

## Worker endpoints

```
Entity Configurations:
  GET /ta/.well-known/openid-federation
  GET /idp/keycloak/.well-known/openid-federation
  GET /idp/okta/.well-known/openid-federation
  GET /idp/entra/.well-known/openid-federation
  GET /rp/portal/.well-known/openid-federation

Federation API (Trust Anchor):
  GET /ta/federation/fetch?sub=<entity-id>    → Subordinate Statement JWT
  GET /ta/federation/list                     → member entity IDs

SPA API:
  GET /api/chain?entity=keycloak|okta|entra   → full self-consistent trust chain
  GET /api/state                              → federation snapshot + stats
  GET /healthz
```

## SPA configuration

| Query param | Default | Description |
|---|---|---|
| `?worker=` | `https://oid-fed-demo-worker.workers.dev` | Override Worker URL for local dev |

## Alternative: Fly.io (Go)

The [wimse-demo](https://github.com/jralmaraz/wimse-demo) repository contains an equivalent Go implementation deployed on Fly.io, demonstrating the same WIMSE/OID-FED concepts as multi-service VMs. Refer to that repo for the Go + Fly.io alternative deployment pattern.
