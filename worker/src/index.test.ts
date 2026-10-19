import { describe, it, expect } from 'vitest';
import worker from './index.js';

const BASE_URL = 'http://localhost:8787';
const env = { BASE_URL };

function req(path: string): Request {
  return new Request(`${BASE_URL}${path}`);
}

async function getJSON(path: string) {
  const resp = await worker.fetch(req(path), env, {} as ExecutionContext);
  return resp.json();
}

async function getText(path: string) {
  const resp = await worker.fetch(req(path), env, {} as ExecutionContext);
  return { status: resp.status, text: await resp.text(), ct: resp.headers.get('content-type') };
}

function decodePayload(jwt: string) {
  return JSON.parse(atob(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
}

// ── Entity Configuration endpoints ──────────────────────────────────────────

describe('Entity Configuration endpoints', () => {
  it('TA EC is a federation+jwt', async () => {
    const { ct, text } = await getText('/ta/.well-known/openid-federation');
    expect(ct).toContain('entity-statement');
    expect(text.split('.')).toHaveLength(3);
  });

  it('TA EC declares all federation API endpoints', async () => {
    const { text } = await getText('/ta/.well-known/openid-federation');
    const p = decodePayload(text);
    const fe = p.metadata?.federation_entity;
    expect(fe.federation_fetch_endpoint).toContain('/federation/fetch');
    expect(fe.federation_list_endpoint).toContain('/federation/list');
    expect(fe.federation_resolve_endpoint).toContain('/federation/resolve');
    expect(fe.trust_mark_status_endpoint).toContain('/trust_mark_status');
    expect(fe.trust_mark_list_endpoint).toContain('/trust_mark_list');
  });

  it('TA EC declares trust_mark_issuers', async () => {
    const { text } = await getText('/ta/.well-known/openid-federation');
    const p = decodePayload(text);
    expect(p.metadata?.federation_entity?.trust_mark_issuers).toBeTruthy();
  });

  it('Keycloak EC contains openid_provider metadata and trust_marks', async () => {
    const { ct, text } = await getText('/idp/keycloak/.well-known/openid-federation');
    expect(ct).toContain('entity-statement');
    const p = decodePayload(text);
    expect(p.metadata?.openid_provider?.issuer).toContain('keycloak');
    expect(p.metadata?.openid_provider?.jwks_uri).toContain('/certs');
    expect(Array.isArray(p.trust_marks)).toBe(true);
    expect(p.trust_marks.length).toBeGreaterThan(0);
    expect(p.trust_marks[0].trust_mark.split('.')).toHaveLength(3); // trust mark is a JWT
  });

  it('Okta EC has certified-idp trust mark', async () => {
    const { text } = await getText('/idp/okta/.well-known/openid-federation');
    const p = decodePayload(text);
    expect(p.trust_marks[0].id).toContain('certified-idp');
  });

  it('Entra EC has treasury-approved trust mark', async () => {
    const { text } = await getText('/idp/entra/.well-known/openid-federation');
    const p = decodePayload(text);
    expect(p.trust_marks[0].id).toContain('treasury-approved');
  });

  it('Entra EC has authority_hints pointing to TA', async () => {
    const { text } = await getText('/idp/entra/.well-known/openid-federation');
    expect(decodePayload(text).authority_hints?.[0]).toContain('/ta');
  });

  it('RP EC has openid_relying_party metadata and verified-rp trust mark', async () => {
    const { text } = await getText('/rp/portal/.well-known/openid-federation');
    const p = decodePayload(text);
    expect(p.metadata?.openid_relying_party?.client_name).toBeTruthy();
    expect(p.trust_marks[0].id).toContain('verified-rp');
  });
});

// ── Protocol JWKS endpoints ──────────────────────────────────────────────────
// These serve OIDC protocol keys — separate from federation keys.

describe('Protocol JWKS endpoints (jwks_uri)', () => {
  it('Keycloak JWKS returns EC public key', async () => {
    const data = await getJSON('/idp/keycloak/protocol/openid-connect/certs') as { keys: { kty: string; crv: string }[] };
    expect(data.keys).toHaveLength(1);
    expect(data.keys[0].kty).toBe('EC');
    expect(data.keys[0].crv).toBe('P-256');
  });

  it('Okta JWKS endpoint works', async () => {
    const data = await getJSON('/idp/okta/v1/keys') as { keys: unknown[] };
    expect(data.keys).toHaveLength(1);
  });

  it('Entra JWKS endpoint works', async () => {
    const data = await getJSON('/idp/entra/discovery/v2.0/keys') as { keys: unknown[] };
    expect(data.keys).toHaveLength(1);
  });

  it('RP JWKS endpoint works', async () => {
    const data = await getJSON('/rp/portal/jwks.json') as { keys: unknown[] };
    expect(data.keys).toHaveLength(1);
  });
});

// ── Federation API ──────────────────────────────────────────────────────────

describe('Federation API — fetch', () => {
  it('fetch returns subordinate statement for keycloak', async () => {
    const state = await getJSON('/api/state') as { federation: { idps: { id: string }[] } };
    const kcID = state.federation.idps[0].id;
    const { ct, text } = await getText(`/ta/federation/fetch?sub=${encodeURIComponent(kcID)}`);
    expect(ct).toContain('entity-statement');
    const p = decodePayload(text);
    expect(p.sub).toBe(kcID);
    expect(p.jwks?.keys).toHaveLength(1); // TA vouches for this key
  });

  it('fetch returns 404 for unknown entity', async () => {
    const { status } = await getText('/ta/federation/fetch?sub=https://unknown.example.com');
    expect(status).toBe(404);
  });
});

describe('Federation API — list', () => {
  it('list returns all 4 subordinate entities', async () => {
    const data = await getJSON('/ta/federation/list') as { entities: string[] };
    expect(data.entities).toHaveLength(4);
  });

  it('list filtered by openid_provider returns 3 IdPs', async () => {
    const data = await getJSON('/ta/federation/list?entity_type=openid_provider') as { entities: string[] };
    expect(data.entities).toHaveLength(3);
  });

  it('list filtered by openid_relying_party returns 1 RP', async () => {
    const data = await getJSON('/ta/federation/list?entity_type=openid_relying_party') as { entities: string[] };
    expect(data.entities).toHaveLength(1);
  });
});

describe('Federation API — resolve', () => {
  it('resolve returns a resolve-response+jwt for keycloak', async () => {
    const state = await getJSON('/api/state') as { federation: { idps: { id: string }[]; trust_anchor: { id: string } } };
    const sub = state.federation.idps[0].id;
    const ta  = state.federation.trust_anchor.id;
    const { ct, text } = await getText(
      `/ta/federation/resolve?sub=${encodeURIComponent(sub)}&trust_anchor=${encodeURIComponent(ta)}`,
    );
    expect(ct).toContain('resolve-response');
    const p = decodePayload(text);
    expect(p.sub).toBe(sub);
    expect(p.trust_anchor).toBe(ta);
    expect(Array.isArray(p.trust_chain)).toBe(true);
    expect(p.trust_chain).toHaveLength(3);
    expect(p.metadata).toBeTruthy();
  });

  it('resolve returns 400 without trust_anchor', async () => {
    const state = await getJSON('/api/state') as { federation: { idps: { id: string }[] } };
    const sub = state.federation.idps[0].id;
    const { status } = await getText(`/ta/federation/resolve?sub=${encodeURIComponent(sub)}`);
    expect(status).toBe(400);
  });

  it('resolve returns 404 for unknown entity', async () => {
    const state = await getJSON('/api/state') as { federation: { trust_anchor: { id: string } } };
    const ta = state.federation.trust_anchor.id;
    const { status } = await getText(
      `/ta/federation/resolve?sub=https://unknown.example.com&trust_anchor=${encodeURIComponent(ta)}`,
    );
    expect(status).toBe(404);
  });
});

// ── Trust Mark endpoints ─────────────────────────────────────────────────────

describe('Trust Mark endpoints', () => {
  it('trust_mark_status returns active=true for Keycloak certified-idp', async () => {
    const state = await getJSON('/api/state') as {
      federation: { idps: { id: string }[] };
      trust_marks: Record<string, string[]>;
    };
    const sub    = state.federation.idps[0].id; // keycloak
    const markID = Object.keys(state.trust_marks).find(k => k.includes('certified-idp'))!;
    const data   = await getJSON(
      `/ta/trust_mark_status?sub=${encodeURIComponent(sub)}&trust_mark_id=${encodeURIComponent(markID)}`,
    ) as { active: boolean };
    expect(data.active).toBe(true);
  });

  it('trust_mark_status returns active=false for Entra certified-idp (holds treasury-approved instead)', async () => {
    const state = await getJSON('/api/state') as {
      federation: { idps: { id: string }[] };
      trust_marks: Record<string, string[]>;
    };
    const entraID = state.federation.idps[2].id; // entra
    const markID  = Object.keys(state.trust_marks).find(k => k.includes('certified-idp'))!;
    const data    = await getJSON(
      `/ta/trust_mark_status?sub=${encodeURIComponent(entraID)}&trust_mark_id=${encodeURIComponent(markID)}`,
    ) as { active: boolean };
    expect(data.active).toBe(false);
  });

  it('trust_mark_list returns entities holding certified-idp', async () => {
    const state = await getJSON('/api/state') as { trust_marks: Record<string, string[]> };
    const markID = Object.keys(state.trust_marks).find(k => k.includes('certified-idp'))!;
    const data   = await getJSON(`/ta/trust_mark_list?trust_mark_id=${encodeURIComponent(markID)}`) as { entities: string[] };
    expect(data.entities).toHaveLength(2); // keycloak + okta
  });

  it('trust_mark_status returns 400 without sub', async () => {
    const { status } = await getText('/ta/trust_mark_status?trust_mark_id=foo');
    expect(status).toBe(400);
  });

  it('trust_mark_list returns 400 without trust_mark_id', async () => {
    const { status } = await getText('/ta/trust_mark_list');
    expect(status).toBe(400);
  });
});

// ── SPA API ──────────────────────────────────────────────────────────────────

describe('/api/chain', () => {
  it('returns a complete trust chain for keycloak', async () => {
    const data = await getJSON('/api/chain?entity=keycloak') as {
      chain: { entityConfig: object; subordinateStatement: object; taConfig: object };
      verified: boolean;
      summary: { chain_length: number };
    };
    expect(data.verified).toBe(true);
    expect(data.summary.chain_length).toBe(3);
  });

  it('returns a complete trust chain for okta', async () => {
    const data = await getJSON('/api/chain?entity=okta') as { verified: boolean };
    expect(data.verified).toBe(true);
  });

  it('returns a complete trust chain for entra', async () => {
    const data = await getJSON('/api/chain?entity=entra') as { verified: boolean };
    expect(data.verified).toBe(true);
  });

  it('returns 400 for unknown entity', async () => {
    const resp = await worker.fetch(req('/api/chain?entity=unknown'), env, {} as ExecutionContext);
    expect(resp.status).toBe(400);
  });
});

describe('/api/state', () => {
  it('returns federation overview with trust marks', async () => {
    const data = await getJSON('/api/state') as {
      federation: { idps: unknown[] };
      stats: { without_federation: { configs_needed: number }; with_federation: { configs_needed: number } };
      trust_marks: Record<string, string[]>;
    };
    expect(data.federation.idps).toHaveLength(3);
    expect(data.stats.without_federation.configs_needed).toBeGreaterThan(
      data.stats.with_federation.configs_needed,
    );
    expect(Object.keys(data.trust_marks)).toHaveLength(3);
  });
});

describe('healthz + CORS + 404', () => {
  it('healthz returns ok', async () => {
    const data = await getJSON('/healthz') as { status: string };
    expect(data.status).toBe('ok');
  });

  it('OPTIONS returns CORS headers', async () => {
    const resp = await worker.fetch(
      new Request(`${BASE_URL}/api/state`, { method: 'OPTIONS' }),
      env, {} as ExecutionContext,
    );
    expect(resp.headers.get('access-control-allow-origin')).toBe('*');
  });

  it('unknown route returns 404', async () => {
    const { status } = await getText('/does-not-exist');
    expect(status).toBe(404);
  });
});
