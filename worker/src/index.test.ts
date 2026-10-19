import { describe, it, expect, beforeAll } from 'vitest';
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

describe('Entity Configuration endpoints', () => {
  it('TA EC is a federation+jwt', async () => {
    const { ct, text } = await getText('/ta/.well-known/openid-federation');
    expect(ct).toContain('entity-statement');
    expect(text.split('.')).toHaveLength(3);
  });

  it('Keycloak EC is a federation+jwt', async () => {
    const { ct, text } = await getText('/idp/keycloak/.well-known/openid-federation');
    expect(ct).toContain('entity-statement');
    const parts = text.split('.');
    expect(parts).toHaveLength(3);
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    expect(payload.metadata?.openid_provider?.issuer).toContain('keycloak');
  });

  it('Okta EC contains openid_provider metadata', async () => {
    const { text } = await getText('/idp/okta/.well-known/openid-federation');
    const payload = JSON.parse(atob(text.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    expect(payload.metadata?.openid_provider?.token_endpoint).toBeTruthy();
  });

  it('Entra EC has authority_hints pointing to TA', async () => {
    const { text } = await getText('/idp/entra/.well-known/openid-federation');
    const payload = JSON.parse(atob(text.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    expect(payload.authority_hints?.[0]).toContain('/ta');
  });

  it('RP EC has openid_relying_party metadata', async () => {
    const { text } = await getText('/rp/portal/.well-known/openid-federation');
    const payload = JSON.parse(atob(text.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    expect(payload.metadata?.openid_relying_party?.client_name).toBeTruthy();
  });
});

describe('Federation API', () => {
  it('fetch returns subordinate statement for keycloak', async () => {
    // Must fetch state first to know the entity ID
    const state = await getJSON('/api/state') as { federation: { idps: { id: string }[] } };
    const kcID = state.federation.idps[0].id;
    const { ct, text } = await getText(`/ta/federation/fetch?sub=${encodeURIComponent(kcID)}`);
    expect(ct).toContain('entity-statement');
    const payload = JSON.parse(atob(text.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    expect(payload.sub).toBe(kcID);
  });

  it('fetch returns 404 for unknown entity', async () => {
    const { status } = await getText('/ta/federation/fetch?sub=https://unknown.example.com');
    expect(status).toBe(404);
  });

  it('list returns all federation members', async () => {
    const data = await getJSON('/ta/federation/list') as { entities: string[] };
    expect(data.entities).toHaveLength(4); // keycloak, okta, entra, rp
  });
});

describe('/api/chain', () => {
  it('returns a complete trust chain for keycloak', async () => {
    const data = await getJSON('/api/chain?entity=keycloak') as {
      chain: { entityConfig: object; subordinateStatement: object; taConfig: object };
      verified: boolean;
      summary: { chain_length: number };
    };
    expect(data.verified).toBe(true);
    expect(data.summary.chain_length).toBe(3);
    expect(data.chain.entityConfig).toBeTruthy();
    expect(data.chain.subordinateStatement).toBeTruthy();
    expect(data.chain.taConfig).toBeTruthy();
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
  it('returns federation overview with stats', async () => {
    const data = await getJSON('/api/state') as {
      federation: { idps: unknown[] };
      stats: { without_federation: { configs_needed: number }; with_federation: { configs_needed: number } };
    };
    expect(data.federation.idps).toHaveLength(3);
    expect(data.stats.without_federation.configs_needed).toBeGreaterThan(
      data.stats.with_federation.configs_needed,
    );
  });
});

describe('healthz + CORS', () => {
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
