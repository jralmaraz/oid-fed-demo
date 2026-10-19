// oid-fed-demo Worker — OpenID Federation 1.0 simulation backend.
// Serves Entity Configurations, Subordinate Statements, and trust chain resolution
// for a simulated FinClear federation (Trust Anchor + 3 IdPs + 1 RP).
//
// All crypto is performed in a single request context so key consistency is guaranteed.
// Keys are regenerated per isolate cold-start — acceptable for a demo.

import { generateKeyPair } from './crypto.js';
import {
  FederationState, EntityID,
  buildTAEntityConfig,
  buildKeycloakEntityConfig,
  buildOktaEntityConfig,
  buildEntraEntityConfig,
  buildRPEntityConfig,
  buildSubordinateStatement,
  buildTrustChain,
} from './entities.js';
import { decodeJWT } from './crypto.js';

export interface Env {
  BASE_URL: string;
}

// Module-level state — generated once per isolate cold-start.
let _state: FederationState | null = null;

async function getState(baseURL: string): Promise<FederationState> {
  if (_state) return _state;

  const [ta, keycloak, okta, entra, rp] = await Promise.all([
    generateKeyPair('ta-1'),
    generateKeyPair('keycloak-1'),
    generateKeyPair('okta-1'),
    generateKeyPair('entra-1'),
    generateKeyPair('rp-1'),
  ]);

  _state = {
    baseURL,
    keys: { ta, keycloak, okta, entra, rp },
    entityIDs: {
      ta:       `${baseURL}/ta`,
      keycloak: `${baseURL}/idp/keycloak`,
      okta:     `${baseURL}/idp/okta`,
      entra:    `${baseURL}/idp/entra`,
      rp:       `${baseURL}/rp/portal`,
    },
  };
  return _state;
}

// ── CORS + JSON helpers ───────────────────────────────────────────────────────

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

function jwt(token: string): Response {
  return new Response(token, {
    headers: {
      'Content-Type': 'application/entity-statement+jwt',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

function notFound(msg: string): Response {
  return json({ error: msg }, 404);
}

// ── Router ────────────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env, _ctx?: ExecutionContext): Promise<Response> {
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        },
      });
    }

    const url  = new URL(request.url);
    const path = url.pathname;
    const s    = await getState(env.BASE_URL);

    // ── Entity Configuration endpoints ──
    // Each entity serves its self-signed EC at /.well-known/openid-federation

    if (path === '/ta/.well-known/openid-federation') {
      return jwt(await buildTAEntityConfig(s));
    }
    if (path === '/idp/keycloak/.well-known/openid-federation') {
      return jwt(await buildKeycloakEntityConfig(s));
    }
    if (path === '/idp/okta/.well-known/openid-federation') {
      return jwt(await buildOktaEntityConfig(s));
    }
    if (path === '/idp/entra/.well-known/openid-federation') {
      return jwt(await buildEntraEntityConfig(s));
    }
    if (path === '/rp/portal/.well-known/openid-federation') {
      return jwt(await buildRPEntityConfig(s));
    }

    // ── Federation API (Trust Anchor) ──

    // GET /ta/federation/fetch?sub=<entity-id>  → Subordinate Statement
    if (path === '/ta/federation/fetch') {
      const sub = url.searchParams.get('sub');
      const leafMap: Record<string, Exclude<EntityID, 'ta'>> = {
        [s.entityIDs.keycloak]: 'keycloak',
        [s.entityIDs.okta]:     'okta',
        [s.entityIDs.entra]:    'entra',
        [s.entityIDs.rp]:       'rp',
      };
      const leafID = sub ? leafMap[sub] : undefined;
      if (!leafID) return notFound(`entity not found: ${sub}`);
      return jwt(await buildSubordinateStatement(s, leafID));
    }

    // GET /ta/federation/list  → list of subordinate entity IDs
    if (path === '/ta/federation/list') {
      return json({
        iss:      s.entityIDs.ta,
        iat:      Math.floor(Date.now() / 1000),
        entities: Object.values(s.entityIDs).filter(id => id !== s.entityIDs.ta),
      });
    }

    // ── SPA API — single-call trust chain resolution ──

    // GET /api/chain?entity=keycloak|okta|entra
    // Returns a complete, self-consistent trust chain in one call.
    if (path === '/api/chain') {
      const entity = url.searchParams.get('entity') as Exclude<EntityID, 'ta' | 'rp'> | null;
      const builderMap = {
        keycloak: buildKeycloakEntityConfig,
        okta:     buildOktaEntityConfig,
        entra:    buildEntraEntityConfig,
      };
      if (!entity || !(entity in builderMap)) {
        return json({ error: 'entity must be keycloak, okta, or entra' }, 400);
      }
      const builder = builderMap[entity];
      const taConfig = await buildTAEntityConfig(s);
      const chain = await buildTrustChain(s, entity, {
        entityConfig: () => builder(s),
        taConfig,
      });
      // Decode all JWTs for the SPA to display
      return json({
        entity:        s.entityIDs[entity],
        chain: {
          entityConfig:         { jwt: chain.entityConfig,         decoded: decodeJWT(chain.entityConfig) },
          subordinateStatement: { jwt: chain.subordinateStatement, decoded: decodeJWT(chain.subordinateStatement) },
          taConfig:             { jwt: chain.taConfig,             decoded: decodeJWT(chain.taConfig) },
        },
        verified: chain.verified,
        summary: {
          leaf_entity:    s.entityIDs[entity],
          trust_anchor:   s.entityIDs.ta,
          chain_length:   3,
          signing_alg:    'ES256',
        },
      });
    }

    // GET /api/state — full federation snapshot for the SPA overview panel
    if (path === '/api/state') {
      const [taEC, kcEC, oktaEC, entraEC, rpEC] = await Promise.all([
        buildTAEntityConfig(s),
        buildKeycloakEntityConfig(s),
        buildOktaEntityConfig(s),
        buildEntraEntityConfig(s),
        buildRPEntityConfig(s),
      ]);
      return json({
        federation: {
          trust_anchor: { id: s.entityIDs.ta,       ec: decodeJWT(taEC) },
          idps: [
            { id: s.entityIDs.keycloak, name: 'Keycloak',      ec: decodeJWT(kcEC)    },
            { id: s.entityIDs.okta,     name: 'Okta',          ec: decodeJWT(oktaEC)  },
            { id: s.entityIDs.entra,    name: 'Entra (Azure)',  ec: decodeJWT(entraEC) },
          ],
          rp: { id: s.entityIDs.rp, name: 'FinClear Portal', ec: decodeJWT(rpEC) },
        },
        stats: {
          without_federation: { configs_needed: 9, label: '3 IdPs × 3 RPs = 9 bilateral configs' },
          with_federation:    { configs_needed: 4, label: '3 IdPs + 1 RP = 4 Entity Configurations' },
        },
      });
    }

    // GET /healthz
    if (path === '/healthz') {
      return json({ status: 'ok', service: 'oid-fed-demo-worker' });
    }

    return notFound(`no route for ${path}`);
  },
};
