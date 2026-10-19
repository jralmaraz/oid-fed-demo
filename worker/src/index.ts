// oid-fed-demo Worker — OpenID Federation 1.0 simulation backend.
//
// Federation endpoints (Trust Anchor):
//   /ta/federation/fetch    — fetch Subordinate Statement         (spec §8.1)
//   /ta/federation/list     — list subordinate entity IDs         (spec §8.2)
//   /ta/federation/resolve  — resolve full trust chain            (spec §8.3)
//   /ta/trust_mark_status   — check if a trust mark is active     (spec §7.4)
//   /ta/trust_mark_list     — list entities holding a trust mark  (spec §7.5)
//
// Entity Configuration endpoints (all entities):
//   /ta/.well-known/openid-federation
//   /idp/{keycloak,okta,entra}/.well-known/openid-federation
//   /rp/portal/.well-known/openid-federation
//
// Protocol JWKS endpoints (OIDC key material, served at each entity's jwks_uri):
//   /idp/keycloak/protocol/openid-connect/certs
//   /idp/okta/v1/keys
//   /idp/entra/discovery/v2.0/keys
//   /rp/portal/jwks.json
//
// SPA API:
//   /api/chain?entity=keycloak|okta|entra
//   /api/state
//   /healthz

import { generateKeyPair, decodeJWT } from './crypto.js';
import {
  FederationState, EntityID, TRUST_MARK,
  buildTAEntityConfig,
  buildKeycloakEntityConfig,
  buildOktaEntityConfig,
  buildEntraEntityConfig,
  buildRPEntityConfig,
  buildSubordinateStatement,
  buildTrustChain,
  buildResolveResponse,
  buildJWKS,
} from './entities.js';

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

// ── Helpers ───────────────────────────────────────────────────────────────────

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}

function jwtResponse(token: string, typ: string): Response {
  return new Response(token, {
    headers: {
      'Content-Type': `application/${typ}`,
      'Access-Control-Allow-Origin': '*',
    },
  });
}

function notFound(msg: string): Response { return json({ error: msg }, 404); }
function badRequest(msg: string): Response { return json({ error: msg }, 400); }

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

    // ── Entity Configuration endpoints ──────────────────────────────────────
    // Every entity in the federation serves a self-signed EC at this path.
    // It contains the entity's public keys, role metadata, and authority_hints.

    if (path === '/ta/.well-known/openid-federation')
      return jwtResponse(await buildTAEntityConfig(s), 'entity-statement+jwt');

    if (path === '/idp/keycloak/.well-known/openid-federation')
      return jwtResponse(await buildKeycloakEntityConfig(s), 'entity-statement+jwt');

    if (path === '/idp/okta/.well-known/openid-federation')
      return jwtResponse(await buildOktaEntityConfig(s), 'entity-statement+jwt');

    if (path === '/idp/entra/.well-known/openid-federation')
      return jwtResponse(await buildEntraEntityConfig(s), 'entity-statement+jwt');

    if (path === '/rp/portal/.well-known/openid-federation')
      return jwtResponse(await buildRPEntityConfig(s), 'entity-statement+jwt');

    // ── Protocol JWKS endpoints ─────────────────────────────────────────────
    // These serve OIDC protocol keys (for ID token / access token verification).
    // Separate concern from federation keys: an RP uses the federation trust
    // chain to decide WHETHER to trust an IdP, then fetches these keys to
    // verify the tokens that IdP issues.

    if (path === '/idp/keycloak/protocol/openid-connect/certs')
      return json(buildJWKS(s.keys.keycloak.publicJWK));

    if (path === '/idp/okta/v1/keys')
      return json(buildJWKS(s.keys.okta.publicJWK));

    if (path === '/idp/entra/discovery/v2.0/keys')
      return json(buildJWKS(s.keys.entra.publicJWK));

    if (path === '/rp/portal/jwks.json')
      return json(buildJWKS(s.keys.rp.publicJWK));

    // ── Federation API ──────────────────────────────────────────────────────

    // GET /ta/federation/fetch?sub=<entity-id>
    // Returns a Subordinate Statement: the TA's signed assertion about one entity.
    // The statement vouches for the entity's federation keys and may apply policy.
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
      return jwtResponse(await buildSubordinateStatement(s, leafID), 'entity-statement+jwt');
    }

    // GET /ta/federation/list[?entity_type=openid_provider|openid_relying_party]
    // Lists entity IDs that are direct subordinates of this TA.
    // Optional entity_type filter lets callers narrow to IdPs or RPs.
    if (path === '/ta/federation/list') {
      const typeFilter = url.searchParams.get('entity_type');
      const all: Array<{ id: string; entity_type: string }> = [
        { id: s.entityIDs.keycloak, entity_type: 'openid_provider' },
        { id: s.entityIDs.okta,     entity_type: 'openid_provider' },
        { id: s.entityIDs.entra,    entity_type: 'openid_provider' },
        { id: s.entityIDs.rp,       entity_type: 'openid_relying_party' },
      ];
      const filtered = typeFilter ? all.filter(e => e.entity_type === typeFilter) : all;
      return json({
        iss:      s.entityIDs.ta,
        iat:      Math.floor(Date.now() / 1000),
        entities: filtered.map(e => e.id),
        // Extra detail for the SPA / educational purposes
        entity_details: filtered,
      });
    }

    // GET /ta/federation/resolve?sub=<entity-id>&trust_anchor=<ta-id>[&type=<entity_type>]
    // The resolve endpoint is the highest-level Federation API call.
    // It returns a resolve-response+jwt containing the full verified trust chain
    // and the resolved (policy-applied) metadata for the requested entity.
    // An RP can use this single call instead of manually fetching + verifying each step.
    if (path === '/ta/federation/resolve') {
      const sub         = url.searchParams.get('sub');
      const trustAnchor = url.searchParams.get('trust_anchor');
      if (!sub)         return badRequest('sub parameter required');
      if (!trustAnchor) return badRequest('trust_anchor parameter required');
      if (trustAnchor !== s.entityIDs.ta)
        return badRequest(`unknown trust_anchor: ${trustAnchor}`);

      const leafMap: Record<string, Exclude<EntityID, 'ta'>> = {
        [s.entityIDs.keycloak]: 'keycloak',
        [s.entityIDs.okta]:     'okta',
        [s.entityIDs.entra]:    'entra',
        [s.entityIDs.rp]:       'rp',
      };
      const leafID = leafMap[sub];
      if (!leafID) return notFound(`entity not found: ${sub}`);

      // Build all three chain JWTs atomically (same isolate = consistent keys)
      const builderMap = {
        keycloak: buildKeycloakEntityConfig,
        okta:     buildOktaEntityConfig,
        entra:    buildEntraEntityConfig,
        rp:       buildRPEntityConfig,
      };
      const ecJWT    = await builderMap[leafID](s);
      const subStmt  = await buildSubordinateStatement(s, leafID);
      const taEC     = await buildTAEntityConfig(s);

      // Resolved metadata = leaf's metadata after applying SubStmt metadata_policy.
      // Our demo policy is empty (no restrictions), so we return the leaf's declared metadata.
      const ecDecoded = decodeJWT(ecJWT);
      const resolvedMetadata = (ecDecoded.payload as Record<string, unknown>).metadata ?? {};

      const resolveJWT = await buildResolveResponse(
        s, leafID, ecJWT, subStmt, taEC,
        resolvedMetadata as Record<string, unknown>,
      );
      return jwtResponse(resolveJWT, 'resolve-response+jwt');
    }

    // ── Trust Mark endpoints ────────────────────────────────────────────────
    // Trust marks let the TA certify entities for specific roles or compliance levels.
    // An RP can require that an IdP holds a specific trust mark before accepting it.

    // GET /ta/trust_mark_status?sub=<entity-id>&trust_mark_id=<id>
    // Returns whether the TA considers the named trust mark currently active for the entity.
    // A trust mark can be revoked (e.g. compliance failure) without updating the EC.
    if (path === '/ta/trust_mark_status') {
      const sub        = url.searchParams.get('sub');
      const markID     = url.searchParams.get('trust_mark_id');
      if (!sub)    return badRequest('sub parameter required');
      if (!markID) return badRequest('trust_mark_id parameter required');

      // Trust mark registry: which entities hold which marks
      const registry: Record<string, string[]> = {
        [TRUST_MARK.certifiedIdP(s.baseURL)]:     [s.entityIDs.keycloak, s.entityIDs.okta],
        [TRUST_MARK.treasuryApproved(s.baseURL)]: [s.entityIDs.entra],
        [TRUST_MARK.verifiedRP(s.baseURL)]:       [s.entityIDs.rp],
      };
      const holders = registry[markID] ?? [];
      const active  = holders.includes(sub);
      return json({ active, sub, trust_mark_id: markID, iss: s.entityIDs.ta, iat: Math.floor(Date.now() / 1000) });
    }

    // GET /ta/trust_mark_list?trust_mark_id=<id>
    // Lists all entity IDs that currently hold the named trust mark.
    // An RP can use this to discover all certified IdPs in the federation.
    if (path === '/ta/trust_mark_list') {
      const markID = url.searchParams.get('trust_mark_id');
      if (!markID) return badRequest('trust_mark_id parameter required');

      const registry: Record<string, string[]> = {
        [TRUST_MARK.certifiedIdP(s.baseURL)]:     [s.entityIDs.keycloak, s.entityIDs.okta],
        [TRUST_MARK.treasuryApproved(s.baseURL)]: [s.entityIDs.entra],
        [TRUST_MARK.verifiedRP(s.baseURL)]:       [s.entityIDs.rp],
      };
      const entities = registry[markID] ?? [];
      return json({ trust_mark_id: markID, iss: s.entityIDs.ta, iat: Math.floor(Date.now() / 1000), entities });
    }

    // ── SPA API — convenience endpoints for the demo frontend ──────────────

    // GET /api/chain?entity=keycloak|okta|entra
    // Returns a complete, self-consistent trust chain in one call.
    // All three JWTs (EC, SubStmt, TA EC) are built atomically — same isolate,
    // same keys — so the chain is always internally consistent.
    if (path === '/api/chain') {
      const entity = url.searchParams.get('entity') as Exclude<EntityID, 'ta' | 'rp'> | null;
      const builderMap = {
        keycloak: buildKeycloakEntityConfig,
        okta:     buildOktaEntityConfig,
        entra:    buildEntraEntityConfig,
      };
      if (!entity || !(entity in builderMap))
        return badRequest('entity must be keycloak, okta, or entra');

      const builder = builderMap[entity];
      const taConfig = await buildTAEntityConfig(s);
      const chain = await buildTrustChain(s, entity, {
        entityConfig: () => builder(s),
        taConfig,
      });
      return json({
        entity:  s.entityIDs[entity],
        chain: {
          entityConfig:         { jwt: chain.entityConfig,         decoded: decodeJWT(chain.entityConfig) },
          subordinateStatement: { jwt: chain.subordinateStatement, decoded: decodeJWT(chain.subordinateStatement) },
          taConfig:             { jwt: chain.taConfig,             decoded: decodeJWT(chain.taConfig) },
        },
        verified: chain.verified,
        summary: {
          leaf_entity:   s.entityIDs[entity],
          trust_anchor:  s.entityIDs.ta,
          chain_length:  3,
          signing_alg:   'ES256',
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
        trust_marks: {
          [TRUST_MARK.certifiedIdP(s.baseURL)]:     [s.entityIDs.keycloak, s.entityIDs.okta],
          [TRUST_MARK.treasuryApproved(s.baseURL)]: [s.entityIDs.entra],
          [TRUST_MARK.verifiedRP(s.baseURL)]:       [s.entityIDs.rp],
        },
      });
    }

    // GET /healthz
    if (path === '/healthz')
      return json({ status: 'ok', service: 'oid-fed-demo-worker' });

    return notFound(`no route for ${path}`);
  },
};
