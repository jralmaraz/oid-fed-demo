// OpenID Federation 1.0 entity definitions.
// Each entity has an identifier URL, a role, and metadata appropriate to that role.
// Entity Configurations and Subordinate Statements are signed JWTs.
//
// Key sets — two distinct uses in OID-FED:
//   federation keys  (in EC `jwks`)  — verify Entity Configs and Subordinate Statements
//   protocol keys    (at `jwks_uri`) — verify OIDC ID tokens / access tokens
// In this demo both key sets use the same per-entity key for simplicity.

import { KeyPair, JWK, signJWT } from './crypto.js';

const now = () => Math.floor(Date.now() / 1000);
const TTL = 3600; // 1 hour — short for a demo; production uses days/weeks

export interface FederationState {
  baseURL:   string;
  keys:      Record<EntityID, KeyPair>;
  entityIDs: Record<EntityID, string>;
}

export type EntityID = 'ta' | 'keycloak' | 'okta' | 'entra' | 'rp';

// Trust mark IDs issued by the TA — used to certify entities for specific roles.
// A trust mark is a JWT the TA issues; entities embed it in their Entity Config.
export const TRUST_MARK = {
  certifiedIdP:     (base: string) => `${base}/ta/trust-mark/certified-idp`,
  treasuryApproved: (base: string) => `${base}/ta/trust-mark/treasury-approved`,
  verifiedRP:       (base: string) => `${base}/ta/trust-mark/verified-rp`,
};

// ── Trust Mark builder ────────────────────────────────────────────────────────
// A trust mark is a JWT signed by the TA asserting that `sub` holds mark `id`.
// Entities embed it in their EC under `trust_marks[].trust_mark`.
export async function buildTrustMark(
  s: FederationState,
  entityID: Exclude<EntityID, 'ta'>,
  markID: string,
): Promise<string> {
  const payload = {
    iss: s.entityIDs.ta,
    sub: s.entityIDs[entityID],
    id:  markID,
    iat: now(),
    exp: now() + TTL,
  };
  return signJWT(payload, s.keys.ta.privateKey, s.keys.ta.kid, 'trust-mark+jwt');
}

// ── Entity Configuration builders ────────────────────────────────────────────

// Trust Anchor Entity Configuration — the root of trust.
// No authority_hints (TA is self-sovereign; it is its own trust root).
export async function buildTAEntityConfig(s: FederationState): Promise<string> {
  const iss = s.entityIDs.ta;
  const payload = {
    iss, sub: iss,
    iat: now(), exp: now() + TTL,
    jwks: { keys: [s.keys.ta.publicJWK] },
    metadata: {
      federation_entity: {
        organization_name: 'FinClear Federation Authority',
        contacts: ['trust@finclear.io'],
        // Federation API endpoints — each one is discoverable from this EC.
        // A conformant RP reads these to know where to call.
        federation_fetch_endpoint:       `${iss}/federation/fetch`,
        federation_list_endpoint:        `${iss}/federation/list`,
        federation_resolve_endpoint:     `${iss}/federation/resolve`,
        trust_mark_status_endpoint:      `${iss}/trust_mark_status`,
        trust_mark_list_endpoint:        `${iss}/trust_mark_list`,
        // Trust marks this TA can issue — declares what roles it certifies.
        trust_mark_issuers: {
          [TRUST_MARK.certifiedIdP(s.baseURL)]:     [iss],
          [TRUST_MARK.treasuryApproved(s.baseURL)]: [iss],
          [TRUST_MARK.verifiedRP(s.baseURL)]:       [iss],
        },
      },
    },
  };
  return signJWT(payload, s.keys.ta.privateKey, s.keys.ta.kid, 'federation+jwt');
}

// Keycloak IdP Entity Configuration — simulates a self-hosted Keycloak instance.
export async function buildKeycloakEntityConfig(s: FederationState): Promise<string> {
  const iss = s.entityIDs.keycloak;
  const markID = TRUST_MARK.certifiedIdP(s.baseURL);
  const trustMark = await buildTrustMark(s, 'keycloak', markID);
  const payload = {
    iss, sub: iss,
    iat: now(), exp: now() + TTL,
    jwks: { keys: [s.keys.keycloak.publicJWK] },
    authority_hints: [s.entityIDs.ta],
    // Trust marks this entity holds, issued by the TA.
    // Any RP can verify a trust mark by: decoding it, checking iss=TA, verifying TA's signature.
    trust_marks: [{ id: markID, trust_mark: trustMark }],
    metadata: {
      openid_provider: {
        issuer: iss,
        authorization_endpoint:  `${iss}/protocol/openid-connect/auth`,
        token_endpoint:          `${iss}/protocol/openid-connect/token`,
        // jwks_uri — where to fetch protocol keys for verifying ID tokens.
        // Distinct from the federation `jwks` used for trust chain verification.
        jwks_uri:                `${iss}/protocol/openid-connect/certs`,
        subject_types_supported:   ['public', 'pairwise'],
        id_token_signing_alg_values_supported: ['RS256', 'ES256'],
        scopes_supported: ['openid', 'profile', 'email'],
        organization_name: 'FinClear Internal IdP (Keycloak)',
        logo_uri: 'https://www.keycloak.org/resources/images/logo.svg',
      },
      federation_entity: {
        organization_name: 'FinClear Internal IdP (Keycloak)',
      },
    },
  };
  return signJWT(payload, s.keys.keycloak.privateKey, s.keys.keycloak.kid, 'federation+jwt');
}

// Okta IdP Entity Configuration — simulates an Okta tenant.
export async function buildOktaEntityConfig(s: FederationState): Promise<string> {
  const iss = s.entityIDs.okta;
  const markID = TRUST_MARK.certifiedIdP(s.baseURL);
  const trustMark = await buildTrustMark(s, 'okta', markID);
  const payload = {
    iss, sub: iss,
    iat: now(), exp: now() + TTL,
    jwks: { keys: [s.keys.okta.publicJWK] },
    authority_hints: [s.entityIDs.ta],
    trust_marks: [{ id: markID, trust_mark: trustMark }],
    metadata: {
      openid_provider: {
        issuer: iss,
        authorization_endpoint:  `${iss}/v1/authorize`,
        token_endpoint:          `${iss}/v1/token`,
        jwks_uri:                `${iss}/v1/keys`,
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        scopes_supported: ['openid', 'profile', 'email', 'groups'],
        organization_name: 'FinClear Partner Network (Okta)',
        logo_uri: 'https://www.okta.com/favicon.ico',
      },
      federation_entity: {
        organization_name: 'FinClear Partner Network (Okta)',
      },
    },
  };
  return signJWT(payload, s.keys.okta.privateKey, s.keys.okta.kid, 'federation+jwt');
}

// Entra (Azure AD) IdP Entity Configuration.
export async function buildEntraEntityConfig(s: FederationState): Promise<string> {
  const iss = s.entityIDs.entra;
  const markID = TRUST_MARK.treasuryApproved(s.baseURL);
  const trustMark = await buildTrustMark(s, 'entra', markID);
  const payload = {
    iss, sub: iss,
    iat: now(), exp: now() + TTL,
    jwks: { keys: [s.keys.entra.publicJWK] },
    authority_hints: [s.entityIDs.ta],
    trust_marks: [{ id: markID, trust_mark: trustMark }],
    metadata: {
      openid_provider: {
        issuer: iss,
        authorization_endpoint:  `${iss}/oauth2/v2.0/authorize`,
        token_endpoint:          `${iss}/oauth2/v2.0/token`,
        jwks_uri:                `${iss}/discovery/v2.0/keys`,
        subject_types_supported: ['public', 'pairwise'],
        id_token_signing_alg_values_supported: ['RS256'],
        scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
        organization_name: 'FinClear Treasury (Entra)',
        logo_uri: 'https://azure.microsoft.com/favicon.ico',
      },
      federation_entity: {
        organization_name: 'FinClear Treasury (Entra)',
      },
    },
  };
  return signJWT(payload, s.keys.entra.privateKey, s.keys.entra.kid, 'federation+jwt');
}

// RP (Relying Party) Entity Configuration — the portal/application.
export async function buildRPEntityConfig(s: FederationState): Promise<string> {
  const iss = s.entityIDs.rp;
  const markID = TRUST_MARK.verifiedRP(s.baseURL);
  const trustMark = await buildTrustMark(s, 'rp', markID);
  const payload = {
    iss, sub: iss,
    iat: now(), exp: now() + TTL,
    jwks: { keys: [s.keys.rp.publicJWK] },
    authority_hints: [s.entityIDs.ta],
    trust_marks: [{ id: markID, trust_mark: trustMark }],
    metadata: {
      openid_relying_party: {
        client_name: 'FinClear Portal',
        redirect_uris: [`${iss}/callback`],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        subject_type: 'public',
        id_token_signed_response_alg: 'ES256',
        // jwks_uri — RP's public key for client authentication (private_key_jwt)
        jwks_uri: `${iss}/jwks.json`,
        organization_name: 'FinClear Portal',
      },
      federation_entity: {
        organization_name: 'FinClear Portal',
      },
    },
  };
  return signJWT(payload, s.keys.rp.privateKey, s.keys.rp.kid, 'federation+jwt');
}

// ── Subordinate Statements (issued by TA about leaf entities) ─────────────────
// The TA vouches for the leaf's identity and public keys.
// `metadata_policy` can constrain or extend the leaf's self-declared metadata.

export async function buildSubordinateStatement(
  s: FederationState,
  leafID: Exclude<EntityID, 'ta'>,
): Promise<string> {
  const sub = s.entityIDs[leafID];
  const iss = s.entityIDs.ta;
  const payload = {
    iss, sub,
    iat: now(), exp: now() + TTL,
    // TA vouches for the leaf's current federation public key.
    // An RP verifies: SubStmt.jwks key == leaf EC key → TA approved this key.
    jwks: { keys: [s.keys[leafID].publicJWK] },
    metadata_policy: {
      // TA can constrain or augment leaf metadata here. e.g.:
      //   subject_types_supported: { subset_of: ['public'] }
      // For this demo we pass through everything without restriction.
    },
    source_endpoint: `${iss}/federation/fetch`,
  };
  return signJWT(payload, s.keys.ta.privateKey, s.keys.ta.kid, 'federation+jwt');
}

// ── Resolve Response (federation/resolve endpoint) ────────────────────────────
// The resolve endpoint answers: "given entity X and trust anchor Y, what is
// the resolved trust chain and final metadata?"
// An RP uses this instead of manually fetching and verifying each step.
// Returns a `resolve-response+jwt` signed by the resolver (the TA here).

export async function buildResolveResponse(
  s: FederationState,
  entityID: Exclude<EntityID, 'ta'>,
  entityConfigJWT: string,
  subStmtJWT: string,
  taConfigJWT: string,
  resolvedMetadata: Record<string, unknown>,
): Promise<string> {
  const payload = {
    iss: s.entityIDs.ta,             // resolver
    sub: s.entityIDs[entityID],      // entity being resolved
    iat: now(), exp: now() + TTL,
    trust_anchor: s.entityIDs.ta,
    // Full trust chain as an ordered array: leaf EC → SubStmt → TA EC
    trust_chain: [entityConfigJWT, subStmtJWT, taConfigJWT],
    // Resolved metadata: the leaf's metadata after applying metadata_policy.
    // With no policy restrictions this is the leaf's self-declared metadata.
    metadata: resolvedMetadata,
  };
  return signJWT(payload, s.keys.ta.privateKey, s.keys.ta.kid, 'resolve-response+jwt');
}

// ── JWKS helper ───────────────────────────────────────────────────────────────
// Returns the raw JWKS object (not signed) for protocol key endpoints.
export function buildJWKS(key: JWK): { keys: JWK[] } {
  return { keys: [key] };
}

// ── Trust Chain builder ───────────────────────────────────────────────────────

export interface TrustChain {
  entity:               string;
  entityConfig:         string;
  subordinateStatement: string;
  taConfig:             string;
  verified:             boolean;
}

export async function buildTrustChain(
  s: FederationState,
  leafID: Exclude<EntityID, 'ta'>,
  builders: {
    entityConfig: () => Promise<string>;
    taConfig:     string;
  },
): Promise<TrustChain> {
  const entityConfig         = await builders.entityConfig();
  const subordinateStatement = await buildSubordinateStatement(s, leafID);
  return {
    entity:               s.entityIDs[leafID],
    entityConfig,
    subordinateStatement,
    taConfig:             builders.taConfig,
    verified:             true,
  };
}
