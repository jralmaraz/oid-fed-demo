// OpenID Federation 1.0 entity definitions.
// Each entity has an identifier URL, a role, and metadata appropriate to that role.
// Entity Configurations and Subordinate Statements are signed JWTs.

import { KeyPair, signJWT } from './crypto.js';

const now = () => Math.floor(Date.now() / 1000);
const TTL = 3600; // 1 hour — short for a demo; production uses days/weeks

export interface FederationState {
  baseURL:   string;
  keys:      Record<EntityID, KeyPair>;
  entityIDs: Record<EntityID, string>;
}

export type EntityID = 'ta' | 'keycloak' | 'okta' | 'entra' | 'rp';

// ── Entity Configuration builders ────────────────────────────────────────────

// Trust Anchor Entity Configuration — the root of trust.
// No authority_hints (TA is self-sovereign).
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
        // Federation API endpoints
        federation_fetch_endpoint:    `${iss}/federation/fetch`,
        federation_list_endpoint:     `${iss}/federation/list`,
        federation_resolve_endpoint:  `${iss}/federation/resolve`,
      },
    },
  };
  return signJWT(payload, s.keys.ta.privateKey, s.keys.ta.kid, 'federation+jwt');
}

// Keycloak IdP Entity Configuration — simulates a self-hosted Keycloak instance.
export async function buildKeycloakEntityConfig(s: FederationState): Promise<string> {
  const iss = s.entityIDs.keycloak;
  const payload = {
    iss, sub: iss,
    iat: now(), exp: now() + TTL,
    jwks: { keys: [s.keys.keycloak.publicJWK] },
    authority_hints: [s.entityIDs.ta],
    metadata: {
      openid_provider: {
        issuer: iss,
        authorization_endpoint:  `${iss}/protocol/openid-connect/auth`,
        token_endpoint:          `${iss}/protocol/openid-connect/token`,
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
  const payload = {
    iss, sub: iss,
    iat: now(), exp: now() + TTL,
    jwks: { keys: [s.keys.okta.publicJWK] },
    authority_hints: [s.entityIDs.ta],
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
  const payload = {
    iss, sub: iss,
    iat: now(), exp: now() + TTL,
    jwks: { keys: [s.keys.entra.publicJWK] },
    authority_hints: [s.entityIDs.ta],
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
  const payload = {
    iss, sub: iss,
    iat: now(), exp: now() + TTL,
    jwks: { keys: [s.keys.rp.publicJWK] },
    authority_hints: [s.entityIDs.ta],
    metadata: {
      openid_relying_party: {
        client_name: 'FinClear Portal',
        redirect_uris: [`${iss}/callback`],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        subject_type: 'public',
        id_token_signed_response_alg: 'ES256',
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

export async function buildSubordinateStatement(
  s: FederationState,
  leafID: Exclude<EntityID, 'ta'>,
): Promise<string> {
  const sub = s.entityIDs[leafID];
  const iss = s.entityIDs.ta;
  const payload = {
    iss, sub,
    iat: now(), exp: now() + TTL,
    // TA vouches for the leaf's current public key
    jwks: { keys: [s.keys[leafID].publicJWK] },
    metadata_policy: {
      // TA may constrain or augment the leaf's metadata claims here.
      // For this demo we pass through everything without restriction.
    },
    source_endpoint: `${iss}/federation/fetch`,
  };
  return signJWT(payload, s.keys.ta.privateKey, s.keys.ta.kid, 'federation+jwt');
}

// ── Trust Chain builder ───────────────────────────────────────────────────────

export interface TrustChain {
  entity:              string;
  entityConfig:        string;
  subordinateStatement: string;
  taConfig:            string;
  verified:            boolean;
}

export async function buildTrustChain(
  s: FederationState,
  leafID: Exclude<EntityID, 'ta'>,
  builders: {
    entityConfig: () => Promise<string>;
    taConfig:     string;
  },
): Promise<TrustChain> {
  const entityConfig        = await builders.entityConfig();
  const subordinateStatement = await buildSubordinateStatement(s, leafID);
  return {
    entity:              s.entityIDs[leafID],
    entityConfig,
    subordinateStatement,
    taConfig:            builders.taConfig,
    verified:            true,
  };
}
