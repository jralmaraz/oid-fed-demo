#!/usr/bin/env tsx
/**
 * OID-FED 1.0 Conformance Walk
 *
 * Discovery-based validation: starts from the Trust Anchor's Entity Config,
 * reads all federation API endpoint URLs declared in its metadata, then walks
 * the full spec-required endpoint set.
 *
 * Validates:
 *   - Entity Configurations (all entities)
 *   - Federation API: fetch, list (with entity_type filter), resolve
 *   - Trust Mark endpoints: status, list
 *   - Protocol JWKS endpoints (jwks_uri per entity)
 *   - JWT structure, required payload fields, Content-Types
 *   - ES256 signature verification (crypto — not just decode)
 *
 * Usage:
 *   npm run conformance                          # local dev (localhost:8787)
 *   npm run conformance -- https://<worker-url> # any deployed Worker
 */

import { createVerify } from 'node:crypto';

const BASE = process.argv[2] ?? 'http://localhost:8787';

// ── Harness ───────────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures: string[] = [];

function pass(label: string) {
  process.stdout.write(`  \x1b[32m✓\x1b[0m ${label}\n`);
  passed++;
}

function fail(label: string, detail?: string) {
  process.stdout.write(`  \x1b[31m✗\x1b[0m ${label}${detail ? `\n      → ${detail}` : ''}\n`);
  failed++;
  failures.push(label);
}

function section(title: string) {
  process.stdout.write(`\n\x1b[1m── ${title} ──\x1b[0m\n`);
}

async function get(url: string): Promise<{ status: number; ct: string; body: string }> {
  const r = await fetch(url);
  return { status: r.status, ct: r.headers.get('content-type') ?? '', body: await r.text() };
}

// ── JWT utilities ─────────────────────────────────────────────────────────────

function decodeJWT(token: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error(`expected 3 JWT parts, got ${parts.length}`);
  const decode = (s: string) =>
    JSON.parse(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  return { header: decode(parts[0]), payload: decode(parts[1]) };
}

// Verify ES256 signature using Node crypto.
// jwk must be a P-256 public key in JWK format.
async function verifyES256(token: string, jwk: Record<string, unknown>): Promise<boolean> {
  try {
    const [h, p, sigB64] = token.split('.');
    const signingInput = `${h}.${p}`;

    // Decode the DER-format signature from compact (r||s) base64url
    const sigBytes = Buffer.from(sigB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

    // Node's createVerify expects the key as a JWK object
    const verify = createVerify('SHA256');
    verify.update(signingInput);

    // Convert JWK to KeyObject via importKey (Node 15+)
    const { webcrypto } = await import('node:crypto');
    const key = await webcrypto.subtle.importKey(
      'jwk',
      jwk as JsonWebKey,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );

    // Use webcrypto for actual verify (handles compact → DER conversion internally)
    const data = new TextEncoder().encode(signingInput);
    return await webcrypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      sigBytes,
      data,
    );
  } catch {
    return false;
  }
}

// ── Checks ────────────────────────────────────────────────────────────────────

function checkJWT(label: string, body: string, expectedTyp: string): ReturnType<typeof decodeJWT> | null {
  const parts = body.split('.');
  if (parts.length !== 3) { fail(label, `not a JWT (${parts.length} parts)`); return null; }
  try {
    const decoded = decodeJWT(body);
    if (decoded.header.typ !== expectedTyp)
      fail(`${label} typ`, `expected "${expectedTyp}", got "${decoded.header.typ}"`);
    else pass(`${label} — typ=${expectedTyp}`);
    if (decoded.header.alg !== 'ES256')
      fail(`${label} alg`, `expected ES256, got "${decoded.header.alg}"`);
    else pass(`${label} — alg=ES256`);
    return decoded;
  } catch (e) {
    fail(label, String(e));
    return null;
  }
}

function require(label: string, obj: Record<string, unknown>, ...keys: string[]) {
  for (const k of keys) {
    if (obj[k] === undefined || obj[k] === null) fail(`${label} — missing "${k}"`);
    else pass(`${label} — has "${k}"`);
  }
}

// ── Main conformance walk ─────────────────────────────────────────────────────

async function run() {
  process.stdout.write(`\x1b[1mOID-FED 1.0 Conformance Walk\x1b[0m\n`);
  process.stdout.write(`Target: \x1b[36m${BASE}\x1b[0m\n`);

  // ── Step 1: Fetch TA Entity Config — the discovery root ──────────────────
  section('Step 1 — Trust Anchor Entity Configuration (discovery root)');

  const taECUrl = `${BASE}/ta/.well-known/openid-federation`;
  const taECRes = await get(taECUrl);

  if (taECRes.status !== 200) { fail('TA EC reachable', `HTTP ${taECRes.status}`); }
  else pass('TA EC reachable (HTTP 200)');

  if (!taECRes.ct.includes('entity-statement')) fail('TA EC Content-Type', taECRes.ct);
  else pass('TA EC Content-Type: application/entity-statement+jwt');

  const taEC = checkJWT('TA EC', taECRes.body, 'federation+jwt');
  if (!taEC) { process.exit(1); }

  const tap = taEC.payload;
  require('TA EC payload', tap, 'iss', 'sub', 'iat', 'exp', 'jwks');
  if (tap.iss !== tap.sub) fail('TA EC iss==sub (self-signed)', `iss=${tap.iss} sub=${tap.sub}`);
  else pass('TA EC iss==sub (self-signed, no authority_hints)');
  if (tap.authority_hints !== undefined) fail('TA EC must NOT have authority_hints');
  else pass('TA EC has no authority_hints (root of trust)');

  // Verify TA EC signature against its own jwks
  const taKeys = (tap.jwks as { keys: Record<string, unknown>[] }).keys;
  const taKeyJWK = taKeys[0];
  const taSigOk = await verifyES256(taECRes.body, taKeyJWK);
  if (taSigOk) pass('TA EC signature verified (ES256)');
  else fail('TA EC signature verification failed');

  // Discover federation API endpoints from TA metadata
  const taFed = (tap.metadata as Record<string, Record<string, unknown>>)?.federation_entity ?? {};
  const fetchEndpoint   = taFed.federation_fetch_endpoint as string;
  const listEndpoint    = taFed.federation_list_endpoint as string;
  const resolveEndpoint = taFed.federation_resolve_endpoint as string;
  const statusEndpoint  = taFed.trust_mark_status_endpoint as string;
  const tmListEndpoint  = taFed.trust_mark_list_endpoint as string;

  for (const [name, ep] of [
    ['federation_fetch_endpoint', fetchEndpoint],
    ['federation_list_endpoint', listEndpoint],
    ['federation_resolve_endpoint', resolveEndpoint],
    ['trust_mark_status_endpoint', statusEndpoint],
    ['trust_mark_list_endpoint', tmListEndpoint],
  ] as [string, string][]) {
    if (ep) pass(`TA EC declares ${name}: ${ep}`);
    else fail(`TA EC missing ${name} in federation_entity metadata`);
  }

  const trustMarkIssuers = taFed.trust_mark_issuers as Record<string, unknown> | undefined;
  if (trustMarkIssuers && Object.keys(trustMarkIssuers).length > 0)
    pass(`TA EC declares ${Object.keys(trustMarkIssuers).length} trust_mark_issuers`);
  else fail('TA EC missing trust_mark_issuers');

  const taID = tap.iss as string;

  // ── Step 2: Discover all entities via federation/list ────────────────────
  section('Step 2 — federation/list (entity discovery)');

  const listRes = await get(listEndpoint);
  if (listRes.status !== 200) fail('list reachable', `HTTP ${listRes.status}`);
  else pass('federation/list reachable (HTTP 200)');

  const listData = JSON.parse(listRes.body) as { entities: string[]; iss: string; iat: number };
  require('list response', listData as unknown as Record<string, unknown>, 'iss', 'iat', 'entities');
  if (!Array.isArray(listData.entities) || listData.entities.length === 0)
    fail('list entities is non-empty array');
  else pass(`list returns ${listData.entities.length} entity IDs`);

  // entity_type filter
  const listIdPRes  = await get(`${listEndpoint}?entity_type=openid_provider`);
  const listIdPs    = (JSON.parse(listIdPRes.body) as { entities: string[] }).entities;
  const listRPRes   = await get(`${listEndpoint}?entity_type=openid_relying_party`);
  const listRPs     = (JSON.parse(listRPRes.body) as { entities: string[] }).entities;
  if (listIdPs.length > 0) pass(`list?entity_type=openid_provider returns ${listIdPs.length} IdPs`);
  else fail('list?entity_type=openid_provider returned empty');
  if (listRPs.length > 0) pass(`list?entity_type=openid_relying_party returns ${listRPs.length} RPs`);
  else fail('list?entity_type=openid_relying_party returned empty');

  const allEntityIDs = listData.entities;

  // ── Step 3: Walk each entity — EC + fetch + protocol JWKS ───────────────
  section('Step 3 — per-entity: Entity Config, Subordinate Statement, protocol JWKS');

  for (const entityID of allEntityIDs) {
    const ecUrl = `${entityID}/.well-known/openid-federation`;
    process.stdout.write(`\n  Entity: \x1b[33m${entityID}\x1b[0m\n`);

    // Entity Config
    const ecRes = await get(ecUrl);
    if (ecRes.status !== 200) { fail(`EC reachable`, `HTTP ${ecRes.status} at ${ecUrl}`); continue; }
    else pass(`EC reachable (HTTP 200)`);
    if (!ecRes.ct.includes('entity-statement')) fail(`EC Content-Type`, ecRes.ct);
    else pass(`EC Content-Type: application/entity-statement+jwt`);

    const ec = checkJWT('EC', ecRes.body, 'federation+jwt');
    if (!ec) continue;

    const ep = ec.payload;
    require('EC payload', ep, 'iss', 'sub', 'iat', 'exp', 'jwks');
    if (ep.iss !== ep.sub) fail('EC iss==sub', `iss=${ep.iss} sub=${ep.sub}`);
    else pass('EC iss==sub');

    // authority_hints must point to TA
    const hints = ep.authority_hints as string[] | undefined;
    if (!hints || !hints.includes(taID)) fail('EC authority_hints includes TA', JSON.stringify(hints));
    else pass('EC authority_hints includes TA');

    // trust_marks present
    const tms = ep.trust_marks as unknown[] | undefined;
    if (!tms || tms.length === 0) fail('EC has trust_marks');
    else {
      pass(`EC has ${tms.length} trust_mark(s)`);
      // Each trust mark must be a valid JWT
      for (const tm of tms as { id: string; trust_mark: string }[]) {
        const tmParts = (tm.trust_mark ?? '').split('.');
        if (tmParts.length === 3) {
          pass(`trust_mark "${tm.id.split('/').pop()}" is a valid JWT`);
          const tmDecoded = decodeJWT(tm.trust_mark);
          if (tmDecoded.header.typ === 'trust-mark+jwt') pass(`trust_mark typ=trust-mark+jwt`);
          else fail(`trust_mark typ`, `got "${tmDecoded.header.typ}"`);
          // Trust mark should be signed by TA — verify against TA key
          const tmSigOk = await verifyES256(tm.trust_mark, taKeyJWK);
          if (tmSigOk) pass(`trust_mark signature verified (signed by TA)`);
          else fail(`trust_mark signature verification failed`);
        } else {
          fail(`trust_mark "${tm.id}" is not a JWT`);
        }
      }
    }

    // Verify leaf EC signature with its own key
    const leafKeys = (ep.jwks as { keys: Record<string, unknown>[] }).keys;
    const leafKey  = leafKeys[0];
    const leafSig  = await verifyES256(ecRes.body, leafKey);
    if (leafSig) pass('EC signature verified (self-signed with own key)');
    else fail('EC signature verification failed');

    // Subordinate Statement — fetch from TA
    const subStmtRes = await get(`${fetchEndpoint}?sub=${encodeURIComponent(entityID)}`);
    if (subStmtRes.status !== 200) fail('SubStmt reachable', `HTTP ${subStmtRes.status}`);
    else pass('SubStmt reachable from federation/fetch');
    if (!subStmtRes.ct.includes('entity-statement')) fail('SubStmt Content-Type', subStmtRes.ct);
    else pass('SubStmt Content-Type: application/entity-statement+jwt');

    const subStmt = checkJWT('SubStmt', subStmtRes.body, 'federation+jwt');
    if (subStmt) {
      const sp = subStmt.payload;
      require('SubStmt payload', sp, 'iss', 'sub', 'jwks', 'source_endpoint');
      if (sp.iss !== taID) fail('SubStmt iss=TA', `got ${sp.iss}`);
      else pass('SubStmt iss=TA');
      if (sp.sub !== entityID) fail('SubStmt sub=entity', `got ${sp.sub}`);
      else pass('SubStmt sub matches entity ID');

      // Key binding: SubStmt.jwks must match EC.jwks (TA vouches for this key)
      const subStmtKey = ((sp.jwks as { keys: Record<string, unknown>[] }).keys[0] as { kid: string }).kid;
      const ecKey = (leafKey as { kid: string }).kid;
      if (subStmtKey === ecKey) pass('SubStmt key binding: SubStmt.jwks.kid == EC.jwks.kid');
      else fail('SubStmt key binding mismatch', `SubStmt kid=${subStmtKey}, EC kid=${ecKey}`);

      // SubStmt signed by TA
      const subSig = await verifyES256(subStmtRes.body, taKeyJWK);
      if (subSig) pass('SubStmt signature verified (signed by TA)');
      else fail('SubStmt signature verification failed');
    }

    // Protocol JWKS (jwks_uri) — only for openid_provider and openid_relying_party
    const md = ep.metadata as Record<string, Record<string, unknown>> | undefined;
    const jwksUri =
      (md?.openid_provider?.jwks_uri ?? md?.openid_relying_party?.jwks_uri) as string | undefined;
    if (jwksUri) {
      const jwksRes = await get(jwksUri);
      if (jwksRes.status !== 200) fail(`protocol JWKS reachable (${jwksUri})`, `HTTP ${jwksRes.status}`);
      else {
        const jwks = JSON.parse(jwksRes.body) as { keys: { kty: string; crv?: string }[] };
        if (Array.isArray(jwks.keys) && jwks.keys.length > 0) {
          pass(`protocol JWKS (${jwksUri.split('/').slice(-1)[0]}) returns ${jwks.keys.length} key(s)`);
          if (jwks.keys[0].kty === 'EC' && jwks.keys[0].crv === 'P-256')
            pass('protocol JWKS key is EC P-256');
          else fail('protocol JWKS key type', JSON.stringify(jwks.keys[0]));
        } else {
          fail(`protocol JWKS has keys`);
        }
      }
    }
  }

  // ── Step 4: federation/resolve ───────────────────────────────────────────
  section('Step 4 — federation/resolve (full trust chain resolution)');

  // Test against each IdP
  for (const entityID of listIdPs) {
    const url = `${resolveEndpoint}?sub=${encodeURIComponent(entityID)}&trust_anchor=${encodeURIComponent(taID)}`;
    const res = await get(url);
    if (res.status !== 200) { fail(`resolve ${entityID}`, `HTTP ${res.status}`); continue; }
    pass(`resolve reachable for ${entityID.split('/').pop()}`);

    if (!res.ct.includes('resolve-response')) fail('resolve Content-Type', res.ct);
    else pass('resolve Content-Type: application/resolve-response+jwt');

    const resolved = checkJWT('resolve-response', res.body, 'resolve-response+jwt');
    if (!resolved) continue;

    const rp = resolved.payload;
    require('resolve payload', rp, 'iss', 'sub', 'trust_anchor', 'trust_chain', 'metadata');

    if (rp.sub === entityID) pass('resolve sub=requested entity');
    else fail('resolve sub mismatch', `expected ${entityID}, got ${rp.sub}`);

    if (rp.trust_anchor === taID) pass('resolve trust_anchor=TA');
    else fail('resolve trust_anchor mismatch');

    const chain = rp.trust_chain as string[];
    if (Array.isArray(chain) && chain.length === 3) pass('resolve trust_chain has 3 JWTs');
    else fail('resolve trust_chain length', `got ${Array.isArray(chain) ? chain.length : typeof chain}`);

    // Resolve response signed by TA
    const resSig = await verifyES256(res.body, taKeyJWK);
    if (resSig) pass('resolve-response signature verified (signed by TA)');
    else fail('resolve-response signature verification failed');
  }

  // Error cases
  const noAnchor = await get(`${resolveEndpoint}?sub=${encodeURIComponent(listIdPs[0])}`);
  if (noAnchor.status === 400) pass('resolve without trust_anchor → 400');
  else fail('resolve without trust_anchor should return 400', `got ${noAnchor.status}`);

  const unknown = await get(`${resolveEndpoint}?sub=https%3A%2F%2Funknown.example.com&trust_anchor=${encodeURIComponent(taID)}`);
  if (unknown.status === 404) pass('resolve unknown entity → 404');
  else fail('resolve unknown entity should return 404', `got ${unknown.status}`);

  // ── Step 5: Trust Mark endpoints ────────────────────────────────────────
  section('Step 5 — Trust Mark status and listing');

  // Collect trust mark IDs from all ECs we visited
  const trustMarkIDs = new Set<string>();
  for (const entityID of allEntityIDs) {
    const ecUrl = `${entityID}/.well-known/openid-federation`;
    const ecRes = await get(ecUrl);
    const ec    = decodeJWT(ecRes.body);
    const tms   = (ec.payload.trust_marks ?? []) as { id: string }[];
    for (const tm of tms) trustMarkIDs.add(tm.id);
  }
  pass(`discovered ${trustMarkIDs.size} distinct trust mark IDs across all entities`);

  for (const markID of trustMarkIDs) {
    // trust_mark_list
    const listUrl = `${tmListEndpoint}?trust_mark_id=${encodeURIComponent(markID)}`;
    const listRes = await get(listUrl);
    if (listRes.status !== 200) { fail(`trust_mark_list reachable (${markID.split('/').pop()})`, `HTTP ${listRes.status}`); continue; }
    const tmList = JSON.parse(listRes.body) as { entities: string[]; trust_mark_id: string };
    require('trust_mark_list response', tmList as unknown as Record<string, unknown>, 'trust_mark_id', 'entities', 'iss', 'iat');
    pass(`trust_mark_list "${markID.split('/').pop()}" → ${tmList.entities.length} holder(s)`);

    // trust_mark_status — positive case: first entity in the list
    if (tmList.entities.length > 0) {
      const sub = tmList.entities[0];
      const statusUrl = `${statusEndpoint}?sub=${encodeURIComponent(sub)}&trust_mark_id=${encodeURIComponent(markID)}`;
      const statusRes = await get(statusUrl);
      if (statusRes.status !== 200) { fail(`trust_mark_status reachable`, `HTTP ${statusRes.status}`); continue; }
      const statusData = JSON.parse(statusRes.body) as { active: boolean };
      require('trust_mark_status response', statusData as unknown as Record<string, unknown>, 'active', 'sub', 'trust_mark_id', 'iss', 'iat');
      if (statusData.active === true) pass(`trust_mark_status active=true for known holder`);
      else fail(`trust_mark_status active should be true for a listed holder`);
    }
  }

  // Error cases
  const noSub = await get(`${statusEndpoint}?trust_mark_id=foo`);
  if (noSub.status === 400) pass('trust_mark_status without sub → 400');
  else fail('trust_mark_status without sub should return 400', `got ${noSub.status}`);

  const noMarkID = await get(tmListEndpoint);
  if (noMarkID.status === 400) pass('trust_mark_list without trust_mark_id → 400');
  else fail('trust_mark_list without trust_mark_id should return 400', `got ${noMarkID.status}`);

  // ── Summary ──────────────────────────────────────────────────────────────
  const total = passed + failed;
  process.stdout.write('\n\x1b[1m─────────────────────────────────────────\x1b[0m\n');
  process.stdout.write(`\x1b[1mConformance results: ${total} checks\x1b[0m\n`);
  process.stdout.write(`  \x1b[32m${passed} passed\x1b[0m\n`);
  if (failed > 0) {
    process.stdout.write(`  \x1b[31m${failed} failed\x1b[0m\n`);
    for (const f of failures) process.stdout.write(`    - ${f}\n`);
    process.exit(1);
  } else {
    process.stdout.write(`  \x1b[1m\x1b[32mAll checks passed — spec conformant ✓\x1b[0m\n`);
  }
}

run().catch(err => { console.error(err); process.exit(1); });
