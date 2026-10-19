// JWT signing and verification using the Web Crypto API (available in Workers).
// All operations use P-256 / ES256 to match OpenID Federation 1.0 requirements.

export interface KeyPair {
  publicKey:  CryptoKey;
  privateKey: CryptoKey;
  publicJWK:  JsonWebKey;
  kid:        string;
}

export async function generateKeyPair(kid: string): Promise<KeyPair> {
  const kp = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const publicJWK = await crypto.subtle.exportKey('jwk', kp.publicKey);
  publicJWK.kid = kid;
  publicJWK.use = 'sig';
  publicJWK.alg = 'ES256';
  return { publicKey: kp.publicKey, privateKey: kp.privateKey, publicJWK, kid };
}

// Sign a JWT with ES256. Header typ defaults to 'JWT'; pass override for 'federation+jwt'.
export async function signJWT(
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
  kid: string,
  typ = 'JWT',
): Promise<string> {
  const header = { alg: 'ES256', typ, kid };
  const enc = (obj: unknown) =>
    btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const signingInput = `${enc(header)}.${enc(payload)}`;
  const data = new TextEncoder().encode(signingInput);

  const sigBuffer = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data);
  const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return `${signingInput}.${sig}`;
}

// Decode a JWT without verifying (for display purposes).
export function decodeJWT(token: string): { header: unknown; payload: unknown } {
  const [h, p] = token.split('.');
  const decode = (s: string) => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/')));
  return { header: decode(h), payload: decode(p) };
}

// Verify an ES256 JWT signature against a public key.
export async function verifyJWT(token: string, publicKey: CryptoKey): Promise<boolean> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const [h, p, sig] = parts;
    const data = new TextEncoder().encode(`${h}.${p}`);
    const sigBytes = Uint8Array.from(atob(sig.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, sigBytes, data);
  } catch {
    return false;
  }
}
