import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { authenticationBytes, identity, publicIdentity, signChallenge } from '../lib/pairing';

describe('persistent pairing identity', () => {
  it('keeps the private key non-extractable while exporting the public key', async () => {
    const keys = await identity();
    expect(keys.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('pkcs8', keys.privateKey)).rejects.toThrow();
    const publicKey = await publicIdentity();
    expect(publicKey.fingerprint).toMatch(/^[0-9A-F]{4}(:[0-9A-F]{4}){15}$/);
    expect(publicKey.spki).not.toContain('=');
    expect((await identity()).privateKey).toBe(keys.privateKey);
  });
  it('signs the host-bound transcript in raw P-256 format', async () => {
    const keys = await identity();
    const nonce = 'x'.repeat(43), pairingId = '11111111-1111-4111-8111-111111111111';
    const sig = await signChallenge(keys, nonce, pairingId, 321);
    const raw = Uint8Array.from(atob(sig.replace(/-/g, '+').replace(/_/g, '/')), character => character.charCodeAt(0));
    expect(raw.length).toBe(64);
    expect(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, keys.publicKey, raw, authenticationBytes(nonce, pairingId, 321))).toBe(true);
    expect(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, keys.publicKey, raw, authenticationBytes(nonce, pairingId, 322))).toBe(false);
    expect(new TextDecoder().decode(authenticationBytes(nonce, pairingId, 321))).toBe(`boltwarden-browser-v1\n${nonce}\n${pairingId}\n321`);
  });
});
