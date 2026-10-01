// Synthetic passkeys only. Shared by disposable Chromium and Firefox profiles.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:https';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash, verify } from 'node:crypto';

export const challenge = Buffer.from('boltwarden-webauthn-browser-proof').toString('base64url');
export const userHandle = Buffer.from('browser-proof-user').toString('base64url');
export const fixtureHtml = `<!doctype html><html><head><title>Boltwarden passkey fixture</title></head><body><h1>Passkey browser proof</h1><script>
const challenge = Uint8Array.from(atob('${challenge}'.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
const user = new TextEncoder().encode('browser-proof-user');
function evidence(value) {
  return { json: value.toJSON(), credentialPrototype: value instanceof PublicKeyCredential,
    responsePrototype: value.response instanceof (value.response.signature ? AuthenticatorAssertionResponse : AuthenticatorAttestationResponse),
    methods: value.response.signature ? null : { algorithm: value.response.getPublicKeyAlgorithm(), publicKey: value.response.getPublicKey().byteLength,
      authenticatorData: value.response.getAuthenticatorData().byteLength, transports: value.response.getTransports() },
    extensions: value.getClientExtensionResults() };
}
window.passkeyFixture = {
  async create(overrides = {}) { return evidence(await navigator.credentials.create({ publicKey: {
    challenge, rp: { id: 'localhost', name: 'Boltwarden test' }, user: { id: user, name: 'alice', displayName: 'Alice' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }], authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    extensions: { credProps: true }, timeout: 10000, ...overrides } })); },
  async get(overrides = {}, signal) { return evidence(await navigator.credentials.get({ publicKey: {
    challenge, rpId: 'localhost', userVerification: 'required', timeout: 10000, ...overrides }, signal })); },
  startGet(overrides = {}) { window.passkeyAbort = new AbortController(); window.passkeyPending = this.get(overrides, window.passkeyAbort.signal).then(value => ({ value }), error => ({ error: error.name })); },
  abort() { window.passkeyAbort.abort(); },
};
</script></body></html>`;

export async function startPasskeyFixture(directory) {
  const key = join(directory, 'localhost-key.pem'), cert = join(directory, 'localhost-cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
  const server = createServer({ key: await readFile(key), cert: await readFile(cert) }, (request, response) => {
    const headers = { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' };
    if (request.url.startsWith('/policy-denied')) headers['Permissions-Policy'] = 'publickey-credentials-get=(), publickey-credentials-create=()';
    response.writeHead(200, headers); response.end(fixtureHtml);
  });
  await new Promise((resolve, reject) => { server.on('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return { origin: `https://localhost:${server.address().port}`, close: () => new Promise(resolve => server.close(resolve)) };
}
function clientData(json, kind, origin) {
  const data = JSON.parse(Buffer.from(json.response.clientDataJSON, 'base64url'));
  assert.deepEqual(data, { type: `webauthn.${kind}`, challenge, origin, crossOrigin: false });
}
export function verifyRegistration(value, origin) {
  assert.equal(value.credentialPrototype, true); assert.equal(value.responsePrototype, true);
  assert.equal(value.json.type, 'public-key'); assert.equal(value.json.id, value.json.rawId);
  assert.equal(value.methods.algorithm, -7); assert(value.methods.publicKey > 64); assert(value.methods.authenticatorData >= 37);
  assert.deepEqual(value.methods.transports, ['internal']); assert.deepEqual(value.extensions, { credProps: { rk: true } });
  clientData(value.json, 'create', origin);
  const data = Buffer.from(value.json.response.authenticatorData, 'base64url');
  assert.deepEqual(data.subarray(0, 32), createHash('sha256').update('localhost').digest()); assert.equal(data[32] & 5, 5);
  assert(Buffer.from(value.json.response.attestationObject, 'base64url').length > data.length);
}
export function verifyAssertion(value, registration, origin) {
  assert.equal(value.credentialPrototype, true); assert.equal(value.responsePrototype, true);
  assert.equal(value.json.id, registration.json.id); clientData(value.json, 'get', origin);
  const response = value.json.response, data = Buffer.from(response.authenticatorData, 'base64url');
  assert.deepEqual(data.subarray(0, 32), createHash('sha256').update('localhost').digest()); assert.equal(data[32] & 5, 5);
  assert.equal(response.userHandle, userHandle);
  assert(verify('sha256', Buffer.concat([data, createHash('sha256').update(Buffer.from(response.clientDataJSON, 'base64url')).digest()]),
    { key: Buffer.from(registration.json.response.publicKey, 'base64url'), format: 'der', type: 'spki' }, Buffer.from(response.signature, 'base64url')),
  'Independent Node crypto verification of authenticator signature failed');
}
