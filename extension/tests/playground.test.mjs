import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { request } from 'node:https';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { createRelyingParty, startPlayground } from '../playground/server.mjs';

const origin = 'https://localhost:8443';
const encoded = value => Buffer.from(value).toString('base64url');
function authenticator() {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const key = keys.publicKey.export({ format: 'jwk' }), id = randomBytes(16), rawId = encoded(id);
  const cose = isoCBOR.encode(new Map([[1, 2], [3, -7], [-1, 1], [-2, new Uint8Array(Buffer.from(key.x, 'base64url'))], [-3, new Uint8Array(Buffer.from(key.y, 'base64url'))]]));
  let userHandle;
  return (options, create = false, overrides = {}) => {
    if (create) userHandle = options.user.id;
    const client = Buffer.from(JSON.stringify({ type: create ? 'webauthn.create' : 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false, ...overrides }));
    let data = Buffer.concat([createHash('sha256').update('localhost').digest(), Buffer.from([create ? 0x5d : 0x1d, 0, 0, 0, 0])]);
    const response = { clientDataJSON: encoded(client) };
    if (create) {
      data = Buffer.concat([data, Buffer.alloc(16), Buffer.from([0, 16]), id, cose]);
      response.attestationObject = encoded(isoCBOR.encode(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', new Uint8Array(data)]])));
    } else {
      response.authenticatorData = encoded(data);
      response.signature = encoded(sign('sha256', Buffer.concat([data, createHash('sha256').update(client).digest()]), keys.privateKey));
      response.userHandle = userHandle;
    }
    return { id: rawId, rawId, type: 'public-key', clientExtensionResults: {}, response };
  };
}
async function register(api, name = 'alice', challengeBytes = 32) {
  const auth = authenticator();
  const { requestId, options } = await api('/api/options', { kind: 'create', name, challengeBytes });
  const result = await api('/api/verify', { requestId, response: auth(options, true) });
  assert.equal(result.verified, true); return auth;
}

test('independent verifier accepts registration, explicit sign-in and discovery at each challenge size', async () => {
  for (const challengeBytes of [32, 8192, 65536]) {
    const api = createRelyingParty(origin), auth = await register(api, 'alice', challengeBytes);
    for (const discoverable of [false, true]) {
      const { requestId, options } = await api('/api/options', { kind: 'get', name: 'alice', discoverable, challengeBytes });
      assert.equal(Buffer.from(options.challenge, 'base64url').length, challengeBytes);
      const body = { requestId, response: auth(options) };
      const result = await api('/api/verify', body);
      assert.equal(result.verified, true); assert.equal(result.account, 'alice'); assert.equal(result.userVerified, true);
      await assert.rejects(api('/api/verify', body), /already used/);
    }
  }
});
test('rejects wrong origin, challenge, account, user handle, signature and missing required verification', async () => {
  const api = createRelyingParty(origin), auth = await register(api);
  await register(api, 'bob');
  for (const mutation of ['origin', 'challenge', 'account', 'handle', 'signature', 'verification']) {
    const { requestId, options } = await api('/api/options', { kind: 'get', name: mutation === 'account' ? 'bob' : 'alice', verification: 'required' });
    const response = auth(options, false, mutation === 'origin' ? { origin: 'https://evil.test' } : mutation === 'challenge' ? { challenge: encoded(randomBytes(32)) } : {});
    if (mutation === 'handle') response.response.userHandle = encoded(randomBytes(32));
    if (mutation === 'signature') response.response.signature = encoded(Buffer.alloc(70));
    if (mutation === 'verification') {
      const data = Buffer.from(response.response.authenticatorData, 'base64url'); data[32] &= ~4; response.response.authenticatorData = encoded(data);
    }
    await assert.rejects(api('/api/verify', { requestId, response }), undefined, mutation);
  }
});
test('expires requests, isolates pending browser requests and clears server records on reset', async () => {
  let now = 0; const api = createRelyingParty(origin, () => now), auth = await register(api);
  const first = await api('/api/options', { kind: 'get', name: 'alice' });
  const second = await api('/api/options', { kind: 'get', name: 'alice' });
  assert.equal((await api('/api/verify', { requestId: first.requestId, response: auth(first.options) })).verified, true);
  now = 120001;
  await assert.rejects(api('/api/verify', { requestId: second.requestId, response: auth(second.options) }), /expired/);
  const third = await api('/api/options', { kind: 'get', name: 'alice' });
  await api('/api/reset');
  assert.deepEqual(await api('/api/state'), { accounts: [] });
  await assert.rejects(api('/api/verify', { requestId: third.requestId, response: auth(third.options) }), /expired/);
});
test('HTTPS server serves the page and rejects cross-origin mutations and wrong hosts', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'boltwarden-playground-test-'));
  const app = await startPlayground({ port: 0, directory });
  const fetch = (path, method = 'GET', headers = {}, body = '') => new Promise((resolve, reject) => {
    const req = request(`${app.origin}${path}`, { method, rejectUnauthorized: false, headers }, response => {
      let text = ''; response.on('data', data => { text += data; }); response.on('end', () => resolve({ status: response.statusCode, text }));
    }); req.on('error', reject); req.end(body);
  });
  try {
    const page = await fetch('/'); assert.equal(page.status, 200); assert.match(page.text, /Create passkey/);
    const login = await fetch('/login'); assert.equal(login.status, 200); assert.match(login.text, /autocomplete="username"/);
    assert.equal((await fetch('/login.css')).status, 200);
    assert.equal((await fetch('/login.js')).status, 200);
    assert.equal((await fetch('/api/reset', 'POST', { origin: 'https://evil.test', 'content-type': 'application/json' }, '{}')).status, 403);
    assert.equal((await fetch('/', 'GET', { host: 'evil.test' })).status, 403);
    assert.equal((await fetch('/api/state', 'POST', { origin: app.origin, 'content-type': 'application/json' }, '{}')).status, 200);
  } finally { await app.close(); await rm(directory, { recursive: true, force: true }); }
});

test('password registration, login and change share the passkey account without exposing hashes', async () => {
  const api = createRelyingParty(origin);
  const username = 'boltwarden-test-alice';
  await api('/api/password', {action: 'register', username, password: 'old', confirmation: 'old'});
  assert.equal((await api('/api/password', {action: 'login', username, password: 'old'})).verified, true);
  await assert.rejects(api('/api/password', {action: 'change', username, password: 'new', confirmation: 'new', oldPassword: 'wrong'}), /incorrect/);
  await api('/api/password', {action: 'change', username, password: 'new', confirmation: 'new', oldPassword: 'old'});
  await assert.rejects(api('/api/password', {action: 'login', username, password: 'old'}), /incorrect/);
  assert.equal((await api('/api/password', {action: 'login', username, password: 'new'})).verified, true);
  await assert.rejects(api('/api/password', {action: 'change', username, password: 'different', confirmation: 'mismatch', oldPassword: 'new'}), /do not match/);
  await register(api);
  assert.deepEqual(await api('/api/state'), {accounts: [{name: 'alice', password: true, passkeys: 1}]});
});

test('example.com usernames support password flows and alias the matching test account', async () => {
  const api = createRelyingParty(origin);
  const username = 'alice@example.com';
  await api('/api/password', { action: 'register', username, password: 'sample-old', confirmation: 'sample-old' });
  assert.equal((await api('/api/password', { action: 'login', username, password: 'sample-old' })).verified, true);
  await api('/api/password', { action: 'change', username, oldPassword: 'sample-old', password: 'sample-new', confirmation: 'sample-new' });
  assert.equal((await api('/api/password', { action: 'login', username: 'boltwarden-test-alice', password: 'sample-new' })).verified, true);
  await register(api);
  assert.deepEqual(await api('/api/state'), { accounts: [{ name: 'alice', password: true, passkeys: 1 }] });
  for (const invalid of ['alice@gmail.com', 'alice@example.com.evil.test', '@example.com', 'alice@example.com\n']) {
    await assert.rejects(api('/api/password', { action: 'register', username: invalid, password: 'sample', confirmation: 'sample' }), /Use boltwarden-test-NAME/);
  }
});
