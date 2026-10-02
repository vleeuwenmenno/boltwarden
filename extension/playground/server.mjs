// Local development relying party. No vault access or mocked authenticator.
import { createServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, access } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { join, resolve } from 'node:path';
import { generateRegistrationOptions, generateAuthenticationOptions,
  verifyRegistrationResponse, verifyAuthenticationResponse } from '@simplewebauthn/server';

const root = fileURLToPath(new URL('../', import.meta.url));
const rpID = 'localhost';

export function createRelyingParty(origin, now = Date.now) {
  const accounts = new Map(), pending = new Map();
  let generation = 0;
  const state = () => ({ accounts: [...accounts.values()].map(account => ({
    name: account.name, passkeys: account.credentials.length, password: !!account.password,
  })) });
  return async function api(path, body = {}) {
    if (path === '/api/state') return state();
    if (path === '/api/reset') { generation++; accounts.clear(); pending.clear(); return state(); }
    if (path === '/api/password') {
      const { action, username, password, oldPassword = '', confirmation } = body;
      const testAccount = typeof username === 'string'
        ? /^(?:boltwarden-test-([a-zA-Z0-9._-]{1,64})|([a-zA-Z0-9._-]{1,64})@example\.com)$/.exec(username)
        : null;
      if (!['register', 'login', 'change'].includes(action) || typeof username !== 'string'
        || !testAccount
        || typeof password !== 'string' || !password || password.length > 4096
        || typeof oldPassword !== 'string' || oldPassword.length > 4096) throw new Error('Use boltwarden-test-NAME or NAME@example.com and a nonempty test password.');
      if (action !== 'login' && confirmation !== password) throw new Error('Passwords do not match.');
      const name = testAccount[1] ?? testAccount[2];
      let account = accounts.get(name);
      if (action === 'register') {
        if (account?.password) throw new Error('Password account already exists. Use Sign in or Change password.');
        if (!account) {
          if (accounts.size >= 100) throw new Error('Reset before adding more accounts.');
          account = { name, id: randomBytes(32), credentials: [] }; accounts.set(name, account);
        }
      } else if (!account?.password || !timingSafeEqual(account.password.hash,
        scryptSync(action === 'change' ? oldPassword : password, account.password.salt, 32))) throw new Error('Test username or password is incorrect.');
      if (action !== 'login') { const salt = randomBytes(16); account.password = { salt, hash: scryptSync(password, salt, 32) }; }
      return { verified: true, message: action === 'register' ? 'Test password account created.' : action === 'change' ? 'Test password changed.' : 'Password sign-in passed.' };
    }
    if (path === '/api/options') {
      for (const [id, request] of pending) if (request.expires <= now()) pending.delete(id);
      if (pending.size >= 100) throw new Error('Too many pending tests. Wait two minutes or reset.');
      const { kind, name, verification = 'preferred', challengeBytes = 32, discoverable = false } = body;
      if (!['create', 'get'].includes(kind) || typeof name !== 'string' || !/^[a-zA-Z0-9._-]{1,64}$/.test(name)
        || !['preferred', 'required', 'discouraged'].includes(verification)
        || ![32, 8192, 65536].includes(challengeBytes) || typeof discoverable !== 'boolean') throw new Error('Invalid test options.');
      let account = accounts.get(name);
      if (kind === 'create' && !account) {
        if (accounts.size >= 100) throw new Error('Reset the playground before adding more accounts.');
        account = { name, id: randomBytes(32), credentials: [] }; accounts.set(name, account);
      }
      if (kind === 'get' && !discoverable && !account?.credentials.length) throw new Error('Create a passkey for this test account first.');
      if (kind === 'create' && account.credentials.length >= 64) throw new Error('Reset before registering more passkeys for this account.');
      const requestGeneration = generation;
      const challenge = randomBytes(challengeBytes);
      const options = kind === 'create'
        ? await generateRegistrationOptions({ rpName: 'Boltwarden playground', rpID,
          userName: `boltwarden-test-${name}`, userDisplayName: `Test: ${name}`, userID: account.id,
          challenge, supportedAlgorithmIDs: [-7], attestationType: 'none',
          excludeCredentials: account.credentials.map(key => ({ id: key.id })),
          authenticatorSelection: { residentKey: 'required', userVerification: verification },
          extensions: { credProps: true } })
        : await generateAuthenticationOptions({ rpID, challenge, userVerification: verification,
          ...(discoverable ? {} : { allowCredentials: account.credentials.map(key => ({ id: key.id })) }) });
      if (requestGeneration !== generation) throw new Error('Test data was reset.');
      const requestId = randomUUID();
      pending.set(requestId, { kind, account, discoverable, challenge: options.challenge,
        verification, expires: now() + 120_000, generation });
      return { requestId, options };
    }
    if (path === '/api/verify') {
      const request = pending.get(body.requestId); pending.delete(body.requestId);
      if (!request || request.expires <= now() || request.generation !== generation) throw new Error('Test expired or already used. Start again.');
      const common = { response: body.response, expectedChallenge: request.challenge,
        expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: request.verification === 'required' };
      let info, account = request.account;
      if (request.kind === 'create') {
        const result = await verifyRegistrationResponse({ ...common, supportedAlgorithmIDs: [-7] });
        if (!result.verified || !result.registrationInfo) throw new Error('Registration verification failed.');
        info = result.registrationInfo;
        if ([...accounts.values()].some(value => value.credentials.some(key => key.id === info.credential.id))) throw new Error('This passkey is already registered.');
        if (request.generation !== generation) throw new Error('Test data was reset.');
        account.credentials.push(info.credential);
      } else {
        if (request.discoverable) account = [...accounts.values()].find(value => value.credentials.some(key => key.id === body.response?.id));
        const key = account?.credentials.find(key => key.id === body.response?.id);
        if (!key) throw new Error('Unknown passkey. Create one in this running playground first.');
        const handle = body.response?.response?.userHandle;
        if ((request.discoverable && !handle) || (handle && handle !== account.id.toString('base64url'))) throw new Error('Wrong test account.');
        const result = await verifyAuthenticationResponse({ ...common, credential: key });
        if (!result.verified) throw new Error('Signature verification failed.');
        info = result.authenticationInfo;
        if (request.generation !== generation) throw new Error('Test data was reset.');
        key.counter = info.newCounter;
      }
      return { verified: true, kind: request.kind, account: account.name, userVerified: info.userVerified,
        message: request.kind === 'create' ? 'Passkey registered. Try signing in.' : 'Signature verified. Sign-in passed.' };
    }
    throw new Error('Unknown test action.');
  };
}

export async function startPlayground({ port = 8443, directory = join(root, '.playground') } = {}) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const key = join(directory, 'localhost-key.pem'), cert = join(directory, 'localhost-cert.pem');
  try { await access(key); await access(cert); }
  catch {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
      '-days', '30', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
  }
  const routes = new Map([
    ['/login', ['playground/login.html', 'text/html']],
    ['/login.css', ['playground/login.css', 'text/css']],
    ['/login.js', ['playground/login.js', 'text/javascript']],
    ['/', ['playground/index.html', 'text/html']], ['/app.js', ['playground/app.js', 'text/javascript']],
    ['/ui.css', ['lib/ui.css', 'text/css']], ['/playground.css', ['playground/style.css', 'text/css']],
    ['/bolt.svg', ['public/bolt.svg', 'image/svg+xml']],
  ]);
  let origin, api;
  const server = createServer({ key: await readFile(key), cert: await readFile(cert) }, async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'; object-src 'none'");
    const json = (status, value) => { response.writeHead(status, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(value)); };
    if (request.headers.host !== new URL(origin).host) { json(403, { error: 'Use the printed localhost URL.' }); return; }
    try {
      const route = routes.get(request.url);
      if (request.method === 'GET' && route) {
        response.writeHead(200, { 'Content-Type': `${route[1]}; charset=utf-8` });
        response.end(await readFile(join(root, route[0]))); return;
      }
      if (request.method !== 'POST' || request.headers.origin !== origin
        || request.headers['content-type'] !== 'application/json') { json(403, { error: 'Same-origin JSON requests only.' }); return; }
      let length = 0; const chunks = [];
      for await (const chunk of request) {
        length += chunk.length; if (length > 256 * 1024) throw new Error('Test request is too large.'); chunks.push(chunk);
      }
      json(200, await api(request.url, JSON.parse(Buffer.concat(chunks).toString())));
    } catch (error) { if (!response.headersSent) json(400, { error: error.message }); else response.end(); }
  });
  server.requestTimeout = 10_000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  origin = `https://localhost:${server.address().port}`; api = createRelyingParty(origin);
  return { origin, close: () => new Promise(resolve => { server.close(resolve); server.closeIdleConnections(); }) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const app = await startPlayground();
  console.log(`Passkey playground: ${app.origin}\nAccept the local certificate warning in your test browser.\nUses your real extension and vault. Server test accounts live in memory.\nReset does not delete vault items; remove boltwarden-test-* items manually.\nCtrl+C stops the server.`);
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, async () => { await app.close(); process.exit(0); });
}
