// Disposable-profile browser-test host. Never installed by the application.
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash, createPrivateKey, generateKeyPairSync, randomBytes, randomUUID, sign, verify } from 'node:crypto';

const stateFile = process.env.BOLTWARDEN_TEST_STATE;
if (!stateFile) throw new Error('BOLTWARDEN_TEST_STATE is required');
let pairing = existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, 'utf8')) : null;
let challenge, authenticated = false, input = Buffer.alloc(0);
let unlocked = true, epoch = 1;
let passkey = existsSync(`${stateFile}.passkey`) ? JSON.parse(readFileSync(`${stateFile}.passkey`, 'utf8')) : null;
const pending = new Map();
function send(message) {
  const data = Buffer.from(JSON.stringify({ version: 1, ...message }));
  const header = Buffer.alloc(4); header.writeUInt32LE(data.length);
  process.stdout.write(Buffer.concat([header, data]));
}
function proof(message, spki) {
  if (!challenge || message.host_pid !== process.pid || message.pairing_id !== challenge.pairing_id) return false;
  const bytes = Buffer.from(`boltwarden-browser-v1\n${challenge.nonce}\n${message.pairing_id}\n${process.pid}`);
  challenge = null;
  return verify('sha256', bytes, { key: Buffer.from(spki, 'base64url'), format: 'der', type: 'spki', dsaEncoding: 'ieee-p1363' }, Buffer.from(message.sig, 'base64url'));
}
function changeLock(nextUnlocked, nextEpoch) {
  unlocked = nextUnlocked; epoch = nextEpoch;
  if (!unlocked) { for (const timer of pending.values()) clearTimeout(timer); pending.clear(); }
  if (authenticated) send({ type: unlocked ? 'Unlocked' : 'Locked', epoch });
}
// Only the disposable test runner owns this file; it simulates desktop lifecycle events.
setInterval(() => {
  try {
    const control = JSON.parse(readFileSync(`${stateFile}.control`, 'utf8'));
    if (Number.isInteger(control.epoch) && control.epoch > epoch) changeLock(control.unlocked === true, control.epoch);
  } catch { /* no test control event */ }
}, 40);
function cbor(value) {
  function head(major, length) {
    if (length < 24) return Buffer.from([(major << 5) | length]);
    if (length < 256) return Buffer.from([(major << 5) | 24, length]);
    const bytes = Buffer.alloc(3); bytes[0] = (major << 5) | 25; bytes.writeUInt16BE(length, 1); return bytes;
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (typeof value === 'string') { const bytes = Buffer.from(value); return Buffer.concat([head(3, bytes.length), bytes]); }
  if (typeof value === 'number') return head(value >= 0 ? 0 : 1, value >= 0 ? value : -1 - value);
  if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([key, child]) => [cbor(key), cbor(child)])]);
  throw new Error('Unsupported fixture CBOR');
}
function receive(message) {
  appendFileSync(`${stateFile}.log`, `${JSON.stringify({ type: message.type, frame_url: message.frame_url, document_id: message.document_id, ...(message.type === 'SaveLogin' ? {login_digest: createHash('sha256').update(JSON.stringify(message.login)).digest('hex')} : {}) })}\n`);
  const reply = payload => send({ id: message.id, ...payload });
  if (message.type === 'Hello') {
    challenge = { nonce: randomBytes(32).toString('base64url'), pairing_id: message.pairing_id ?? randomUUID() };
    reply({ type: 'Challenge', ...challenge, paired: pairing?.id === challenge.pairing_id }); return;
  }
  if (message.type === 'RequestPairing') {
    if (!proof(message, message.public_key_spki)) throw new Error('Invalid pairing proof');
    pairing = { id: message.pairing_id, spki: message.public_key_spki }; writeFileSync(stateFile, JSON.stringify(pairing));
    authenticated = true; reply({ type: 'Paired', pairing_id: pairing.id }); return;
  }
  if (message.type === 'Authenticate') {
    if (!pairing || !proof(message, pairing.spki)) throw new Error('Invalid authentication proof');
    authenticated = true; reply({ type: 'Authenticated', pairing_id: pairing.id }); return;
  }
  if (!authenticated) { reply({ type: 'Error', code: 'Unauthorized', message: 'Pair first' }); return; }
  if (message.type === 'Status') { reply({ type: 'Status', enabled: true, unlocked, epoch }); return; }
  if (message.type === 'RequestUnlock') {
    reply({ type: 'UnlockRequested' });
    setTimeout(() => changeLock(true, epoch + 1), 120); return;
  }
  if (!unlocked && ['ListCards', 'FillCard', 'ListMatches', 'ListTotpMatches', 'FillLogin', 'FillTotp', 'SaveLogin', 'PasskeyGet', 'PasskeyCreate'].includes(message.type)) { reply({ type: 'Error', code: 'Locked', message: 'Vault locked' }); return; }
  if (message.type === 'ListCards') {
    reply({type:'Matches',items:[{id:'card',name:'Test Visa',username:'Visa •••• 1111',reprompt:false,requires_confirmation:false,revision:'1'}],epoch,next_offset:null}); return;
  }
  if (message.type === 'FillCard') {
    reply({type:'Card',card:{cardholder:'Alice Example',number:'4111111111111111',code:'123',exp_month:'3',exp_year:'2030',brand:'Visa'},document_id:message.document_id,epoch}); return;
  }
  if (message.type === 'ListMatches' || message.type === 'ListTotpMatches') {
    const item = { id: 'one', name: 'Test login', username: 'alice', reprompt: false, requires_confirmation: message.frame_url.includes('/insecure'), revision: '1' };
    reply({ type: 'Matches', items: message.frame_url.includes('/multiple') ? [item, { ...item, id: 'two', name: 'Other login', username: 'bob' }] : [item], epoch, next_offset: null, warning: null }); return;
  }
  if (message.type === 'Cancel') { clearTimeout(pending.get(message.request_id)); pending.delete(message.request_id); reply({ type: 'Cancelled', request_id: message.request_id }); return; }
  if (message.type === 'SaveLogin') { reply({type: 'LoginSaved', saved: true}); return; }
  if (message.type === 'FillTotp') {
    reply({ type: 'Totp', code: '012345', expires_at: Math.floor(Date.now() / 1000) + 30, document_id: message.document_id, epoch }); return;
  }
  if (message.type === 'FillLogin') {
    const respond = () => { pending.delete(message.id); reply({ type: 'Credentials', username: message.item_id === 'two' ? 'bob' : 'alice', password: 'test-password-only', document_id: message.document_id, epoch }); };
    if (message.frame_url.includes('/slow')) pending.set(message.id, setTimeout(respond, 800)); else respond();
    return;
  }
  if (message.type === 'PasskeyGet' || message.type === 'PasskeyCreate') {
    if (message.frame_url.includes('/deny')) { reply({ type: 'Error', code: 'NotAllowedError', message: 'User declined' }); return; }
    if (message.frame_url.includes('/fallback')) { reply({ type: 'Error', code: 'FallbackRequested', message: 'Other device selected' }); return; }
    const respond = () => {
      pending.delete(message.id);
      const create = message.type === 'PasskeyCreate';
      if (create) {
        const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        passkey = { id: randomBytes(32).toString('base64url'), private: keys.privateKey.export({ format: 'jwk' }),
          public: keys.publicKey.export({ format: 'jwk' }), spki: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
          user: message.options.user.id };
        writeFileSync(`${stateFile}.passkey`, JSON.stringify(passkey));
      }
      if (!passkey) { reply({ type: 'Error', code: 'Unavailable', message: 'No synthetic passkey' }); return; }
      const client = Buffer.from(JSON.stringify({ type: create ? 'webauthn.create' : 'webauthn.get', challenge: message.options.challenge,
        origin: new URL(message.frame_url).origin, crossOrigin: false }));
      let data = Buffer.concat([createHash('sha256').update('localhost').digest(), Buffer.from([create ? 0x45 : 0x05, 0, 0, 0, 0])]);
      const result = { type: 'PasskeyResult', kind: create ? 'create' : 'get', credential_id: passkey.id,
        client_data_json: client.toString('base64url'), document_id: message.document_id, epoch };
      if (create) {
        const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(passkey.public.x, 'base64url')], [-3, Buffer.from(passkey.public.y, 'base64url')]]));
        const id = Buffer.from(passkey.id, 'base64url'), length = Buffer.alloc(2); length.writeUInt16BE(id.length);
        data = Buffer.concat([data, Buffer.alloc(16), length, id, cose]);
        Object.assign(result, { attestation_object: cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', data]])).toString('base64url'),
          public_key: passkey.spki, public_key_algorithm: -7, transports: ['internal'], ...(message.options.cred_props ? { cred_props: true } : {}) });
        send({ type: 'MatchesChanged', epoch });
      } else Object.assign(result, { signature: sign('sha256', Buffer.concat([data, createHash('sha256').update(client).digest()]),
        createPrivateKey({ key: passkey.private, format: 'jwk' })).toString('base64url'), user_handle: passkey.user });
      result.authenticator_data = data.toString('base64url'); reply(result);
    };
    if (message.frame_url.includes('/slow')) pending.set(message.id, setTimeout(respond, 1800)); else respond();
    return;
  }
  reply({ type: 'Error', code: 'InvalidRequest', message: 'Unknown test request' });
}
send({ type: 'HostContext', host_pid: process.pid });
process.stdin.on('data', chunk => {
  input = Buffer.concat([input, chunk]);
  while (input.length >= 4) {
    const length = input.readUInt32LE(0);
    if (length > 256 * 1024) process.exit(2);
    if (input.length < length + 4) return;
    const frame = input.subarray(4, length + 4); input = input.subarray(length + 4);
    try { receive(JSON.parse(frame.toString('utf8'))); }
    catch (error) { process.stderr.write(`${error.message}\n`); process.exit(2); }
  }
});
process.stdin.on('end', () => process.exit());
