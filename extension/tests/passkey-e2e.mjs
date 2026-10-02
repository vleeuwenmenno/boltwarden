// Real Chromium extension, real native messaging, synthetic logins, disposable HOME/profile.
// Requires Node >=22.12 and Chromium; no external automation dependency or personal profile.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { startPlayground } from '../playground/server.mjs';
import { startPasskeyFixture, verifyRegistration, verifyAssertion } from './passkey-fixture.mjs';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const identities = JSON.parse(await readFile(join(root, 'lib/browser-identities.json'), 'utf8'));
const directory = await mkdtemp(join(tmpdir(), 'boltwarden-extension-e2e-'));
const screenshots = process.env.BOLTWARDEN_TEST_SCREENSHOTS;
const home = join(directory, 'home'), profile = join(directory, 'profile');
const log = [];
const fixture = await startPasskeyFixture(directory), site = fixture.origin;
let browser, socket, playground;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(test, label, milliseconds = 15000) {
  const end = Date.now() + milliseconds;
  let last;
  while (Date.now() < end) { try { const result = await test(); if (result) return result; } catch (error) { last = error; } await delay(50); }
  throw new Error(`${label} timed out${last ? `: ${last.message}` : ''}`);
}
function quote(value) { return `'${value.replaceAll("'", "'\\''")}'`; }

try {
  await mkdir(home, { recursive: true }); await mkdir(profile, { recursive: true });
  const launcher = join(directory, 'native-host');
  await writeFile(launcher, `#!/bin/sh\nexec ${quote(process.execPath)} ${quote(join(root, 'tests/native-host.mjs'))} "$@"\n`, { mode: 0o700 });
  const manifest = { name: identities.host_name, description: 'Boltwarden test host', path: launcher, type: 'stdio', allowed_origins: [`chrome-extension://${identities.chrome_id}/`] };
  for (const parent of [join(profile, 'NativeMessagingHosts'), join(home, '.config/chromium/NativeMessagingHosts')]) {
    await mkdir(parent, { recursive: true }); await writeFile(join(parent, `${identities.host_name}.json`), JSON.stringify(manifest));
  }
  const extension = join(root, '.output/chrome-mv3');
  assert(existsSync(join(extension, 'manifest.json')), 'Run npm run build first');
  browser = spawn(process.env.CHROMIUM_BIN ?? 'chromium', [
    '--headless=new', '--ignore-certificate-errors', '--no-sandbox', '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-sync',
    '--password-store=basic', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
    `--disable-extensions-except=${extension}`, `--load-extension=${extension}`, 'about:blank',
  ], { env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, '.config'), BOLTWARDEN_TEST_STATE: join(directory, 'pairing.json') }, stdio: ['ignore', 'ignore', 'pipe'] });
  browser.stderr.on('data', chunk => { if (log.length < 100) log.push(chunk.toString()); });
  browser.on('error', error => { log.push(error.message); });
  const endpoint = await until(async () => {
    if (browser.exitCode !== null) throw new Error(`Chromium exited: ${log.join('').slice(-2000)}`);
    return existsSync(join(profile, 'DevToolsActivePort')) && (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).trim().split('\n');
  }, 'Chromium debugging endpoint');
  socket = new WebSocket(`ws://127.0.0.1:${endpoint[0]}${endpoint[1]}`);
  await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, { once: true }); socket.addEventListener('error', reject, { once: true }); });
  let id = 0;
  const pending = new Map();
  socket.addEventListener('message', ({ data }) => {
    const message = JSON.parse(data); const entry = pending.get(message.id); if (!entry) return;
    pending.delete(message.id); clearTimeout(entry.timer);
    if (message.error) entry.reject(new Error(message.error.message)); else entry.resolve(message.result);
  });
  function send(method, params = {}, sessionId) {
    const requestId = ++id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(requestId); reject(new Error(`CDP ${method} timed out`)); }, 15000);
      pending.set(requestId, { resolve, reject, timer }); socket.send(JSON.stringify({ id: requestId, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }
  async function evaluate(session, expression) {
    const result = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, userGesture: true }, session);
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text);
    return result.result.value;
  }
  const attach = async targetId => (await send('Target.attachToTarget', { targetId, flatten: true })).sessionId;
  const worker = await until(async () => (await send('Target.getTargets')).targetInfos.find(target => target.type === 'service_worker' && target.url.includes(identities.chrome_id)), 'Extension service worker');
  const workerSession = await attach(worker.targetId);
  const website = await send('Target.createTarget', { url: `${site}/single` });
  const websiteSession = await attach(website.targetId);
  await send('Target.activateTarget', { targetId: website.targetId });
  await until(() => evaluate(websiteSession, 'document.readyState === "complete"'), 'Website load');
  // Give document_start/idle extension contexts an opportunity to connect.
  await delay(100);
  async function popup() {
    await send('Target.activateTarget', { targetId: website.targetId });
    await evaluate(workerSession, 'chrome.action.openPopup()');
    const target = await until(async () => (await send('Target.getTargets')).targetInfos.find(target => target.url === `chrome-extension://${identities.chrome_id}/popup.html`), 'Extension popup');
    return { target, session: await attach(target.targetId) };
  }
  const text = session => evaluate(session, 'document.body.innerText');
  async function click(session, label) {
    // Wait for asynchronous fingerprint loading, not just the button label.
    await until(() => evaluate(session, `(() => { const button = [...document.querySelectorAll('button')].find(button => button.textContent.includes(${JSON.stringify(label)})); return Boolean(button && !button.disabled); })()`), `Enabled ${label} button`);
    await evaluate(session, `(() => { const button = [...document.querySelectorAll('button')].find(button => button.textContent.includes(${JSON.stringify(label)})); if (!button || button.disabled) throw Error('Button not ready'); button.click(); })()`);
  }
  async function screenshot(session, name, captureBeyondViewport = true) {
    if (!screenshots) return;
    await mkdir(screenshots, { recursive: true });
    const { data } = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport }, session);
    await writeFile(join(screenshots, `${name}.png`), Buffer.from(data, 'base64'));
  }
  async function key(session, value) {
    const code = value === 'Enter' ? 13 : value === 'Escape' ? 27 : undefined;
    await send('Input.dispatchKeyEvent', { type: 'keyDown', key: value, code: value,
      windowsVirtualKeyCode: code, nativeVirtualKeyCode: code,
      ...(value === 'Enter' ? { text: '\r', unmodifiedText: '\r' } : {}) }, session);
    await send('Input.dispatchKeyEvent', { type: 'keyUp', key: value, code: value,
      windowsVirtualKeyCode: code, nativeVirtualKeyCode: code }, session);
  }
  const panel = await popup();
  await until(async () => (await text(panel.session)).includes('Pair with Boltwarden'), 'Pairing UI');
  await click(panel.session, 'Pair with Boltwarden');
  await until(() => existsSync(join(directory, 'pairing.json')), 'Signed pairing proof');
  await until(async () => !(await text(panel.session)).includes('Pair with Boltwarden'), 'Paired UI');
  await send('Target.closeTarget', { targetId: panel.target.targetId });
  await send('Target.activateTarget', { targetId: website.targetId });
  await send('WebAuthn.enable', {}, websiteSession);
  await send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal',
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } }, websiteSession);
  async function navigate(path) {
    await send('Page.navigate', { url: `${site}${path}` }, websiteSession);
    await until(() => evaluate(websiteSession, `location.pathname === ${JSON.stringify(path)} && !!window.passkeyFixture`), 'Fixture navigation');
    await delay(100);
  }
  const logs = async () => (await readFile(join(directory, 'pairing.json.log'), 'utf8')).trim().split('\n').map(JSON.parse);
  const calls = async type => (await logs()).filter(message => message.type === type).length;
  await navigate('/cards');
  await evaluate(websiteSession, 'document.querySelector("[name=card_number]").focus()');
  const cardPanel = await popup();
  await until(async () => (await text(cardPanel.session)).includes('Test Visa'), 'Masked card picker');
  assert(!(await text(cardPanel.session)).includes('4111111111111111'));
  await click(cardPanel.session, 'Test Visa');
  await until(() => evaluate(websiteSession, 'document.querySelector("[name=card_number]").value === "4111111111111111"'), 'Card number filled');
  assert.equal(await evaluate(websiteSession, 'document.querySelector("[name=cvv]").value'), '123');
  assert.equal(await evaluate(websiteSession, 'document.querySelector("[name=expiration_month]").value'), '3');
  assert.equal(await evaluate(websiteSession, '!!window.cardSubmitted'), false);
  await send('Target.closeTarget', {targetId:cardPanel.target.targetId});
  await navigate('/');
  const registration = await evaluate(websiteSession, 'passkeyFixture.create()');
  verifyRegistration(registration, site);
  assert.equal(await calls('PasskeyCreate'), 1, 'Creation must use native bridge');
  const assertion = await evaluate(websiteSession, 'passkeyFixture.get()');
  verifyAssertion(assertion, registration, site);
  const legacyOptionsAssertion = await evaluate(websiteSession, 'passkeyFixture.get({ hints: ["security-key", "hybrid"], extensions: { appid: "https://www.gstatic.com/securitykey/origins.json" } })');
  verifyAssertion(legacyOptionsAssertion, registration, site);
  assert.deepEqual(legacyOptionsAssertion.extensions, {}, 'RP-scoped passkeys must not claim use of the legacy AppID');
  verifyAssertion(await evaluate(websiteSession, 'passkeyFixture.getCrossRealm()'), registration, site);
  assert.equal(await calls('PasskeyGet'), 3, 'Plain, cross-realm and legacy-option assertions must use native bridge');

  await navigate('/early-passkey');
  const early = await evaluate(websiteSession, 'earlyAssertion');
  verifyAssertion(early, registration, site);
  assert.notEqual(await evaluate(websiteSession, 'document.readyState'), 'complete', 'Passkey must work before slow subresources finish loading');
  await navigate('/');

  await writeFile(join(directory, 'pairing.json.control'), JSON.stringify({ unlocked: false, epoch: 2 }));
  await delay(200);
  verifyAssertion(await evaluate(websiteSession, 'passkeyFixture.get()'), registration, site);
  assert((await calls('RequestUnlock')) > 0, 'Locked paired vault must request desktop unlock');

  await navigate('/deny');
  assert.equal(await evaluate(websiteSession, 'passkeyFixture.get().then(() => "unexpected", error => error.name)'), 'NotAllowedError');
  await navigate('/fallback');
  const beforeFallback = await calls('PasskeyCreate');
  const fallback = await evaluate(websiteSession, 'passkeyFixture.create()');
  assert.notEqual(fallback.json.id, registration.json.id, 'Explicit other-device fallback must use browser authenticator');
  assert.equal(await calls('PasskeyCreate'), beforeFallback + 1);

  await navigate('/unsupported');
  const beforeUnsupported = await calls('PasskeyCreate');
  const unsupported = await evaluate(websiteSession, 'passkeyFixture.create({ attestation: "direct" })');
  assert(unsupported.credentialPrototype); assert.equal(await calls('PasskeyCreate'), beforeUnsupported, 'Unsupported attestation must remain native');

  await navigate('/iframe-parent');
  const beforeFrame = await calls('PasskeyCreate');
  const framed = await evaluate(websiteSession, `new Promise((resolve, reject) => {
    const frame = document.createElement('iframe'); frame.src = '/iframe-child';
    frame.onload = () => frame.contentWindow.passkeyFixture.create().then(resolve, reject); document.body.append(frame);
  })`);
  assert.notEqual(framed.json.id, registration.json.id); assert.equal(await calls('PasskeyCreate'), beforeFrame, 'Iframe passkeys remain native');

  await navigate('/policy-denied');
  const beforePolicy = await calls('PasskeyGet');
  assert.equal(await evaluate(websiteSession, 'passkeyFixture.get().then(() => "unexpected", error => error.name)'), 'NotAllowedError');
  assert.equal(await calls('PasskeyGet'), beforePolicy, 'Permissions-Policy denial must not reach desktop');

  await navigate('/slow');
  const beforeSlow = await calls('PasskeyGet');
  await evaluate(websiteSession, 'passkeyFixture.startGet()');
  await until(async () => await calls('PasskeyGet') > beforeSlow, 'Pending assertion');
  await evaluate(websiteSession, 'passkeyFixture.abort()');
  assert.equal((await evaluate(websiteSession, 'window.passkeyPending')).error, 'AbortError');
  await until(async () => await calls('Cancel') > 0, 'Native cancellation');
  await delay(100);
  await evaluate(websiteSession, 'passkeyFixture.startGet()');
  await until(async () => await calls('PasskeyGet') > beforeSlow + 1, 'Second pending assertion');
  await evaluate(websiteSession, 'history.pushState({}, "", "/replacement")');
  assert.equal((await evaluate(websiteSession, 'window.passkeyPending')).error, 'AbortError');
  await navigate('/slow');
  const cancellations = await calls('Cancel');
  assert.equal(await evaluate(websiteSession, 'passkeyFixture.get({ timeout: 1200 }).then(() => "unexpected", error => error.name)'), 'NotAllowedError');
  await until(async () => await calls('Cancel') > cancellations, 'Deadline cancellation');
  playground = await startPlayground({port: 0, directory: join(directory, 'playground')});
  await send('Page.navigate', {url: playground.origin}, websiteSession);
  await until(() => evaluate(websiteSession, 'document.readyState === "complete" && !!document.getElementById("create")'), 'Playground load');
  for (const [button, message, type] of [['create', 'Passkey registered', 'PasskeyCreate'], ['get', 'Signature verified', 'PasskeyGet'], ['discover', 'Signature verified', 'PasskeyGet']]) {
    const before = await calls(type);
    await evaluate(websiteSession, `document.getElementById('challenge').value = '65536'; document.getElementById('${button}').click()`);
    await until(() => evaluate(websiteSession, `document.getElementById('status').dataset.state === 'success' && document.getElementById('status').textContent.includes('${message}') && !document.getElementById('${button}').disabled`), `Playground ${button}`);
    assert.equal(await calls(type), before + 1, 'Playground must use extension, not virtual browser fallback');
  }
  const savesBeforeSuggestion = await calls('SaveLogin');
  await evaluate(websiteSession, "document.getElementById('test-password').scrollIntoView({block:'center'}); document.getElementById('test-password').focus()");
  await evaluate(websiteSession, 'new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
  await key(websiteSession, 'ArrowDown');
  await screenshot(websiteSession, 'password-suggestion', false);
  async function clickGenerator(label) {
    const { root } = await send('DOM.getDocument', { depth: -1, pierce: true }, websiteSession);
    const walk = node => [node, ...(node.children ?? []).flatMap(walk), ...(node.shadowRoots ?? []).flatMap(walk)];
    const button = walk(root).find(node => label === 'Length' ? node.nodeName === 'INPUT' && node.attributes?.includes('length') : node.nodeName === 'BUTTON' && walk(node).some(child => child.nodeValue === label));
    assert.ok(button, `Generator button: ${label}`);
    await send('DOM.scrollIntoViewIfNeeded', { nodeId: button.nodeId }, websiteSession);
    const { model } = await send('DOM.getBoxModel', { nodeId: button.nodeId }, websiteSession);
    const x = (model.content[0] + model.content[4]) / 2, y = (model.content[1] + model.content[5]) / 2;
    await send('Input.dispatchMouseEvent', { type: 'mousePressed', x, y, button: 'left', clickCount: 1 }, websiteSession);
    await send('Input.dispatchMouseEvent', { type: 'mouseReleased', x, y, button: 'left', clickCount: 1 }, websiteSession);
    await delay(100);
  }
  await clickGenerator('Length');
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'a', code: 'KeyA', windowsVirtualKeyCode: 65, modifiers: 2 }, websiteSession);
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'a', code: 'KeyA', windowsVirtualKeyCode: 65, modifiers: 2 }, websiteSession);
  await send('Input.insertText', { text: '18' }, websiteSession);
  await clickGenerator('Generate another');
  await clickGenerator('Use suggested password');
  assert.equal(await evaluate(websiteSession, "document.getElementById('test-password').value.length === 18 && document.getElementById('test-password').value === document.getElementById('confirm-password').value"), true);
  await delay(150);
  assert.equal(await calls('SaveLogin'), savesBeforeSuggestion, 'Generating and filling must never save');
  await evaluate(websiteSession, "document.getElementById('confirm-password').value = 'mismatch'; document.getElementById('confirm-password').dispatchEvent(new Event('input', {bubbles:true}))");
  await key(websiteSession, 'Enter'); await delay(150);
  assert.equal(await calls('SaveLogin'), savesBeforeSuggestion, 'Mismatched confirmation must not submit or save');
  for (const [action, password, oldPassword] of [['register', 'test-original', ''], ['change', 'test-updated', 'test-original'], ['login', 'test-updated', '']]) {
    const before = await calls('SaveLogin');
    const unlocksBefore = await calls('RequestUnlock');
    if (action === 'register') {
      await writeFile(join(directory, 'pairing.json.control'), JSON.stringify({ unlocked: false, epoch: 100 }));
      await delay(300);
    }
    await evaluate(websiteSession, `(() => {
      document.getElementById('password-action').value = '${action}'; document.getElementById('password-action').onchange();
      document.getElementById('test-password').value = '${password}'; document.getElementById('confirm-password').value = '${password}'; document.getElementById('old-password').value = '${oldPassword}';
      document.getElementById('confirm-password').dispatchEvent(new Event('input', {bubbles:true}));
      document.getElementById('test-password').scrollIntoView({block: 'center'}); document.getElementById('test-password').focus();
    })()`);
    await key(websiteSession, 'Enter');
    await until(async () => await calls('SaveLogin') === before + 1, `Password ${action} captured`);
    await until(() => evaluate(websiteSession, "document.getElementById('password-status').dataset.state === 'success' && document.getElementById('test-password').value === ''"), `Password ${action} server check`);
    const captured = (await logs()).filter(message => message.type === 'SaveLogin').at(-1);
    if (action === 'register') assert.equal(await calls('RequestUnlock'), unlocksBefore + 1, 'Locked submission must request unlock before saving');
    assert.equal(captured.login_digest, createHash('sha256').update(JSON.stringify({username: 'boltwarden-test-alice', password})).digest('hex'));
  }
  await evaluate(websiteSession, `(() => {
    document.getElementById('password-action').value = 'change'; document.getElementById('password-action').onchange();
    document.getElementById('test-password').value = 'new-sentinel'; document.getElementById('confirm-password').value = 'new-sentinel';
    document.getElementById('old-password').scrollIntoView({block:'center'}); document.getElementById('old-password').focus();
  })()`);
  await evaluate(websiteSession, 'new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
  const lookupsBeforeCurrent = await calls('ListMatches');
  await key(websiteSession, 'ArrowDown');
  await until(async () => await calls('ListMatches') > lookupsBeforeCurrent, 'Current password inline lookup');
  await delay(200); await key(websiteSession, 'Enter');
  await until(() => evaluate(websiteSession, "document.getElementById('old-password').value === 'test-password-only'"), 'Current password inline fill');
  assert.equal(await evaluate(websiteSession, "document.getElementById('test-password').value === 'new-sentinel' && document.getElementById('confirm-password').value === 'new-sentinel' && document.getElementById('test-username').value === 'boltwarden-test-alice'"), true);
  console.log('Playground password registration, change and login submissions reached the native bridge with the expected new password.');
  await screenshot(websiteSession, 'passkey-playground');
  console.log('Local playground passed: registration, sign-in and account discovery verified independently with 64 KiB challenges.');
  console.log('Chromium passkey proof passed: signed pairing, ES256 create/get, prototypes/methods/JSON, independent signature, unlock, denial without fallback, explicit native fallback, unsupported attestation, iframe delegation, policy denial, AbortSignal, deadline and SPA cancellation.');
} catch (error) {
  console.error(log.join('').slice(-3000)); throw error;
} finally {
  socket?.close(); browser?.kill('SIGTERM');
  if (browser && browser.exitCode === null) await Promise.race([new Promise(resolve => browser.once('exit', resolve)), delay(3000)]);
  if (browser && browser.exitCode === null) browser.kill('SIGKILL');
  await playground?.close();
  await fixture.close();
  if (process.env.BOLTWARDEN_KEEP_TEST_PROFILE) console.log(`Preserved test profile: ${directory}`);
  else await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
