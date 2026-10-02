// Real Chromium extension, real native messaging, synthetic logins, disposable HOME/profile.
// Requires Node >=22.12 and Chromium; no external automation dependency or personal profile.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
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
const log = [], fixture = '<!doctype html><html><head><title>Boltwarden fixture</title></head><body><form><label>User <input id="username" autocomplete="username"></label><label>Password <input id="password" type="password" autocomplete="current-password"></label><button>Sign in</button></form></body></html>';
const server = createServer((_request, response) => { response.writeHead(200, { 'Content-Type': 'text/html' }); response.end(fixture); });
await new Promise((resolve, reject) => { server.on('error', reject); server.listen(0, '127.0.0.1', resolve); });
const site = `http://127.0.0.1:${server.address().port}`;
let browser, socket;
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
    '--headless=new', '--no-sandbox', '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-sync',
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
    // CDP can expose the worker target before extension APIs are initialized.
    await until(() => evaluate(workerSession, 'typeof chrome !== "undefined" && typeof chrome.action?.openPopup === "function"'), 'Extension action API');
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
  async function screenshot(session, name) {
    if (!screenshots) return;
    await mkdir(screenshots, { recursive: true });
    const { data } = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }, session);
    await writeFile(join(screenshots, `${name}.png`), Buffer.from(data, 'base64'));
  }
  async function key(session, value) {
    // Synchronize the popup target before native button keyboard activation.
    await send('Page.bringToFront', {}, session);
    await evaluate(session, 'new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve(true))))');
    const code = value === 'Enter' ? 13 : value === 'Escape' ? 27 : undefined;
    await send('Input.dispatchKeyEvent', { type: 'keyDown', key: value, code: value,
      windowsVirtualKeyCode: code, nativeVirtualKeyCode: code,
      ...(value === 'Enter' ? { text: '\r', unmodifiedText: '\r' } : {}) }, session);
    await send('Input.dispatchKeyEvent', { type: 'keyUp', key: value, code: value,
      windowsVirtualKeyCode: code, nativeVirtualKeyCode: code }, session);
  }
  let panel = await popup();
  await until(async () => (await text(panel.session)).includes('Pair with Boltwarden'), 'Pairing button');
  await screenshot(panel.session, 'pairing');
  await click(panel.session, 'Pair with Boltwarden');
  await until(async () => (await text(panel.session)).includes('Test login'), 'Paired match list');
  assert(existsSync(join(directory, 'pairing.json')), 'Native host verified pairing proof');
  await screenshot(panel.session, 'ready');
  await writeFile(join(directory, 'pairing.json.control'), JSON.stringify({ unlocked: false, epoch: 2 }));
  await until(async () => (await text(panel.session)).includes('Vault locked'), 'Live lock state');
  assert(!(await text(panel.session)).includes('Test login'), 'Lock must remove visible login names');
  assert(!(await text(panel.session)).includes('alice'), 'Lock must remove visible usernames');
  await screenshot(panel.session, 'locked');
  await click(panel.session, 'Unlock');
  await until(async () => (await text(panel.session)).includes('Test login'), 'Automatic matches after desktop unlock');
  await click(panel.session, 'Test login');
  await until(async () => await evaluate(websiteSession, 'document.querySelector("#password").value') === 'test-password-only', 'Password fill');
  assert.equal(await evaluate(websiteSession, 'document.querySelector("#username").value'), 'alice');
  await send('Target.closeTarget', { targetId: panel.target.targetId });

  await send('Page.navigate', { url: `${site}/multiple` }, websiteSession);
  await until(() => evaluate(websiteSession, 'location.pathname === "/multiple" && document.readyState === "complete"'), 'Multiple-match page');
  await delay(100); panel = await popup();
  await until(async () => (await text(panel.session)).includes('Other login'), 'Multiple-match picker');
  assert.equal(await evaluate(websiteSession, 'document.querySelector("#password").value'), '');
  await screenshot(panel.session, 'multiple');
  await evaluate(panel.session, `(() => { const field = document.querySelector('input[type="search"]'); if (!field) throw Error('Search not found'); field.focus(); field.value = 'bob'; field.dispatchEvent(new Event('input', { bubbles: true })); })()`);
  await until(async () => (await text(panel.session)).includes('Other login') && !(await text(panel.session)).includes('Test login'), 'Local match filtering');
  await screenshot(panel.session, 'filtered');
  await key(panel.session, 'Enter');
  await until(async () => await evaluate(websiteSession, 'document.querySelector("#username").value') === 'bob', 'Selected account fill');
  await send('Target.closeTarget', { targetId: panel.target.targetId });

  await send('Page.navigate', { url: `${site}/insecure` }, websiteSession);
  await until(() => evaluate(websiteSession, 'location.pathname === "/insecure" && document.readyState === "complete"'), 'Insecure confirmation page');
  await delay(100); panel = await popup();
  await until(async () => (await text(panel.session)).includes('Test login'), 'Insecure match list');
  await click(panel.session, 'Test login');
  await until(() => evaluate(panel.session, 'document.querySelector("[role=alertdialog]") !== null'), 'Confirmation dialog');
  assert((await evaluate(panel.session, 'document.activeElement.textContent')).includes('Cancel'), 'Risk confirmation must initially focus Cancel');
  await screenshot(panel.session, 'confirmation');
  await key(panel.session, 'Enter');
  await until(() => evaluate(panel.session, 'document.querySelector("[role=alertdialog]") === null'), 'Cancel confirmation with Enter');
  assert.equal(await evaluate(websiteSession, 'document.querySelector("#password").value'), '', 'Cancel must not fill');
  await click(panel.session, 'Test login');
  await until(() => evaluate(panel.session, 'document.querySelector("[role=alertdialog]") !== null'), 'Reopened confirmation');
  await click(panel.session, 'Confirm and fill');
  await until(async () => await evaluate(websiteSession, 'document.querySelector("#password").value') === 'test-password-only', 'Explicitly confirmed fill');
  await send('Target.closeTarget', { targetId: panel.target.targetId });

  await send('Page.navigate', { url: `${site}/slow` }, websiteSession);
  await until(() => evaluate(websiteSession, 'location.pathname === "/slow" && document.readyState === "complete"'), 'Delayed-fill page');
  await delay(100); panel = await popup();
  await until(async () => (await text(panel.session)).includes('Test login'), 'Delayed match list');
  await click(panel.session, 'Test login');
  await delay(100);
  await send('Page.navigate', { url: `${site}/replacement` }, websiteSession);
  await until(() => evaluate(websiteSession, 'location.pathname === "/replacement" && document.readyState === "complete"'), 'Replacement document');
  await delay(1000);
  assert.equal(await evaluate(websiteSession, 'document.querySelector("#password").value'), '', 'Navigation must cancel delayed fills');
  const messages = (await readFile(join(directory, 'pairing.json.log'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert(messages.some(message => message.type === 'Cancel'), 'Navigation should cancel the native operation');
  const optionsTarget = await send('Target.createTarget', { url: `chrome-extension://${identities.chrome_id}/options.html` });
  const optionsSession = await attach(optionsTarget.targetId);
  await until(async () => (await text(optionsSession)).includes('This browser is paired'), 'Connection settings');
  await screenshot(optionsSession, 'options');
  console.log('Chromium e2e passed: real pairing proof, live lock/unlock, popup fill, search/keyboard picker, explicit risk confirmation, same-origin navigation cancellation.');
} catch (error) {
  console.error(log.join('').slice(-3000)); throw error;
} finally {
  socket?.close(); browser?.kill('SIGTERM');
  if (browser && browser.exitCode === null) await Promise.race([new Promise(resolve => browser.once('exit', resolve)), delay(3000)]);
  if (browser && browser.exitCode === null) browser.kill('SIGKILL');
  await new Promise(resolve => server.close(resolve));
  await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
