// Disposable Firefox profile, real WebExtension/native messaging, synthetic keys only.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer, createConnection } from 'node:net';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startPasskeyFixture, verifyRegistration, verifyAssertion } from './passkey-fixture.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const identities = JSON.parse(await readFile(join(root, 'lib/browser-identities.json'), 'utf8'));
const directory = await mkdtemp(join(tmpdir(), 'boltwarden-passkey-firefox-'));
const home = join(directory, 'home'), profile = join(directory, 'profile');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(test, label, milliseconds = 15000) {
  const end = Date.now() + milliseconds; let last;
  while (Date.now() < end) {
    try { const result = await test(); if (result) return result; } catch (error) { last = error; }
    await delay(50);
  }
  throw new Error(`${label} timed out${last ? `: ${last.message}` : ''}`);
}
const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
let browser, socket, fixture, logs = '';
const pending = new Map();
try {
  await mkdir(home, { recursive: true }); await mkdir(profile, { recursive: true });
  fixture = await startPasskeyFixture(directory);
  const listener = createServer();
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = listener.address().port; await new Promise(resolve => listener.close(resolve));
  await writeFile(join(profile, 'user.js'), [
    `user_pref("marionette.port", ${port});`,
    'user_pref("browser.shell.checkDefaultBrowser", false);',
    'user_pref("browser.startup.homepage_override.mstone", "ignore");',
    'user_pref("app.normandy.enabled", false);',
    'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
  ].join('\n'));
  const launcher = join(directory, 'native-host');
  await writeFile(launcher, `#!/bin/sh\nexec ${quote(process.execPath)} ${quote(join(root, 'tests/native-host.mjs'))} "$@"\n`, { mode: 0o700 });
  const manifestPath = join(home, '.mozilla/native-messaging-hosts'); await mkdir(manifestPath, { recursive: true });
  await writeFile(join(manifestPath, `${identities.host_name}.json`), JSON.stringify({
    name: identities.host_name, description: 'Boltwarden synthetic test host', path: launcher, type: 'stdio', allowed_extensions: [identities.firefox_id],
  }));
  const extension = join(root, '.output/firefox-mv3');
  assert(existsSync(join(extension, 'manifest.json')), 'Run npm run build first');
  browser = spawn(process.env.FIREFOX_BIN ?? 'firefox', [
    '--headless', '--no-remote', '--profile', profile, '--marionette', '--remote-allow-system-access', 'about:blank',
  ], { env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, '.config'), BOLTWARDEN_TEST_STATE: join(directory, 'pairing.json') }, stdio: ['ignore', 'ignore', 'pipe'] });
  browser.stderr.on('data', chunk => { if (logs.length < 20000) logs += chunk; });
  browser.on('error', error => { logs += error.message; });
  socket = await until(() => new Promise((resolve, reject) => {
    if (browser.exitCode !== null) { reject(new Error(logs)); return; }
    const connection = createConnection({ host: '127.0.0.1', port });
    connection.once('connect', () => resolve(connection)); connection.once('error', reject);
  }), 'Firefox Marionette endpoint');
  let input = Buffer.alloc(0), serial = 0;
  socket.on('data', chunk => {
    input = Buffer.concat([input, chunk]);
    for (;;) {
      const colon = input.indexOf(58); if (colon < 0) return;
      const length = Number(input.subarray(0, colon)); if (input.length < colon + 1 + length) return;
      const message = JSON.parse(input.subarray(colon + 1, colon + 1 + length)); input = input.subarray(colon + 1 + length);
      if (!Array.isArray(message)) continue;
      const entry = pending.get(message[1]); if (!entry) continue;
      pending.delete(message[1]); clearTimeout(entry.timer);
      if (message[2]) entry.reject(new Error(`${message[2].error}: ${message[2].message}`)); else entry.resolve(message[3]);
    }
  });
  function send(method, params = {}) {
    const id = ++serial;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timed out`)); }, 20000);
      pending.set(id, { resolve, reject, timer }); const data = JSON.stringify([0, id, method, params]);
      socket.write(`${Buffer.byteLength(data)}:${data}`);
    });
  }
  async function evaluate(expression) {
    // Keep page promises in the page while Marionette polls their serialized
    // result. ExecuteAsyncScript can report a bare null when Firefox's native
    // authenticator prompt opens; polling exposes the actual fallback or error.
    const slot = `__boltwardenTestResult${++serial}`;
    await send('WebDriver:ExecuteScript', {
      script: `window[${JSON.stringify(slot)}] = {done:false}; Promise.resolve().then(() => (${expression})).then(value => { window[${JSON.stringify(slot)}] = {done:true,ok:true,value}; }, error => { window[${JSON.stringify(slot)}] = {done:true,ok:false,name:error.name,error:error.message}; }); return true;`,
      args: [], newSandbox: false, sandbox: null,
    });
    const value = await until(async () => {
      const result = await send('WebDriver:ExecuteScript', {
        script: `return window[${JSON.stringify(slot)}] || null;`, args: [], newSandbox: false, sandbox: null,
      });
      return result.value?.done ? result.value : null;
    }, `Firefox page operation ${expression}`);
    await send('WebDriver:ExecuteScript', {
      script: `delete window[${JSON.stringify(slot)}];`, args: [], newSandbox: false, sandbox: null,
    });
    if (!value.ok) throw new Error(`${value.name}: ${value.error}`);
    return value.value;
  }
  const session = await send('WebDriver:NewSession', { acceptInsecureCerts: true });
  await send('Addon:Install', { path: extension, temporary: true });
  await send('Marionette:SetContext', { value: 'chrome' });
  const { value: hostname } = await send('WebDriver:ExecuteScript', {
    script: `return WebExtensionPolicy.getByID(${JSON.stringify(identities.firefox_id)}).mozExtensionHostname;`, args: [], newSandbox: true, sandbox: 'default',
  });
  await send('Marionette:SetContext', { value: 'content' });
  await send('WebDriver:Navigate', { url: `moz-extension://${hostname}/popup.html` });
  await until(() => evaluate('document.body.innerText.includes("Pair with Boltwarden")'), 'Pairing page');
  await evaluate('([...document.querySelectorAll("button")].find(button => button.textContent.includes("Pair with Boltwarden")).click(), true)');
  await until(() => existsSync(join(directory, 'pairing.json')), 'Authenticated native pairing');
  await until(() => evaluate('document.body.innerText.includes("Connected") && !document.body.innerText.includes("Pair with Boltwarden")'), 'Authenticated extension state');
  const navigate = async path => {
    await send('WebDriver:Navigate', { url: `${fixture.origin}${path}` });
    await until(() => evaluate('Boolean(window.passkeyFixture) && document.readyState === "complete"'), 'Completed passkey fixture');
  };
  await navigate('/');
  const registration = await evaluate('passkeyFixture.create()');
  verifyRegistration(registration, fixture.origin);
  const assertion = await evaluate('passkeyFixture.get()');
  verifyAssertion(assertion, registration, fixture.origin);
  await navigate('/deny');
  assert.equal(await evaluate('passkeyFixture.get().then(() => "unexpected", error => error.name)'), 'NotAllowedError');
  await navigate('/slow');
  await evaluate('(passkeyFixture.startGet(), true)');
  await delay(100);
  await evaluate('(passkeyFixture.abort(), true)');
  assert.equal((await evaluate('passkeyPending')).error, 'AbortError');
  const nativeLog = await readFile(join(directory, 'pairing.json.log'), 'utf8');
  assert(nativeLog.includes('PasskeyCreate') && nativeLog.includes('PasskeyGet'), 'Both WebAuthn methods reached the paired native host');
  assert(nativeLog.includes('Cancel'), 'Abort reaches native request cancellation');
  console.log(`Firefox ${session.capabilities.browserVersion}: passkey creation, assertion, credential methods, denial, and abort passed.`);
} catch (error) {
  console.error(error);
  if (existsSync(join(directory, 'pairing.json.log'))) console.error(await readFile(join(directory, 'pairing.json.log'), 'utf8'));
  if (logs) console.error(logs.slice(-5000));
  process.exitCode = 1;
} finally {
  for (const entry of pending.values()) clearTimeout(entry.timer);
  socket?.destroy();
  if (browser && browser.exitCode === null) {
    const stopped = new Promise(resolve => browser.once('exit', resolve));
    browser.kill(); await Promise.race([stopped, delay(3000)]);
    if (browser.exitCode === null) { browser.kill('SIGKILL'); await stopped; }
  }
  await fixture?.close();
  await rm(directory, { recursive: true, force: true });
}
