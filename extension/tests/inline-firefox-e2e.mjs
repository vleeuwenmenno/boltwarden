// Disposable Firefox profile, trusted keyboard input, synthetic logins only.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createServer, createConnection } from 'node:net';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer as createHttpsServer } from 'node:https';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const identities = JSON.parse(await readFile(join(root, 'lib/browser-identities.json'), 'utf8'));
const directory = await mkdtemp(join(tmpdir(), 'boltwarden-inline-firefox-'));
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

async function startInlineFixture(directory) {
  const key = join(directory, 'key.pem'), cert = join(directory, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
  const form = email => `<form><label>Username<input id="username" ${email ? 'type="email" autocomplete="email"' : 'autocomplete="username"'}></label><label>Password<input id="password" type="password" autocomplete="current-password"></label><button type="button" id="other">Other action</button></form>`;
  const style = '<style>body{font:16px system-ui;margin:60px}label{display:block;margin:18px 0}input{display:block;width:280px;height:34px;margin:8px 0}</style>';
  const server = createHttpsServer({ key: await readFile(key), cert: await readFile(cert) }, (request, response) => {
    const path = new URL(request.url, 'https://localhost').pathname;
    response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
    response.end(`<!doctype html><html><head><title>Inline Firefox fixture</title>${style}</head><body><h1>Synthetic login fixture</h1>${path === '/iframe' ? '<button id="outside" type="button">Outside frame</button><iframe src="/slow" style="width:600px;height:350px"></iframe>' : path === '/dynamic' ? '<div id="slot"></div>' : path === '/shadow' ? '<div id="shadow"></div>' : path === '/otp' ? '<form><label>Zescijferige code<input id="otp" name="passcode" autocomplete="one-time-code" maxlength="6"></label></form>' : path === '/otp-split' ? '<form>' + Array.from({length:6}, (_, i) => `<input id="otp${i}" maxlength="1" autocomplete="one-time-code" style="width:42px;display:inline-block;padding:4px">`).join('') + '</form>' : form(path === '/email')}<script>
      ${path === '/shadow' ? `document.querySelector('#shadow').attachShadow({mode:'open'}).innerHTML=${JSON.stringify(style + form(false))};` : ''}
      window.addForm=()=>document.querySelector('#slot').innerHTML=${JSON.stringify(form(false))};
    </script></body></html>`);
  });
  await new Promise((resolve, reject) => { server.on('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return { origin: `https://localhost:${server.address().port}`, close: () => new Promise(resolve => server.close(resolve)) };
}

let browser, socket, fixture, logs = '';
const pending = new Map();
try {
  await mkdir(home, { recursive: true }); await mkdir(profile, { recursive: true });
  fixture = await startInlineFixture(directory);
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

  const messages = async () => (await readFile(join(directory, 'pairing.json.log'), 'utf8')).trim().split('\n').map(JSON.parse);
  const calls = async type => (await messages()).filter(message => message.type === type).length;
  const field = selector => `(document.querySelector('#shadow')?.shadowRoot ?? document).querySelector(${JSON.stringify(selector)})`;
  const navigate = async path => {
    await send('WebDriver:Navigate', { url: `${fixture.origin}${path}` });
    await until(() => evaluate(`document.readyState === 'complete' && !!document.querySelector('[data-boltwarden-inline]')`), 'Inline content script');
  };
  async function clickField(selector = '#username') {
    const { value: element } = await send('WebDriver:ExecuteScript', { script: `return ${field(selector)};`, args: [], newSandbox: false, sandbox: null });
    await send('WebDriver:ElementClick', { id: element['element-6066-11e4-a52e-4f735466cecf'] });
  }
  async function key(value) {
    const keys = { ArrowDown: '\uE015', Enter: '\uE007', Escape: '\uE00C', Tab: '\uE004' };
    await send('WebDriver:PerformActions', { actions: [{ type: 'key', id: 'inline-keyboard', actions: [
      { type: 'keyDown', value: keys[value] }, { type: 'keyUp', value: keys[value] },
    ] }] });
    await send('WebDriver:ReleaseActions');
  }
  async function openInline(selector = '#username') {
    await clickField(selector); const before = await calls('ListMatches'); await key('ArrowDown');
    await until(async () => await calls('ListMatches') > before, 'Trusted inline listing');
    // The list reply includes one final document inspection before rendering.
    await delay(200);
  }
  async function checkFilled() {
    await until(async () => await evaluate(`${field('#password')}.value`) === 'test-password-only', 'Trusted inline fill');
    assert.equal(await evaluate(`${field('#username')}.value`), 'alice');
  }
  await navigate('/single'); await clickField();
  const initial = await calls('ListMatches');
  await evaluate(`(${field('#username')}.dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowDown',bubbles:true})), true)`);
  await delay(150); assert.equal(await calls('ListMatches'), initial, 'Synthetic keyboard must not open inline listing');
  await openInline(); const escaped = await calls('FillLogin'); await key('Escape'); await key('Enter'); await delay(150);
  assert.equal(await calls('FillLogin'), escaped, 'Escape dismisses without filling');
  for (const [path, selector] of [['/single', '#username'], ['/email', '#username'], ['/single', '#password'], ['/shadow', '#username'], ['/dynamic', '#username']]) {
    await navigate(path); if (path === '/dynamic') await evaluate('(addForm(), true)');
    await openInline(selector); await key('Enter'); await checkFilled();
  }
  for (const [path, selector] of [['/otp', '#otp'], ['/otp-split', '#otp0']]) {
    await navigate(path); await clickField(selector); const before = await calls('ListTotpMatches'); await key('ArrowDown');
    await until(async () => await calls('ListTotpMatches') > before, 'OTP matching account');
    await delay(200); await key('Enter');
    await until(async () => await evaluate(`[...document.querySelectorAll('input')].map(input => input.value).join('')`) === '012345', 'OTP fill');
  }
  await navigate('/slow'); await openInline(); const beforeSlow = await calls('FillLogin'); await key('Enter');
  await until(async () => await calls('FillLogin') > beforeSlow, 'Delayed native fill');
  await evaluate('(document.querySelector("#other").focus(), true)'); await delay(1000);
  assert.equal(await evaluate('document.querySelector("#password").value'), '', 'Changed focus cancels delayed fill');
  assert((await calls('Cancel')) > 0, 'Changed focus reaches native cancellation');
  await navigate('/iframe');
  await send('WebDriver:SwitchToFrame', { id: 0 });
  await until(() => evaluate(`!!document.querySelector('[data-boltwarden-inline]')`), 'Iframe content script');
  await openInline(); const beforeFrame = await calls('FillLogin'); await key('Enter');
  await until(async () => await calls('FillLogin') > beforeFrame, 'Delayed iframe fill');
  await send('WebDriver:SwitchToFrame', { id: null });
  const { value: outside } = await send('WebDriver:FindElement', { using: 'css selector', value: '#outside' });
  await send('WebDriver:ElementClick', { id: outside['element-6066-11e4-a52e-4f735466cecf'] });
  await delay(1000);
  await send('WebDriver:SwitchToFrame', { id: 0 });
  assert.equal(await evaluate('document.querySelector("#password").value'), '', 'Moving focus out of an iframe cancels its pending fill');
  await send('WebDriver:SwitchToFrame', { id: null });
  console.log(`Firefox ${session.capabilities.browserVersion}: inline trusted keyboard, username/email/password, Escape, synthetic-event rejection, dynamic forms, open shadow roots, and delayed-fill field/iframe focus cancellation passed.`);

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
