// Real Chromium extension, real native messaging, synthetic logins, disposable HOME/profile.
// Requires Node >=22.12 and Chromium; no external automation dependency or personal profile.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
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
const form = (email = false) => `<form><label>${email ? 'Email' : 'Username'}<input id="username" ${email ? 'type="email" autocomplete="email"' : 'autocomplete="username"'}></label><label>Password<input id="password" type="password" autocomplete="current-password"></label><button type="button" id="other">Other action</button></form>`;
const html = path => `<!doctype html><html><head><title>Inline login fixture</title><style>
body{margin:0;background:#11131a;color:#edf0f5;font:16px system-ui;display:grid;place-items:center;min-height:100vh}main{width:380px;padding:36px;border:1px solid #343947;border-radius:16px;background:#1c202b}h1{font-size:24px}label{display:block;margin:22px 0 8px}input{box-sizing:border-box;width:100%;margin-top:8px;padding:12px 38px 12px 12px;color:#f0f3f9;background:#11141c;border:1px solid #4c546b;border-radius:6px;font:16px system-ui}button{padding:10px 14px;border-radius:6px;border:1px solid #4c546b;background:#30394d;color:white}p{color:#adb6ca}
</style></head><body><main><h1>Sign in to Example</h1><p>Synthetic browser test credentials only.</p>${path === '/iframe' ? '<button id="outside" type="button">Outside frame</button><iframe id="frame" src="/slow" style="width:100%;height:480px;border:0"></iframe>' : path === '/dynamic' ? '<div id="slot"></div>' : path === '/shadow' ? '<div id="shadow"></div>' : path === '/otp' ? '<form><label>Zescijferige code<input id="otp" name="passcode" autocomplete="one-time-code" maxlength="6"></label></form>' : path === '/otp-split' ? '<form>' + Array.from({length:6}, (_, i) => `<input id="otp${i}" maxlength="1" autocomplete="one-time-code" style="width:42px;display:inline-block;padding:4px">`).join('') + '</form>' : form(path === '/email')}</main><script>
${path === '/shadow' ? `document.querySelector('#shadow').attachShadow({mode:'open'}).innerHTML = ${JSON.stringify('<style>label{display:block;margin:18px 0;color:#edf0f5}input{display:block;margin-top:8px;width:280px;height:34px}</style>' + form())};` : ''}
window.addForm = () => document.querySelector('#slot').innerHTML = ${JSON.stringify(form())};
</script></body></html>`;
const respond = (request, response) => { response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' }); response.end(html(new URL(request.url, 'https://localhost').pathname)); };
const keyPath = join(directory, 'key.pem'), certPath = join(directory, 'cert.pem');
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
const server = createHttpsServer({ key: await readFile(keyPath), cert: await readFile(certPath) }, respond);
const httpServer = createHttpServer(respond);
for (const listening of [server, httpServer]) await new Promise((resolve, reject) => { listening.on('error', reject); listening.listen(0, '127.0.0.1', resolve); });
const site = `https://localhost:${server.address().port}`, httpSite = `http://localhost:${httpServer.address().port}`;
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
  await writeFile(launcher, `#!/bin/sh\nexec ${quote(process.execPath)} ${quote(join(root, 'tests/inline-native-host.mjs'))} "$@"\n`, { mode: 0o700 });
  const manifest = { name: identities.host_name, description: 'Boltwarden test host', path: launcher, type: 'stdio', allowed_origins: [`chrome-extension://${identities.chrome_id}/`] };
  for (const parent of [join(profile, 'NativeMessagingHosts'), ...['chromium', 'google-chrome', 'vivaldi'].map(name => join(home, '.config', name, 'NativeMessagingHosts'))]) {
    await mkdir(parent, { recursive: true }); await writeFile(join(parent, `${identities.host_name}.json`), JSON.stringify(manifest));
  }
  const extension = join(root, '.output/chrome-mv3');
  assert(existsSync(join(extension, 'manifest.json')), 'Run npm run build first');
  browser = spawn(process.env.CHROMIUM_BIN ?? 'chromium', [
    ...(process.env.BOLTWARDEN_TEST_HEADFUL === '1' ? ['--ozone-platform=x11', '--disable-gpu'] : ['--headless=new']), '--ignore-certificate-errors', '--window-size=1080,900', '--no-sandbox', '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-sync',
    '--password-store=basic', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
    ...(String(process.env.CHROMIUM_BIN).includes('vivaldi') ? [] : [`--disable-extensions-except=${extension}`]), `--load-extension=${extension}`, 'about:blank',
  ], { env: { ...process.env, HOME: home, VIVALDI_FFMPEG_AUTO: '0', XDG_CONFIG_HOME: join(home, '.config'), BOLTWARDEN_TEST_STATE: join(directory, 'pairing.json') }, stdio: ['ignore', 'ignore', 'pipe'] });
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
  let workerSession = await attach(worker.targetId);
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
  const panel = await popup();
  await until(async () => (await text(panel.session)).includes('Pair with Boltwarden'), 'Pairing button');
  await click(panel.session, 'Pair with Boltwarden');
  await until(async () => (await text(panel.session)).includes('Test login'), 'Paired match list');
  assert(existsSync(join(directory, 'pairing.json')), 'Native host verified pairing proof');
  await send('Target.closeTarget', { targetId: panel.target.targetId });
  // Keep pairing storage, but restart the extension background. No toolbar warm-up.
  await send('ServiceWorker.enable', {}, websiteSession);
  await send('ServiceWorker.stopAllWorkers', {}, websiteSession);
  await until(async () => !(await send('Target.getTargets')).targetInfos.some(target => target.targetId === worker.targetId), 'Stopped extension worker');
  await send('Page.navigate', {url: `${site}/single?cold-start`}, websiteSession);
  const restartedWorker = await until(async () => (await send('Target.getTargets')).targetInfos.find(target => target.type === 'service_worker' && target.url.includes(identities.chrome_id)), 'Restarted extension worker');
  workerSession = await attach(restartedWorker.targetId);

  const messages = async () => (await readFile(join(directory, 'pairing.json.log'), 'utf8')).trim().split('\n').map(JSON.parse);
  const calls = async type => (await messages()).filter(message => message.type === type).length;
  const field = selector => `(document.querySelector('#frame')?.contentDocument ?? document.querySelector('#shadow')?.shadowRoot ?? document).querySelector(${JSON.stringify(selector)})`;
  async function navigate(path, origin = site) {
    await send('Page.navigate', { url: `${origin}${path}` }, websiteSession);
    await until(() => evaluate(websiteSession, `location.pathname === ${JSON.stringify(path)} && document.readyState === 'complete'`), 'Fixture navigation');
    await send('Page.bringToFront', {}, websiteSession);
    await until(() => evaluate(websiteSession, `!!document.querySelector('[data-boltwarden-inline]')`), 'Inline content script');
  }
  async function clickField(selector = '#username') {
    const rect = await evaluate(websiteSession, `(() => {const field=${field(selector)}; const r=field.getBoundingClientRect();const parent=document.querySelector('#frame')?.getBoundingClientRect();return {x:(parent?.x??0)+r.x+10,y:(parent?.y??0)+r.y+r.height/2};})()`);
    await send('Page.bringToFront', {}, websiteSession);
    await send('Input.dispatchMouseEvent', { type:'mousePressed', button:'left', clickCount:1, ...rect }, websiteSession);
    await send('Input.dispatchMouseEvent', { type:'mouseReleased', button:'left', clickCount:1, ...rect }, websiteSession);
  }
  async function inlineNodes() {
    const { root: document } = await send('DOM.getDocument', { depth:-1, pierce:true }, websiteSession);
    const all = [];
    const walk = node => { all.push(node); for (const child of [...(node.children ?? []), ...(node.shadowRoots ?? []), ...(node.contentDocument ? [node.contentDocument] : [])]) walk(child); };
    walk(document);
    const host = all.find(node => node.attributes?.includes('data-boltwarden-inline') && node.shadowRoots?.some(root => root.children?.some(child => child.nodeName === 'BUTTON' && !child.attributes?.includes('hidden'))));
    if (!host) return [];
    const scoped = [];
    const visit = node => { scoped.push(node); for (const child of [...(node.children ?? []), ...(node.shadowRoots ?? []), ...(node.contentDocument ? [node.contentDocument] : [])]) visit(child); };
    visit(host); return scoped;
  }
  const attr = (node, name) => { const i = node.attributes?.indexOf(name) ?? -1; return i < 0 ? undefined : node.attributes[i+1]; };
  const inlineText = async () => (await inlineNodes()).filter(node => node.nodeType === 3).map(node => node.nodeValue).join(' ');
  async function openInline(useIcon = false) {
    await clickField();
    if (useIcon) {
      const mark = await until(async () => (await inlineNodes()).find(node => attr(node, 'aria-label') === 'Show Boltwarden logins'), 'Inline icon');
      const { model } = await send('DOM.getBoxModel', { nodeId: mark.nodeId }, websiteSession);
      const point = { x:(model.border[0]+model.border[4])/2, y:(model.border[1]+model.border[5])/2 };
      await send('Input.dispatchMouseEvent', { type:'mousePressed', button:'left', clickCount:1, ...point }, websiteSession);
      await send('Input.dispatchMouseEvent', { type:'mouseReleased', button:'left', clickCount:1, ...point }, websiteSession);
    } else await key(websiteSession, 'ArrowDown');
    await until(async () => (await inlineText()).includes('Test login'), 'Inline matching login');
  }
  async function checkFilled() {
    await until(async () => await evaluate(websiteSession, `${field('#password')}.value`) === 'test-password-only', 'Inline password fill');
    assert.equal(await evaluate(websiteSession, `${field('#username')}.value`), 'alice');
  }
  await navigate('/single');
  await openInline(true);
  await screenshot(websiteSession, 'inline-ready');
  const beforeSynthetic = await calls('FillLogin');
  const row = (await inlineNodes()).find(node => attr(node, 'role') === 'option');
  assert(row, 'Expected an inline login row');
  const object = await send('DOM.resolveNode', { nodeId: row.nodeId }, websiteSession);
  await send('Runtime.callFunctionOn', { objectId: object.object.objectId, functionDeclaration:'function(){this.click()}' }, websiteSession);
  await delay(150);
  assert.equal(await calls('FillLogin'), beforeSynthetic, 'Untrusted synthetic click must not request credentials');
  await key(websiteSession, 'Enter'); await checkFilled();

  for (const path of ['/email', '/shadow', '/dynamic']) {
    await navigate(path);
    if (path === '/dynamic') await evaluate(websiteSession, 'window.addForm()');
    await openInline(); await key(websiteSession, 'Enter'); await checkFilled();
  }

  await navigate('/slow-sync');
  await openInline();
  const beforeSyncCancel = await calls('Cancel');
  await key(websiteSession, 'Enter'); await checkFilled();
  assert.equal(await calls('Cancel'), beforeSyncCancel, 'A sync event during fill must preserve the approved operation');

  for (const [path, selector] of [['/otp', '#otp'], ['/otp-split', '#otp0']]) {
    await navigate(path); await clickField(selector); await key(websiteSession, 'ArrowDown');
    await until(async () => (await inlineText()).includes('012 345'), 'OTP code preview');
    await screenshot(websiteSession, path === '/otp' ? 'otp-preview' : 'otp-split-preview');
    await key(websiteSession, 'Enter');
    await until(async () => await evaluate(websiteSession, `[...document.querySelectorAll('input')].map(input => input.value).join('')`) === '012345', 'OTP fill');
  }

  await navigate('/slow');
  await openInline();
  const beforeSlow = await calls('FillLogin'), beforeCancel = await calls('Cancel');
  await key(websiteSession, 'Enter');
  await until(async () => await calls('FillLogin') > beforeSlow, 'Pending native fill');
  await clickField('#other');
  await until(async () => await calls('Cancel') > beforeCancel, 'Focus-change cancellation');
  await delay(900);
  assert.equal(await evaluate(websiteSession, `${field('#password')}.value`), '', 'Moving focus must suppress delayed credentials');

  await navigate('/iframe');
  await openInline();
  const beforeFrameFill = await calls('FillLogin'), beforeFrameCancel = await calls('Cancel');
  await key(websiteSession, 'Enter');
  await until(async () => await calls('FillLogin') > beforeFrameFill, 'Pending framed fill');
  const outside = await evaluate(websiteSession, `(() => { const r=document.querySelector('#outside').getBoundingClientRect();return {x:r.x+10,y:r.y+r.height/2}; })()`);
  await send('Input.dispatchMouseEvent', { type:'mousePressed', button:'left', clickCount:1, ...outside }, websiteSession);
  await send('Input.dispatchMouseEvent', { type:'mouseReleased', button:'left', clickCount:1, ...outside }, websiteSession);
  await until(async () => await calls('Cancel') > beforeFrameCancel, 'Frame focus-change cancellation');
  await delay(900);
  assert.equal(await evaluate(websiteSession, `${field('#password')}.value`), '', 'Leaving a frame must suppress delayed credentials');

  await navigate('/single');
  await openInline();
  await writeFile(join(directory, 'pairing.json.control'), JSON.stringify({ unlocked: false, epoch: 2 }));
  await until(async () => (await inlineText()).includes('Unlock Boltwarden'), 'Inline lock state');
  assert(!(await inlineText()).includes('Loading'), 'Locked menu must not keep loading');
  const lockedMatches = await calls('ListMatches');
  await key(websiteSession, 'Escape');
  await key(websiteSession, 'ArrowDown');
  await until(async () => (await inlineText()).includes('Unlock Boltwarden'), 'Reopened locked menu');
  assert.equal(await calls('ListMatches'), lockedMatches, 'Do not query matches while locked');
  await key(websiteSession, 'Enter');
  await until(async () => (await inlineText()).includes('Test login'), 'Inline matches after unlock');
  await key(websiteSession, 'Enter'); await checkFilled();

  await navigate('/single', httpSite);
  await clickField(); await key(websiteSession, 'ArrowDown');
  await until(async () => (await inlineText()).includes('toolbar'), 'HTTP toolbar fallback');
  await screenshot(websiteSession, 'inline-http-confirmation');
  const beforeHttp = await calls('FillLogin');
  await key(websiteSession, 'Enter');
  const confirmationPopup = await until(async () => (await send('Target.getTargets')).targetInfos.find(target => target.url === `chrome-extension://${identities.chrome_id}/popup.html`), 'HTTP toolbar popup');
  assert.equal(await calls('FillLogin'), beforeHttp, 'HTTP inline choice must not directly release credentials');
  await send('Target.closeTarget', { targetId: confirmationPopup.targetId });
  console.log(`${process.env.CHROMIUM_BIN ?? 'chromium'} inline e2e passed: trusted keyboard fill, email fields, dynamic forms, open shadow roots, synthetic-event refusal, field/frame focus-change cancellation, HTTP toolbar handoff.`);

} catch (error) {
  console.error(log.join('').slice(-3000)); throw error;
} finally {
  socket?.close(); browser?.kill('SIGTERM');
  if (browser && browser.exitCode === null) await Promise.race([new Promise(resolve => browser.once('exit', resolve)), delay(3000)]);
  if (browser && browser.exitCode === null) browser.kill('SIGKILL');
  await Promise.all([server, httpServer].map(listening => new Promise(resolve => listening.close(resolve))));
  await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
