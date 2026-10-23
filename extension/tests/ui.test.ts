// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from 'preact';
import { act } from 'preact/test-utils';
import type { UiPage, UiStateChange } from '../lib/ui-types';
import type { NativeSnapshot } from '../lib/native';

const h = vi.hoisted(() => {
  const event = () => ({ listeners: [] as Array<(value: any) => void>, addListener(callback: (value: any) => void) { this.listeners.push(callback); }, emit(value?: any) { this.listeners.forEach(callback => callback(value)); } });
  const port = { onMessage: event(), onDisconnect: event(), disconnect: vi.fn() };
  const stored: Record<string, unknown> = {};
  const changed: Array<(changes: Record<string, { newValue?: unknown }>, area: string) => void> = [];
  const storage = { local: { get: vi.fn(async (key: string) => key in stored ? { [key]: stored[key] } : {}),
    set: vi.fn(async (items: Record<string, unknown>) => { Object.assign(stored, items); for (const listener of changed) listener(Object.fromEntries(Object.entries(items).map(([key, newValue]) => [key, { newValue }])), 'local'); }) },
    onChanged: { addListener: (listener: typeof changed[number]) => changed.push(listener), removeListener: (listener: typeof changed[number]) => changed.splice(changed.indexOf(listener), 1) } };
  return { port, stored, storage, extension: { isAllowedIncognitoAccess: vi.fn(async () => true) }, runtime: { getManifest: vi.fn(() => ({ version: '9.8.7' })), connect: vi.fn(() => port), sendMessage: vi.fn(), openOptionsPage: vi.fn(), reload: vi.fn() } };
});
vi.mock('wxt/browser', () => ({ browser: { runtime: h.runtime, extension: h.extension, storage: h.storage } }));
import { mount } from '../lib/ui';
import { BUILD, STALE_MESSAGE, UNKNOWN_ACTION } from '../lib/build';
import { parseReleases } from '../lib/releases';

const login = { id: 'one', name: 'Work login', username: 'alice', revision: '1', reprompt: false, requires_confirmation: false };
const frame = { targetId: 'document-one', origin: 'https://example.com', crossOrigin: false, items: [login, { ...login, id: 'two', name: 'Personal login', username: 'bob' }], more: false };
let page: UiPage;
let connection: NativeSnapshot;
let app: HTMLElement;
const response = (value: unknown) => ({ ok: true, value });
const calls = (type: string) => h.runtime.sendMessage.mock.calls.filter(([value]) => value.type === type);
const buttons = () => Array.from(document.querySelectorAll<HTMLButtonElement>('button'));
const button = (label: string) => buttons().find(value => value.textContent === label || value.getAttribute('aria-label') === label)!;
const field = () => document.querySelector<HTMLInputElement>('input[type=search]')!;
const rows = () => Array.from(document.querySelectorAll<HTMLButtonElement>('.login'));
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
async function key(target: HTMLElement, value: string, extra: KeyboardEventInit = {}) {
  await act(() => { target.dispatchEvent(new KeyboardEvent('keydown', { key: value, bubbles: true, cancelable: true, ...extra })); });
}
async function click(target: HTMLElement) { await act(() => target.click()); }
async function input(value: string) {
  await act(() => { field().value = value; field().dispatchEvent(new Event('input', { bubbles: true })); });
}
async function push(state: NativeSnapshot['state'], reason: UiStateChange['reason'] = 'state') {
  connection = { state, epoch: connection.epoch + 1 };
  await act(() => h.port.onMessage.emit({ type: 'state-changed', connection, reason }));
}
async function open(options = false) {
  await act(() => mount(options));
  await vi.waitFor(() => expect(calls('state').length).toBeGreaterThan(0));
  if (!options && connection.state === 'ready') await vi.waitFor(() => expect(rows()).toHaveLength(2));
}
beforeEach(() => {
  vi.clearAllMocks(); h.port.onMessage.listeners.length = 0; h.port.onDisconnect.listeners.length = 0;
  for (const key of Object.keys(h.stored)) delete h.stored[key];
  document.body.innerHTML = '<div id="app"></div>'; app = document.getElementById('app')!;
  page = structuredClone({ frames: [frame] }); connection = { state: 'ready', epoch: 1 };
  h.runtime.sendMessage.mockImplementation(async ({ type }) => response(type === 'state' ? { connection, fingerprint: 'ABCD:1234', build: BUILD } : type === 'list' ? page : null));
});
afterEach(() => { act(() => render(null, app)); });

describe('popup selection', () => {
  it('filters loaded names and usernames locally without requesting more vault data', async () => {
    await open(); const requestCount = h.runtime.sendMessage.mock.calls.length;
    expect(field().placeholder).toBe('Filter this page’s logins');
    await input('PERSONAL bob');
    expect(rows()).toHaveLength(1); expect(rows()[0]?.textContent).toContain('Personal login');
    expect(h.runtime.sendMessage).toHaveBeenCalledTimes(requestCount);
    await input('missing'); expect(rows()).toHaveLength(0); expect(app.textContent).toContain('No matching logins');
    expect(document.querySelector('.no-matches p')?.textContent).toBe('Try another name or username.');
    await key(field(), 'Escape'); expect(rows()).toHaveLength(2); expect(field().value).toBe('');
    expect(app.textContent).not.toContain('No vault is stored');
  });

  it.each([
    'Select a visible login field, then reopen Boltwarden. Reload the page if this extension was just installed.',
    'No matching logins for this page.',
  ])('preserves the page explanation when typing without loaded matches: %s', async message => {
    page = { frames: [], message };
    await act(() => mount());
    await vi.waitFor(() => expect(document.querySelector('.no-matches p')?.textContent).toBe(message));
    const requestCount = h.runtime.sendMessage.mock.calls.length;
    await input('Git');
    expect(document.querySelector('.no-matches h2')?.textContent).toBe('No logins for this page');
    expect(document.querySelector('.no-matches p')?.textContent).toBe(message);
    expect(app.textContent).not.toContain('Try another name or username.');
    expect(h.runtime.sendMessage).toHaveBeenCalledTimes(requestCount);
    expect(calls('fill')).toHaveLength(0);
  });

  it('navigates rows with arrows and prevents duplicate fills before a render', async () => {
    const fill = deferred<unknown>();
    const original = h.runtime.sendMessage.getMockImplementation()!;
    h.runtime.sendMessage.mockImplementation((message: any) => message.type === 'fill' ? fill.promise : original(message));
    await open(); await key(field(), 'ArrowDown');
    expect(document.querySelector('.login.selected')?.textContent).toContain('Personal login');
    await act(() => {
      field().dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
      field().dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    });
    expect(calls('fill')).toHaveLength(1);
    expect(calls('fill')[0]![0]).toMatchObject({ targetId: frame.targetId, itemId: 'two', confirmCrossOrigin: false, confirmInsecure: false });
    await act(() => fill.resolve(response(null))); await vi.waitFor(() => expect(app.textContent).toContain('Filled'));
  });

  it('opens a guarded confirmation with Cancel focused, traps Tab, and preserves explicit flags', async () => {
    page.frames[0]!.crossOrigin = true; page.frames[0]!.items[0]!.requires_confirmation = true;
    await open(); await key(field(), 'Enter');
    expect(document.querySelector('[role=alertdialog]')).not.toBeNull();
    expect(document.activeElement).toBe(button('Cancel')); expect(rows()).toHaveLength(0);
    expect(app.textContent).toContain('https://example.com'); expect(app.textContent).toContain('uses HTTP');
    await key(button('Cancel'), 'Tab', { shiftKey: true }); expect(document.activeElement).toBe(button('Confirm and fill'));
    await key(button('Confirm and fill'), 'Tab'); expect(document.activeElement).toBe(button('Cancel'));
    expect(calls('fill')).toHaveLength(0);
    await key(button('Cancel'), 'Escape'); expect(document.querySelector('[role=alertdialog]')).toBeNull(); expect(document.activeElement).toBe(field());
    await key(field(), 'Enter'); await click(button('Confirm and fill'));
    expect(calls('fill')[0]![0]).toMatchObject({ confirmCrossOrigin: true, confirmInsecure: true });
  });

  it('retains filtering when explicitly loading another matching page', async () => {
    page.frames[0]!.more = true;
    const original = h.runtime.sendMessage.getMockImplementation()!;
    h.runtime.sendMessage.mockImplementation((message: any) => message.type === 'more'
      ? response({ ...frame, items: [...frame.items, { ...login, id: 'three', name: 'Other', username: 'bob' }] }) : original(message));
    await open(); await input('bob'); await click(button('Load more matching logins'));
    await vi.waitFor(() => expect(rows()).toHaveLength(2)); expect(field().value).toBe('bob'); expect(calls('more')).toHaveLength(1);
  });
});

describe('popup invalidation', () => {
  it('clears a confirmation immediately on lock and refreshes once after unlock', async () => {
    page.frames[0]!.crossOrigin = true;
    await open(); await click(rows()[0]!); await push('locked');
    expect(document.querySelector('[role=alertdialog]')).toBeNull(); expect(app.textContent).not.toContain('alice');
    expect(app.textContent).toContain('Vault locked');
    const before = calls('list').length;
    await push('ready'); await vi.waitFor(() => expect(rows()).toHaveLength(2));
    expect(calls('list')).toHaveLength(before + 1);
    await push('ready'); expect(calls('list')).toHaveLength(before + 1);
  });

  it('discards a delayed old lookup after lock and never restores its summaries', async () => {
    const stale = deferred<unknown>();
    const original = h.runtime.sendMessage.getMockImplementation()!;
    h.runtime.sendMessage.mockImplementation((message: any) => message.type === 'list' ? stale.promise : original(message));
    await act(() => mount()); await vi.waitFor(() => expect(calls('list')).toHaveLength(1));
    await push('locked'); await act(() => stale.resolve(response(page)));
    expect(rows()).toHaveLength(0); expect(app.textContent).not.toContain('alice'); expect(app.textContent).toContain('Vault locked');
  });

  it('recovers initial handshake state races without a refresh loop', async () => {
    const snapshot = deferred<unknown>();
    h.runtime.sendMessage.mockImplementationOnce(() => snapshot.promise);
    await act(() => mount()); await vi.waitFor(() => expect(calls('state')).toHaveLength(1));
    await push('connecting'); await push('ready');
    await act(() => snapshot.resolve(response({ connection, fingerprint: 'ABCD:1234', build: BUILD })));
    await vi.waitFor(() => expect(rows()).toHaveLength(2));
    expect(calls('list')).toHaveLength(1); expect(calls('state')).toHaveLength(2);
  });

  it('clears stale matches after a refresh fails', async () => {
    await open();
    const original = h.runtime.sendMessage.getMockImplementation()!;
    h.runtime.sendMessage.mockImplementation((message: any) => message.type === 'list' ? { ok: false, error: 'Page changed.' } : original(message));
    await click(button('Refresh')); expect(rows()).toHaveLength(0); expect(app.textContent).not.toContain('alice');
    await vi.waitFor(() => expect(document.querySelector('[role=alert]')?.textContent).toContain('Page changed.'));
  });

  it('hides changed summaries while preserving an ongoing fill and desktop approval', async () => {
    const fill = deferred<unknown>();
    const original = h.runtime.sendMessage.getMockImplementation()!;
    h.runtime.sendMessage.mockImplementation((message: any) => message.type === 'fill' ? fill.promise : original(message));
    page.frames[0]!.items[0]!.reprompt = true;
    await open(); await click(rows()[0]!); const before = calls('list').length;
    await push('ready', 'matches');
    expect(rows()).toHaveLength(0); expect(calls('list')).toHaveLength(before);
    expect(app.textContent).toContain('Verify your master password');
    await act(() => fill.resolve(response(null)));
    await vi.waitFor(() => expect(app.textContent).toContain('Filled')); expect(calls('list')).toHaveLength(before);
  });

  it('defers page discovery until an invalidated fill finishes', async () => {
    const fill = deferred<unknown>();
    const original = h.runtime.sendMessage.getMockImplementation()!;
    h.runtime.sendMessage.mockImplementation((message: any) => message.type === 'fill' ? fill.promise : original(message));
    await open(); await click(rows()[0]!); const before = calls('list').length;
    await push('ready', 'page'); expect(rows()).toHaveLength(0); expect(calls('list')).toHaveLength(before);
    await act(() => fill.resolve({ ok: false, error: 'Page changed.' }));
    await vi.waitFor(() => expect(rows()).toHaveLength(2));
    expect(calls('list')).toHaveLength(before + 1); expect(calls('fill')).toHaveLength(1);
  });

  it('keeps setup details in options without discovering the active page', async () => {
    await open(true); expect(calls('list')).toHaveLength(0);
    expect(app.textContent).toContain('Extension 9.8.7');
    expect(app.textContent).toContain('Browser integration API v1');
    expect(app.textContent).toContain('Pending saves stay in browser session storage'); expect(app.textContent).toContain('ABCD:1234');
    expect(document.querySelector('a[href="/privacy.html"]')?.textContent).toBe('Privacy and data handling');
    expect(app.textContent).toContain('boltwarden install-browser');
  });
});

it('shows retained saves while locked and exposes retry and discard without a password', async () => {
  connection = { state: 'locked', epoch: 2 };
  const pending = { id: 'pending-one', origin: 'https://example.test', username: 'alice', message: 'Unlock to finish saving.', busy: false };
  h.runtime.sendMessage.mockImplementation(async ({ type }) => response(type === 'state'
    ? { connection, fingerprint: 'ABCD:1234', build: BUILD } : type === 'pending-saves' ? [pending] : null));
  await open(true);
  await vi.waitFor(() => expect(app.textContent).toContain('Password awaiting save'));
  expect(app.textContent).toContain('browser session ends');
  const buttons = [...app.querySelectorAll('button')];
  await act(() => buttons.find(button => button.textContent === 'Retry save')!.click());
  expect(h.runtime.sendMessage).toHaveBeenCalledWith({ type: 'retry-save', id: 'pending-one' });
  await act(() => buttons.find(button => button.textContent === 'Discard')!.click());
  expect(h.runtime.sendMessage).toHaveBeenCalledWith({ type: 'discard-save', id: 'pending-one' });
});

describe('outdated background', () => {
  it('asks to reload when the background is from an older build', async () => {
    h.runtime.sendMessage.mockImplementation(async ({ type }) => response(type === 'state' ? { connection, fingerprint: 'ABCD:1234' } : type === 'list' ? page : []));
    await open(true);
    await vi.waitFor(() => expect(app.textContent).toContain(STALE_MESSAGE));
    await click(button('Reload extension'));
    expect(h.runtime.reload).toHaveBeenCalled();
  });
  it('turns an unknown action into the reload notice instead of a raw error', async () => {
    h.runtime.sendMessage.mockImplementation(async ({ type }) => type === 'pending-saves' ? { ok: false, error: UNKNOWN_ACTION }
      : response(type === 'state' ? { connection, fingerprint: 'ABCD:1234', build: BUILD } : type === 'list' ? page : null));
    await open(true);
    await vi.waitFor(() => expect(app.textContent).toContain('Reload Boltwarden'));
    expect(app.textContent).not.toContain(UNKNOWN_ACTION);
    expect(app.textContent).not.toContain('Pending passwords unavailable');
  });
  it('shows no notice when the builds match', async () => {
    await open(true);
    expect(app.textContent).not.toContain('Reload Boltwarden');
  });
});

describe('private windows notice', () => {
  it('tells the user how to enable private windows only when they are not allowed', async () => {
    await open(true);
    expect(app.textContent).not.toContain('not enabled in private windows');
    act(() => render(null, app));
    h.extension.isAllowedIncognitoAccess.mockResolvedValueOnce(false);
    await open(true);
    await vi.waitFor(() => expect(app.textContent).toContain('Boltwarden is not enabled in private windows'));
    expect(app.textContent).toContain('Allow in Incognito');
  });
});

describe('release notices', () => {
  const NOW = 1_790_000_000;
  const info = (tag: string) => ({ version: tag.replace(/^(extension-)?v/, ''), tag, url: `https://github.com/vleeuwenmenno/boltwarden/releases/tag/${tag}`, published_at: NOW });
  const snapshot = (overrides: Record<string, unknown> = {}, desktop: Record<string, unknown> = {}) => ({ state: 'fresh', auto_check: true, checked_at: NOW, complete: true,
    desktop: { installed: '1.0.0-rc.5', update: 'available', offer: info('v1.0.0'), dismissed: false, stable: info('v1.0.0'), ...desktop },
    extension: info('extension-v9.9.0'), ...overrides });
  let releases: unknown;
  let releaseCalls: Array<Record<string, unknown>>;
  function serve(next: () => unknown = () => releases) {
    releaseCalls = [];
    h.runtime.sendMessage.mockImplementation(async (message: any) => {
      if (message.type === 'releases') {
        releaseCalls.push(message);
        const value = next();
        return response({ connection, ...(value ? { releases: value } : {}) });
      }
      return response(message.type === 'state' ? { connection, fingerprint: 'ABCD:1234', build: BUILD, ...(releases ? { releases } : {}) } : message.type === 'list' ? page : null);
    });
  }
  // The background hands pages metadata that the native client already validated.
  const meta = (value: unknown) => ({ desktopVersion: '1.0.0-rc.5', releases: parseReleases(value), receivedAt: Date.now() });
  const notices = () => Array.from(document.querySelectorAll('.release-notice'));
  beforeEach(() => { releases = meta(snapshot()); serve(); });
  afterEach(() => { vi.useRealTimers(); });

  it('shows compact popup notices with store-lag wording, without stealing focus from the search', async () => {
    connection = { state: 'locked', epoch: 1 };
    await act(() => mount());
    await vi.waitFor(() => expect(notices()).toHaveLength(2));
    expect(notices()[0]!.textContent).toContain('Boltwarden desktop 1.0.0 is available');
    expect(notices()[1]!.textContent).toContain('Boltwarden extension 9.9.0 was published on GitHub');
    expect(notices()[1]!.textContent).toContain('Browser store updates may still be pending');
    expect(notices()[1]!.textContent).not.toMatch(/ready to install/i);
    expect(notices()[0]!.querySelector('a')?.getAttribute('href')).toBe('https://github.com/vleeuwenmenno/boltwarden/releases/tag/v1.0.0');
    expect(document.querySelector('.release-notices img')).toBeNull();
    expect(app.textContent).toContain('Vault locked');
    // Opening the popup reads the cache without asking for a check.
    expect(releaseCalls).toEqual([{ type: 'releases' }]);
  });

  it('keeps search focus and login rows when notices are shown', async () => {
    await open();
    await vi.waitFor(() => expect(notices()).toHaveLength(2));
    expect(document.activeElement).toBe(field());
    expect(rows()).toHaveLength(2);
  });

  it('persists a per-version dismissal and shows a later version again', async () => {
    connection = { state: 'locked', epoch: 1 };
    await act(() => mount());
    await vi.waitFor(() => expect(notices()).toHaveLength(2));
    await click(notices()[1]!.querySelector('button')!);
    await vi.waitFor(() => expect(notices()).toHaveLength(1));
    expect(h.stored['release-notices']).toEqual({ notices: true, dismissed: { extension: '9.9.0' } });
    expect(notices()[0]!.textContent).toContain('desktop');
    await act(() => h.port.onMessage.emit({ type: 'state-changed', reason: 'releases', connection, releases: meta(snapshot({ extension: info('extension-v9.9.1') })) }));
    await vi.waitFor(() => expect(notices()).toHaveLength(2));
  });

  it('hides popup notices when switched off in options', async () => {
    h.stored['release-notices'] = { notices: false, dismissed: {} };
    connection = { state: 'locked', epoch: 1 };
    await act(() => mount());
    await vi.waitFor(() => expect(releaseCalls).toHaveLength(1));
    expect(notices()).toHaveLength(0);
  });

  it('ignores malformed release data in a push and keeps the connection', async () => {
    releases = { invalid: true, receivedAt: 1 };
    await open(true);
    await vi.waitFor(() => expect(app.textContent).toContain('could not read'));
    expect(app.textContent).toContain('Paired with Boltwarden desktop');
  });

  it.each([
    ['up to date', meta(snapshot({ extension: info('extension-v9.8.7') }, { update: 'up_to_date', offer: undefined })), ['Desktop app 1.0.0-rc.5', 'Up to date.', 'This extension 9.8.7', 'Last checked']],
    ['newer releases', meta(snapshot()), ['Version 1.0.0 is available.', 'Version 9.9.0 was published on GitHub. Browser store updates may still be pending.']],
    ['incomplete list', meta(snapshot({ complete: false, extension: info('extension-v9.8.7') }, { update: 'unknown', offer: undefined })), ['Could not confirm that this is the newest version.']],
    ['failed check', meta(snapshot({ state: 'error', error: 'network', extension: info('extension-v9.8.7') }, { update: 'up_to_date', offer: undefined })), ['The last check failed: GitHub could not be reached.', 'Could not confirm']],
    ['older desktop', { desktopVersion: '1.0.0-rc.4', receivedAt: 1 }, ['(1.0.0-rc.4) does not share release information']],
    ['desktop without a checker', meta(snapshot({ state: 'unsupported' })), ['does not share release information']],
    ['development desktop', meta(snapshot({}, { installed: '1.0.0+3.gabc', update: 'development', offer: undefined })), ['Development build; updates are not offered. Latest release: 1.0.0.']],
  ])('shows versions and honest status in options: %s', async (_name, value, texts) => {
    releases = value;
    await open(true);
    await vi.waitFor(() => expect(document.querySelector('.releases')?.textContent).toContain(texts[0]));
    const text = document.querySelector('.releases')!.textContent!;
    for (const expected of texts) expect(text).toContain(expected);
    if (_name !== 'up to date') expect(text).not.toContain('Up to date.');
    if (_name === 'older desktop' || _name === 'desktop without a checker') expect(button('Check now')).toBeUndefined();
  });

  it('asks to start the desktop when disconnected, without a false up-to-date claim', async () => {
    connection = { state: 'disconnected', epoch: 0 }; releases = undefined;
    await open(true);
    await vi.waitFor(() => expect(document.querySelector('.releases')?.textContent).toContain('Start Boltwarden desktop to check for updates.'));
    expect(document.querySelector('.releases')?.textContent).not.toContain('Up to date');
    expect(button('Check now')).toBeUndefined();
  });

  const advance = async (ms: number) => { await act(async () => { await vi.advanceTimersByTimeAsync(ms); }); };
  const flush = () => advance(0);
  it('checks on request, polls every two seconds while checking, and stops when complete', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] });
    const answers = ['fresh', 'checking', 'checking', 'fresh'];
    serve(() => meta(snapshot({ state: answers.shift() ?? 'fresh' })));
    await act(() => mount(true)); await flush(); await flush();
    expect(releaseCalls).toEqual([{ type: 'releases' }]);
    await click(button('Check now')); await flush();
    expect(releaseCalls.at(-1)).toEqual({ type: 'releases', check: true });
    expect(document.querySelector('.releases')?.textContent).toContain('Checking for updates…');
    await advance(1999); expect(releaseCalls).toHaveLength(2);
    await advance(1); expect(releaseCalls).toHaveLength(3);
    await advance(2000); expect(releaseCalls).toHaveLength(4);
    expect(document.querySelector('.releases')?.textContent).not.toContain('Checking for updates…');
    await advance(60_000); expect(releaseCalls).toHaveLength(4);
    // Only the explicit click asked for a check.
    expect(releaseCalls.filter(call => call.check)).toHaveLength(1);
  });

  it('stops polling after 40 seconds and on close even if the desktop keeps checking', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] });
    releases = meta(snapshot({ state: 'checking' }));
    serve(() => meta(snapshot({ state: 'checking' })));
    await act(() => mount(true)); await flush();
    await advance(60_000);
    const calls = releaseCalls.length;
    expect(calls).toBeLessThanOrEqual(22); expect(calls).toBeGreaterThan(15);
    await advance(60_000); expect(releaseCalls).toHaveLength(calls);
    act(() => render(null, app));
    releaseCalls.length = 0;
    await act(() => mount(true)); await flush();
    await advance(4_000);
    expect(releaseCalls.length).toBeGreaterThan(1);
    act(() => render(null, app));
    const closed = releaseCalls.length;
    await advance(20_000); expect(releaseCalls).toHaveLength(closed);
  });

  it('does not poll an older desktop that ignores the check request', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] });
    releases = { receivedAt: 1 };
    serve(() => ({ receivedAt: 1 }));
    await act(() => mount(true)); await flush();
    await click(button('Check now') ?? document.body);
    await advance(20_000);
    expect(releaseCalls).toEqual([{ type: 'releases' }]);
    expect(app.textContent).toContain('does not share release information');
  });

  it('counts down the reported wait before allowing another check, then reads again', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] });
    releases = meta(snapshot({ retry_after_seconds: 5 }));
    serve(() => releaseCalls.length > 1 ? meta(snapshot()) : meta(snapshot({ retry_after_seconds: 5 })));
    await act(() => mount(true)); await flush();
    expect(document.querySelector('.releases')?.textContent).toContain('You can check again in 5 s.');
    expect(button('Check now').disabled).toBe(true);
    await advance(2000);
    expect(document.querySelector('.releases')?.textContent).toContain('You can check again in 3 s.');
    await advance(3000); await flush();
    expect(button('Check now').disabled).toBe(false);
    expect(releaseCalls.length).toBe(2);
    expect(releaseCalls.every(call => !call.check)).toBe(true);
  });
});
