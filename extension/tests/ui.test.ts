// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from 'preact';
import { act } from 'preact/test-utils';
import type { UiPage, UiStateChange } from '../lib/ui-types';
import type { NativeSnapshot } from '../lib/native';

const h = vi.hoisted(() => {
  const event = () => ({ listeners: [] as Array<(value: any) => void>, addListener(callback: (value: any) => void) { this.listeners.push(callback); }, emit(value?: any) { this.listeners.forEach(callback => callback(value)); } });
  const port = { onMessage: event(), onDisconnect: event(), disconnect: vi.fn() };
  return { port, runtime: { connect: vi.fn(() => port), sendMessage: vi.fn(), openOptionsPage: vi.fn() } };
});
vi.mock('wxt/browser', () => ({ browser: { runtime: h.runtime } }));
import { mount } from '../lib/ui';

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
  document.body.innerHTML = '<div id="app"></div>'; app = document.getElementById('app')!;
  page = structuredClone({ frames: [frame] }); connection = { state: 'ready', epoch: 1 };
  h.runtime.sendMessage.mockImplementation(async ({ type }) => response(type === 'state' ? { connection, fingerprint: 'ABCD:1234' } : type === 'list' ? page : null));
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
    await act(() => fill.resolve(response(null))); await vi.waitFor(() => expect(app.textContent).toContain('Login filled'));
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
    await act(() => snapshot.resolve(response({ connection, fingerprint: 'ABCD:1234' })));
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
    await vi.waitFor(() => expect(app.textContent).toContain('Login filled')); expect(calls('list')).toHaveLength(before);
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
    expect(app.textContent).toContain('No vault is stored'); expect(app.textContent).toContain('ABCD:1234');
    expect(app.textContent).toContain('boltwarden install-browser');
  });
});
