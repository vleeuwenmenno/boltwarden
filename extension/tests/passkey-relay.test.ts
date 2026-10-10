import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => {
  const event = () => ({ listeners: [] as Array<(...args: any[]) => any>,
    addListener(callback: (...args: any[]) => any) { this.listeners.push(callback); },
    removeListener(callback: (...args: any[]) => any) { this.listeners = this.listeners.filter(value => value !== callback); },
    emit(...args: any[]) { return this.listeners.map(callback => callback(...args)); } });
  const settings: Record<string, unknown> = {};
  const dialog = { show: vi.fn(), close: vi.fn() };
  return { event, settings, dialog, browser: { runtime: { id: 'extension', onMessage: event(), connect: vi.fn() },
    storage: { local: { get: vi.fn(async () => ({ settings: { ...settings } })), set: vi.fn() } } } };
});
vi.mock('wxt/browser', () => ({ browser: h.browser }));
vi.mock('../lib/passkey-dialog', () => ({ showUnavailableDialog: (...args: unknown[]) => { h.dialog.show(...args); return { close: h.dialog.close }; } }));
vi.mock('wxt/utils/define-content-script', () => ({ defineContentScript: (value: unknown) => value }));
import relay from '../entrypoints/passkey-relay.content';

let listeners: Map<string, (event: any) => void>;
let connection: ReturnType<typeof setup>;
function setup() {
  const port = { postMessage: vi.fn(), disconnect: vi.fn(), onMessage: h.event(), onDisconnect: h.event() };
  h.browser.runtime.connect.mockReturnValue(port);
  listeners = new Map();
  const window = {} as { top?: unknown }; window.top = window;
  vi.stubGlobal('window', window); vi.stubGlobal('isSecureContext', true);
  vi.stubGlobal('location', { protocol: 'https:', origin: 'https://example.com' });
  vi.stubGlobal('document', { visibilityState: 'visible' });
  relay.main!({ isInvalid: false, addEventListener(_target: unknown, type: string, listener: (event: any) => void) { listeners.set(type, listener); }, onInvalidated() {} } as never);
  return port;
}
function request() {
  const channel = { postMessage: vi.fn(), close: vi.fn(), onmessage: undefined as undefined | ((event: any) => void) };
  listeners.get('message')!({ isTrusted: true, source: window, origin: location.origin,
    data: { source: 'boltwarden-webauthn-v1', type: 'request', id: 'request', kind: 'get', options: {
      challenge: 'AQID', allow_credentials: [], user_verification: 'required', timeout_ms: 60000,
    } }, ports: [channel] });
  return channel;
}

beforeEach(() => {
  vi.useFakeTimers(); vi.clearAllMocks(); h.browser.runtime.onMessage.listeners.length = 0;
  for (const key of Object.keys(h.settings)) delete h.settings[key];
  connection = setup();
});
const operations = () => connection.postMessage.mock.calls.map(([message]) => message).filter(message => message.type === 'operation');
/** The dialog's `choose` callback from the most recent showUnavailableDialog call. */
const chosen = () => (h.dialog.show.mock.calls.at(-1)![1] as { choose(choice: string): void }).choose;
function sent() {
  const channel = request();
  connection.onMessage.emit({ type: 'generation', generation: 'current', ready: true });
  connection.onMessage.emit({ type: 'unavailable', id: 'request', generation: 'current', reason: 'unpaired' });
  return channel;
}
afterEach(() => { vi.clearAllTimers(); vi.unstubAllGlobals(); vi.useRealTimers(); });

describe('passkey relay document readiness', () => {
  it('uses a coherent epoch timing pair when Firefox rounds timeOrigin independently', () => {
    vi.stubGlobal('performance', { timeOrigin: 1001, getEntriesByType: () => [{ responseStart: 3 }],
      timing: { navigationStart: 1000, responseStart: 1000, domLoading: 1003 } });
    const page = setup();
    expect(page.postMessage).toHaveBeenCalledWith(expect.objectContaining({
      type: 'identify', navigation_start: 1000, binding_end: 1003,
    }));
  });
  it('does not combine incomplete legacy timing with modern timing', () => {
    vi.stubGlobal('performance', { timeOrigin: 1001, getEntriesByType: () => [{ responseStart: 3 }],
      timing: { navigationStart: 1000, responseStart: 0, domLoading: 0 } });
    const page = setup();
    expect(page.postMessage).toHaveBeenCalledWith(expect.objectContaining({
      type: 'identify', navigation_start: 1001, binding_end: 1004,
    }));
  });
  it('preserves an unsent request through startup generations, then cancels a sent request on replacement', () => {
    const channel = request();
    expect(channel.postMessage).toHaveBeenCalledWith({ type: 'ack', id: 'request' });
    connection.onMessage.emit({ type: 'generation', generation: 'initial', ready: false });
    connection.onMessage.emit({ type: 'generation', generation: 'current', ready: false });
    expect(connection.postMessage.mock.calls.some(([message]) => message.type === 'operation')).toBe(false);
    expect(channel.close).not.toHaveBeenCalled();
    connection.onMessage.emit({ type: 'generation', generation: 'current', ready: true });
    expect(connection.postMessage).toHaveBeenCalledWith(expect.objectContaining({ type: 'operation', generation: 'current' }));
    connection.onMessage.emit({ type: 'generation', generation: 'replacement', ready: false });
    expect(channel.postMessage).toHaveBeenCalledWith(expect.objectContaining({ type: 'error', name: 'AbortError' }));
    expect(channel.close).toHaveBeenCalled();
  });
  it('does not fall back after 1.5 seconds on a slow-loading page', async () => {
    const channel = request();
    connection.onMessage.emit({type: 'generation', generation: 'loading', ready: false});
    await vi.advanceTimersByTimeAsync(2500);
    expect(channel.close).not.toHaveBeenCalled();
    connection.onMessage.emit({type: 'generation', generation: 'loading', ready: true});
    expect(connection.postMessage).toHaveBeenCalledWith(expect.objectContaining({type: 'operation', generation: 'loading'}));
  });
  it('treats a background that never marks the page ready as not responding, and never sends afterwards', async () => {
    h.settings.passkeyUnavailable = 'browser';
    const channel = request();
    connection.onMessage.emit({ type: 'generation', generation: 'unknown', ready: false });
    await vi.advanceTimersByTimeAsync(9900);
    expect(channel.close).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(200);
    expect(channel.postMessage).toHaveBeenCalledWith({ type: 'fallback', reason: 'unavailable-not-responding', id: 'request' });
    connection.onMessage.emit({ type: 'generation', generation: 'unknown', ready: true });
    expect(operations()).toHaveLength(0);
  });
});

describe('passkey relay when Boltwarden is unavailable', () => {
  it('asks by default and holds the request while the dialog is open', async () => {
    const channel = sent();
    await vi.waitFor(() => expect(h.dialog.show).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ reason: 'unpaired', site: undefined })));
    connection.onMessage.emit({ type: 'generation', generation: 'current', ready: true });
    expect(operations()).toHaveLength(1);
    expect(channel.close).not.toHaveBeenCalled();
  });
  it('retries the same request within the original deadline', async () => {
    sent();
    await vi.waitFor(() => expect(h.dialog.show).toHaveBeenCalled());
    await vi.advanceTimersByTimeAsync(5000);
    chosen()('retry');
    expect(operations()).toHaveLength(2);
    expect(operations()[1]).toMatchObject({ id: 'request', generation: 'current' });
    // The dialog appeared within the first fraction of a second of the 60 s request.
    expect(operations()[1].options.timeout_ms).toBeGreaterThan(54000);
    expect(operations()[1].options.timeout_ms).toBeLessThanOrEqual(55000);
  });
  it('hands the request to the browser or cancels it on request', async () => {
    let channel = sent();
    await vi.waitFor(() => expect(h.dialog.show).toHaveBeenCalledTimes(1));
    chosen()('browser');
    expect(channel.postMessage).toHaveBeenCalledWith({ type: 'fallback', reason: 'user-chose-browser', id: 'request' });
    channel = sent();
    await vi.waitFor(() => expect(h.dialog.show).toHaveBeenCalledTimes(2));
    chosen()('cancel');
    expect(channel.postMessage).toHaveBeenCalledWith(expect.objectContaining({ type: 'error', name: 'NotAllowedError', id: 'request' }));
  });
  it('follows the setting without asking', async () => {
    h.settings.passkeyUnavailable = 'cancel';
    const channel = sent();
    await vi.waitFor(() => expect(channel.close).toHaveBeenCalled());
    expect(channel.postMessage).toHaveBeenCalledWith(expect.objectContaining({ type: 'error', name: 'NotAllowedError' }));
    expect(h.dialog.show).not.toHaveBeenCalled();
  });
  it('closes the dialog when the page aborts the request', async () => {
    const channel = sent();
    await vi.waitFor(() => expect(h.dialog.show).toHaveBeenCalled());
    channel.onmessage!({ data: { type: 'cancel', id: 'request' } });
    expect(h.dialog.close).toHaveBeenCalled();
    expect(channel.postMessage).toHaveBeenCalledWith(expect.objectContaining({ type: 'error', name: 'AbortError' }));
  });
});
