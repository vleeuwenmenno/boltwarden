import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => {
  const event = () => ({ listeners: [] as Array<(...args: any[]) => any>,
    addListener(callback: (...args: any[]) => any) { this.listeners.push(callback); },
    removeListener(callback: (...args: any[]) => any) { this.listeners = this.listeners.filter(value => value !== callback); },
    emit(...args: any[]) { return this.listeners.map(callback => callback(...args)); } });
  return { event, browser: { runtime: { id: 'extension', onMessage: event(), connect: vi.fn() } } };
});
vi.mock('wxt/browser', () => ({ browser: h.browser }));
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

beforeEach(() => { vi.useFakeTimers(); vi.clearAllMocks(); h.browser.runtime.onMessage.listeners.length = 0; connection = setup(); });
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); vi.unstubAllGlobals(); });

describe('passkey relay document readiness', () => {
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
  it('falls back promptly when no trusted readiness arrives and never sends the queued request later', async () => {
    const channel = request();
    connection.onMessage.emit({ type: 'generation', generation: 'unknown', ready: false });
    await vi.advanceTimersByTimeAsync(1500);
    expect(channel.postMessage).toHaveBeenCalledWith({ type: 'fallback', id: 'request' });
    connection.onMessage.emit({ type: 'generation', generation: 'unknown', ready: true });
    expect(connection.postMessage.mock.calls.some(([message]) => message.type === 'operation')).toBe(false);
  });
});
