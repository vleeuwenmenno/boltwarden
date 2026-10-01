import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { normalize, credential } from '../lib/passkey-page';
import { decode, isOperation, isPasskeyResult, PASSKEY_PORT, type PasskeyResult } from '../lib/passkey-types';
import { NativeError } from '../lib/protocol';
import type { NativeClient } from '../lib/native';

const h = vi.hoisted(() => {
  const event = () => ({ listeners: [] as Array<(...args: any[]) => any>, addListener(callback: (...args: any[]) => any) { this.listeners.push(callback); }, emit(...args: any[]) { return this.listeners.map(callback => callback(...args)); } });
  const browser = {
    runtime: { id: 'extension', onConnect: event() },
    webRequest: { onBeforeRequest: event(), onHeadersReceived: event(), onBeforeRedirect: event(), onErrorOccurred: event() },
    webNavigation: { onBeforeNavigate: event(), onErrorOccurred: event(), onCommitted: event(), onCompleted: event(), onHistoryStateUpdated: event(), onReferenceFragmentUpdated: event(), getFrame: vi.fn() },
    tabs: { sendMessage: vi.fn(), query: vi.fn(), get: vi.fn(), onRemoved: event(), onActivated: event() },
    windows: { onFocusChanged: event(), WINDOW_ID_NONE: -1 },
  };
  return { browser, event };
});
vi.mock('wxt/browser', () => ({ browser: h.browser }));
import { installPasskeyBroker, policyAllows } from '../lib/passkey-background';
const get = { publicKey: { challenge: Uint8Array.of(1, 2, 3) } };
const create: CredentialCreationOptions = { publicKey: { challenge: Uint8Array.of(1, 2, 3), rp: { name: 'Example' },
  user: { id: Uint8Array.of(4), name: 'alice', displayName: 'Alice' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }] } };
const result: PasskeyResult = { type: 'PasskeyResult', kind: 'get', credential_id: 'AQID', client_data_json: 'BAUG',
  authenticator_data: 'BwgJ', signature: 'CgsM', user_handle: null, document_id: 'doc', epoch: 1 };
afterEach(() => { vi.unstubAllGlobals(); });

describe('WebAuthn serialization boundary', () => {
  it('preserves BufferSource offsets and clamps the browser timeout', () => {
    const source = Uint8Array.of(99, 1, 2, 3, 99);
    const operation = normalize('get', { publicKey: { challenge: source.subarray(1, 4), timeout: 999_999 } });
    expect(operation?.options.challenge).toBe('AQID'); expect(operation?.options.timeout_ms).toBe(60000);
    source[1] = 88; expect(operation?.options.challenge).toBe('AQID');
    expect(normalize('get', { publicKey: { challenge: new DataView(source.buffer, 2, 2), timeout: 0 } })?.options.timeout_ms).toBe(1000);
  });
  it('delegates conditional, unsupported extensions, attestation and algorithms to the browser', () => {
    expect(normalize('get', { ...get, mediation: 'conditional' })).toBeNull();
    expect(normalize('get', { publicKey: { ...get.publicKey, extensions: { appid: 'https://example.com' } } })).toBeNull();
    expect(normalize('create', { publicKey: { ...create.publicKey!, attestation: 'direct' } })).toBeNull();
    expect(normalize('create', { publicKey: { ...create.publicKey!, pubKeyCredParams: [{ type: 'public-key', alg: -257 }] } })).toBeNull();
    expect(normalize('create', create)?.kind).toBe('create');
  });
  it('bounds untrusted descriptors and response fields', () => {
    expect(normalize('get', { publicKey: { ...get.publicKey, allowCredentials: [{ type: 'public-key', id: new Uint8Array(1024) }] } })).toBeNull();
    expect(isOperation({ ...normalize('get', get), options: { ...normalize('get', get)?.options, timeout_ms: 60001 } })).toBe(false);
    expect(isPasskeyResult(result)).toBe(true); expect(isPasskeyResult({ ...result, signature: 'bad=' })).toBe(false);
    expect(isPasskeyResult({ ...result, epoch: Number.MAX_SAFE_INTEGER + 1 })).toBe(false);
  });
  it('reconstructs normal prototypes and methods without native internal-slot claims', () => {
    class PublicKeyCredential {} class AuthenticatorAssertionResponse {} class AuthenticatorAttestationResponse {}
    vi.stubGlobal('PublicKeyCredential', PublicKeyCredential); vi.stubGlobal('AuthenticatorAssertionResponse', AuthenticatorAssertionResponse); vi.stubGlobal('AuthenticatorAttestationResponse', AuthenticatorAttestationResponse);
    const assertion = credential(result);
    expect(assertion).toBeInstanceOf(PublicKeyCredential); expect(assertion.response).toBeInstanceOf(AuthenticatorAssertionResponse);
    expect(assertion.rawId).toEqual(decode('AQID')); expect((assertion.toJSON().response as any).userHandle).toBeNull();
    const registration = credential({ ...result, kind: 'create', attestation_object: 'AQID', public_key: 'BAUG', public_key_algorithm: -7, transports: ['internal'], cred_props: true });
    const response = registration.response as globalThis.AuthenticatorAttestationResponse;
    expect(response).toBeInstanceOf(AuthenticatorAttestationResponse); expect(response.getPublicKeyAlgorithm()).toBe(-7);
    const transports = response.getTransports(); transports.push('usb'); expect(response.getTransports()).toEqual(['internal']);
    expect(registration.getClientExtensionResults()).toEqual({ credProps: { rk: true } });
  });
});

describe('trusted passkey broker', () => {
  let native: { snapshot: { state: string; epoch: number }; connect: ReturnType<typeof vi.fn>; request: ReturnType<typeof vi.fn> };
  let broker: ReturnType<typeof installPasskeyBroker>;
  const tab = { id: 1, windowId: 10, active: true, url: 'https://example.com/login' };
  beforeEach(() => {
    vi.clearAllMocks();
    for (const group of Object.values(h.browser)) for (const value of Object.values(group)) if (value && typeof value === 'object' && 'listeners' in value) value.listeners.length = 0;
    h.browser.tabs.get.mockResolvedValue(tab); h.browser.tabs.query.mockResolvedValue([tab]);
    h.browser.webNavigation.getFrame.mockResolvedValue({ url: tab.url, documentId: 'doc' });
    native = { snapshot: { state: 'ready', epoch: 1 }, connect: vi.fn(async () => {}), request: vi.fn(async request => ({ ...result, document_id: request.document_id })) };
    broker = installPasskeyBroker(native as unknown as NativeClient);
  });
  function port(overrides = {}, timing = { navigation_start: 1, response_start: 1000 }, autoComplete = true) {
    const messages: any[] = [];
    let queued: Record<string, unknown> | undefined;
    const emit = (extra: Record<string, unknown>) => connection.onMessage.emit({ type: 'operation', id: 'request',
      generation: messages.filter(message => message.type === 'generation').at(-1)?.generation,
      ...normalize('get', get), visible: true, policy_allowed: true, ...extra });
    const token = crypto.randomUUID(); h.browser.tabs.sendMessage.mockResolvedValue({ token });
    const connection = { name: PASSKEY_PORT, sender: { id: 'extension', frameId: 0, url: tab.url, origin: 'https://example.com', tab, documentId: 'doc', ...overrides },
      onMessage: h.event(), onDisconnect: h.event(), disconnect: vi.fn(), postMessage: (message: any) => {
        messages.push(message);
        if (message.type === 'generation' && message.ready && queued) { const next = queued; queued = undefined; emit(next); }
      } };
    h.browser.runtime.onConnect.emit(connection);
    connection.onMessage.emit({ type: 'identify', token, ...timing });
    if (autoComplete) h.browser.webNavigation.onCompleted.emit({ tabId: 1, frameId: 0, url: tab.url, timeStamp: timing.response_start + 1 });
    return { connection, messages, token, call(extra = {}) {
      if (messages.filter(message => message.type === 'generation').at(-1)?.ready) emit(extra);
      else queued = extra;
    } };
  }
  it('derives all URLs and document identity from browser metadata, including Firefox without origin', async () => {
    const page = port({ origin: undefined }); page.call({ top_url: 'https://evil.com', frame_url: 'https://evil.com', document_id: 'spoof' });
    await vi.waitFor(() => expect(page.messages.at(-1)?.type).toBe('result'));
    expect(native.request.mock.calls[0]![0]).toMatchObject({ top_url: tab.url, frame_url: tab.url, document_id: page.messages[0].generation });
    for (const sender of [{ origin: 'null' }, { origin: 'https://evil.com' }, { frameId: 2 }, { id: 'other' }, { url: 'http://example.com' }]) expect(port(sender).connection.disconnect).toHaveBeenCalled();
  });
  it('requires a known policy when the isolated DOM has no policy API', async () => {
    const page = port({}, { navigation_start: 1, response_start: 20 }); page.call({ policy_allowed: undefined });
    await vi.waitFor(() => expect(page.messages.at(-1)?.type).toBe('fallback'), { timeout: 2000 }); expect(native.request).not.toHaveBeenCalled();
    h.browser.webRequest.onBeforeRequest.emit({ tabId: 1, requestId: 'response', url: tab.url, timeStamp: 40 });
    h.browser.webRequest.onHeadersReceived.emit({ tabId: 1, requestId: 'response', url: tab.url, responseHeaders: [] });
    const replacement = port({}, { navigation_start: 30, response_start: 50 }); replacement.call({ policy_allowed: undefined });
    await vi.waitFor(() => expect(replacement.messages.at(-1)?.type).toBe('result'));
  });
  it('waits for late Firefox response headers bound to the observed request', async () => {
    h.browser.webRequest.onBeforeRequest.emit({ tabId: 1, requestId: 'response', url: tab.url, timeStamp: 10 });
    const page = port({ origin: undefined }); page.call({ policy_allowed: undefined });
    await Promise.resolve(); await Promise.resolve(); expect(native.request).not.toHaveBeenCalled();
    h.browser.webRequest.onHeadersReceived.emit({ tabId: 1, requestId: 'response', url: tab.url, responseHeaders: [] });
    await vi.waitFor(() => expect(page.messages.at(-1)?.type).toBe('result'));
  });
  it('never gives a same-URL replacement the prior request permissions', async () => {
    h.browser.webRequest.onBeforeRequest.emit({ tabId: 1, requestId: 'old', url: tab.url, timeStamp: 10 });
    const old = port(); old.call({ policy_allowed: undefined });
    await Promise.resolve(); await Promise.resolve();
    h.browser.webRequest.onBeforeRequest.emit({ tabId: 1, requestId: 'new', url: tab.url, timeStamp: 20 });
    const replacement = port(); replacement.call({ policy_allowed: undefined });
    h.browser.webRequest.onHeadersReceived.emit({ tabId: 1, requestId: 'old', url: tab.url, responseHeaders: [] });
    await Promise.resolve(); await Promise.resolve(); expect(native.request).not.toHaveBeenCalled();
    h.browser.webRequest.onHeadersReceived.emit({ tabId: 1, requestId: 'new', url: tab.url,
      responseHeaders: [{ name: 'Permissions-Policy', value: 'publickey-credentials-get=()' }] });
    await vi.waitFor(() => expect(replacement.messages.at(-1)?.type).toBe('fallback'), { timeout: 2000 });
    expect(native.request).not.toHaveBeenCalled();
    expect(old.messages.some(message => message.type === 'result')).toBe(false);
  });
  it('rejects old same-URL policy when replacement port arrives before its request event', async () => {
    h.browser.webRequest.onBeforeRequest.emit({ tabId: 1, requestId: 'old', url: tab.url, timeStamp: 10 });
    h.browser.webRequest.onHeadersReceived.emit({ tabId: 1, requestId: 'old', url: tab.url, responseHeaders: [] });
    port({}, { navigation_start: 1, response_start: 20 });
    const replacement = port({}, { navigation_start: 30, response_start: 50 });
    replacement.call({ policy_allowed: undefined });
    await vi.waitFor(() => expect(replacement.messages.at(-1)?.type).toBe('fallback'), { timeout: 2000 });
    expect(native.request).not.toHaveBeenCalled();
  });
  it('pins a response to one relay lifetime even if rounded navigation intervals overlap', async () => {
    h.browser.webRequest.onBeforeRequest.emit({ tabId: 1, requestId: 'old', url: tab.url, timeStamp: 10 });
    h.browser.webRequest.onHeadersReceived.emit({ tabId: 1, requestId: 'old', url: tab.url, responseHeaders: [] });
    port(); const replacement = port(); replacement.call({ policy_allowed: undefined });
    await vi.waitFor(() => expect(replacement.messages.at(-1)?.type).toBe('fallback'), { timeout: 2000 });
    expect(native.request).not.toHaveBeenCalled();
  });
  it('keeps explicit denial separate from native fallback', async () => {
    native.request.mockRejectedValueOnce(new NativeError('NotAllowedError', 'Declined'));
    const page = port(); page.call(); await vi.waitFor(() => expect(page.messages.at(-1)).toMatchObject({ type: 'error', name: 'NotAllowedError' }));
    native.request.mockRejectedValueOnce(new NativeError('FallbackRequested', 'Other device'));
    page.call(); await vi.waitFor(() => expect(page.messages.at(-1)?.type).toBe('fallback'), { timeout: 2000 });
  });
  it('ignores MatchesChanged and desktop focus loss but aborts document replacement', async () => {
    let signal: AbortSignal | undefined;
    native.request.mockImplementation((_request, abortSignal) => new Promise((_resolve, reject) => { signal = abortSignal; abortSignal.addEventListener('abort', () => reject(abortSignal.reason)); }));
    const page = port(); page.call(); await vi.waitFor(() => expect(signal).toBeDefined());
    broker.nativeChanged({ state: 'ready', epoch: 1 }, { type: 'MatchesChanged', epoch: 1 }); h.browser.windows.onFocusChanged.emit(-1);
    expect(signal?.aborted).toBe(false);
    h.browser.webNavigation.onBeforeNavigate.emit({ tabId: 1, frameId: 0 });
    await vi.waitFor(() => expect(page.messages.some(message => message.type === 'error' && message.name === 'AbortError')).toBe(true)); expect(signal?.aborted).toBe(true);
  });
  it('aborts a pending ceremony when a ready vault changes epoch', async () => {
    let signal: AbortSignal | undefined;
    native.request.mockImplementation((_request, abortSignal) => new Promise((_resolve, reject) => {
      signal = abortSignal; abortSignal.addEventListener('abort', () => reject(abortSignal.reason));
    }));
    const page = port(); page.call(); await vi.waitFor(() => expect(signal).toBeDefined());
    // NativeClient updates its snapshot before delivering the event. Comparing
    // with that current snapshot would miss the request's original epoch.
    native.snapshot = { state: 'ready', epoch: 2 };
    broker.nativeChanged({ state: 'ready', epoch: 2 }, { type: 'Unlocked', epoch: 2 });
    await vi.waitFor(() => expect(page.messages.at(-1)).toMatchObject({ type: 'error', name: 'AbortError' }));
    expect(signal?.aborted).toBe(true);
    expect(page.messages.some(message => message.type === 'fallback' || message.type === 'result')).toBe(false);
  });
  it('keeps a pending ceremony through same-epoch ready and match updates', async () => {
    let signal: AbortSignal | undefined;
    let complete: (() => void) | undefined;
    native.request.mockImplementation((request, abortSignal) => new Promise((resolve, reject) => {
      signal = abortSignal; complete = () => resolve({ ...result, document_id: request.document_id });
      abortSignal.addEventListener('abort', () => reject(abortSignal.reason));
    }));
    const page = port(); page.call(); await vi.waitFor(() => expect(complete).toBeDefined());
    broker.nativeChanged({ state: 'ready', epoch: 1 }, { type: 'Unlocked', epoch: 1 });
    broker.nativeChanged({ state: 'ready', epoch: 1 }, { type: 'MatchesChanged', epoch: 1 });
    expect(signal?.aborted).toBe(false); complete!();
    await vi.waitFor(() => expect(page.messages.at(-1)?.type).toBe('result'));
  });
  it('captures the request epoch after a legitimate unlock instead of cancelling it', async () => {
    native.snapshot = { state: 'locked', epoch: 1 };
    let unlockSignal: AbortSignal | undefined;
    native.request.mockImplementation(async (request, abortSignal) => {
      if (request.type === 'RequestUnlock') { unlockSignal = abortSignal; return { type: 'UnlockRequested' }; }
      return { ...result, document_id: request.document_id, epoch: 2 };
    });
    const page = port(); page.call(); await vi.waitFor(() => expect(unlockSignal).toBeDefined());
    native.snapshot = { state: 'ready', epoch: 2 };
    broker.nativeChanged({ state: 'ready', epoch: 2 }, { type: 'Unlocked', epoch: 2 });
    await vi.waitFor(() => expect(page.messages.at(-1)?.type).toBe('result'));
    expect(unlockSignal?.aborted).toBe(false);
    expect(native.request.mock.calls.map(([request]) => request.type)).toEqual(['RequestUnlock', 'PasskeyGet']);
  });
  it('recovers a surviving document after failed navigation without accepting stale failures', async () => {
    const page = port();
    h.browser.webNavigation.onBeforeNavigate.emit({ tabId: 1, frameId: 0, url: 'https://example.com/failed' });
    h.browser.webNavigation.onErrorOccurred.emit({ tabId: 1, frameId: 0, url: 'https://example.com/older' });
    await Promise.resolve(); expect(page.messages.filter(message => message.type === 'generation')).toHaveLength(2);
    h.browser.webNavigation.onErrorOccurred.emit({ tabId: 1, frameId: 0, url: 'https://example.com/failed' });
    await vi.waitFor(() => expect(page.messages.filter(message => message.type === 'generation')).toHaveLength(3));
    page.call({ generation: page.messages.at(-1).generation });
    await vi.waitFor(() => expect(page.messages.at(-1)?.type).toBe('result'));
  });
  it('recovers a fresh Firefox port after delayed navigation events and ignores older completion', async () => {
    const page = port({ documentId: undefined, origin: undefined }, { navigation_start: 100, response_start: 120 }, false);
    h.browser.webNavigation.onBeforeNavigate.emit({ tabId: 1, frameId: 0, url: tab.url, timeStamp: 100 });
    h.browser.webRequest.onBeforeRequest.emit({ tabId: 1, requestId: 'new', url: tab.url, timeStamp: 110 });
    h.browser.webNavigation.onCompleted.emit({ tabId: 1, frameId: 0, url: tab.url, timeStamp: 90 });
    expect(h.browser.tabs.sendMessage).not.toHaveBeenCalled();
    h.browser.webRequest.onHeadersReceived.emit({ tabId: 1, requestId: 'new', url: tab.url, responseHeaders: [] });
    h.browser.webNavigation.onCompleted.emit({ tabId: 1, frameId: 0, url: tab.url, timeStamp: 150 });
    page.call({ generation: page.messages.at(-1).generation, policy_allowed: undefined });
    await vi.waitFor(() => expect(page.messages.at(-1)?.type).toBe('result'));
    expect(h.browser.tabs.sendMessage).toHaveBeenCalledWith(1, { type: 'passkey-document-check' }, { frameId: 0 });
  });
  it('announces readiness only after a current-token completion newer than this navigation', async () => {
    const page = port({ documentId: undefined }, { navigation_start: 100, response_start: 120 }, false);
    expect(page.messages.at(-1)).toMatchObject({ type: 'generation', ready: false });
    h.browser.webNavigation.onCompleted.emit({ tabId: 1, frameId: 0, url: tab.url, timeStamp: 90 });
    await Promise.resolve(); expect(page.messages.some(message => message.ready)).toBe(false);
    h.browser.webNavigation.onCompleted.emit({ tabId: 1, frameId: 0, url: tab.url, timeStamp: 140 });
    await vi.waitFor(() => expect(page.messages.at(-1)).toMatchObject({ type: 'generation', ready: true }));
    const generation = page.messages.at(-1).generation;
    h.browser.webNavigation.onBeforeNavigate.emit({ tabId: 1, frameId: 0, url: tab.url, timeStamp: 105 });
    await Promise.resolve(); expect(page.messages.at(-1).generation).toBe(generation);
    page.call(); await vi.waitFor(() => expect(page.messages.at(-1)?.type).toBe('result'));
  });
  it('rejects a retired same-URL Firefox document after the native response', async () => {
    const page = port({ documentId: undefined, origin: undefined });
    native.request.mockImplementation(async request => { h.browser.tabs.sendMessage.mockResolvedValue({ token: 'replacement' }); return { ...result, document_id: request.document_id }; });
    page.call();
    await vi.waitFor(() => expect(page.messages.at(-1)).toMatchObject({ type: 'error', name: 'AbortError' }));
    expect(page.messages.some(message => message.type === 'result')).toBe(false);
  });
  it('does not release a result when the browser switches active tabs during the RPC', async () => {
    native.request.mockImplementation(async request => { h.browser.tabs.query.mockResolvedValue([{ id: 2 }]); return { ...result, document_id: request.document_id }; });
    const page = port(); page.call(); await vi.waitFor(() => expect(page.messages.at(-1)).toMatchObject({ type: 'error', name: 'AbortError' }));
    expect(page.messages.some(message => message.type === 'result')).toBe(false);
  });
});

describe('conservative response policy fallback', () => {
  const policy = (value: string) => policyAllows([{ name: 'Permissions-Policy', value }], 'https://example.com', 'get');
  it('allows default self, wildcard and explicit own origin', () => {
    for (const value of ['', 'camera=()', 'publickey-credentials-get=*', 'publickey-credentials-get=(self)', 'publickey-credentials-get=("https://example.com")']) expect(policy(value)).toBe(true);
  });
  it('delegates denials, malformed directives and duplicate restrictions to native browser', () => {
    for (const value of ['publickey-credentials-get=()', 'publickey-credentials-get=("https://other.com")', 'publickey-credentials-get=(self garbage)', 'publickey-credentials-get=self', 'publickey-credentials-get=*, publickey-credentials-get=()']) expect(policy(value)).toBe(false);
    expect(policyAllows([{ name: 'Feature-Policy', value: "publickey-credentials-get 'none'" }], 'https://example.com', 'get')).toBe(false);
  });
});
