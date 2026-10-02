import { beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => {
  const event = () => ({ listeners: [] as Array<(...args: any[]) => any>, addListener(callback: (...args: any[]) => any) { this.listeners.push(callback); }, emit(...args: any[]) { return this.listeners.map(callback => callback(...args)); } });
  const browser = {
    runtime: { id: 'extension', onConnect: event(), onMessage: event(), getURL: (path: string) => `chrome-extension://extension${path}`, connectNative: vi.fn() },
    storage: { session: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, local: { get: vi.fn(), set: vi.fn() } },
    action: { setBadgeText: vi.fn(async () => {}), setTitle: vi.fn(async () => {}), openPopup: vi.fn(async () => {}) },
    webRequest: { onBeforeRequest: event(), onHeadersReceived: event(), onBeforeRedirect: event(), onErrorOccurred: event() },
    webNavigation: { onBeforeNavigate: event(), onErrorOccurred: event(), onCommitted: event(), onCompleted: event(), onDOMContentLoaded: event(), onHistoryStateUpdated: event(), onReferenceFragmentUpdated: event(), getFrame: vi.fn() },
    tabs: { sendMessage: vi.fn(), query: vi.fn(), get: vi.fn(), onRemoved: event(), onActivated: event() },
    windows: { onFocusChanged: event(), WINDOW_ID_NONE: -1 }, commands: { onCommand: event() },
  };
  const native = { snapshot: { state: 'ready', epoch: 1 }, connect: vi.fn(async () => {}), refreshStatus: vi.fn(async () => {}), request: vi.fn(), pair: vi.fn(), onChange: (_snapshot: any, _event?: any) => {} };
  return { browser, native, event };
});
vi.mock('wxt/browser', () => ({ browser: h.browser }));
vi.mock('wxt/utils/define-background', () => ({ defineBackground: (main: unknown) => main }));
vi.mock('../lib/native', () => ({ NativeClient: class { constructor() { return h.native; } } }));
vi.mock('../lib/pairing', () => ({ publicIdentity: async () => ({ fingerprint: 'TEST' }) }));
import main from '../entrypoints/background';

const one = { id: 'login', name: 'Example', username: 'alice', reprompt: false, requires_confirmation: false, revision: '1' };
let tab: { id: number; windowId: number; active: boolean; url: string };
beforeEach(() => {
  vi.clearAllMocks();
  for (const group of Object.values(h.browser)) for (const value of Object.values(group)) {
    if (value && typeof value === 'object' && 'listeners' in value) value.listeners.length = 0;
  }
  tab = { id: 1, windowId: 10, active: true, url: 'https://example.com/login' };
  h.native.snapshot = { state: 'ready', epoch: 1 };
  h.browser.tabs.query.mockImplementation(async () => [tab]); h.browser.tabs.get.mockImplementation(async () => tab);
  h.browser.webNavigation.getFrame.mockImplementation(async () => ({ url: tab.url, documentId: 'doc' }));
  h.native.request.mockImplementation(async (request: any) => request.type === 'ListMatches'
    ? { type: 'Matches', items: [one], epoch: h.native.snapshot.epoch, next_offset: null }
    : { type: 'Credentials', username: 'alice', password: 'secret', document_id: request.document_id, epoch: h.native.snapshot.epoch });
  (main as unknown as () => void)();
});
function documentPort(frameId = 0, url = tab.url, origin = new URL(url).origin, inspection: { token?: string | null; focused?: boolean; formCount?: number; kind?: string } = {}) {
  const messages: any[] = [];
  const onMessage = h.event(), onDisconnect = h.event();
  const port = { name: 'boltwarden-document-v1', sender: { id: 'extension', tab, frameId, url, origin, documentId: 'doc' }, onMessage, onDisconnect,
    disconnect: vi.fn(), postMessage(message: any) {
      messages.push(message);
      if (message.type === 'inspect') queueMicrotask(() => onMessage.emit({ ...message, type: 'inspected', token: 'target', focused: true, formCount: 1, ...inspection }));
      if (message.type === 'fill') queueMicrotask(() => onMessage.emit({ ...message, type: 'filled' }));
    } };
  h.browser.runtime.onConnect.emit(port);
  return { port, messages };
}
function ui(message: object, url = 'chrome-extension://extension/popup.html') {
  return h.browser.runtime.onMessage.emit(message, { id: 'extension', url })[0];
}
function uiPort(url = 'chrome-extension://extension/popup.html', id = 'extension') {
  const messages: any[] = [];
  const port = { name: 'boltwarden-ui-v1', sender: { id, url }, onMessage: h.event(), onDisconnect: h.event(),
    disconnect: vi.fn(), postMessage: (message: any) => messages.push(message) };
  h.browser.runtime.onConnect.emit(port);
  return { port, messages };
}
let inlineId = 0;
function sendInline(document: ReturnType<typeof documentPort>, action: string, fields: Record<string, unknown> = {}) {
  const id = `inline-${++inlineId}`;
  const generation = document.messages.findLast(message => message.type === 'generation')?.generation;
  document.port.onMessage.emit({ type: 'inline-request', id, generation, action, token: 'target', ...fields });
  return id;
}
async function inline(document: ReturnType<typeof documentPort>, action: string, fields: Record<string, unknown> = {}) {
  const id = sendInline(document, action, fields);
  await vi.waitFor(() => expect(document.messages.some(message => message.type === 'inline-response' && message.id === id)).toBe(true));
  return document.messages.find(message => message.type === 'inline-response' && message.id === id);
}
async function shortcut() { h.browser.commands.onCommand.emit('autofill'); await vi.waitFor(() => expect(h.native.request).toHaveBeenCalled()); }
const fillCalls = () => h.native.request.mock.calls.filter(([request]) => request.type === 'FillLogin');

describe('trusted document routing', () => {
  it('rejects UI subscriptions from websites, other extensions, and unrecognized extension pages', () => {
    for (const [url, id] of [[tab.url, 'extension'], ['chrome-extension://extension/popup.html', 'other'],
      ['chrome-extension://extension/popup.html?spoof', 'extension']]) {
      const { port, messages } = uiPort(url, id);
      expect(port.disconnect).toHaveBeenCalledOnce(); expect(messages).toHaveLength(0);
    }
    expect(uiPort('chrome-extension://extension/options.html').messages).toEqual([
      { type: 'state-changed', reason: 'state', connection: { state: 'ready', epoch: 1 } },
    ]);
  });
  it('pushes native changes without a feedback loop from unchanged status responses', () => {
    const { port, messages } = uiPort();
    h.native.onChange(h.native.snapshot);
    expect(messages).toHaveLength(1);
    h.native.snapshot = { state: 'locked', epoch: 2 }; h.native.onChange(h.native.snapshot, { type: 'Locked', epoch: 2 });
    expect(messages.at(-1)).toMatchObject({ reason: 'state', connection: { state: 'locked', epoch: 2 } });
    h.native.onChange(h.native.snapshot);
    expect(messages).toHaveLength(2);
    h.native.snapshot = { state: 'ready', epoch: 3 }; h.native.onChange(h.native.snapshot, { type: 'Unlocked', epoch: 3 });
    expect(messages.at(-1)).toMatchObject({ reason: 'state', connection: { state: 'ready', epoch: 3 } });
    h.native.onChange(h.native.snapshot, { type: 'MatchesChanged', epoch: 3 });
    expect(messages.at(-1)).toMatchObject({ reason: 'matches' });
    expect(messages).toHaveLength(4);
    port.onDisconnect.emit();
    h.native.snapshot = { state: 'disconnected', epoch: 3 }; h.native.onChange(h.native.snapshot);
    expect(messages).toHaveLength(4);
  });
  it('pushes page invalidation and replacement but not discovery cleanup', async () => {
    const { messages } = uiPort();
    documentPort();
    expect(messages.at(-1)).toMatchObject({ reason: 'page' });
    await ui({ type: 'list' }); const count = messages.length;
    await ui({ type: 'list' });
    expect(messages).toHaveLength(count);
    h.browser.webNavigation.onBeforeNavigate.emit({ tabId: 1, frameId: 0, url: 'https://example.com/other' });
    expect(messages).toHaveLength(count + 1);
    expect(messages.at(-1)).toMatchObject({ reason: 'page' });
    documentPort();
    expect(messages).toHaveLength(count + 2);
    h.browser.tabs.onActivated.emit({ tabId: 2 });
    expect(messages.at(-1)).toMatchObject({ reason: 'page' });
  });
  it('rejects opaque/mismatched origins and page messages posing as popup actions', async () => {
    const { port } = documentPort(0, tab.url, 'null');
    expect(port.disconnect).toHaveBeenCalledOnce();
    expect(ui({ type: 'pair' }, tab.url)).toBeUndefined();
    expect(h.native.pair).not.toHaveBeenCalled();
  });
  it('fills exactly one eligible shortcut match using background-derived URLs', async () => {
    const { messages } = documentPort(); await shortcut();
    await vi.waitFor(() => expect(messages.filter(value => value.type === 'fill')).toHaveLength(1));
    expect(fillCalls()[0]?.[0]).toMatchObject({ interaction: 'shortcut', top_url: tab.url, frame_url: tab.url, item_id: 'login' });
  });
  it('opens the picker without requesting credentials for multiple matches', async () => {
    documentPort();
    h.native.request.mockResolvedValue({ type: 'Matches', items: [one, { ...one, id: 'two' }], epoch: 1, next_offset: null });
    await shortcut(); await vi.waitFor(() => expect(h.browser.action.openPopup).toHaveBeenCalledOnce());
    expect(fillCalls()).toHaveLength(0);
  });
  it('requires popup interaction for reprompt items', async () => {
    documentPort();
    h.native.request.mockResolvedValue({ type: 'Matches', items: [{ ...one, reprompt: true }], epoch: 1, next_offset: null });
    await shortcut(); await vi.waitFor(() => expect(h.browser.action.openPopup).toHaveBeenCalledOnce());
    expect(fillCalls()).toHaveLength(0);
  });
  it('discards delayed credentials after same-origin navigation', async () => {
    const { messages } = documentPort();
    let complete!: (response: any) => void;
    h.native.request.mockImplementation(async (request: any) => request.type === 'ListMatches'
      ? { type: 'Matches', items: [one], epoch: 1, next_offset: null }
      : new Promise(resolve => { complete = resolve; }));
    await shortcut(); await vi.waitFor(() => expect(fillCalls()).toHaveLength(1));
    const request = fillCalls()[0]![0];
    h.browser.webNavigation.onBeforeNavigate.emit({ tabId: 1, frameId: 0, url: 'https://example.com/other' });
    tab.url = 'https://example.com/other';
    complete({ type: 'Credentials', username: 'alice', password: 'secret', epoch: 1, document_id: request.document_id });
    await vi.waitFor(() => expect(h.browser.action.setTitle).toHaveBeenCalledWith(expect.objectContaining({ title: expect.stringContaining('page changed') })));
    expect(messages.some(value => value.type === 'fill')).toBe(false);
  });
  it('rediscovers a surviving document after an aborted navigation without reusing old targets', async () => {
    const { messages } = documentPort();
    const before = await ui({ type: 'list' }); const oldTarget = before.value.frames[0].targetId;
    const details = { tabId: 1, frameId: 0, url: 'https://example.com/aborted' };
    h.browser.webNavigation.onBeforeNavigate.emit(details);
    const navigationGeneration = messages.at(-1).generation;
    h.browser.webNavigation.onErrorOccurred.emit(details);
    await vi.waitFor(() => expect(messages.at(-1).generation).not.toBe(navigationGeneration));
    const stale = await ui({ type: 'fill', targetId: oldTarget, itemId: 'login' });
    expect(stale.ok).toBe(false); expect(fillCalls()).toHaveLength(0);
    const after = await ui({ type: 'list' });
    expect(after.ok).toBe(true); expect(after.value.frames).toHaveLength(1);
    expect(after.value.frames[0].targetId).not.toBe(oldTarget);
  });
  it.each([
    { url: 'https://example.com/replacement', documentId: 'doc' },
    { url: 'https://example.com/login', documentId: 'replacement' },
  ])('does not revive a navigation when trusted frame identity changed: %j', async frame => {
    const { messages } = documentPort();
    const details = { tabId: 1, frameId: 0, url: 'https://example.com/aborted' };
    h.browser.webNavigation.onBeforeNavigate.emit(details);
    const generation = messages.at(-1).generation;
    h.browser.webNavigation.getFrame.mockResolvedValue(frame);
    h.browser.webNavigation.onErrorOccurred.emit(details);
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(messages.at(-1).generation).toBe(generation);
    const result = await ui({ type: 'list' });
    expect(result.value.frames).toEqual([]); expect(h.native.request).not.toHaveBeenCalled();
  });
  it('does not let a delayed failed-navigation check recover a newer navigation', async () => {
    const { messages } = documentPort();
    const first = { tabId: 1, frameId: 0, url: 'https://example.com/first' };
    h.browser.webNavigation.onBeforeNavigate.emit(first);
    let complete!: (frame: any) => void;
    h.browser.webNavigation.getFrame.mockImplementation(() => new Promise(resolve => { complete = resolve; }));
    h.browser.webNavigation.onErrorOccurred.emit(first);
    h.browser.webNavigation.onBeforeNavigate.emit({ ...first, url: 'https://example.com/second' });
    const generation = messages.at(-1).generation;
    complete({ url: tab.url, documentId: 'doc' });
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(messages.at(-1).generation).toBe(generation);
    const result = await ui({ type: 'list' });
    expect(result.value.frames).toEqual([]); expect(h.native.request).not.toHaveBeenCalled();
  });
  it('clears stale summaries while allowing a sync during an active fill', async () => {
    const { messages } = documentPort();
    const original = h.native.request.getMockImplementation()!;
    h.native.request.mockImplementation(async (request: any, signal: AbortSignal) => {
      if (request.type === 'FillLogin') { h.native.snapshot.epoch = 2; h.native.onChange(h.native.snapshot, { type: 'MatchesChanged', epoch: 2 }); expect(signal.aborted).toBe(false); }
      return original(request, signal);
    });
    await shortcut(); await vi.waitFor(() => expect(messages.some(value => value.type === 'fill')).toBe(true));
  });
  it('does not treat desktop approval focus loss as a tab/window switch', async () => {
    const { messages } = documentPort();
    const original = h.native.request.getMockImplementation()!;
    h.native.request.mockImplementation(async (request: any, signal: AbortSignal) => {
      if (request.type === 'FillLogin') { h.browser.windows.onFocusChanged.emit(-1); expect(signal.aborted).toBe(false); }
      return original(request, signal);
    });
    await shortcut(); await vi.waitFor(() => expect(messages.some(value => value.type === 'fill')).toBe(true));
  });
  it('requires confirmation for a cross-origin frame even with the same hostname on another port', async () => {
    const frameUrl = 'https://example.com:8443/login'; documentPort(2, frameUrl);
    h.browser.webNavigation.getFrame.mockResolvedValue({ url: frameUrl, documentId: 'doc' });
    const view = await ui({ type: 'list' });
    expect(view.ok).toBe(true); expect(view.value.frames[0].crossOrigin).toBe(true);
    const result = await ui({ type: 'fill', targetId: view.value.frames[0].targetId, itemId: 'login' });
    expect(result.ok).toBe(false); expect(fillCalls()).toHaveLength(0);
  });
  it('does not fall back to the top form when the focused frame is ambiguous', async () => {
    documentPort(0, tab.url, new URL(tab.url).origin, { focused: false });
    documentPort(2, tab.url, new URL(tab.url).origin, { focused: true, token: null, formCount: 2 });
    await shortcut();
    await vi.waitFor(() => expect(h.browser.action.setTitle).toHaveBeenCalledWith(expect.objectContaining({ title: expect.stringContaining('unambiguous') })));
    expect(fillCalls()).toHaveLength(0);
  });
  it.each(['inspect', 'matches'])('does not fill the top form when a same-origin frame fails %s', async stage => {
    documentPort(0, tab.url, new URL(tab.url).origin, { focused: false });
    const { port } = documentPort(2, tab.url, new URL(tab.url).origin, { focused: true });
    if (stage === 'inspect') {
      const postMessage = port.postMessage;
      port.postMessage = message => {
        if (message.type === 'inspect') queueMicrotask(() => port.onMessage.emit({ ...message, type: 'failure' }));
        else postMessage(message);
      };
    }
    const original = h.native.request.getMockImplementation()!;
    h.native.request.mockImplementation(async (request: any, signal: AbortSignal) => {
      if (stage === 'matches' && request.type === 'ListMatches' && request.document_id.startsWith('1:2:')) throw new Error('Timed out');
      return original(request, signal);
    });
    await shortcut(); await vi.waitFor(() => expect(h.browser.action.openPopup).toHaveBeenCalledOnce());
    expect(fillCalls()).toHaveLength(0);
    const result = await ui({ type: 'list' });
    expect(result.value.frames).toHaveLength(1);
    expect(result.value.warning).toContain('Some frames could not be checked');
  });
  it('does not fill across same-origin frames omitted by the discovery bound', async () => {
    for (let frame = 0; frame < 33; frame++) documentPort(frame, tab.url, new URL(tab.url).origin, { focused: false });
    await shortcut(); await vi.waitFor(() => expect(h.browser.action.openPopup).toHaveBeenCalledOnce());
    expect(fillCalls()).toHaveLength(0);
    expect(h.native.request.mock.calls.filter(([request]) => request.type === 'ListMatches')).toHaveLength(32);
  });
  it('limits matching across many frames to two concurrent daemon requests', async () => {
    for (let frame = 0; frame < 8; frame++) documentPort(frame);
    const original = h.native.request.getMockImplementation()!;
    let concurrent = 0, maximum = 0;
    h.native.request.mockImplementation(async (request: any, signal: AbortSignal) => {
      concurrent++; maximum = Math.max(maximum, concurrent);
      await new Promise(resolve => setTimeout(resolve, 5)); concurrent--;
      return original(request, signal);
    });
    await shortcut(); await vi.waitFor(() => expect(fillCalls()).toHaveLength(1));
    expect(maximum).toBeLessThanOrEqual(2);
  });
  it('discards a delayed credential response when the vault locks', async () => {
    const { messages } = documentPort();
    const original = h.native.request.getMockImplementation()!;
    h.native.request.mockImplementation(async (request: any, signal: AbortSignal) => {
      if (request.type === 'FillLogin') { h.native.snapshot = { state: 'locked', epoch: 2 }; h.native.onChange(h.native.snapshot, { type: 'Locked', epoch: 2 }); expect(signal.aborted).toBe(true); }
      return original(request, signal);
    });
    await shortcut();
    await vi.waitFor(() => expect(h.browser.action.setTitle).toHaveBeenCalledWith(expect.objectContaining({ title: expect.stringContaining('page changed') })));
    expect(messages.some(value => value.type === 'fill')).toBe(false);
  });
});

describe('inline document routing', () => {
  it('lists and fills only the exact pinned form using browser-derived URLs and popup authorization', async () => {
    const document = documentPort();
    const result = await inline(document, 'list', { top_url: 'https://attacker.test', frame_url: 'https://attacker.test' });
    expect(result.ok).toBe(true);
    expect(document.messages.filter(message => message.type === 'inspect').every(message => message.requestedToken === 'target')).toBe(true);
    const filled = await inline(document, 'fill', { targetId: result.value.frame.targetId, itemId: 'login' });
    expect(filled.ok).toBe(true);
    expect(fillCalls()[0]?.[0]).toMatchObject({ top_url: tab.url, frame_url: tab.url, interaction: 'popup', confirm_insecure: false, confirm_cross_origin: false });
    expect(document.messages.filter(message => message.type === 'fill')).toEqual([expect.objectContaining({ token: 'target', scope: 'inline', password: 'secret' })]);
    expect(filled.value).not.toHaveProperty('password');
  });
  it('does not expose inline actions through popup runtime messages or rejected document ports', async () => {
    const invalid = documentPort(0, tab.url, 'null');
    sendInline(invalid, 'list');
    expect(invalid.port.disconnect).toHaveBeenCalledOnce();
    expect(h.native.request).not.toHaveBeenCalled();
    expect(await ui({ type: 'inline-request', action: 'list', token: 'target' })).toMatchObject({ ok: false });
  });
  it.each([{ token: 'different' }, { focused: false }, { token: null }])('refuses a different or unfocused form: %j', async inspection => {
    const document = documentPort(0, tab.url, new URL(tab.url).origin, inspection);
    expect((await inline(document, 'list')).ok).toBe(false);
    expect(h.native.request).not.toHaveBeenCalled();
  });
  it('does not let another document, wrong token or stale generation use a target', async () => {
    const first = documentPort(); const second = documentPort(2);
    const result = await inline(first, 'list');
    await inline(second, 'list');
    expect((await inline(second, 'fill', { targetId: result.value.frame.targetId, itemId: 'login' })).ok).toBe(false);
    expect((await inline(first, 'fill', { targetId: result.value.frame.targetId, itemId: 'login', token: 'other' })).ok).toBe(false);
    const count = first.messages.filter(message => message.type === 'inline-response').length;
    sendInline(first, 'fill', { targetId: result.value.frame.targetId, itemId: 'login', generation: 'old' });
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(first.messages.filter(message => message.type === 'inline-response')).toHaveLength(count);
    expect(fillCalls()).toHaveLength(0);
  });
  it('rejects an item not offered by this target', async () => {
    const document = documentPort(); const result = await inline(document, 'list');
    expect((await inline(document, 'fill', { targetId: result.value.frame.targetId, itemId: 'unlisted' })).ok).toBe(false);
    expect(fillCalls()).toHaveLength(0);
  });
  it.each(['cross-origin', 'downgrade', 'http'])('requires the toolbar for %s even if content supplies confirmation flags', async kind => {
    if (kind === 'http') tab.url = 'http://example.com/login';
    const frameUrl = kind === 'cross-origin' ? 'https://frame.example.net/login' : tab.url;
    const document = documentPort(kind === 'cross-origin' ? 2 : 0, frameUrl);
    h.browser.webNavigation.getFrame.mockResolvedValue({ url: frameUrl, documentId: 'doc' });
    if (kind === 'downgrade') h.native.request.mockResolvedValue({ type: 'Matches', items: [{ ...one, requires_confirmation: true }], epoch: 1, next_offset: null });
    const result = await inline(document, 'list');
    expect(result.ok).toBe(true);
    const denied = await inline(document, 'fill', { targetId: result.value.frame.targetId, itemId: 'login', confirmInsecure: true, confirmCrossOrigin: true });
    expect(denied).toMatchObject({ ok: false, error: expect.stringContaining('toolbar popup') });
    expect(fillCalls()).toHaveLength(0);
    expect((await inline(document, 'open-popup')).ok).toBe(true);
    expect(h.browser.action.openPopup).toHaveBeenCalledOnce();
  });
  it('sends protected items to the daemon for fresh approval and does not fill before it replies', async () => {
    const document = documentPort(); let complete!: (value: any) => void;
    h.native.request.mockImplementation(async (request: any) => request.type === 'ListMatches'
      ? { type: 'Matches', items: [{ ...one, reprompt: true }], epoch: 1, next_offset: null }
      : new Promise(resolve => { complete = resolve; }));
    const result = await inline(document, 'list');
    const pending = inline(document, 'fill', { targetId: result.value.frame.targetId, itemId: 'login' });
    await vi.waitFor(() => expect(fillCalls()).toHaveLength(1));
    expect(fillCalls()[0]![0].interaction).toBe('popup');
    expect(document.messages.some(message => message.type === 'fill')).toBe(false);
    h.browser.windows.onFocusChanged.emit(-1);
    complete({ type: 'Credentials', username: 'alice', password: 'secret', epoch: 1, document_id: fillCalls()[0]![0].document_id });
    expect((await pending).ok).toBe(true);
  });
  it.each(['dismiss', 'focus', 'lock', 'tab', 'navigation', 'disconnect'])('suppresses delayed credentials after %s', async cause => {
    const document = documentPort(); let complete!: (value: any) => void; let signal!: AbortSignal;
    h.native.request.mockImplementation(async (request: any, abort: AbortSignal) => request.type === 'ListMatches'
      ? { type: 'Matches', items: [one], epoch: 1, next_offset: null }
      : new Promise(resolve => { signal = abort; complete = resolve; }));
    const result = await inline(document, 'list');
    sendInline(document, 'fill', { targetId: result.value.frame.targetId, itemId: 'login' });
    await vi.waitFor(() => expect(fillCalls()).toHaveLength(1));
    if (cause === 'dismiss') await inline(document, 'dismiss');
    if (cause === 'focus') {
      const original = document.port.postMessage;
      document.port.postMessage = message => {
        if (message.type === 'inspect') queueMicrotask(() => document.port.onMessage.emit({ ...message, type: 'inspected', token: 'target', focused: false }));
        else original(message);
      };
    }
    if (cause === 'lock') { h.native.snapshot = { state: 'locked', epoch: 2 }; h.native.onChange(h.native.snapshot, { type: 'Locked', epoch: 2 }); }
    if (cause === 'tab') { tab.active = false; h.browser.tabs.onActivated.emit({ tabId: 2 }); }
    if (cause === 'navigation') h.browser.webNavigation.onBeforeNavigate.emit({ tabId: 1, frameId: 0, url: tab.url });
    if (cause === 'disconnect') document.port.onDisconnect.emit();
    if (cause !== 'focus') expect(signal.aborted).toBe(true);
    complete({ type: 'Credentials', username: 'alice', password: 'secret', epoch: 1, document_id: fillCalls()[0]![0].document_id });
    await new Promise(resolve => setTimeout(resolve, 20));
    expect(document.messages.some(message => message.type === 'fill')).toBe(false);
  });
  it('keeps popup and inline targets independent during discovery and dismissal', async () => {
    const document = documentPort();
    const inlineResult = await inline(document, 'list');
    const popup = await ui({ type: 'list' });
    expect((await inline(document, 'fill', { targetId: inlineResult.value.frame.targetId, itemId: 'login' })).ok).toBe(true);
    await inline(document, 'list'); await inline(document, 'dismiss');
    expect((await ui({ type: 'fill', targetId: popup.value.frames[0].targetId, itemId: 'login' })).ok).toBe(true);
  });
  it('rediscovers the current form when inline explicitly hands off to the toolbar', async () => {
    const document = documentPort();
    const old = await ui({ type: 'list' });
    await inline(document, 'list');
    expect((await inline(document, 'open-popup')).ok).toBe(true);
    const current = await ui({ type: 'list' });
    expect(current.value.frames[0].targetId).not.toBe(old.value.frames[0].targetId);
    expect((await ui({ type: 'fill', targetId: old.value.frames[0].targetId, itemId: 'login' })).ok).toBe(false);
    expect(fillCalls()).toHaveLength(0);
  });
  it.each(['failed-list', 'disconnect'])('opens the toolbar after %s clears the inline target', async reason => {
    const document = documentPort();
    if (reason === 'failed-list') {
      h.native.request.mockRejectedValueOnce(new Error('Native host unavailable'));
      expect((await inline(document, 'list')).ok).toBe(false);
    } else {
      expect((await inline(document, 'list')).ok).toBe(true);
      h.native.snapshot = { state: 'disconnected', epoch: 1 }; h.native.onChange(h.native.snapshot);
    }
    expect((await inline(document, 'open-popup')).ok).toBe(true);
    expect(h.browser.action.openPopup).toHaveBeenCalledOnce();
    expect(fillCalls()).toHaveLength(0);
  });
  it('paginates only the stored offset and refuses changed epochs or non-progressing cursors', async () => {
    for (const failure of ['none', 'epoch', 'cursor']) {
      const document = documentPort();
      h.native.request.mockResolvedValueOnce({ type: 'Matches', items: [one], epoch: 1, next_offset: 50 });
      const result = await inline(document, 'list');
      h.native.request.mockResolvedValueOnce({ type: 'Matches', items: [{ ...one, id: 'two' }], epoch: failure === 'epoch' ? 2 : 1, next_offset: failure === 'cursor' ? 50 : null });
      const more = await inline(document, 'more', { targetId: result.value.frame.targetId, offset: 999 });
      expect(h.native.request.mock.lastCall?.[0].offset).toBe(50);
      expect(more.ok).toBe(failure === 'none');
      if (failure === 'none') expect(more.value.frame.items.map((item: any) => item.id)).toEqual(['login', 'two']);
    }
  });
  it('unlocks a freshly pinned field without first requesting matches while locked', async () => {
    h.native.snapshot = { state: 'locked', epoch: 1 };
    const document = documentPort();
    h.native.request.mockResolvedValue({ type: 'UnlockRequested' });
    expect((await inline(document, 'unlock')).ok).toBe(true);
    expect(h.native.request).toHaveBeenCalledExactlyOnceWith({ type: 'RequestUnlock' }, expect.any(AbortSignal));
    expect(fillCalls()).toHaveLength(0);
  });
  it('shows locked or unpaired state and unlocks only on explicit request without pairing', async () => {
    h.native.snapshot = { state: 'locked', epoch: 1 };
    const document = documentPort();
    expect((await inline(document, 'list')).value.connection.state).toBe('locked');
    expect(h.native.request).not.toHaveBeenCalled();
    h.native.request.mockResolvedValue({ type: 'UnlockRequested' });
    expect((await inline(document, 'unlock')).ok).toBe(true);
    expect(h.native.request).toHaveBeenCalledWith({ type: 'RequestUnlock' }, expect.any(AbortSignal));
    h.native.snapshot = { state: 'unpaired', epoch: 1 };
    expect((await inline(document, 'list')).value.connection.state).toBe('unpaired');
    expect(h.native.pair).not.toHaveBeenCalled();
  });
  it('pushes actual state changes and explicit match invalidation without a status loop', () => {
    const document = documentPort();
    const initial = document.messages.filter(message => message.type === 'inline-state').length;
    h.native.onChange(h.native.snapshot);
    expect(document.messages.filter(message => message.type === 'inline-state')).toHaveLength(initial);
    h.native.onChange(h.native.snapshot, { type: 'MatchesChanged', epoch: 1 });
    expect(document.messages.at(-1)).toMatchObject({ type: 'inline-state', reason: 'matches' });
    h.native.snapshot = { state: 'locked', epoch: 2 }; h.native.onChange(h.native.snapshot, { type: 'Locked', epoch: 2 });
    expect(document.messages.at(-1)).toMatchObject({ type: 'inline-state', reason: 'state', connection: { state: 'locked', epoch: 2 } });
  });
});


describe('verification code routing', () => {
  it.each([false, true])('releases only a fresh code to the pinned OTP form (expired: %s)', async expired => {
    h.native.request.mockImplementation(async (request: any) => request.type === 'ListTotpMatches'
      ? { type: 'Matches', items: [one], epoch: 1, next_offset: null }
      : { type: 'Totp', code: '012345', expires_at: expired ? 1 : Math.floor(Date.now() / 1000) + 30, document_id: request.document_id, epoch: 1 });
    const document = documentPort(0, tab.url, new URL(tab.url).origin, {kind: 'totp'});
    const result = await inline(document, 'list');
    expect(result.ok).toBe(true);
    expect(result.value.frame.kind).toBe('totp');
    const filled = await inline(document, 'fill', {targetId: result.value.frame.targetId, itemId: 'login'});
    expect(filled.ok).toBe(!expired);
    expect(h.native.request.mock.calls.some(([request]) => request.type === 'FillTotp')).toBe(true);
    const delivered = document.messages.filter(message => message.type === 'fill');
    expect(delivered).toHaveLength(expired ? 0 : 1);
    if (!expired) {
      expect(delivered[0]).toMatchObject({kind: 'totp', code: '012345', token: 'target'});
      expect(delivered[0]).not.toHaveProperty('password');
    }
    expect(filled.value ?? {}).not.toHaveProperty('code');
  });
});


describe('OTP toolbar and shortcut', () => {
  it.each(['popup', 'shortcut'])('uses code-only requests for %s', async interaction => {
    h.native.request.mockImplementation(async (request: any) => request.type === 'ListTotpMatches'
      ? {type: 'Matches', items: [one], epoch: 1, next_offset: null}
      : {type: 'Totp', code: '012345', expires_at: Math.floor(Date.now()/1000) + 30, document_id: request.document_id, epoch: 1});
    const document = documentPort(0, tab.url, new URL(tab.url).origin, {kind: 'totp'});
    if (interaction === 'popup') {
      const listed = await ui({type: 'list'});
      expect((await ui({type: 'fill', targetId: listed.value.frames[0].targetId, itemId: 'login'})).ok).toBe(true);
    } else await shortcut();
    await vi.waitFor(() => expect(document.messages.some(message => message.type === 'fill')).toBe(true));
    expect(h.native.request.mock.calls.find(([request]) => request.type === 'FillTotp')?.[0]).toMatchObject({interaction});
    expect(document.messages.find(message => message.type === 'fill')).toMatchObject({kind: 'totp', code: '012345'});
    expect(fillCalls()).toHaveLength(0);
  });
});

describe('inline code previews', () => {
  it.each([false, true])('checks item verification before preview (protected: %s)', async reprompt => {
    h.native.request.mockImplementation(async (request: any) => request.type === 'ListTotpMatches'
      ? {type: 'Matches', items: [{...one, reprompt}], epoch: 1, next_offset: null}
      : {type: 'Totp', code: '012345', expires_at: Math.floor(Date.now()/1000) + 30, document_id: request.document_id, epoch: 1});
    const document = documentPort(0, tab.url, new URL(tab.url).origin, {kind: 'totp'});
    const listed = await inline(document, 'list');
    const result = await inline(document, 'preview', {targetId: listed.value.frame.targetId, itemId: 'login'});
    expect(result.ok).toBe(!reprompt);
    expect(h.native.request.mock.calls.filter(([request]) => request.type === 'FillTotp')).toHaveLength(reprompt ? 0 : 1);
    expect(document.messages.filter(message => message.type === 'fill')).toHaveLength(0);
    if (!reprompt) expect(result.value.preview).toMatchObject({itemId: 'login', code: '012345'});
  });
  it('discards a pending preview after locking', async () => {
    let complete!: (value: any) => void;
    h.native.request.mockImplementation(async (request: any) => request.type === 'ListTotpMatches'
      ? {type: 'Matches', items: [one], epoch: 1, next_offset: null}
      : new Promise(resolve => {complete = resolve;}));
    const document = documentPort(0, tab.url, new URL(tab.url).origin, {kind: 'totp'});
    const listed = await inline(document, 'list');
    const pending = inline(document, 'preview', {targetId: listed.value.frame.targetId, itemId: 'login'});
    await vi.waitFor(() => expect(complete).toBeDefined());
    const request = h.native.request.mock.calls.find(([request]) => request.type === 'FillTotp')![0];
    h.native.snapshot = {state: 'locked', epoch: 2}; h.native.onChange(h.native.snapshot, {type: 'Locked', epoch: 2});
    complete({type: 'Totp', code: '012345', expires_at: Math.floor(Date.now()/1000) + 30, document_id: request.document_id, epoch: 1});
    expect((await pending).ok).toBe(false);
  });
});


it('preserves the initial inline lookup through native connection startup', async () => {
  h.native.snapshot = {state: 'disconnected', epoch: 0};
  h.native.onChange(h.native.snapshot);
  const document = documentPort();
  h.native.connect.mockImplementationOnce(async () => {
    h.native.snapshot = {state: 'connecting', epoch: 0}; h.native.onChange(h.native.snapshot);
    h.native.snapshot = {state: 'ready', epoch: 1}; h.native.onChange(h.native.snapshot);
  });
  const result = await inline(document, 'list');
  expect(result.ok).toBe(true);
  expect(result.value.frame.items[0].id).toBe('login');
});

describe('submitted password saves', () => {
  it('uses the browser-owned top-level URL, survives navigation, and drops captured plaintext after completion', async () => {
    h.native.request.mockResolvedValue({type: 'LoginSaved', saved: true});
    const document = documentPort();
    const login = {username: 'alice', password: 'new-password'};
    document.port.onMessage.emit({type: 'save-login', id: 'save', generation: 'old-after-navigation', login, top_url: 'https://evil.test'});
    await vi.waitFor(() => expect(document.messages.some(message => message.type === 'save-status')).toBe(true));
    expect(h.native.request.mock.calls[0]![0]).toMatchObject({type: 'SaveLogin', top_url: tab.url, frame_url: tab.url});
    expect(login).toEqual({username: '', password: ''});
  });
  it('rejects iframe and HTTP captures and limits concurrent saves per tab', async () => {
    h.native.request.mockImplementation(() => new Promise(() => {}));
    const send = (document: ReturnType<typeof documentPort>) => document.port.onMessage.emit({type: 'save-login', id: 'save', login: {username: 'alice', password: 'secret'}});
    send(documentPort(2)); send(documentPort(0, 'http://example.com/login'));
    expect(h.native.request).not.toHaveBeenCalled();
    const document = documentPort(); send(document); send(document);
    await vi.waitFor(() => expect(h.native.request).toHaveBeenCalledTimes(1));
  });
});
