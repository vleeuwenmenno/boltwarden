import { browser } from 'wxt/browser';
import { NativeClient, type NativeSnapshot } from './native';
import { expect, NativeError, webUrl, type Push } from './protocol';
import { isOperation, PASSKEY_PORT, type PasskeyOperation } from './passkey-types';

type Port = ReturnType<typeof browser.runtime.connect>;
interface Policy { requestId: string; url: string; get: boolean; create: boolean }
interface Pending { id: string; controller: AbortController; phase: 'preflight' | 'unlock' | 'request'; requestEpoch?: number; wake?: () => void }
interface Document { port: Port; tabId: number; windowId: number; documentId?: string; token?: string; navigationStart?: number; responseStart?: number; url: string; generation: string; ready: boolean; completedAt?: number; navigating: boolean; navigation?: string; navigationStarted?: number; requestId?: string; policy?: Policy; pending?: Pending }
const changed = () => new DOMException('The page changed. Try again.', 'AbortError');
const withoutFragment = (url: string) => url.split('#')[0];

/** Only a known top-level response can supply fallback policy information. A
 * malformed relevant directive is delegated to the native browser, never guessed. */
export function policyAllows(headers: { name: string; value?: string }[], origin: string, kind: 'get' | 'create'): boolean {
  const feature = `publickey-credentials-${kind}`;
  for (const header of headers) {
    if (header.name.toLowerCase() === 'feature-policy' && header.value?.includes(feature)) return false;
    if (header.name.toLowerCase() !== 'permissions-policy') continue;
    for (const directive of (header.value ?? '').split(',')) {
      const part = directive.trim();
      if (!new RegExp(`^${feature}(?:\\s|=|$)`, 'i').test(part)) continue;
      const match = part.match(new RegExp(`^${feature}\\s*=\\s*(.*)$`, 'i'));
      const value = match?.[1]?.trim();
      if (value === '*') continue;
      if (!value?.startsWith('(') || !value.endsWith(')')) return false;
      const inner = value.slice(1, -1).trim();
      const tokens = inner.match(/self|"[^"]*"/g) ?? [];
      if (inner.replace(/self|"[^"]*"/g, '').trim() || !tokens.length) return false;
      if (!tokens.some(token => token === 'self' || token === JSON.stringify(origin))) return false;
    }
  }
  return true;
}

export function installPasskeyBroker(native: NativeClient) {
  const policies = new Map<number, Policy>();
  const requests = new Map<number, { id: string; url: string; timeStamp: number; token?: string }>();
  const completions = new Map<number, { tabId: number; frameId: number; url: string; timeStamp: number }>();
  const documents = new Map<number, Document>();
  function bindResponse(document: Document) {
    const request = requests.get(document.tabId), policy = policies.get(document.tabId);
    // Browser navigation timing is read inside the isolated relay. Its exact
    // interval excludes earlier same-URL documents and later BFCache responses.
    // A request can belong to only one relay lifetime, even with rounded clocks.
    if (!document.token || document.navigationStart === undefined || document.responseStart === undefined || !request
      || request.timeStamp < document.navigationStart || request.timeStamp > document.responseStart
      || !Number.isFinite(request.timeStamp) || (request.token && request.token !== document.token)
      || withoutFragment(request.url) !== withoutFragment(document.url)) return false;
    request.token = document.token;
    document.requestId = request.id;
    document.policy = policy?.requestId === request.id ? policy : undefined;
    return true;
  }
  function announce(document: Document) {
    try { document.port.postMessage({ type: 'generation', generation: document.generation, ready: document.ready }); } catch { /* disconnected */ }
  }
  function completedNavigation(document: Document, url: string, timeStamp: number) {
    return document.ready && document.completedAt !== undefined && document.navigationStart !== undefined
      && document.responseStart !== undefined && Number.isFinite(timeStamp)
      && document.navigationStart <= timeStamp && timeStamp <= document.responseStart
      && timeStamp < document.completedAt && withoutFragment(url) === withoutFragment(document.url);
  }
  function cancel(document: Document, reason: Error = changed()) { document.pending?.controller.abort(reason); document.pending?.wake?.(); }
  function invalidate(tabId: number, navigating: boolean, url?: string, navigation?: string, timeStamp?: number) {
    const document = documents.get(tabId);
    if (!document) return;
    cancel(document); document.generation = crypto.randomUUID(); document.ready = false; document.navigating = navigating; document.navigation = navigating ? navigation : undefined; document.navigationStarted = navigating ? timeStamp : undefined;
    if (url) document.url = url;
    announce(document);
  }

  browser.webRequest.onBeforeRequest.addListener(details => {
    requests.set(details.tabId, { id: details.requestId, url: details.url, timeStamp: details.timeStamp });
    policies.delete(details.tabId);
    const document = documents.get(details.tabId);
    const lateOwnRequest = document && completedNavigation(document, details.url, details.timeStamp)
      && (!document.requestId || document.requestId === details.requestId) && bindResponse(document);
    if (!lateOwnRequest) invalidate(details.tabId, true, undefined, details.url, details.timeStamp);
    const completion = completions.get(details.tabId);
    if (completion && completion.timeStamp >= details.timeStamp) completed(completion);
    return undefined;
  }, { urls: ['https://*/*'], types: ['main_frame'] });
  browser.webRequest.onHeadersReceived.addListener(details => {
    const url = webUrl(details.url);
    if (!url || url.protocol !== 'https:' || !details.responseHeaders) return undefined;
    if (requests.get(details.tabId)?.id !== details.requestId) return undefined;
    const policy = { requestId: details.requestId, url: details.url,
      get: policyAllows(details.responseHeaders, url.origin, 'get'), create: policyAllows(details.responseHeaders, url.origin, 'create') };
    policies.set(details.tabId, policy);
    const document = documents.get(details.tabId);
    // Firefox can deliver headers after the new document port. Bind that late
    // response to the exact observed request, never merely to the same URL.
    if (document && !document.navigating && bindResponse(document)) document.pending?.wake?.();
    return undefined;
  }, { urls: ['https://*/*'], types: ['main_frame'] }, ['responseHeaders']);
  const dropResponse = (details: { tabId: number; requestId: string }) => {
    if (policies.get(details.tabId)?.requestId === details.requestId) policies.delete(details.tabId);
    if (requests.get(details.tabId)?.id === details.requestId) requests.delete(details.tabId);
  };
  browser.webRequest.onBeforeRedirect.addListener(dropResponse, { urls: ['https://*/*'], types: ['main_frame'] });
  browser.webRequest.onErrorOccurred.addListener(dropResponse, { urls: ['https://*/*'], types: ['main_frame'] });
  browser.webNavigation.onBeforeNavigate.addListener(details => {
    if (details.frameId !== 0) return;
    const document = documents.get(details.tabId);
    if (!document || !completedNavigation(document, details.url, details.timeStamp)) {
      invalidate(details.tabId, true, undefined, details.url, details.timeStamp);
    }
    const completion = completions.get(details.tabId);
    if (completion && completion.timeStamp >= details.timeStamp) completed(completion);
  });
  browser.webNavigation.onErrorOccurred.addListener(details => {
    const document = documents.get(details.tabId);
    if (details.frameId !== 0 || !document?.navigating || document.navigation !== details.url) return;
    const generation = document.generation;
    // A failed navigation can leave its original document alive. Only browser
    // metadata matching the same port and generation permits reusing that page.
    void Promise.all([browser.webNavigation.getFrame({ tabId: document.tabId, frameId: 0 }), currentDocument(document)]).then(([frame, current]) => {
      if (!current || documents.get(document.tabId) !== document || document.generation !== generation || !document.navigating
        || frame?.url !== document.url || (document.documentId && frame.documentId !== document.documentId)) return;
      document.navigating = false; document.navigation = undefined; document.navigationStarted = undefined;
      document.ready = true; announce(document); document.pending?.wake?.();
    }).catch(() => { /* navigation no longer has a live document */ });
  });
  // Runtime ports can arrive before Firefox delivers navigation events. A
  // current-frame isolated token proves which surviving port owns the committed
  // document, even when Firefox does not expose documentId.
  async function currentDocument(document: Document) {
    if (!document.token) return false;
    const reply = await browser.tabs.sendMessage(document.tabId, { type: 'passkey-document-check' }, { frameId: 0 }).catch(() => null);
    return reply?.token === document.token;
  }
  function completed(details: { tabId: number; frameId: number; url: string; timeStamp: number }) {
    if (details.frameId !== 0) return;
    if ((completions.get(details.tabId)?.timeStamp ?? 0) > details.timeStamp) return;
    completions.set(details.tabId, details);
    const document = documents.get(details.tabId), request = requests.get(details.tabId);
    if (!document || document.navigationStart === undefined || details.timeStamp < document.navigationStart
      || document.url !== details.url || (document.navigationStarted ?? 0) > details.timeStamp
      || (request?.timeStamp ?? 0) > details.timeStamp) return;
    const generation = document.generation;
    void Promise.all([browser.webNavigation.getFrame({ tabId: document.tabId, frameId: 0 }), currentDocument(document)]).then(([frame, current]) => {
      if (!current || requests.get(document.tabId) !== request || documents.get(document.tabId) !== document || document.generation !== generation
        || frame?.url !== document.url || (document.documentId && frame.documentId !== document.documentId)) return;
      document.navigating = false; document.navigation = undefined; document.navigationStarted = undefined;
      document.completedAt = details.timeStamp; document.ready = true;
      bindResponse(document); announce(document);
      document.pending?.wake?.();
    }).catch(() => { /* frame was replaced while proving its identity */ });
  }
  browser.webNavigation.onCompleted.addListener(completed);
  browser.webNavigation.onDOMContentLoaded.addListener(completed);
  for (const event of [browser.webNavigation.onHistoryStateUpdated, browser.webNavigation.onReferenceFragmentUpdated]) {
    event.addListener(details => {
      if (details.frameId !== 0) return;
      invalidate(details.tabId, false, details.url);
      completed(details);
    });
  }
  browser.tabs.onRemoved.addListener(tabId => { policies.delete(tabId); requests.delete(tabId); completions.delete(tabId); const document = documents.get(tabId); if (document) cancel(document); documents.delete(tabId); });
  browser.tabs.onActivated.addListener(({ tabId, windowId }) => {
    for (const document of documents.values()) if (document.windowId === windowId && document.tabId !== tabId) cancel(document);
  });
  browser.windows.onFocusChanged.addListener(windowId => {
    // Desktop consent steals focus; a different browser window cancels instead.
    if (windowId !== browser.windows.WINDOW_ID_NONE) for (const document of documents.values()) if (document.windowId !== windowId) cancel(document);
  });

  async function validate(document: Document, generation: string, signal: AbortSignal) {
    if (signal.aborted) throw signal.reason;
    if (documents.get(document.tabId) !== document || document.navigating || document.generation !== generation) throw changed();
    const [tab, frame, active] = await Promise.all([
      browser.tabs.get(document.tabId), browser.webNavigation.getFrame({ tabId: document.tabId, frameId: 0 }),
      browser.tabs.query({ active: true, lastFocusedWindow: true }),
    ]);
    if (!document.documentId && !await currentDocument(document)) throw changed();
    if (signal.aborted) throw signal.reason;
    if (!frame || !tab.active || active[0]?.id !== document.tabId || frame.url !== document.url
      || (document.documentId && frame.documentId !== document.documentId)
      || documents.get(document.tabId) !== document || document.generation !== generation || document.navigating) throw changed();
    const url = webUrl(frame.url);
    if (!url || url.protocol !== 'https:') throw new DOMException('A secure top-level page is required.', 'SecurityError');
    return { top_url: url.href, frame_url: url.href, document_id: generation };
  }
  async function navigationReady(document: Document, pending: Pending) {
    if (!document.navigating) return;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => { pending.wake = undefined; reject(changed()); }, 1000);
      pending.wake = () => {
        if (!pending.controller.signal.aborted && document.navigating) return;
        clearTimeout(timer); pending.wake = undefined;
        if (pending.controller.signal.aborted) reject(pending.controller.signal.reason); else resolve();
      };
      pending.wake();
    });
  }
  async function policyReady(document: Document, pending: Pending) {
    if (document.policy || !document.token || document.navigationStart === undefined || document.responseStart === undefined) return;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => { pending.wake = undefined; resolve(); }, 1000);
      pending.wake = () => {
        if (!pending.controller.signal.aborted && !document.policy) return;
        clearTimeout(timer); pending.wake = undefined;
        if (pending.controller.signal.aborted) reject(pending.controller.signal.reason); else resolve();
      };
      pending.wake();
    });
  }
  async function unlock(document: Document, pending: Pending) {
    if (native.snapshot.state !== 'locked') return;
    pending.phase = 'unlock';
    await native.request({ type: 'RequestUnlock' }, pending.controller.signal);
    await new Promise<void>((resolve, reject) => {
      pending.wake = () => {
        if (pending.controller.signal.aborted) reject(pending.controller.signal.reason);
        else if (native.snapshot.state === 'ready') resolve();
        else if (native.snapshot.state !== 'locked') reject(new NativeError('Unavailable', 'Desktop vault is unavailable.'));
      };
      pending.wake();
    });
    pending.wake = undefined;
  }
  async function run(document: Document, message: PasskeyOperation & { id: string; generation: string; policy_allowed?: boolean; visible?: boolean }) {
    const generation = document.generation;
    const pending: Pending = { id: message.id, controller: new AbortController(), phase: 'preflight' };
    document.pending = pending;
    const deadline = Date.now() + message.options.timeout_ms;
    const timer = setTimeout(() => { cancel(document, new DOMException('The passkey request timed out.', 'NotAllowedError')); }, message.options.timeout_ms);
    const reply = (value: Record<string, unknown>) => {
      try { document.port.postMessage({ ...value, id: message.id, generation }); } catch { /* caller gone */ }
    };
    try {
      await navigationReady(document, pending);
      await validate(document, generation, pending.controller.signal);
      if (message.policy_allowed === undefined) await policyReady(document, pending);
      if (message.visible !== true || message.policy_allowed === false
        || (message.policy_allowed !== true && document.policy?.[message.kind] !== true)) {
        reply({ type: 'fallback', reason: 'document-policy-or-visibility' }); return;
      }
      await validate(document, generation, pending.controller.signal);
      await native.connect();
      if (!['ready', 'locked'].includes(native.snapshot.state)) { reply({ type: 'fallback', reason: `native-${native.snapshot.state}` }); return; }
      await unlock(document, pending);
      const context = await validate(document, generation, pending.controller.signal);
      const remaining = Math.floor(deadline - Date.now());
      if (remaining < 1000) throw new DOMException('The passkey request timed out.', 'NotAllowedError');
      pending.requestEpoch = native.snapshot.epoch;
      pending.phase = 'request';
      const response = expect(await native.request(message.kind === 'get'
        ? { type: 'PasskeyGet', ...context, options: { ...message.options, timeout_ms: remaining } }
        : { type: 'PasskeyCreate', ...context, options: { ...message.options, timeout_ms: remaining } }, pending.controller.signal), 'PasskeyResult');
      await validate(document, generation, pending.controller.signal);
      if (native.snapshot.state !== 'ready' || response.document_id !== generation || response.kind !== message.kind || response.epoch !== native.snapshot.epoch) throw changed();
      reply({ type: 'result', result: response });
    } catch (error) {
      const reason = pending.controller.signal.aborted ? pending.controller.signal.reason : error;
      if (reason instanceof NativeError && (['FallbackRequested', 'Unsupported', 'Unavailable', 'NotSupportedError'].includes(reason.code)
        || (pending.phase !== 'request' && ['Disconnected', 'Unpaired', 'Disabled'].includes(reason.code)))) reply({ type: 'fallback', reason: `native-${reason.code}` });
      else reply({ type: 'error', name: reason instanceof DOMException ? reason.name
        : reason instanceof NativeError ? ({ Cancelled: 'AbortError', Timeout: 'NotAllowedError', Locked: 'NotAllowedError', Busy: 'NotAllowedError' }[reason.code] ?? reason.code) : 'UnknownError',
      message: reason instanceof Error ? reason.message : 'The passkey request failed.' });
    } finally {
      clearTimeout(timer); pending.wake = undefined;
      if (document.pending === pending) document.pending = undefined;
    }
  }

  browser.runtime.onConnect.addListener(port => {
    if (port.name !== PASSKEY_PORT) return;
    const sender = port.sender, url = sender?.url ? webUrl(sender.url) : null;
    if (sender?.id !== browser.runtime.id || sender.frameId !== 0 || sender.tab?.id === undefined
      || !url || url.protocol !== 'https:' || (sender.origin !== undefined && sender.origin !== url.origin)) { port.disconnect(); return; }
    const existing = documents.get(sender.tab.id);
    if (existing) { cancel(existing); existing.port.disconnect(); }
    const document: Document = { port, tabId: sender.tab.id, windowId: sender.tab.windowId, documentId: sender.documentId,
      url: url.href, generation: crypto.randomUUID(), ready: false, navigating: true };
    documents.set(document.tabId, document);
    port.onMessage.addListener(message => {
      if (message?.type === 'identify' && !document.token && typeof message.token === 'string' && message.token.length <= 64) {
        document.token = message.token;
        if (Number.isFinite(message.navigation_start) && Number.isFinite(message.response_start)
          && message.navigation_start > 0 && message.response_start > message.navigation_start) {
          document.navigationStart = message.navigation_start; document.responseStart = message.response_start;
        }
        bindResponse(document);
        const completion = completions.get(document.tabId); if (completion) completed(completion);
        return;
      }
      if (!message || message.generation !== document.generation || typeof message.id !== 'string' || message.id.length > 64) return;
      if (message.type === 'cancel' && document.pending?.id === message.id) { cancel(document); return; }
      const { id, generation, policy_allowed, visible } = message;
      if (message.type !== 'operation' || !isOperation(message)) return;
      if (!document.ready) {
        port.postMessage({ type: 'error', id, generation: document.generation, name: 'AbortError', message: 'The document is not ready.' });
        return;
      }
      if (document.pending) { port.postMessage({ type: 'error', id, generation: document.generation, name: 'NotAllowedError', message: 'Another passkey request is pending.' }); return; }
      void run(document, { ...message, id, generation, policy_allowed, visible });
    });
    port.onDisconnect.addListener(() => { cancel(document); if (documents.get(document.tabId) === document) documents.delete(document.tabId); });
    announce(document);
  });
  return {
    nativeChanged(snapshot: NativeSnapshot, _event?: Push) {
      for (const document of documents.values()) {
        if (!document.pending) continue;
        // Policy changes invalidate daemon approvals while leaving the vault
        // unlocked. Capture the epoch only after a legitimate unlock completes.
        if (document.pending.phase === 'request'
          && (snapshot.state === 'locked' || snapshot.epoch !== document.pending.requestEpoch)) cancel(document);
        if (['disabled', 'unpaired', 'disconnected'].includes(snapshot.state)) cancel(document,
          document.pending.phase === 'request' ? changed() : new NativeError('Unavailable', 'Desktop vault is unavailable.'));
        document.pending.wake?.();
      }
    },
  };
}
