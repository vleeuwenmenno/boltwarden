import { pairingBrowserLabel } from '../lib/browser-label';
import { pendingSaves } from '../lib/pending-saves';
import { defineBackground } from 'wxt/utils/define-background';
import { browser } from 'wxt/browser';
import { NativeClient } from '../lib/native';
import { publicIdentity } from '../lib/pairing';
import { clearCard, expect, HOST_NAME, NativeError, webUrl, type Match, type PageContext } from '../lib/protocol';
import type { UiFrame, UiPage, UiResult } from '../lib/ui-types';
import { installPasskeyBroker } from '../lib/passkey-background';
import { PASSKEY_PORT } from '../lib/passkey-types';
import { readSettings } from '../lib/settings';
import { CLIPBOARD_PERMISSION, copyFromBackground } from '../lib/clipboard';
const CLEAR_CLIPBOARD = 'clear-copied-code';

type Port = ReturnType<typeof browser.runtime.connect>;
interface DocumentState {
  port: Port; tabId: number; frameId: number; windowId: number; documentId?: string;
  url: string; origin: string; generation: string; navigating: boolean;
  navigation?: { frameId: number; url: string };
  pending: Map<string, { resolve(value: Record<string, unknown>): void; reject(error: Error): void; timer: ReturnType<typeof setTimeout> }>;
}
interface Target {
  scope?: 'inline';
  kind?: 'login' | 'totp' | 'card';
  id: string; document: DocumentState; generation: string; token: string; context: PageContext;
  controller: AbortController; items: Match[]; epoch: number; crossOrigin: boolean; focused: boolean; nextOffset: number | null; filling: boolean; warning?: string | null;
}
interface InlineState {
  token: string; generation: string; controller: AbortController; busy: boolean; kind?: 'login' | 'totp' | 'card'; target?: Target;
}
const changed = () => new Error('The page changed. Select a login field and try again.');

export default defineBackground(() => {
  const documents = new Map<string, DocumentState>();
  const targets = new Map<string, Target>();
  const inlineTargets = new Map<DocumentState, InlineState>();
  let inlineWork = 0;
  const pickerTabs = new Set<number>();
  const shortcutBlocked = new Set<number>();
  const discoveryWarnings = new Map<number, string>();
  const uiPorts = new Set<Port>();
  let activeWindow: number | undefined;
  let activeTabId: number | undefined;
  const native = new NativeClient(() => browser.runtime.connectNative(HOST_NAME), {
    async read() { const data = await browser.storage.local.get('pairing_id'); return typeof data.pairing_id === 'string' ? data.pairing_id : undefined; },
    async write(id) { await browser.storage.local.set({ pairing_id: id }); },
  });
  let previousSnapshot = { ...native.snapshot };
  const passkeys = installPasskeyBroker(native);

  const saves = pendingSaves(native, browser.storage.session, () => notifyUi('page'), (entry, message) => {
    const destination = documents.get(`${entry.tabId}:0`);
    if (destination?.origin === new URL(entry.url).origin) {
      try { destination.port.postMessage({ type: 'save-status', generation: destination.generation, message }); } catch { /* tab closed */ }
    }
  });
  const saving = new Set<number>();
  async function saveLogin(document: DocumentState, sourceUrl: string, message: Record<string, any>) {
    const login = message.login;
    if (document.frameId !== 0 || !sourceUrl.startsWith('https:') || saving.has(document.tabId)
      || !login || typeof login.username !== 'string' || typeof login.password !== 'string'
      || !login.password || login.password.length > 4096 || login.username.length > 1024) return;
    saving.add(document.tabId);
    try { await saves.add(document.tabId, sourceUrl, document.documentId ?? document.generation, login); }
    finally { login.password = ''; login.username = ''; saving.delete(document.tabId); }
  }

  function trustedUi(sender: Port['sender']) {
    return sender?.id === browser.runtime.id
      && [browser.runtime.getURL('/popup.html'), browser.runtime.getURL('/options.html')].includes(sender.url ?? '');
  }
  function notifyUi(reason: 'state' | 'matches' | 'page', ports: Iterable<Port> = uiPorts) {
    for (const port of ports) {
      try { port.postMessage({ type: 'state-changed', connection: { ...native.snapshot }, reason }); }
      catch { uiPorts.delete(port); }
    }
  }
  function notifyPage(tabId?: number) {
    if (tabId === undefined || activeTabId === undefined || activeTabId === tabId) notifyUi('page');
    notifyInline('page', tabId);
  }

  function notifyInline(reason: 'state' | 'matches' | 'page', tabId?: number) {
    for (const document of documents.values()) {
      if (tabId !== undefined && document.tabId !== tabId) continue;
      try { document.port.postMessage({ type: 'inline-state', generation: document.generation, connection: { ...native.snapshot }, reason }); }
      catch { /* disconnected document */ }
    }
  }
  function clearInline(document: DocumentState) {
    inlineTargets.get(document)?.controller.abort();
    inlineTargets.delete(document);
  }

  function clearTargets(tabId?: number, includeInline = true) {
    for (const [id, target] of targets) {
      if (tabId !== undefined && target.document.tabId !== tabId) continue;
      target.controller.abort(); targets.delete(id);
    }
    if (includeInline) for (const document of inlineTargets.keys()) {
      if (tabId === undefined || document.tabId === tabId) clearInline(document);
    }
    if (tabId !== undefined) { pickerTabs.delete(tabId); shortcutBlocked.delete(tabId); discoveryWarnings.delete(tabId); }
    else { pickerTabs.clear(); shortcutBlocked.clear(); discoveryWarnings.clear(); }
  }
  function invalidate(document: DocumentState, navigating = true) {
    clearInline(document);
    for (const [id, target] of targets) {
      if (target.document === document) { target.controller.abort(); targets.delete(id); }
    }
    for (const pending of document.pending.values()) { clearTimeout(pending.timer); pending.reject(changed()); }
    document.pending.clear(); document.generation = crypto.randomUUID(); document.navigating = navigating;
    document.navigation = undefined;
    try { document.port.postMessage({ type: 'generation', generation: document.generation }); } catch { /* document gone */ }
  }
  function badge(text: string, tabId?: number, title = 'Boltwarden') {
    void browser.action.setBadgeText({ text, ...(tabId !== undefined ? { tabId } : {}) }).catch(() => {});
    void browser.action.setTitle({ title, ...(tabId !== undefined ? { tabId } : {}) }).catch(() => {});
  }
  native.onChange = (snapshot, event) => {
    passkeys.nativeChanged(snapshot, event);
    void saves.resume().catch(() => {});
    const stateChanged = snapshot.state !== previousSnapshot.state || snapshot.epoch !== previousSnapshot.epoch || snapshot.error !== previousSnapshot.error;
    const matchesChanged = event?.type === 'MatchesChanged'
      || (!event && snapshot.state === 'ready' && snapshot.epoch !== previousSnapshot.epoch);
    if (matchesChanged) {
      // A stale-vault refresh can occur inside ListMatches/FillLogin. Preserve those
      // operations, but prevent another click from using an old match summary.
      for (const target of targets.values()) if (!target.filling) target.items = [];
      for (const state of inlineTargets.values()) if (state.target && !state.target.filling) state.target.items = [];
      pickerTabs.clear();
    } else if (event || (snapshot.state !== 'ready' && snapshot.state !== 'connecting')) clearTargets();
    previousSnapshot = { ...snapshot };
    const text = snapshot.state === 'ready' ? '' : snapshot.state === 'locked' ? 'L' : '!';
    badge(text, undefined, snapshot.error ?? `Boltwarden: ${snapshot.state}`);
    if (matchesChanged || stateChanged) {
      notifyUi(matchesChanged ? 'matches' : 'state');
      notifyInline(matchesChanged ? 'matches' : 'state');
    }
  };

  // Listeners are installed synchronously so event-page/service-worker wakeups are handled.
  browser.runtime.onConnect.addListener(port => {
    if (port.name === PASSKEY_PORT) return;
    const sender = port.sender;
    if (port.name === 'boltwarden-ui-v1') {
      if (!trustedUi(sender)) { port.disconnect(); return; }
      uiPorts.add(port);
      port.onDisconnect.addListener(() => uiPorts.delete(port));
      notifyUi('state', [port]);
      return;
    }
    const parsed = sender?.url ? webUrl(sender.url) : null;
    if (port.name !== 'boltwarden-document-v1' || sender?.id !== browser.runtime.id
      || sender.tab?.id === undefined || sender.frameId === undefined || !parsed
      || (sender.origin !== undefined && sender.origin !== parsed.origin)) { port.disconnect(); return; }
    const key = `${sender.tab.id}:${sender.frameId}`;
    const old = documents.get(key);
    if (old) { invalidate(old); old.port.disconnect(); }
    const document: DocumentState = { port, tabId: sender.tab.id, frameId: sender.frameId,
      windowId: sender.tab.windowId, documentId: sender.documentId, url: parsed.href, origin: parsed.origin,
      generation: crypto.randomUUID(), navigating: false, pending: new Map() };
    documents.set(key, document);
    port.onMessage.addListener(message => {
      if (!message || typeof message !== 'object' || typeof message.id !== 'string' || message.id.length > 64) return;
      // A submit may be followed immediately by navigation. Its source remains the
      // browser-owned URL of this content-script connection, never a page-supplied URL.
      if (message.type === 'save-login') { void saveLogin(document, parsed.href, message); return; }
      if (message.generation !== document.generation) return;
      if (message.type === 'inline-request') {
        if (message.id.length > 64) return;
        const generation = document.generation;
        void inlineRequest(document, message).then(value => {
          if (documents.get(key) === document && document.generation === generation) {
            port.postMessage({ type: 'inline-response', id: message.id, generation, ok: true, value });
          }
        }, error => {
          if (documents.get(key) === document && document.generation === generation) {
            port.postMessage({ type: 'inline-response', id: message.id, generation, ok: false,
              error: error instanceof Error ? error.message : 'Browser request failed.' });
          }
        }).catch(() => {});
        return;
      }
      const pending = document.pending.get(message.id);
      if (!pending) return;
      document.pending.delete(message.id); clearTimeout(pending.timer);
      if (message.type === 'failure') pending.reject(new Error('The login form changed. Select a login field and try again.'));
      else pending.resolve(message);
    });
    port.onDisconnect.addListener(() => {
      invalidate(document);
      if (documents.get(key) === document) { documents.delete(key); notifyPage(document.tabId); }
    });
    port.postMessage({ type: 'generation', generation: document.generation });
    notifyPage(document.tabId);
  });

  browser.webNavigation.onBeforeNavigate.addListener(details => {
    if (details.frameId === 0) clearTargets(details.tabId);
    for (const document of documents.values()) {
      if (document.tabId !== details.tabId || (details.frameId !== 0 && document.frameId !== details.frameId)) continue;
      invalidate(document);
      document.navigation = { frameId: details.frameId, url: details.url };
    }
    notifyPage(details.tabId);
  });
  browser.webNavigation.onErrorOccurred.addListener(details => {
    // Failed navigation can leave the old document and its content port alive.
    // Browser metadata, port identity and generation must all still name that document.
    void (async () => {
      let recovered = false;
      const pending = Array.from(documents.values()).filter(document => document.tabId === details.tabId
        && document.navigating && document.navigation?.frameId === details.frameId && document.navigation.url === details.url);
      await Promise.all(pending.map(async document => {
        const generation = document.generation;
        const frame = await browser.webNavigation.getFrame({ tabId: document.tabId, frameId: document.frameId }).catch(() => null);
        if (documents.get(`${document.tabId}:${document.frameId}`) !== document || document.generation !== generation
          || !document.navigating || frame?.url !== document.url
          || (document.documentId && frame.documentId !== document.documentId)) return;
        invalidate(document, false); recovered = true;
      }));
      if (recovered) notifyPage(details.tabId);
    })();
  });
  const sameDocumentNavigation = (details: { tabId: number; frameId: number; url: string }) => {
    const document = documents.get(`${details.tabId}:${details.frameId}`);
    if (!document || document.navigating) return;
    const parsed = webUrl(details.url);
    if (!parsed || parsed.origin !== document.origin) { invalidate(document); notifyPage(details.tabId); return; }
    if (details.frameId === 0) clearTargets(details.tabId);
    invalidate(document, false); document.url = parsed.href;
    notifyPage(details.tabId);
  };
  browser.webNavigation.onHistoryStateUpdated.addListener(sameDocumentNavigation);
  browser.webNavigation.onReferenceFragmentUpdated.addListener(sameDocumentNavigation);
  browser.tabs.onRemoved.addListener(tabId => {
    clearTargets(tabId);
    for (const [key, document] of documents) if (document.tabId === tabId) { invalidate(document); documents.delete(key); }
    notifyPage(tabId);
  });
  browser.tabs.onActivated.addListener(({ tabId }) => {
    for (const target of Array.from(targets.values())) if (target.document.tabId !== tabId) clearTargets(target.document.tabId);
    for (const document of inlineTargets.keys()) if (document.tabId !== tabId) clearInline(document);
    activeTabId = tabId; notifyPage();
  });
  browser.windows.onFocusChanged.addListener(windowId => {
    // Desktop approval dialogs temporarily take focus; that alone must not cancel approval.
    if (windowId === browser.windows.WINDOW_ID_NONE) return;
    if (activeWindow !== undefined && activeWindow !== windowId) { clearTargets(); activeTabId = undefined; notifyPage(); }
    activeWindow = windowId;
  });

  function ask(document: DocumentState, message: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (document.navigating) return Promise.reject(changed());
    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { document.pending.delete(id); reject(new Error('Reload this page to enable filling.')); }, 2000);
      document.pending.set(id, { resolve, reject, timer });
      try { document.port.postMessage({ ...message, id, generation: document.generation }); }
      catch { clearTimeout(timer); document.pending.delete(id); reject(changed()); }
    });
  }
  async function activeTab() {
    const [tab] = await browser.tabs.query({ active: true, lastFocusedWindow: true });
    if (tab?.id === undefined || !tab.url || !webUrl(tab.url)) throw new Error('Open a website to fill a login.');
    activeWindow = tab.windowId;
    activeTabId = tab.id;
    return tab as typeof tab & { id: number; url: string };
  }
  async function validate(target: Target) {
    const document = target.document;
    if (target.controller.signal.aborted || document.navigating || document.generation !== target.generation
      || (target.scope === 'inline' ? inlineTargets.get(document)?.target !== target : targets.get(target.id) !== target)) throw changed();
    const [tab, frame, current] = await Promise.all([
      browser.tabs.get(document.tabId), browser.webNavigation.getFrame({ tabId: document.tabId, frameId: document.frameId }),
      target.scope === 'inline' ? activeTab() : Promise.resolve(undefined),
    ]);
    if (!tab.active || tab.windowId !== document.windowId || (activeWindow !== undefined && activeWindow !== document.windowId)
      || (current !== undefined && current.id !== document.tabId)
      || tab.url !== target.context.top_url || frame?.url !== target.context.frame_url
      || (document.documentId && frame.documentId !== document.documentId)
      || document.generation !== target.generation || target.controller.signal.aborted) throw changed();
  }
  async function discover(tabId?: number): Promise<Target[]> {
    const tab = await activeTab();
    if (tabId !== undefined && tab.id !== tabId) throw changed();
    clearTargets(tab.id, false);
    if (native.snapshot.state !== 'ready') return [];
    const tabDocuments = Array.from(documents.values()).filter(document => document.tabId === tab.id);
    const candidates = tabDocuments.filter(document => !document.navigating).sort((a, b) => a.frameId - b.frameId).slice(0, 32);
    const unresolved = new Set(tabDocuments.filter(document => !candidates.includes(document)));
    const inspect = async (document: DocumentState): Promise<Target | null> => {
      const generation = document.generation;
      const inspected = await ask(document, { type: 'inspect' });
      if (inspected.type === 'inspected' && inspected.focused === true && inspected.token === null && document.origin === new URL(tab.url).origin) shortcutBlocked.add(tab.id);
      if (inspected.type !== 'inspected' || generation !== document.generation) throw changed();
      if (inspected.token === null) return null;
      if (typeof inspected.token !== 'string' || inspected.token.length > 64) throw changed();
      const target: Target = { kind: inspected.kind === 'card' ? 'card' : inspected.kind === 'totp' ? 'totp' : 'login', id: crypto.randomUUID(), document, generation, token: inspected.token,
        context: { top_url: tab.url, frame_url: document.url, document_id: `${document.tabId}:${document.frameId}:${generation}` },
        controller: new AbortController(), items: [], epoch: native.snapshot.epoch,
        crossOrigin: new URL(tab.url).origin !== document.origin, focused: inspected.focused === true, nextOffset: null, filling: false };
      if (target.kind === 'card' && (new URL(tab.url).protocol !== 'https:' || new URL(document.url).protocol !== 'https:')) return null;
      targets.set(target.id, target);
      try {
        await validate(target);
        const matches = expect(await native.request({ type: target.kind === 'card' ? 'ListCards' : target.kind === 'totp' ? 'ListTotpMatches' : 'ListMatches', ...target.context }, target.controller.signal), 'Matches');
        await validate(target);
        if (matches.epoch !== native.snapshot.epoch) throw changed();
        target.items = matches.items; target.epoch = matches.epoch; target.nextOffset = matches.next_offset; target.warning = matches.warning;
        return target;
      } catch (error) { target.controller.abort(); targets.delete(target.id); throw error; }
    };
    const results: PromiseSettledResult<Target | null>[] = [];
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(2, candidates.length) }, async () => {
      while (next < candidates.length) {
        const index = next++;
        try { results[index] = { status: 'fulfilled', value: await inspect(candidates[index]!) }; }
        catch (reason) { unresolved.add(candidates[index]!); results[index] = { status: 'rejected', reason }; }
      }
    }));
    if (unresolved.size) {
      discoveryWarnings.set(tab.id, 'Some frames could not be checked. Reload the page or choose a login below.');
      if (Array.from(unresolved).some(document => document.origin === new URL(tab.url).origin)) shortcutBlocked.add(tab.id);
    }
    if (results.length && results.every(result => result.status === 'rejected')) {
      const first = results[0];
      if (first?.status === 'rejected') throw first.reason;
    }
    return results.flatMap(result => result.status === 'fulfilled' && result.value ? [result.value] : []);
  }
  function page(found: Target[], tabId = found[0]?.document.tabId): UiPage {
    return { frames: found.filter(target => target.items.length > 0).map(target => ({ kind: target.kind, targetId: target.id,
      origin: target.document.origin, crossOrigin: target.crossOrigin, items: target.items, more: target.nextOffset !== null })),
      warning: Array.from(new Set([...found.flatMap(target => target.warning ? [target.warning] : []),
        ...(tabId !== undefined && discoveryWarnings.has(tabId) ? [discoveryWarnings.get(tabId)!] : [])])).join(' ') || undefined,
      ...(found.some(target => target.items.length > 0) ? {} : { message: found.length ? 'No matching vault items for this page.' : 'Select a visible login or payment field, then reopen Boltwarden. Reload the page if this extension was just installed.' }) };
  }
  function assertInline(document: DocumentState, state: InlineState) {
    if (inlineTargets.get(document) !== state || state.controller.signal.aborted
      || documents.get(`${document.tabId}:${document.frameId}`) !== document
      || document.navigating || document.generation !== state.generation) throw changed();
  }
  async function validateInline(document: DocumentState, state: InlineState) {
    assertInline(document, state);
    const [tab, frame] = await Promise.all([activeTab(), browser.webNavigation.getFrame({ tabId: document.tabId, frameId: document.frameId })]);
    assertInline(document, state);
    if (tab.id !== document.tabId || tab.windowId !== document.windowId || frame?.url !== document.url
      || (document.documentId && frame.documentId !== document.documentId)) throw changed();
    return tab;
  }
  async function inspectInline(document: DocumentState, state: InlineState) {
    await validateInline(document, state);
    const reply = await ask(document, { type: 'inspect', requestedToken: state.token });
    assertInline(document, state);
    if (reply.type !== 'inspected' || reply.token !== state.token || reply.focused !== true) throw changed();
    const kind = reply.kind === 'card' ? 'card' : reply.kind === 'totp' ? 'totp' : 'login';
    if (state.kind && state.kind !== kind) throw changed();
    state.kind = kind;
    return validateInline(document, state);
  }
  function inlineFrame(target: Target): UiFrame {
    const insecure = new URL(target.context.top_url).protocol !== 'https:' || new URL(target.context.frame_url).protocol !== 'https:';
    return { kind: target.kind, targetId: target.id, origin: target.document.origin, crossOrigin: target.crossOrigin,
      items: insecure ? target.items.map(item => ({ ...item, requires_confirmation: true })) : target.items, more: target.nextOffset !== null };
  }
  function inlineMatches(target: Target, matches: ReturnType<typeof expect<'Matches'>>, offset: number) {
    if (matches.epoch !== native.snapshot.epoch || native.snapshot.state !== 'ready' || matches.items.length > 50
      || (matches.next_offset !== null && (!Number.isSafeInteger(matches.next_offset) || matches.next_offset <= offset || matches.next_offset > 10_000))) throw changed();
    if (offset !== 0 && matches.epoch !== target.epoch) throw changed();
    const items = offset === 0 ? [] : [...target.items];
    const seen = new Set(items.map(item => item.id));
    for (const item of matches.items) if (!seen.has(item.id)) { items.push(item); seen.add(item.id); }
    target.items = items.slice(0, 200); target.epoch = matches.epoch;
    target.nextOffset = items.length >= 200 ? null : matches.next_offset;
    target.warning = items.length >= 200 && matches.next_offset !== null
      ? 'Open the toolbar popup to see more matching logins.' : matches.warning;
  }
  async function inlineRequest(document: DocumentState, data: Record<string, unknown>) {
    if (typeof data.token !== 'string' || !data.token.length || data.token.length > 64) throw changed();
    let state = inlineTargets.get(document);
    if (data.action === 'dismiss') {
      if (state?.token === data.token) clearInline(document);
      return { connection: { ...native.snapshot } };
    }
    if (!['list', 'more', 'preview', 'fill', 'unlock', 'open-popup'].includes(String(data.action))) throw changed();
    if (inlineWork >= 2) throw new Error('Another login request is in progress. Try again.');
    if (data.action === 'list' || ((data.action === 'open-popup' || data.action === 'unlock') && !state)) {
      clearInline(document);
      state = { token: data.token, generation: document.generation, controller: new AbortController(), busy: false };
      inlineTargets.set(document, state);
    }
    if (!state || state.token !== data.token || state.busy) throw changed();
    const current = state;
    current.busy = true; inlineWork++;
    try {
      const tab = await inspectInline(document, current);
      if (current.kind === 'card') {
        if (new URL(tab.url).protocol !== 'https:' || new URL(document.url).protocol !== 'https:') throw changed();
        if (data.action === 'list') return { connection: { ...native.snapshot }, message: 'Choose a credit card in the toolbar popup.' };
        if (data.action !== 'open-popup') throw new Error('Select a card in the toolbar popup.');
      }
      if (data.action === 'list') {
        await native.connect();
        await inspectInline(document, current);
        if (native.snapshot.state !== 'ready') return { connection: { ...native.snapshot } };
        const target: Target = { scope: 'inline', kind: current.kind, id: crypto.randomUUID(), document, generation: current.generation,
          token: current.token, context: { top_url: tab.url, frame_url: document.url, document_id: `${document.tabId}:${document.frameId}:${current.generation}` },
          controller: current.controller, items: [], epoch: native.snapshot.epoch,
          crossOrigin: new URL(tab.url).origin !== document.origin, focused: true, nextOffset: null, filling: false };
        current.target = target;
        await validate(target);
        const matches = expect(await native.request({ type: target.kind === 'card' ? 'ListCards' : target.kind === 'totp' ? 'ListTotpMatches' : 'ListMatches', ...target.context }, target.controller.signal), 'Matches');
        await inspectInline(document, current); await validate(target);
        inlineMatches(target, matches, 0);
        return { connection: { ...native.snapshot }, frame: inlineFrame(target), warning: target.warning ?? undefined,
          ...(target.items.length ? {} : { message: 'No matching logins for this page.' }) };
      }
      if (data.action === 'unlock') {
        if (native.snapshot.state === 'locked') await native.request({ type: 'RequestUnlock' }, current.controller.signal);
        await validateInline(document, current);
        return { connection: { ...native.snapshot } };
      }
      if (data.action === 'open-popup') {
        // This explicit handoff must inspect the current field, rather than reuse
        // an older toolbar selection from another form in the same document.
        clearTargets(document.tabId, false);
        await openPicker(document.tabId);
        clearInline(document);
        return { connection: { ...native.snapshot }, message: 'Use the Boltwarden toolbar button to continue.' };
      }
      const target = current.target;
      if (!target || target.id !== data.targetId || target.epoch !== native.snapshot.epoch || native.snapshot.state !== 'ready') throw changed();
      await validate(target);
      if (data.action === 'preview') {
        const item = target.items.find(candidate => candidate.id === data.itemId);
        // Preview must never trigger a protected-item prompt or bypass destination consent.
        if (target.kind !== 'totp' || !item || item.reprompt || item.requires_confirmation || target.crossOrigin
          || new URL(target.context.frame_url).protocol !== 'https:' || new URL(target.context.top_url).protocol !== 'https:') throw changed();
        const code = expect(await native.request({ type: 'FillTotp', ...target.context, item_id: item.id, revision: item.revision,
          interaction: 'popup', confirm_insecure: false, confirm_cross_origin: false }, current.controller.signal), 'Totp');
        try {
          await inspectInline(document, current); await validate(target);
          if (native.snapshot.state !== 'ready' || code.epoch !== native.snapshot.epoch || code.document_id !== target.context.document_id
            || Date.now() >= code.expires_at * 1000) throw changed();
          return { connection: { ...native.snapshot }, frame: inlineFrame(target), warning: target.warning ?? undefined,
            preview: { itemId: item.id, code: code.code, expiresAt: code.expires_at } };
        } finally { code.code = ''; }
      }
      if (data.action === 'fill') {
        if (typeof data.itemId !== 'string') throw changed();
        const item = target.items.find(candidate => candidate.id === data.itemId);
        if (!item) throw changed();
        if (target.crossOrigin || item.requires_confirmation || new URL(target.context.frame_url).protocol !== 'https:'
          || new URL(target.context.top_url).protocol !== 'https:') throw new NativeError('ConfirmationRequired', 'Use the toolbar popup to confirm this login.');
        await fill(target, data.itemId, 'popup', false, false);
        return { connection: { ...native.snapshot }, message: 'Login filled.' };
      }
      if (target.filling || target.nextOffset === null) throw changed();
      const offset = target.nextOffset;
      const matches = expect(await native.request({ type: target.kind === 'card' ? 'ListCards' : target.kind === 'totp' ? 'ListTotpMatches' : 'ListMatches', ...target.context, offset }, target.controller.signal), 'Matches');
      await inspectInline(document, current); await validate(target);
      inlineMatches(target, matches, offset);
      return { connection: { ...native.snapshot }, frame: inlineFrame(target), warning: target.warning ?? undefined };
    } catch (error) {
      if (!(error instanceof NativeError && error.code === 'ConfirmationRequired') && inlineTargets.get(document) === current) clearInline(document);
      throw error;
    } finally { current.busy = false; inlineWork--; }
  }
  async function fill(target: Target, itemId: string, interaction: 'shortcut' | 'popup', insecure: boolean, crossOrigin: boolean) {
    if (target.filling) throw new Error('This login is already being filled.');
    const item = target.items.find(candidate => candidate.id === itemId);
    if (!item) throw changed();
    if (target.kind === 'card' && (target.scope === 'inline' || interaction !== 'popup'
      || new URL(target.context.top_url).protocol !== 'https:' || new URL(target.context.frame_url).protocol !== 'https:')) throw new Error('Select a card in the toolbar popup on an HTTPS page.');
    if (interaction === 'shortcut' && (item.reprompt || item.requires_confirmation || target.crossOrigin)) throw new Error('Use the toolbar popup to confirm this login.');
    if (target.crossOrigin && !crossOrigin) throw new Error('Confirm the destination frame before filling.');
    if (item.requires_confirmation && !insecure) throw new Error('Confirm filling on this insecure page.');
    await validate(target);
    target.filling = true;
    let credentials: ReturnType<typeof expect<'Credentials'>> | ReturnType<typeof expect<'Totp'>> | ReturnType<typeof expect<'Card'>> | undefined;
    try {
      const response = await native.request({ type: target.kind === 'card' ? 'FillCard' : target.kind === 'totp' ? 'FillTotp' : 'FillLogin', ...target.context, item_id: item.id, revision: item.revision,
        interaction, confirm_insecure: insecure, confirm_cross_origin: crossOrigin }, target.controller.signal);
      credentials = target.kind === 'card' ? expect(response, 'Card') : target.kind === 'totp' ? expect(response, 'Totp') : expect(response, 'Credentials');
      if (target.scope === 'inline') {
        const state = inlineTargets.get(target.document);
        if (!state || state.target !== target) throw changed();
        await inspectInline(target.document, state);
      }
      await validate(target);
      if (native.snapshot.state !== 'ready' || credentials.epoch !== native.snapshot.epoch
        || credentials.document_id !== target.context.document_id) throw changed();
      if (credentials.type === 'Totp' && Date.now() >= credentials.expires_at * 1000 - 1000) throw new Error('Verification code expired. Choose the account again for a fresh code.');
      // Never auto-submit cards or a fill the user had to confirm (insecure page or embedded frame).
      // Only on HTTPS pages: on HTTP a network attacker could inject the form being submitted.
      const secure = new URL(target.context.top_url).protocol === 'https:' && new URL(target.context.frame_url).protocol === 'https:';
      const submit = credentials.type !== 'Card' && secure && !insecure && !crossOrigin && !target.crossOrigin && !item.requires_confirmation
        && (await readSettings(browser.storage)).autoSubmit ? { submit: true } : {};
      const payload = credentials.type === 'Card' ? { kind: 'card', card: credentials.card } : credentials.type === 'Totp' ? { kind: 'totp', code: credentials.code, expiresAt: credentials.expires_at, ...submit }
        : { username: credentials.username, password: credentials.password, ...submit };
      const reply = await ask(target.document, { type: 'fill', token: target.token, ...(target.scope ? { scope: target.scope } : {}), ...payload })
        .finally(() => { if ('card' in payload && payload.card) clearCard(payload.card); else if ('code' in payload) payload.code = ''; else { payload.username = ''; payload.password = ''; } });
      if (reply.type !== 'filled') throw changed();
      badge('', target.document.tabId, 'Boltwarden: login filled');
      if (target.kind === 'login' && !item.reprompt) await copyTotp(target, item, interaction);
    } finally {
      if (credentials?.type === 'Credentials') { credentials.username = ''; credentials.password = ''; }
      if (credentials?.type === 'Card') clearCard(credentials.card);
      if (credentials?.type === 'Totp') credentials.code = '';
      if (target.scope === 'inline') {
        if (inlineTargets.get(target.document)?.target === target) clearInline(target.document);
      } else clearTargets(target.document.tabId, false);
    }
  }
  // Best effort: the login is already filled, so a missing code, declined permission,
  // or clipboard failure must not turn the fill into an error. Protected items are
  // skipped so the copy never causes a second master-password prompt.
  async function copyTotp(target: Target, item: Match, interaction: 'shortcut' | 'popup') {
    try {
      const settings = await readSettings(browser.storage);
      if (!settings.copyTotp || !await browser.permissions.contains(CLIPBOARD_PERMISSION)) return;
      const response = await native.request({ type: 'FillTotp', ...target.context, item_id: item.id, revision: item.revision,
        // Its own signal: auto-submit navigates the page, which aborts the fill target's controller.
        interaction, confirm_insecure: false, confirm_cross_origin: false }, AbortSignal.timeout(15_000));
      const code = expect(response, 'Totp');
      try {
        if (code.document_id === target.context.document_id && Date.now() < code.expires_at * 1000) {
          await copyFromBackground(code.code);
          // An alarm survives the background being suspended; creating it again restarts the wait.
          await browser.alarms.create(CLEAR_CLIPBOARD, { delayInMinutes: settings.clearClipboardSeconds / 60 });
        }
      } finally { code.code = ''; }
    } catch { /* No code for this login, or the copy was refused. */ }
  }
  // Wipes the clipboard once the copy-code wait is over. Without clipboard read access it cannot
  // check what is there, so anything copied in the meantime is wiped too (the setting says so).
  browser.alarms.onAlarm.addListener(alarm => {
    if (alarm.name === CLEAR_CLIPBOARD) void copyFromBackground('').catch(() => {});
  });
  async function openPicker(tabId: number) {
    pickerTabs.add(tabId);
    badge('!', tabId, 'Boltwarden: click the toolbar button to select a login');
    try { await browser.action.openPopup(); } catch { /* Firefox 128 requires a still-active user gesture. */ }
  }
  browser.commands.onCommand.addListener(command => {
    if (command !== 'autofill') return;
    void (async () => {
      const tab = await activeTab();
      await native.connect();
      if (native.snapshot.state === 'locked') { await native.request({ type: 'RequestUnlock' }); badge('L', tab.id, 'Unlock Boltwarden, then press the shortcut again'); return; }
      if (native.snapshot.state !== 'ready') { await openPicker(tab.id); return; }
      const found = await discover(tab.id);
      if (shortcutBlocked.has(tab.id)) {
        if (discoveryWarnings.has(tab.id)) await openPicker(tab.id);
        else badge('!', tab.id, 'Select an unambiguous login field, then try again');
        return;
      }
      const eligible = found.filter(target => !target.crossOrigin);
      const focused = eligible.filter(target => target.focused);
      const target = focused.length === 1 ? focused[0] : eligible.find(candidate => candidate.document.frameId === 0);
      if (target && target.kind !== 'card' && target.items.length === 1 && target.nextOffset === null && !target.items[0]!.reprompt && !target.items[0]!.requires_confirmation) {
        await fill(target, target.items[0]!.id, 'shortcut', false, false);
      } else await openPicker(tab.id);
    })().catch(error => badge('!', undefined, error instanceof Error ? error.message : 'Open Boltwarden to continue'));
  });

  browser.runtime.onMessage.addListener((message: unknown, sender) => {
    if (!trustedUi(sender) || !message || typeof message !== 'object' || !('type' in message)) return;
    const data = message as Record<string, unknown>;
    const run = async (): Promise<unknown> => {
      switch (data.type) {
        case 'state': {
          await native.connect().catch(() => {});
          return { connection: native.snapshot, fingerprint: (await publicIdentity()).fingerprint };
        }
        case 'pending-saves': return saves.list();
        case 'retry-save': await saves.retry(String(data.id)); return null;
        case 'discard-save': await saves.discard(String(data.id)); return null;
        case 'retry': await native.connect(); await native.refreshStatus(); return native.snapshot;
        case 'pair': await native.pair(await pairingBrowserLabel(browser.runtime, globalThis.navigator)); return native.snapshot;
        case 'unlock': await native.request({ type: 'RequestUnlock' }); return null;
        case 'list': {
          await native.connect(); await native.refreshStatus();
          const tab = await activeTab();
          const existing = Array.from(targets.values()).filter(target => target.document.tabId === tab.id);
          if (pickerTabs.has(tab.id) && existing.length) {
            for (const target of existing) await validate(target);
            return page(existing, tab.id);
          }
          return page(await discover(tab.id), tab.id);
        }
        case 'fill': {
          if (typeof data.targetId !== 'string' || typeof data.itemId !== 'string') throw changed();
          const target = targets.get(data.targetId);
          if (!target) throw changed();
          await fill(target, data.itemId, 'popup', data.confirmInsecure === true, data.confirmCrossOrigin === true);
          return null;
        }
        case 'more': {
          if (typeof data.targetId !== 'string') throw changed();
          const target = targets.get(data.targetId);
          if (!target || target.filling || target.nextOffset === null) throw changed();
          await validate(target);
          const offset = target.nextOffset;
          const matches = expect(await native.request({ type: target.kind === 'card' ? 'ListCards' : target.kind === 'totp' ? 'ListTotpMatches' : 'ListMatches', ...target.context, offset }, target.controller.signal), 'Matches');
          await validate(target);
          if (matches.epoch !== target.epoch || (matches.next_offset !== null && matches.next_offset <= offset)) throw changed();
          const seen = new Set(target.items.map(item => item.id));
          target.items.push(...matches.items.filter(item => !seen.has(item.id)));
          target.nextOffset = matches.next_offset;
          target.warning = matches.warning;
          return page([target]).frames[0];
        }
        default: throw new NativeError('InvalidRequest', 'Unknown browser action.');
      }
    };
    return run().then(value => ({ ok: true, value } satisfies UiResult<unknown>), error => ({ ok: false, error: error instanceof Error ? error.message : 'Browser request failed.' } satisfies UiResult<never>));
  });
});
