import { defineContentScript } from 'wxt/utils/define-content-script';
import { browser } from 'wxt/browser';
import { isOperation, PASSKEY_CHANNEL, PASSKEY_PORT } from '../lib/passkey-types';
import { readSettings } from '../lib/settings';
import { showUnavailableDialog, type UnavailableChoice } from '../lib/passkey-dialog';

/** A background that has not marked this document ready by then is treated as not responding. */
const READY_LIMIT = 10_000;

export default defineContentScript({
  matches: ['https://*/*'], allFrames: false, runAt: 'document_start',
  main(ctx) {
    if (!isSecureContext || window.top !== window || location.protocol !== 'https:') return;
    const documentToken = crypto.randomUUID();
    const identify = (message: unknown, sender: { id?: string }) => {
      if (sender.id === browser.runtime.id && (message as { type?: string })?.type === 'passkey-document-check') return Promise.resolve({ token: documentToken });
    };
    browser.runtime.onMessage.addListener(identify);
    let connection: ReturnType<typeof browser.runtime.connect> | undefined;
    let generation = '';
    let ready = false;
    let readyTimer: ReturnType<typeof setTimeout> | undefined;
    // `held` keeps a request back while the user decides what to do with it.
    let pending: { id: string; channel: MessagePort; message: Record<string, unknown>; options: { timeout_ms: number }; deadline: number; sent: boolean; held: boolean } | undefined;
    let dialog: { close(): void } | undefined;
    const finish = (message: Record<string, unknown>) => {
      if (!pending) return;
      dialog?.close(); dialog = undefined;
      try { pending.channel.postMessage({ ...message, id: pending.id }); } catch { /* caller gone */ }
      pending.channel.close(); pending = undefined; clearTimeout(readyTimer); readyTimer = undefined;
    };
    const cancelled = () => ({ type: 'error', name: 'NotAllowedError', message: 'The passkey request was cancelled.' });
    const waitForReady = () => {
      clearTimeout(readyTimer);
      readyTimer = setTimeout(() => { if (pending && !pending.sent) void unavailable('not-responding'); }, READY_LIMIT);
    };
    const choose = (current: NonNullable<typeof pending>, choice: UnavailableChoice) => {
      dialog = undefined;
      if (pending !== current) return;
      if (choice === 'browser') { finish({ type: 'fallback', reason: 'user-chose-browser' }); return; }
      if (choice === 'cancel') { finish(cancelled()); return; }
      // A retry keeps the page's original deadline rather than starting a new one.
      const remaining = Math.floor(current.deadline - Date.now());
      if (remaining < 1000) { finish({ type: 'error', name: 'NotAllowedError', message: 'The passkey request timed out.' }); return; }
      current.message = { ...current.message, options: { ...current.options, timeout_ms: remaining } };
      current.sent = false; current.held = false;
      waitForReady(); connect(); flush();
    };
    const unavailable = async (reason: string) => {
      const current = pending;
      if (!current || current.held) return;
      current.held = true; clearTimeout(readyTimer); readyTimer = undefined;
      const settings = await readSettings(browser.storage);
      if (pending !== current) return;
      console.info('[Boltwarden] Passkey unavailable:', reason, settings.passkeyUnavailable);
      if (settings.passkeyUnavailable === 'browser') { finish({ type: 'fallback', reason: `unavailable-${reason}` }); return; }
      if (settings.passkeyUnavailable === 'cancel') { finish(cancelled()); return; }
      dialog?.close();
      dialog = showUnavailableDialog(document, { reason, site: location.host, theme: settings.theme, choose: choice => choose(current, choice) });
    };
    const flush = () => {
      if (pending && !pending.sent && !pending.held && generation && ready && connection) {
        clearTimeout(readyTimer); readyTimer = undefined;
        pending.sent = true; connection.postMessage({ ...pending.message, generation });
      }
    };
    const connect = () => {
      if (ctx.isInvalid || connection) return;
      const port = browser.runtime.connect({ name: PASSKEY_PORT }); connection = port;
      port.onMessage.addListener(message => {
        if (connection !== port || !message || typeof message !== 'object') return;
        if (message.type === 'generation') {
          if (pending?.sent && generation && message.generation !== generation) finish({ type: 'error', name: 'AbortError', message: 'The page changed.' });
          generation = message.generation; ready = message.ready === true; flush();
        } else if (pending && message.id === pending.id && message.generation === generation) {
          if (message.type === 'unavailable') void unavailable(typeof message.reason === 'string' ? message.reason : 'unknown');
          else finish(message);
        }
      });
      const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
      // Firefox rounds timeOrigin independently, and a request event can be
      // timestamped after the first response byte on a fast local navigation.
      // Bound it by the browser's navigation-to-parser-start epoch interval,
      // before this document can run page scripts or initiate another navigation.
      // BFCache restores keep the old timing; no tolerance window is added.
      const legacy = performance.timing;
      const epochTiming = legacy && legacy.navigationStart > 0 && legacy.domLoading >= legacy.navigationStart;
      port.postMessage({ type: 'identify', token: documentToken,
        navigation_start: epochTiming ? legacy.navigationStart : performance.timeOrigin,
        binding_end: epochTiming ? legacy.domLoading
          : navigation && navigation.responseStart > 0 ? performance.timeOrigin + navigation.responseStart : undefined });
      port.onDisconnect.addListener(() => {
        if (connection !== port) return;
        connection = undefined; generation = ''; ready = false;
        finish({ type: 'error', name: 'AbortError', message: 'The browser connection was interrupted.' });
      });
    };
    ctx.addEventListener(window, 'message', event => {
      if (!event.isTrusted || event.source !== window || event.origin !== location.origin
        || event.data?.source !== PASSKEY_CHANNEL || event.data.type !== 'request'
        || typeof event.data.id !== 'string' || event.data.id.length > 64 || event.ports.length !== 1) return;
      const channel = event.ports[0]!;
      const id: string = event.data.id;
      if (!isOperation(event.data) || pending) { channel.postMessage({ id: event.data.id, type: 'fallback' }); channel.close(); return; }
      const policy = (document as Document & { featurePolicy?: { allowsFeature(name: string): boolean }; permissionsPolicy?: { allowsFeature(name: string): boolean } });
      let allowed: boolean | undefined;
      try { allowed = (policy.permissionsPolicy ?? policy.featurePolicy)?.allowsFeature(`publickey-credentials-${event.data.kind}`); } catch { /* require trusted response headers instead */ }
      pending = { id, channel, sent: false, held: false, options: event.data.options, deadline: Date.now() + event.data.options.timeout_ms,
        message: { type: 'operation', id, kind: event.data.kind, options: event.data.options, policy_allowed: allowed, visible: document.visibilityState === 'visible' } };
      channel.onmessage = ({ data }) => {
        if (!pending || data?.type !== 'cancel' || data.id !== pending.id) return;
        try { connection?.postMessage({ type: 'cancel', generation, id: pending.id }); } catch { /* disconnected */ }
        finish({ type: 'error', name: 'AbortError', message: 'The request was aborted.' });
      };
      // A queued operation belongs to this isolated document, not to an initial
      // background generation that delayed navigation events can still replace.
      waitForReady();
      channel.postMessage({ type: 'ack', id: pending.id }); connect(); flush();
    });
    ctx.addEventListener(window, 'pagehide', () => { connection?.disconnect(); connection = undefined; generation = ''; ready = false; finish({ type: 'error', name: 'AbortError', message: 'The page changed.' }); });
    ctx.addEventListener(window, 'pageshow', connect);
    ctx.onInvalidated(() => { browser.runtime.onMessage.removeListener(identify); connection?.disconnect(); connection = undefined; finish({ type: 'error', name: 'AbortError', message: 'Extension reloaded.' }); });
    connect();
  },
});
