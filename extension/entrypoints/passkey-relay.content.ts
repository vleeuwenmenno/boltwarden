import { defineContentScript } from 'wxt/utils/define-content-script';
import { browser } from 'wxt/browser';
import { isOperation, PASSKEY_CHANNEL, PASSKEY_PORT } from '../lib/passkey-types';

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
    let pending: { id: string; channel: MessagePort; message: Record<string, unknown>; sent: boolean } | undefined;
    const finish = (message: Record<string, unknown>) => {
      if (!pending) return;
      try { pending.channel.postMessage({ ...message, id: pending.id }); } catch { /* caller gone */ }
      pending.channel.close(); pending = undefined; clearTimeout(readyTimer); readyTimer = undefined;
    };
    const flush = () => {
      if (pending && !pending.sent && generation && ready && connection) {
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
        } else if (pending && message.id === pending.id && message.generation === generation) finish(message);
      });
      const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
      port.postMessage({ type: 'identify', token: documentToken, navigation_start: performance.timeOrigin,
        response_start: navigation && navigation.responseStart > 0 ? performance.timeOrigin + navigation.responseStart : undefined });
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
      pending = { id, channel, sent: false, message: { type: 'operation', id,
        kind: event.data.kind, options: event.data.options, policy_allowed: allowed, visible: document.visibilityState === 'visible' } };
      channel.onmessage = ({ data }) => {
        if (!pending || data?.type !== 'cancel' || data.id !== pending.id) return;
        try { connection?.postMessage({ type: 'cancel', generation, id: pending.id }); } catch { /* disconnected */ }
        finish({ type: 'error', name: 'AbortError', message: 'The request was aborted.' });
      };
      // A queued operation belongs to this isolated document, not to an initial
      // background generation that delayed navigation events can still replace.
      readyTimer = setTimeout(() => {
        if (pending && !pending.sent) finish({ type: 'fallback', reason: 'document-readiness-timeout' });
      }, Math.max(1000, event.data.options.timeout_ms - 500));
      channel.postMessage({ type: 'ack', id: pending.id }); connect(); flush();
    });
    ctx.addEventListener(window, 'pagehide', () => { connection?.disconnect(); connection = undefined; generation = ''; ready = false; finish({ type: 'error', name: 'AbortError', message: 'The page changed.' }); });
    ctx.addEventListener(window, 'pageshow', connect);
    ctx.onInvalidated(() => { browser.runtime.onMessage.removeListener(identify); connection?.disconnect(); connection = undefined; finish({ type: 'error', name: 'AbortError', message: 'Extension reloaded.' }); });
    connect();
  },
});
