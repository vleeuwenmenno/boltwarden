import { fillCard } from '../lib/cards';
import { isCard, clearCard } from '../lib/protocol';
import { defineContentScript } from 'wxt/utils/define-content-script';
import { browser } from 'wxt/browser';
import { activeInput, autofillForms, fillForm, fillOtp, formContains, formKind, sameForm, selectForm, visibleInput, type LoginForm } from '../lib/forms';
import { installPasswordCapture, saveNotice } from '../lib/password-capture';
import { createInlineController } from '../lib/inline';
import type { InlineAction, InlineValue } from '../lib/inline-types';

export default defineContentScript({
  matches: ['http://*/*', 'https://*/*'],
  allFrames: true,
  runAt: 'document_idle',
  main(ctx) {
    let port: ReturnType<typeof browser.runtime.connect> | undefined;
    let generation = '';
    type Pin = { token: string; form: LoginForm; url: string };
    let selected: Pin | undefined;
    let inlinePin: (Pin & { input: HTMLInputElement }) | undefined;
    let reconnect: number | undefined;
    let suspended = false;
    let inline: ReturnType<typeof createInlineController> | undefined;
    const pending = new Map<string, { generation: string; resolve(value: InlineValue): void; reject(error: Error): void; timer: ReturnType<typeof setTimeout> }>();
    const failPending = () => {
      for (const request of pending.values()) { clearTimeout(request.timer); request.reject(new Error('The page or browser connection changed. Try again.')); }
      pending.clear();
    };
    const currentInline = (token: string) => !!inlinePin && token === inlinePin.token && inlinePin.url === location.href
      && activeInput(document) === inlinePin.input && visibleInput(inlinePin.input)
      && autofillForms(document).some(form => sameForm(form, inlinePin!.form));
    const request = (action: InlineAction, fields: { token: string; targetId?: string; itemId?: string }) => new Promise<InlineValue>((resolve, reject) => {
      if (!port || !generation || (action !== 'dismiss' && !currentInline(fields.token))) { reject(new Error('Boltwarden is not connected to this page.')); return; }
      const id = crypto.randomUUID();
      const timer = setTimeout(() => { pending.delete(id); reject(new Error('Boltwarden did not respond. Try again.')); }, action === 'fill' || action === 'unlock' ? 65_000 : 30_000);
      pending.set(id, { generation, resolve, reject, timer });
      try { port.postMessage({ type: 'inline-request', id, generation, action, ...fields }); }
      catch { clearTimeout(timer); pending.delete(id); reject(new Error('Boltwarden is not connected to this page.')); }
    });
    const createInline = () => {
      if (inline || ctx.isInvalid || suspended) return;
      inline = createInlineController(document, {
        pin(input) {
          const form = autofillForms(document).find(form => formContains(form, input));
          if (!form || activeInput(document) !== input || !visibleInput(input)) return undefined;
          inlinePin = { token: crypto.randomUUID(), form, url: location.href, input };
          return inlinePin.token;
        },
        current: currentInline,
        request,
        release() { inlinePin = undefined; },
      });
    };

    const connect = () => {
      if (ctx.isInvalid || port || suspended) return;
      createInline();
      const connection = browser.runtime.connect({ name: 'boltwarden-document-v1' });
      port = connection;
      connection.onMessage.addListener(message => {
        if (!message || typeof message !== 'object' || port !== connection) return;
        if (message.type === 'generation' && typeof message.generation === 'string') {
          failPending(); generation = message.generation; selected = undefined; inlinePin = undefined; inline?.reset(); return;
        }
        if (message.generation !== generation) return;
        if (message.type === 'inline-state') { inline?.state(message.connection, message.reason); return; }
        if (message.type === 'save-status' && typeof message.message === 'string') { saveNotice(document, message.message); return; }
        if (typeof message.id !== 'string') return;
        if (message.type === 'inline-response') {
          const waiting = pending.get(message.id);
          if (!waiting || waiting.generation !== generation) return;
          pending.delete(message.id); clearTimeout(waiting.timer);
          if (message.ok && message.value) waiting.resolve(message.value);
          else waiting.reject(new Error(typeof message.error === 'string' ? message.error : 'Could not load logins.'));
          return;
        }
        try {
          if (message.type === 'inspect') {
            const forms = autofillForms(document);
            const active = activeInput(document);
            if (typeof message.requestedToken === 'string') {
              const focused = currentInline(message.requestedToken);
              connection.postMessage({ type: 'inspected', id: message.id, generation, token: focused ? inlinePin!.token : null, focused, kind: focused ? formKind(inlinePin!.form) : undefined, formCount: forms.length });
            } else {
              const form = selectForm(forms, active);
              selected = form ? { token: crypto.randomUUID(), form, url: location.href } : undefined;
              connection.postMessage({ type: 'inspected', id: message.id, generation, token: selected?.token ?? null, kind: form ? formKind(form) : undefined,
                focused: document.hasFocus() && (active instanceof HTMLInputElement || active instanceof HTMLSelectElement) && ['text', 'email', 'tel', 'password', 'number', 'month', 'select-one'].includes(active.type),
                formCount: forms.length });
            }
          } else if (message.type === 'fill') {
            const isInline = message.scope === 'inline';
            const target = isInline ? inlinePin : selected;
            if (isInline) inlinePin = undefined; else selected = undefined;
            const current = () => !!target && target.url === location.href && message.generation === generation
              && autofillForms(document).some(form => sameForm(form, target.form))
              && (!isInline || ('input' in target && (activeInput(document) === target.input || !!target.form.otp && formContains(target.form, activeInput(document))) && visibleInput(target.input as HTMLInputElement)));
            if (!target || target.token !== message.token || !current()) {
              throw new Error('The page or login form changed. Try again.');
            }
            if (target.form.card) {
              if (isInline || location.protocol !== 'https:' || message.kind !== 'card' || !isCard(message.card)) throw new Error('Expected an explicit secure card fill.');
              try { fillCard(target.form.card, message.card, visibleInput, current); } finally { clearCard(message.card); }
            } else if (target.form.otp) {
              if (message.kind !== 'totp' || typeof message.code !== 'string' || typeof message.expiresAt !== 'number') throw new Error('Expected a verification code.');
              fillOtp(target.form, message.code, message.expiresAt, visibleInput, current);
            } else {
              if (message.kind === 'totp' || message.kind === 'card' || typeof message.username !== 'string' || typeof message.password !== 'string') throw new Error('Expected login credentials.');
              fillForm(target.form, message.username, message.password, visibleInput, current);
            }
            if (isInline) inline?.reset();
            connection.postMessage({ type: 'filled', id: message.id, generation });
          }
        } catch (error) {
          if (message.type === 'fill' && message.scope === 'inline') inline?.reset();
          connection.postMessage({ type: 'failure', id: message.id, generation,
            message: error instanceof Error ? error.message : 'Could not fill this page.' });
        }
      });
      connection.onDisconnect.addListener(() => {
        if (port !== connection) return;
        port = undefined; selected = undefined; inlinePin = undefined; generation = ''; failPending(); inline?.reset();
        if (!suspended) reconnect = ctx.setTimeout(connect, 1000);
      });
    };

    const stop = () => {
      suspended = true; clearTimeout(reconnect); selected = undefined; inlinePin = undefined; generation = ''; failPending();
      inline?.destroy(); inline = undefined;
      const old = port; port = undefined; old?.disconnect();
    };
    ctx.addEventListener(window, 'pagehide', stop);
    ctx.addEventListener(window, 'pageshow', () => { suspended = false; connect(); });
    ctx.onInvalidated(stop);
    if (window.top === window && location.protocol === 'https:') {
      const cleanup = installPasswordCapture(document, login => {
        if (port && generation && !suspended) {
          try { port.postMessage({ type: 'save-login', id: crypto.randomUUID(), generation, login }); }
          catch { /* A disconnected extension cannot offer a save. */ }
        }
        login.password = ''; login.username = '';
      });
      ctx.onInvalidated(cleanup);
    }
    connect();
  },
});
