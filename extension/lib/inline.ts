import { activeInput, loginForms, visibleInput } from './forms';
import type { NativeSnapshot } from './native';
import type { InlineAction, InlineValue, InlineState } from './inline-types';
import css from './inline.css?inline';
import bolt from '../public/bolt.svg?raw';

export interface InlineOptions {
  pin(input: HTMLInputElement): string | undefined;
  current(token: string): boolean;
  request(action: InlineAction, fields: { token: string; targetId?: string; itemId?: string }): Promise<InlineValue>;
  release(): void;
}

/** Isolated-world UI: no page messaging, HTML from vault values, or input values. */
export function createInlineController(doc: Document, options: InlineOptions) {
  const host = doc.createElement('div'); host.dataset.boltwardenInline = '';
  const root = host.attachShadow({ mode: 'closed' });
  const sheet = new CSSStyleSheet(); sheet.replaceSync(css); root.adoptedStyleSheets = [sheet];
  const mark = doc.createElement('button'); mark.className = 'mark'; mark.type = 'button'; mark.tabIndex = -1;
  mark.setAttribute('aria-label', 'Show Boltwarden logins'); mark.title = 'Boltwarden'; mark.hidden = true;
  const svg = new DOMParser().parseFromString(bolt, 'image/svg+xml').documentElement;
  mark.append(doc.importNode(svg, true));
  const menu = doc.createElement('div'); menu.className = 'menu'; menu.hidden = true;
  menu.setAttribute('role', 'listbox'); menu.setAttribute('aria-label', 'Logins for this page');
  root.append(mark, menu); doc.documentElement.append(host);
  let field: HTMLInputElement | undefined, token: string | undefined, value: InlineValue | undefined;
  let open = false, busy = false, index = 0, revision = 0, dead = false, animation = 0;
  let activeAction: InlineAction | undefined;
  const observed = new Set<Document | ShadowRoot>();
  const controller = new AbortController();
  const listen = (target: EventTarget, type: string, handler: EventListener, capture = false) => target.addEventListener(type, handler, { capture, signal: controller.signal });
  const eligible = (input: Element | null): input is HTMLInputElement => input instanceof HTMLInputElement && visibleInput(input)
    && loginForms(doc).some(form => form.username === input || form.password === input);
  function close(notify = true) {
    const previous = token;
    revision++; open = false; busy = false; activeAction = undefined; token = undefined; value = undefined; menu.hidden = true; menu.replaceChildren(); mark.setAttribute('aria-expanded', 'false');
    options.release();
    if (notify && previous) void options.request('dismiss', { token: previous }).catch(() => {});
  }
  function position() {
    if (!field || !eligible(field)) { close(); field = undefined; mark.hidden = true; return; }
    const rect = field.getBoundingClientRect(), width = doc.defaultView!.innerWidth, height = doc.defaultView!.innerHeight;
    mark.style.left = `${Math.max(2, Math.min(width - 28, rect.right - 30))}px`;
    mark.style.top = `${Math.max(2, Math.min(height - 28, rect.top + (rect.height - 26) / 2))}px`;
    const menuWidth = Math.max(0, Math.min(340, width - 16));
    menu.style.width = `${menuWidth}px`; menu.style.left = `${Math.max(8, Math.min(width - menuWidth - 8, rect.left))}px`;
    const below = Math.max(0, height - rect.bottom - 12), above = Math.max(0, rect.top - 12);
    const up = below < 180 && above > below;
    const maximum = Math.min(300, up ? above : below);
    menu.style.maxHeight = `${maximum}px`;
    menu.style.top = up ? `${Math.max(8, rect.top - Math.min(menu.scrollHeight, maximum) - 4)}px` : `${Math.max(8, rect.bottom + 4)}px`;
  }
  function observeRoots() {
    const scan = (node: Document | ShadowRoot) => {
      if (!observed.has(node)) { observer.observe(node, { subtree: true, childList: true, attributes: true,
        attributeFilter: ['disabled', 'readonly', 'hidden', 'inert', 'type', 'autocomplete', 'name', 'id', 'style', 'class', 'aria-hidden', 'aria-disabled'] }); observed.add(node); }
      for (const element of node.querySelectorAll('*')) if (element.shadowRoot) scan(element.shadowRoot);
    };
    scan(doc);
  }
  function refresh() {
    if (dead) return;
    observeRoots();
    const active = activeInput(doc);
    if (active !== field) { close(); field = eligible(active) ? active : undefined; }
    if (token && !options.current(token)) close();
    if (field && (!eligible(field) || doc.visibilityState === 'hidden')) { close(); field = undefined; }
    mark.hidden = !field;
    if (field) position();
  }
  function schedule() {
    if (!animation && !dead) animation = requestAnimationFrame(() => { animation = 0; refresh(); });
  }
  const observer = new MutationObserver(records => {
    if (records.some(record => record.target !== host && !(record.type === 'childList' && [...record.addedNodes, ...record.removedNodes].every(node => node === host)))) schedule();
  });
  const current = () => !!token && !!field && activeInput(doc) === field && eligible(field) && options.current(token);
  function text(message: string, warning = false) {
    const element = doc.createElement('div'); element.className = warning ? 'message warning' : 'message'; element.textContent = message; menu.append(element);
  }
  function action(label: string, kind: InlineAction) {
    const button = doc.createElement('button'); button.type = 'button'; button.tabIndex = -1; button.className = 'action'; button.textContent = label; button.disabled = busy;
    button.addEventListener('click', event => { if (event.isTrusted) void perform(kind); }); menu.append(button);
  }
  function render() {
    menu.replaceChildren(); menu.hidden = !open;
    mark.setAttribute('aria-expanded', String(open));
    if (!open) return;
    const heading = doc.createElement('div'); heading.className = 'heading'; heading.textContent = 'Boltwarden · Logins for this page'; menu.append(heading);
    if (busy) text('Working…');
    else if (!value) text('Choose a login field and try again.');
    else if (value.connection.state === 'locked') { text('Unlock Boltwarden on your desktop to see matching logins.'); action('Unlock Boltwarden', 'unlock'); }
    else if (value.connection.state !== 'ready') { text(value.message ?? 'Open Boltwarden to connect this browser.'); action('Open Boltwarden', 'open-popup'); }
    else if (value.frame?.crossOrigin || value.frame?.items.some(item => item.requires_confirmation)) {
      text('Use the toolbar popup to confirm this destination.'); action('Open toolbar confirmation', 'open-popup');
    } else {
      if (value.warning) text(value.warning, true);
      const items = value.frame?.items ?? [];
      index = Math.min(index, Math.max(0, items.length - 1));
      if (!items.length) text(value.message ?? 'No matching logins for this page.');
      for (const [row, item] of items.entries()) {
        const button = doc.createElement('button'); button.type = 'button'; button.tabIndex = -1; button.className = 'login'; button.setAttribute('role', 'option');
        button.setAttribute('aria-selected', String(row === index)); button.setAttribute('aria-label', `${item.name}, ${item.username ?? ''}${item.reprompt ? ', master password required' : ''}`);
        const name = doc.createElement('strong'); name.textContent = item.name;
        const username = doc.createElement('span'); username.className = 'username'; username.textContent = item.username ?? '';
        button.append(name, username);
        if (item.reprompt) { const lock = doc.createElement('span'); lock.className = 'lock'; lock.textContent = 'Locked'; lock.setAttribute('aria-hidden', 'true'); button.append(lock); }
        button.addEventListener('click', event => { if (event.isTrusted) { index = row; void perform('fill', item.id); } }); menu.append(button);
      }
      if (value.frame?.more) action('More matching logins', 'more');
    }
    position();
  }
  async function perform(kind: InlineAction, itemId?: string) {
    if (busy || !current() || !token) return;
    const requestToken = token, requestRevision = revision;
    busy = true; activeAction = kind; render();
    try {
      const result = await options.request(kind, { token: requestToken, ...(value?.frame ? { targetId: value.frame.targetId } : {}), ...(itemId ? { itemId } : {}) });
      if (dead || revision !== requestRevision || token !== requestToken) return;
      if (kind === 'fill' || kind === 'open-popup') { close(false); return; }
      if (!current()) { close(); return; }
      value = result; busy = false; activeAction = undefined; render();
    } catch (error) {
      if (dead || revision !== requestRevision || token !== requestToken) return;
      busy = false; activeAction = undefined; value = undefined; render();
      text(error instanceof Error ? error.message : 'Could not load logins.'); action('Open Boltwarden', 'open-popup');
    }
  }
  function show(event: Event) {
    if (!event.isTrusted || busy) return;
    refresh(); if (!field) return;
    if (open) { close(); return; }
    token = options.pin(field); if (!token) return;
    revision++; open = true; index = 0; value = undefined; void perform('list');
  }
  listen(root, 'pointerdown', event => { if (event.isTrusted) event.preventDefault(); });
  listen(mark, 'click', show);
  listen(doc, 'focusin', () => refresh(), true);
  listen(doc, 'focusout', () => queueMicrotask(refresh), true);
  listen(doc, 'pointerdown', event => { if (event.isTrusted && !event.composedPath().includes(host) && event.composedPath()[0] !== field) close(); }, true);
  listen(doc, 'keydown', event => {
    const key = event as KeyboardEvent;
    if (!key.isTrusted || !field || activeInput(doc) !== field) return;
    if (key.key === 'Tab') { close(); return; }
    if (key.key === 'Escape' && open) { key.preventDefault(); key.stopPropagation(); close(); return; }
    if (key.key === 'ArrowDown' && !open) { key.preventDefault(); key.stopPropagation(); show(key); return; }
    if (!open) return;
    if (busy) {
      if (['ArrowDown', 'ArrowUp', 'Enter'].includes(key.key)) { key.preventDefault(); key.stopPropagation(); }
      return;
    }
    const items = value?.frame?.items ?? [];
    if (key.key === 'ArrowDown' || key.key === 'ArrowUp') {
      key.preventDefault(); key.stopPropagation(); if (items.length) index = (index + (key.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length;
      render(); menu.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' });
    } else if (key.key === 'Enter') {
      key.preventDefault(); key.stopPropagation();
      if (value?.frame?.crossOrigin || items.some(item => item.requires_confirmation)) void perform('open-popup');
      else if (value?.connection.state === 'locked') void perform('unlock');
      else if (items[index]) void perform('fill', items[index]!.id);
    }
  }, true);
  listen(doc, 'visibilitychange', () => { if (doc.visibilityState === 'hidden') { close(); mark.hidden = true; } else refresh(); });
  listen(window, 'resize', () => { position(); }); listen(doc, 'scroll', () => { position(); }, true);
  refresh();
  return {
    reset() { close(false); refresh(); },
    state(connection: NativeSnapshot, reason: InlineState['reason'] = 'state') {
      if (reason === 'matches' && activeAction === 'fill') return;
      if (!open || !current()) { close(false); refresh(); return; }
      revision++; busy = false; activeAction = undefined; value = { connection }; render();
      if (['ready', 'locked', 'unpaired'].includes(connection.state)) void perform('list');
    },
    destroy() { if (dead) return; close(false); dead = true; controller.abort(); observer.disconnect(); cancelAnimationFrame(animation); host.remove(); },
  };
}
