import { activeInput, formContains, loginForms, visibleInput } from './forms';
import { newPasswordFields, generatePassword, fillGeneratedPassword, defaultGeneratorOptions, type GeneratorOptions } from './password-generator';
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
  let generatedFields: HTMLInputElement[] | undefined, suggestion: string | undefined, generationError: string | undefined;
  let generatorOptions: GeneratorOptions | undefined;
  const generatorFocused = () => !!generatedFields && doc.activeElement === host && !!root.activeElement;
  let activeAction: InlineAction | undefined;
  let connection: NativeSnapshot | undefined;
  const observed = new Set<Document | ShadowRoot>();
  const controller = new AbortController();
  const listen = (target: EventTarget, type: string, handler: EventListener, capture = false) => target.addEventListener(type, handler, { capture, signal: controller.signal });
  const generatorFields = (input: HTMLInputElement) => doc.location.protocol === 'https:' && doc.defaultView?.top === doc.defaultView ? newPasswordFields(input) : undefined;
  const eligible = (input: Element | null): input is HTMLInputElement => input instanceof HTMLInputElement && visibleInput(input)
    && (!!generatorFields(input) || loginForms(doc).some(form => formContains(form, input)));
  function close(notify = true) {
    const previous = token;
    revision++; open = false; busy = false; activeAction = undefined; token = undefined; value = undefined; menu.hidden = true; menu.replaceChildren(); mark.setAttribute('aria-expanded', 'false');
    generatedFields = undefined; suggestion = undefined; generationError = undefined;
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
    if (active !== field && !generatorFocused()) { close(); field = eligible(active) ? active : undefined; }
    if ((token && !options.current(token)) || (generatedFields && !current())) close();
    if (field && (!eligible(field) || doc.visibilityState === 'hidden')) { close(); field = undefined; }
    mark.hidden = !field;
    mark.setAttribute('aria-label', field && generatorFields(field) ? 'Suggest a password' : 'Show Boltwarden logins');
    if (field) position();
  }
  function schedule() {
    if (!animation && !dead) animation = requestAnimationFrame(() => { animation = 0; refresh(); });
  }
  const observer = new MutationObserver(records => {
    if (records.some(record => record.target !== host && !(record.type === 'childList' && [...record.addedNodes, ...record.removedNodes].every(node => node === host)))) schedule();
  });
  const current = () => {
    if (!field || (activeInput(doc) !== field && !generatorFocused()) || !eligible(field)) return false;
    if (generatedFields) {
      const fields = generatorFields(field);
      return !!fields && fields.length === generatedFields.length && fields.every((value, i) => value === generatedFields![i]);
    }
    return !!token && options.current(token);
  };
  function regenerate(rebuild = false) {
    if (!generatedFields || !current()) { close(); return; }
    try { suggestion = generatePassword(generatedFields, generatorOptions); generationError = undefined; }
    catch (error) { suggestion = undefined; generationError = error instanceof Error ? error.message : 'Could not generate a password.'; }
    const focus = (root.activeElement as HTMLElement | null)?.dataset.control;
    if (!rebuild && menu.querySelector('.generator-controls')) {
      // Preserve controls and buttons across input/change/click. Replacing them
      // during blur can remove the pending click target before its click fires.
      const button = menu.querySelector<HTMLButtonElement>('.suggested-password')!;
      button.hidden = !suggestion;
      button.querySelector('code')!.textContent = suggestion ?? '';
      const error = menu.querySelector<HTMLElement>('.generation-error')!;
      error.textContent = generationError ?? ''; error.hidden = !generationError;
      position();
    } else render();
    if (focus) menu.querySelector<HTMLElement>(`[data-control="${focus}"]`)?.focus();
  }
  function useSuggestion() {
    if (!field || !generatedFields || !suggestion || !current()) return;
    try { fillGeneratedPassword(field, generatedFields, suggestion, current); close(false); }
    catch (error) { suggestion = undefined; generationError = error instanceof Error ? error.message : 'Could not fill password.'; render(); }
  }
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
    if (generatedFields) {
      const heading = doc.createElement('div'); heading.className = 'heading'; heading.textContent = 'Boltwarden · New password'; menu.append(heading);
      {
        const button = doc.createElement('button'); button.type = 'button'; button.tabIndex = 0; button.className = 'action suggested-password';
        button.setAttribute('role', 'option'); button.setAttribute('aria-selected', 'true');
        const label = doc.createElement('strong'); label.textContent = 'Use suggested password';
        button.hidden = !suggestion;
        const preview = doc.createElement('code'); preview.textContent = suggestion ?? '';
        button.append(label, preview); button.addEventListener('click', event => { if (event.isTrusted) useSuggestion(); }); menu.append(button);
      }
      const error = doc.createElement('div'); error.className = 'message warning generation-error';
      error.textContent = generationError ?? ''; error.hidden = !generationError; menu.append(error);
      const settings = generatorOptions ?? { ...defaultGeneratorOptions, length: suggestion?.length ?? 20 };
      const controls = doc.createElement('div'); controls.className = 'generator-controls';
      const typeLabel = doc.createElement('label'); typeLabel.textContent = 'Type';
      const type = doc.createElement('select'); type.dataset.control = 'type';
      for (const [value, title] of [['random', 'Random password'], ['memorable', 'Memorable password'], ['pin', 'PIN code']]) {
        const option = doc.createElement('option'); option.value = value!; option.textContent = title!; type.append(option);
      }
      type.value = settings.type;
      type.addEventListener('change', event => {
        if (!event.isTrusted) return;
        generatorOptions = { ...(generatorOptions ?? settings), type: type.value as GeneratorOptions['type'], length: type.value === 'random' ? 20 : 6 }; regenerate(true);
      });
      typeLabel.append(type); controls.append(typeLabel);
      const lengthLabel = doc.createElement('label'); lengthLabel.textContent = settings.type === 'memorable' ? 'Words' : settings.type === 'pin' ? 'Digits' : 'Length';
      const length = doc.createElement('input'); length.type = 'number'; length.dataset.control = 'length';
      length.min = settings.type === 'random' ? '8' : '4'; length.max = settings.type === 'memorable' ? '12' : '128'; length.value = String(settings.length);
      length.addEventListener('input', event => { if (event.isTrusted) { generatorOptions = { ...(generatorOptions ?? settings), length: Number(length.value) }; regenerate(); } });
      lengthLabel.append(length); controls.append(lengthLabel);
      if (settings.type !== 'pin') for (const key of ['numbers', 'symbols'] as const) {
        const label = doc.createElement('label'); label.className = 'generator-toggle';
        const toggle = doc.createElement('input'); toggle.type = 'checkbox'; toggle.checked = settings[key]; toggle.dataset.control = key;
        toggle.addEventListener('change', event => { if (event.isTrusted) { generatorOptions = { ...(generatorOptions ?? settings), [key]: toggle.checked }; regenerate(); } });
        label.append(toggle, key === 'numbers' ? 'Numbers' : 'Symbols'); controls.append(label);
      }
      menu.append(controls);
      if (settings.type === 'pin') text('PIN codes are weaker than passwords. Use only where a PIN is required.');
      text('Fills new password and confirmation. Saving is offered after you submit.');
      const another = doc.createElement('button'); another.type = 'button'; another.tabIndex = 0; another.className = 'action'; another.textContent = 'Generate another';
      another.addEventListener('click', event => { if (event.isTrusted) regenerate(); }); menu.append(another);
      menu.setAttribute('role', 'group'); menu.setAttribute('aria-label', 'Suggested password'); position(); return;
    }
    menu.setAttribute('role', 'listbox'); menu.setAttribute('aria-label', 'Logins for this page');
    const heading = doc.createElement('div'); heading.className = 'heading'; heading.textContent = value?.frame?.kind === 'totp' ? 'Boltwarden · Verification codes' : 'Boltwarden · Logins for this page'; menu.append(heading);
    if (busy && activeAction !== 'preview') text(activeAction === 'unlock' ? 'Unlock Boltwarden on your desktop…' : activeAction === 'fill' ? 'Filling login…' : 'Loading matching logins…');
    else if (!value) text('Choose a login field and try again.');
    else if (value.connection.state === 'locked') { text('Unlock Boltwarden on your desktop to see matching logins.'); action('Unlock Boltwarden', 'unlock'); }
    else if (value.connection.state !== 'ready') {
      const messages = {
        connecting: 'Connecting to Boltwarden…',
        unpaired: 'Pair this browser with Boltwarden to see matching logins.',
        disabled: 'Enable browser integration in Boltwarden desktop settings.',
        disconnected: 'Open Boltwarden desktop and check Settings → Browser setup.',
      };
      text(value.message ?? messages[value.connection.state]); action('Open Boltwarden', 'open-popup');
    }
    else if (value.frame?.crossOrigin || value.frame?.items.some(item => item.requires_confirmation)) {
      text('Use the toolbar popup to confirm this destination.'); action('Open toolbar confirmation', 'open-popup');
    } else {
      if (value.warning) text(value.warning, true);
      const items = value.frame?.items ?? [];
      index = Math.min(index, Math.max(0, items.length - 1));
      if (!items.length) text(value.message ?? (value.frame?.kind === 'totp' ? 'No matching accounts with a saved verification code.' : 'No matching logins for this page.'));
      for (const [row, item] of items.entries()) {
        const button = doc.createElement('button'); button.type = 'button'; button.tabIndex = -1; button.className = 'login'; button.setAttribute('role', 'option');
        button.setAttribute('aria-selected', String(row === index)); button.setAttribute('aria-label', `${item.name}, ${item.username ?? ''}${item.reprompt ? ', master password required' : ''}`);
        const name = doc.createElement('strong'); name.textContent = item.name;
        const username = doc.createElement('span'); username.className = 'username'; username.textContent = item.username ?? '';
        if (value.frame?.kind === 'totp') {
          button.classList.add('otp-row');
          const account = doc.createElement('span'); account.className = 'account'; account.append(name, username); button.append(account);
          const preview = value.preview;
          if (row === index && preview?.itemId === item.id && preview.expiresAt * 1000 > Date.now()) {
            const seconds = Math.max(0, Math.ceil(preview.expiresAt - Date.now() / 1000));
            const details = doc.createElement('span'); details.className = 'otp-preview';
            const code = doc.createElement('span'); code.className = 'otp-code';
            code.textContent = preview.code.length % 2 === 0 ? `${preview.code.slice(0, preview.code.length / 2)} ${preview.code.slice(preview.code.length / 2)}` : preview.code;
            const expiry = doc.createElement('span'); expiry.className = `otp-expiry${seconds <= 5 ? ' expiring' : ''}`;
            expiry.textContent = `${seconds}s`; expiry.title = `New code in ${seconds} seconds`;
            details.append(code, expiry); button.append(details);
            button.setAttribute('aria-label', `${item.name}, ${item.username ?? ''}, code ${preview.code}, expires in ${seconds} seconds, fill code`);
          } else if (row === index && !item.reprompt) {
            const hint = doc.createElement('span'); hint.className = 'otp-expiry'; hint.textContent = '••• •••'; button.append(hint);
          }
        } else button.append(name, username);
        if (item.reprompt) { const lock = doc.createElement('span'); lock.className = 'lock'; lock.textContent = 'Locked'; lock.setAttribute('aria-hidden', 'true'); button.append(lock); }
        button.addEventListener('click', event => { if (event.isTrusted) { index = row; void perform('fill', item.id); } }); menu.append(button);
      }
      if (value.frame?.more) action('More matching logins', 'more');
    }
    position();
    const item = value?.frame?.items[index];
    if (!busy && value?.connection.state === 'ready' && value.frame?.kind === 'totp' && !value.frame.crossOrigin
      && item && !item.reprompt && !item.requires_confirmation
      && (!value.preview || value.preview.itemId !== item.id || value.preview.expiresAt * 1000 <= Date.now())) {
      queueMicrotask(() => { if (!busy && open && current()) void perform('preview', item.id); });
    }
  }
  const countdown = setInterval(() => {
    if (open && !busy && value?.frame?.kind === 'totp' && current()) render();
  }, 1000);
  async function perform(kind: InlineAction, itemId?: string) {
    if (busy || !current() || !token) return;
    const requestToken = token, requestRevision = revision;
    busy = true; activeAction = kind; render();
    try {
      const result = await options.request(kind, { token: requestToken, ...(value?.frame ? { targetId: value.frame.targetId } : {}), ...(itemId ? { itemId } : {}) });
      if (dead || revision !== requestRevision || token !== requestToken) return;
      if (kind === 'fill' || kind === 'open-popup') { close(false); return; }
      if (!current()) { close(); return; }
      connection = result.connection; value = result; busy = false; activeAction = undefined; render();
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
    generatedFields = generatorFields(field);
    if (generatedFields) { revision++; open = true; index = 0; regenerate(); return; }
    token = options.pin(field); if (!token) return;
    revision++; open = true; index = 0; value = connection ? { connection } : undefined;
    if (connection && ['locked', 'unpaired', 'disabled'].includes(connection.state)) render(); else void perform('list');
  }
  listen(root, 'pointerdown', event => {
    if (!event.isTrusted) return;
    // Actions keep the current input focused; editable generator controls may
    // take focus. This also prevents a button click from committing a blur first.
    const target = event.target;
    if (!generatedFields || !(target instanceof Element) || !target.closest('.generator-controls')) event.preventDefault();
  });
  listen(mark, 'click', show);
  listen(doc, 'focusin', () => refresh(), true);
  listen(doc, 'focusout', schedule, true);
  listen(doc, 'pointerdown', event => { if (event.isTrusted && !event.composedPath().includes(host) && event.composedPath()[0] !== field) close(); }, true);
  listen(doc, 'keydown', event => {
    const key = event as KeyboardEvent;
    if (!key.isTrusted || !field) return;
    if (generatorFocused()) { if (key.key === 'Escape') { key.preventDefault(); field.focus(); close(); } return; }
    if (activeInput(doc) !== field) return;
    if (key.key === 'Tab') {
      if (generatedFields && open && !key.shiftKey) { key.preventDefault(); menu.querySelector<HTMLButtonElement>('.suggested-password')?.focus(); } else close();
      return;
    }
    if (key.key === 'Escape' && open) { key.preventDefault(); key.stopPropagation(); close(); return; }
    if (key.key === 'ArrowDown' && !open) { key.preventDefault(); key.stopPropagation(); show(key); return; }
    if (!open) return;
    if (generatedFields) {
      if (['Enter', 'ArrowDown', 'ArrowUp'].includes(key.key)) { key.preventDefault(); key.stopPropagation(); if (key.key === 'Enter') useSuggestion(); }
      return;
    }
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
    state(next: NativeSnapshot, reason: InlineState['reason'] = 'state') {
      const unchanged = connection?.state === next.state && connection.epoch === next.epoch && connection.error === next.error;
      connection = next;
      if (generatedFields) { if (!current()) { close(false); refresh(); } return; }
      if (!open || !current()) { close(false); refresh(); return; }
      // Native sync and unrelated frame events may arrive while a lookup is pending.
      // Restarting the lookup here invalidates its reply and can keep the menu loading forever.
      if (activeAction === 'list' && (next.state === 'connecting' || next.state === 'ready')) return;
      if (next.state === 'ready' && (activeAction === 'list' || activeAction === 'more' || activeAction === 'preview' || activeAction === 'fill')
        && (reason === 'matches' || unchanged)) return;
      if (unchanged && reason === 'state') return;
      revision++; busy = false; activeAction = undefined; value = { connection: next }; render();
      // Locked/unpaired state is already authoritative. Only fetch matches when ready.
      if (next.state === 'ready') void perform('list');
    },
    destroy() { if (dead) return; close(false); dead = true; clearInterval(countdown); controller.abort(); observer.disconnect(); cancelAnimationFrame(animation); host.remove(); },
  };
}
