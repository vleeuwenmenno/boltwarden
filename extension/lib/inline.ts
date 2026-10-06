import { activeInput, formContains, autofillForms, visibleInput } from './forms';
import { newPasswordFields, generatePassword, fillGeneratedPassword, defaultGeneratorOptions, type GeneratorOptions } from './password-generator';
import type { NativeSnapshot } from './native';
import type { InlineAction, InlineValue, InlineState } from './inline-types';
import type { Settings } from './settings';
import { autocompleteOf, suppressFormHistory } from './autocomplete';
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
  try {
    const sheet = new CSSStyleSheet(); sheet.replaceSync(css); root.adoptedStyleSheets = [sheet];
  } catch {
    // Firefox ESR rejects constructed sheets through content-script Xray wrappers.
    // Keep the fallback inside the same closed shadow root, away from page styles.
    const style = doc.createElement('style'); style.textContent = css; root.append(style);
  }
  const mark = doc.createElement('button'); mark.className = 'mark'; mark.type = 'button'; mark.tabIndex = -1;
  mark.setAttribute('aria-label', 'Show Boltwarden logins'); mark.title = 'Boltwarden'; mark.hidden = true;
  const svg = new DOMParser().parseFromString(bolt, 'image/svg+xml').documentElement;
  mark.append(doc.importNode(svg, true));
  const menu = doc.createElement('div'); menu.className = 'menu'; menu.hidden = true;
  menu.setAttribute('role', 'listbox'); menu.setAttribute('aria-label', 'Logins for this page');
  // One persistent live region outside the listbox, so filter changes are announced.
  const status = doc.createElement('div'); status.className = 'sr-only'; status.setAttribute('role', 'status');
  root.append(mark, menu, status); doc.documentElement.append(host);
  let field: HTMLInputElement | undefined, token: string | undefined, value: InlineValue | undefined;
  let open = false, busy = false, index = 0, revision = 0, dead = false, animation = 0;
  let generatedFields: HTMLInputElement[] | undefined, suggestion: string | undefined, generationError: string | undefined;
  let generatorOptions: GeneratorOptions | undefined;
  let autoOpen = false;
  // Closing the menu with the mark or Escape stops auto-open for that field. Focus can briefly
  // leave the field (clicking the mark, page handlers), so only focusing a different field or
  // reloading resets it. Clicking away is not a dismissal.
  let dismissedField: HTMLInputElement | undefined;
  let lastGesture = 0, focusPending = false;
  // Automatic menus ignore fills until they have been on screen briefly, and every menu only
  // fills while it is actually on top, so a lured click on a hidden menu does nothing.
  let armedAt = 0, filtering = false;
  // Automatic menus (field click or page focus) stay hidden until they have logins to show, start
  // with nothing selected, and let Enter and typing reach the page until the user picks a row.
  let quiet = false, automatic = false, holdUntil = 0;
  let retryTarget: HTMLInputElement | undefined, retries = 0, retryTimer: ReturnType<typeof setTimeout> | undefined;
  // Hides the browser's typed-history dropdown on the current login field (advanced setting).
  let hideHistory = false, restoreHistory: (() => void) | undefined;
  function updateHistory() {
    restoreHistory?.(); restoreHistory = undefined;
    if (hideHistory && field && loginField() && !generatorFields(field)) restoreHistory = suppressFormHistory(field);
  }
  // The page's own favicon, loaded once when a field first qualifies rather than when the
  // menu opens, so the request does not reveal menu use. `ok` stays unset until it loads.
  let icon: { url: string; ok?: boolean } | undefined;
  const generatorFocused = () => !!generatedFields && doc.activeElement === host && !!root.activeElement;
  let activeAction: InlineAction | undefined;
  let connection: NativeSnapshot | undefined;
  const observed = new Set<Document | ShadowRoot>();
  const controller = new AbortController();
  const listen = (target: EventTarget, type: string, handler: EventListener, capture = false) => target.addEventListener(type, handler, { capture, signal: controller.signal });
  const generatorFields = (input: HTMLInputElement) => doc.location.protocol === 'https:' && doc.defaultView?.top === doc.defaultView ? newPasswordFields(input) : undefined;
  const eligible = (input: Element | null): input is HTMLInputElement => input instanceof HTMLInputElement && visibleInput(input)
    && (!!generatorFields(input) || autofillForms(doc).some(form => (!form.card || doc.location.protocol === 'https:') && formContains(form, input)));
  const cardField = () => !!field && autofillForms(doc).some(form => !!form.card && formContains(form, field!));
  // What the user typed into a username or email field narrows the loaded logins. The value is
  // only compared locally and shown as text; it never leaves this frame.
  const filterText = () => filtering && field && value?.frame?.kind !== 'totp' && autofillForms(doc).some(form => form.username === field)
    ? field.value.trim().toLowerCase() : '';
  const shownItems = () => {
    const items = value?.frame?.items ?? [], query = filterText();
    return query ? items.filter(item => (item.username ?? item.name).toLowerCase().includes(query)) : items;
  };
  const loginField = () => !!field && autofillForms(doc).some(form => !form.card && formContains(form, field!));
  function close(notify = true) {
    const previous = token;
    revision++; open = false; quiet = false; automatic = false; busy = false; activeAction = undefined; token = undefined; value = undefined; menu.hidden = true; menu.replaceChildren(); mark.setAttribute('aria-expanded', 'false');
    generatedFields = undefined; suggestion = undefined; generationError = undefined;
    options.release();
    if (notify && previous) void options.request('dismiss', { token: previous }).catch(() => {});
  }
  function position() {
    if (!field || !eligible(field)) { close(); field = undefined; mark.hidden = true; return; }
    const rect = field.getBoundingClientRect(), width = doc.defaultView!.innerWidth, height = doc.defaultView!.innerHeight;
    const top = Math.max(2, Math.min(height - 28, rect.top + (rect.height - 26) / 2));
    // Code digits often run to the field's right edge (or fill one box per digit), so the mark
    // sits just outside the last code box instead, when the viewport has room.
    const code = autofillForms(doc).find(form => form.otp && formContains(form, field!))?.otp;
    const codeRight = code ? Math.max(...code.map(box => box.getBoundingClientRect().right)) : undefined;
    const right = codeRight !== undefined && codeRight + 30 <= width - 2 ? codeRight + 30 : markRight(rect, top);
    mark.style.left = `${Math.max(2, Math.min(width - 28, right - 26))}px`;
    mark.style.top = `${top}px`;
    // Match the field width where it is wide enough to fit a login, within the viewport.
    const menuWidth = Math.max(0, Math.min(Math.max(280, rect.width), 520, width - 16));
    menu.style.width = `${menuWidth}px`; menu.style.left = `${Math.max(8, Math.min(width - menuWidth - 8, rect.left))}px`;
    const below = Math.max(0, height - rect.bottom - 12), above = Math.max(0, rect.top - 12);
    const up = below < 180 && above > below;
    const maximum = Math.min(300, up ? above : below);
    menu.style.maxHeight = `${maximum}px`;
    menu.style.top = up ? `${Math.max(8, rect.top - Math.min(menu.scrollHeight, maximum) - 4)}px` : `${Math.max(8, rect.bottom + 4)}px`;
  }
  // Sites often put their own small controls (show password, clear) inside the right end of
  // the field. Step left past any such control so the mark does not cover it. Large overlays
  // (decorative code boxes, floating labels) are ignored, and the mark never leaves the field.
  function markRight(rect: DOMRect, top: number) {
    let right = rect.right - 4;
    for (let step = 0; step < 3 && right - 26 > rect.left + rect.width / 2; step++) {
      const blocker = doc.elementsFromPoint?.(right - 13, top + 13).find(element => element !== host && element !== field
        && !element.contains(field!) && !field!.contains(element));
      const box = blocker?.getBoundingClientRect();
      if (!box || box.width > 48 || box.height > rect.height + 8 || box.left >= right || box.right <= right - 26) break;
      right = box.left - 4;
    }
    return right;
  }
  function observeRoots() {
    const scan = (node: Document | ShadowRoot) => {
      if (!observed.has(node)) { observer.observe(node, { subtree: true, childList: true, characterData: true, attributes: true,
        attributeFilter: ['disabled', 'readonly', 'hidden', 'inert', 'type', 'autocomplete', 'name', 'id', 'style', 'class', 'aria-hidden', 'aria-disabled', 'aria-label', 'aria-labelledby', 'form'] }); observed.add(node); }
      for (const element of node.querySelectorAll('*')) if (element.shadowRoot) scan(element.shadowRoot);
    };
    scan(doc);
  }
  function refresh() {
    if (dead) return;
    observeRoots();
    const active = activeInput(doc);
    if (active !== field && !generatorFocused()) { close(); field = eligible(active) ? active : undefined; if (field && field !== dismissedField) dismissedField = undefined;
      focusPending = !!field && Date.now() - lastGesture > 500; updateHistory(); }
    if ((token && !options.current(token)) || (generatedFields && !current())) close();
    if (field && (!eligible(field) || doc.visibilityState === 'hidden')) { close(); field = undefined; }
    // A focused input that is not usable yet (page still fading in or laying out) produces no
    // further events, so check it again a few times over about two seconds.
    if (!field && active instanceof HTMLInputElement && active.type !== 'hidden') {
      if (retryTarget !== active) { retryTarget = active; retries = 0; }
      if (retries < 8 && !retryTimer) retryTimer = setTimeout(() => { retryTimer = undefined; retries++; refresh(); queueMicrotask(focusOpen); }, 250);
    } else retryTarget = undefined;
    mark.hidden = !field;
    mark.setAttribute('aria-label', field && generatorFields(field) ? 'Suggest a password' : cardField() ? 'Choose a credit card with Boltwarden' : 'Show Boltwarden logins');
    if (field) { loadIcon(); position(); }
  }
  function loadIcon() {
    if (icon) return;
    let url: string | undefined;
    try {
      url = [...doc.querySelectorAll<HTMLLinkElement>('link[rel~="icon" i]')].map(link => link.href).find(href => /^(https?:|data:image\/)/i.test(href))
        ?? (/^https?:$/.test(doc.location.protocol) ? new URL('/favicon.ico', doc.location.href).href : undefined);
    } catch { url = undefined; }
    icon = url ? { url } : { url: '', ok: false };
    if (!url) return;
    const probe = doc.createElement('img'); probe.referrerPolicy = 'no-referrer';
    const done = (ok: boolean) => { if (icon?.url !== url) return; icon.ok = ok; if (open && !generatedFields && !dead) render(); };
    probe.addEventListener('load', () => done(probe.naturalWidth > 0), { once: true });
    probe.addEventListener('error', () => done(false), { once: true });
    probe.src = url;
  }
  function siteIcon(name: string) {
    if (icon?.ok) {
      const image = doc.createElement('img'); image.className = 'site-icon'; image.alt = ''; image.referrerPolicy = 'no-referrer'; image.src = icon.url;
      return image;
    }
    // Shown through CSS so the letter stays out of the row's text and accessible name.
    const letter = doc.createElement('span'); letter.className = 'site-icon letter'; letter.setAttribute('aria-hidden', 'true');
    letter.dataset.letter = (name.trim()[0] ?? '?').toUpperCase(); return letter;
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
    menu.replaceChildren(); menu.hidden = !open || quiet; if (!filterText()) status.textContent = '';
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
    if (cardField()) {
      menu.setAttribute('role', 'group'); menu.setAttribute('aria-label', 'Credit cards');
      text('Choose a credit card in the Boltwarden toolbar popup.');
      action('Choose credit card', 'open-popup');
      position(); return;
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
      const items = shownItems(), query = filterText(), total = value.frame?.items.length ?? 0;
      index = Math.min(index, Math.max(0, items.length - 1));
      if (query && total) {
        const hint = doc.createElement('div'); hint.className = 'filter-hint'; hint.setAttribute('aria-hidden', 'true');
        const typed = field!.value.trim(), shown = typed.length > 32 ? `${typed.slice(0, 31)}…` : typed;
        hint.textContent = items.length ? `Filtering by “${shown}” · ${items.length} of ${total}` : `No logins match “${shown}”`;
        menu.append(hint); if (status.textContent !== hint.textContent) status.textContent = hint.textContent;
      }
      if (!items.length && !(query && total)) text(value.message ?? (value.frame?.kind === 'totp' ? 'No matching accounts with a saved verification code.' : 'No matching logins for this page.'));
      for (const [row, item] of items.entries()) {
        const button = doc.createElement('button'); button.type = 'button'; button.tabIndex = -1; button.className = 'login'; button.setAttribute('role', 'option');
        button.setAttribute('aria-selected', String(row === index)); button.setAttribute('aria-label', `${item.name}, ${item.username ?? ''}${item.reprompt ? ', master password required' : ''}`);
        const name = doc.createElement('strong'); name.textContent = item.name;
        const username = doc.createElement('span'); username.className = 'username'; username.textContent = item.username ?? '';
        if (value.frame?.kind === 'totp') {
          button.classList.add('otp-row'); button.append(siteIcon(item.name));
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
        } else button.append(siteIcon(item.name), name, username);
        if (item.reprompt) { const lock = doc.createElement('span'); lock.className = 'lock'; lock.textContent = 'Locked'; lock.setAttribute('aria-hidden', 'true'); button.append(lock); }
        button.addEventListener('click', event => { if (event.isTrusted && usable(event.clientX, event.clientY)) { index = row; void perform('fill', item.id); } }); menu.append(button);
      }
      if (value.frame?.more) action('More matching logins', 'more');
    }
    position();
    const item = shownItems()[index];
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
      connection = result.connection; value = result; busy = false; activeAction = undefined;
      if (quiet && kind === 'list') { if (!shownItems().length) { close(); return; } quiet = false; }
      render();
    } catch (error) {
      if (dead || revision !== requestRevision || token !== requestToken) return;
      if (quiet) { close(); return; }
      busy = false; activeAction = undefined; value = undefined; render();
      text(error instanceof Error ? error.message : 'Could not load logins.'); action('Open Boltwarden', 'open-popup');
    }
  }
  function show(event: Event) {
    if (!event.isTrusted || busy) return;
    refresh(); if (!field) return;
    if (open) { close(); dismissedField = field; return; }
    openMenu();
  }
  // Pages often focus the login or code field themselves (autofocus, or after moving to the
  // next step). That focus has no click, so open the menu once for it when the connection
  // allows. Focus that follows the user's own click or key press is left to the click rule.
  function focusOpen() {
    if (!focusPending || dead || !autoOpen || open || busy || !field || field === dismissedField || activeInput(doc) !== field) return;
    if (!connection || !['ready', 'locked'].includes(connection.state) || Date.now() < holdUntil) return;
    focusPending = false;
    if (loginField() && !generatorFields(field) && autoAllowed()) openMenu('page');
  }
  // The menu must be visible to the user: armed, the page not faded, and our host on top here.
  function usable(x: number, y: number) {
    if (Date.now() < armedAt) return false;
    const style = getComputedStyle(doc.documentElement);
    if (parseFloat(style.opacity) < 1 || (style.filter && style.filter !== 'none')) return false;
    const top = doc.elementsFromPoint?.(x, y)[0];
    return !top || top === host;
  }
  const menuCentre = () => { const box = menu.getBoundingClientRect(); return [box.left + box.width / 2, box.top + Math.min(box.height / 2, 40)] as const; };
  // Locked vaults only prompt automatically on real login forms, not on any email field.
  const strongField = () => !!field && autofillForms(doc).some(form => formContains(form, field!) && (!!form.password || !!form.otp
    || autocompleteOf(field!).split(/\s+/).some(token => token === 'username' || token === 'current-password')));
  const autoAllowed = () => Date.now() >= holdUntil && !!connection && (connection.state === 'ready' || (connection.state === 'locked' && strongField()));
  function openMenu(mode: 'manual' | 'click' | 'page' = 'manual') {
    if (!field) return;
    automatic = mode !== 'manual'; armedAt = automatic ? Date.now() + 400 : 0; filtering = false;
    quiet = automatic && connection?.state === 'ready';
    generatedFields = generatorFields(field);
    if (generatedFields) { revision++; open = true; index = 0; regenerate(); return; }
    token = options.pin(field); if (!token) return;
    revision++; open = true; index = automatic ? -1 : 0; value = connection ? { connection } : undefined;
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
  // Clicking a username, email, password, or verification-code field opens the menu, as if the
  // mark was clicked. Code inputs are often covered by decorative boxes, so the test is that the
  // click left the field focused rather than that it hit the input. Cards and new-password
  // fields keep the explicit mark, and the menu only opens unprompted when it has logins or an
  // unlock prompt to offer.
  listen(doc, 'click', event => {
    if (!autoOpen || !event.isTrusted || open || busy) return;
    refresh();
    if (field && field !== dismissedField && activeInput(doc) === field && !event.composedPath().includes(host) && loginField() && !generatorFields(field)
      && autoAllowed()) openMenu('click');
  }, true);
  listen(doc, 'focusin', () => { refresh(); queueMicrotask(focusOpen); }, true);
  // Any user input before the connection is ready cancels a pending focus open.
  const gesture = (event: Event) => { if (event.isTrusted) { lastGesture = Date.now(); focusPending = false; } };
  listen(doc, 'pointerdown', gesture, true); listen(doc, 'keydown', gesture, true);
  listen(doc, 'input', event => {
    if (!event.isTrusted || !open || generatedFields || event.composedPath()[0] !== field) return;
    // Typing a password or code by hand means the user is not picking from the menu.
    if (automatic && !autofillForms(doc).some(form => form.username === field)) { close(); return; }
    if (!busy && value?.frame) { filtering = true; index = automatic ? -1 : 0; render(); }
  }, true);
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
    if (key.key === 'Escape' && open) { key.preventDefault(); key.stopPropagation(); close(); dismissedField = field; return; }
    if (key.key === 'ArrowDown' && !open) { key.preventDefault(); key.stopPropagation(); show(key); return; }
    if (!open) return;
    if (generatedFields) {
      if (['Enter', 'ArrowDown', 'ArrowUp'].includes(key.key)) { key.preventDefault(); key.stopPropagation(); if (key.key === 'Enter') useSuggestion(); }
      return;
    }
    // Nothing chosen yet (automatic menu): Enter belongs to the page, and closes the menu.
    if (key.key === 'Enter' && index < 0) { close(); return; }
    if (quiet) return;
    if (busy) {
      if (['ArrowDown', 'ArrowUp', 'Enter'].includes(key.key)) { key.preventDefault(); key.stopPropagation(); }
      return;
    }
    const items = shownItems();
    if (key.key === 'ArrowDown' || key.key === 'ArrowUp') {
      key.preventDefault(); key.stopPropagation();
      if (items.length) index = index < 0 ? (key.key === 'ArrowDown' ? 0 : items.length - 1) : (index + (key.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length;
      render(); menu.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' });
    } else if (key.key === 'Enter') {
      if (!items.length && value?.connection.state === 'ready' && !cardField()) { close(); return; }
      key.preventDefault(); key.stopPropagation();
      if (cardField() || value?.frame?.crossOrigin || items.some(item => item.requires_confirmation)) void perform('open-popup');
      else if (value?.connection.state === 'locked') void perform('unlock');
      else if (items[index] && usable(...menuCentre())) void perform('fill', items[index]!.id);
    }
  }, true);
  listen(doc, 'visibilitychange', () => { if (doc.visibilityState === 'hidden') { close(); mark.hidden = true; } else refresh(); });
  listen(window, 'resize', () => { position(); }); listen(doc, 'scroll', () => { position(); }, true);
  refresh();
  return {
    reset() { close(false); refresh(); },
    /** No automatic opening for a while, e.g. while a fill and submit or a password step is in progress. */
    hold(ms: number) { holdUntil = Math.max(holdUntil, Date.now() + ms); },
    configure(settings: Pick<Settings, 'autoOpen' | 'theme'> & Partial<Pick<Settings, 'suppressFormHistory'>>) {
      autoOpen = settings.autoOpen; queueMicrotask(focusOpen);
      if (hideHistory !== (settings.suppressFormHistory ?? false)) { hideHistory = settings.suppressFormHistory ?? false; updateHistory(); }
      for (const element of [mark, menu]) { if (settings.theme === 'system') delete element.dataset.theme; else element.dataset.theme = settings.theme; }
    },
    state(next: NativeSnapshot, reason: InlineState['reason'] = 'state') {
      const unchanged = connection?.state === next.state && connection.epoch === next.epoch && connection.error === next.error;
      connection = next;
      if (generatedFields) { if (!current()) { close(false); refresh(); } return; }
      if (!open || !current()) { close(false); refresh(); queueMicrotask(focusOpen); return; }
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
    destroy() { if (dead) return; close(false); dead = true; clearTimeout(retryTimer); restoreHistory?.(); restoreHistory = undefined; clearInterval(countdown); controller.abort(); observer.disconnect(); cancelAnimationFrame(animation); host.remove(); },
  };
}
