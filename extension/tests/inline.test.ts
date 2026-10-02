// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createInlineController, type InlineOptions } from '../lib/inline';
import type { InlineValue } from '../lib/inline-types';
import { activeInput } from '../lib/forms';

let shadow: ShadowRoot;
const controllers: ReturnType<typeof createInlineController>[] = [];
const ready: InlineValue = { connection: { state: 'ready', epoch: 1 }, frame: { targetId: 'target-one', origin: 'https://login.test', crossOrigin: false, more: false, items: [
  { id: 'first', name: 'Personal', username: 'alice', reprompt: false, requires_confirmation: false, revision: 'one' },
  { id: 'second', name: 'Work', username: 'bob', reprompt: true, requires_confirmation: false, revision: 'two' },
] } };
const trusted = (target: EventTarget, type: string, key?: string) => {
  const event = key ? new KeyboardEvent(type, { key, bubbles: true, cancelable: true, composed: true }) : new MouseEvent(type, { bubbles: true, cancelable: true, composed: true });
  // Only the browser can set isTrusted in production; this models its input in the DOM fixture.
  Object.defineProperty(event, 'isTrusted', { value: true }); target.dispatchEvent(event); return event;
};
const settle = async () => { await Promise.resolve(); await Promise.resolve(); };
function form(root: ParentNode = document.body) {
  const container = document.createElement('form'); container.innerHTML = '<input autocomplete="username"><input type="password" autocomplete="current-password">';
  root.appendChild(container);
  for (const input of container.querySelectorAll('input')) {
    input.getBoundingClientRect = () => new DOMRect(20, 30, 240, 32);
    input.getClientRects = () => [input.getBoundingClientRect()] as unknown as DOMRectList;
  }
  return { username: container.querySelector('input')!, password: container.querySelector<HTMLInputElement>('input[type=password]')! };
}
function setup(request = vi.fn<InlineOptions['request']>().mockResolvedValue(ready)) {
  let token: string | undefined, pinned: HTMLInputElement | undefined;
  const ui = createInlineController(document, {
    pin(input) { pinned = input; token = crypto.randomUUID(); return token; },
    current(candidate) { return candidate === token && activeInput(document) === pinned; },
    request,
    release() { token = undefined; pinned = undefined; },
  });
  controllers.push(ui); return { ui, request, mark: shadow.querySelector<HTMLButtonElement>('.mark')!, menu: shadow.querySelector<HTMLElement>('.menu')! };
}
beforeEach(() => {
  document.body.replaceChildren();
  const attach = Element.prototype.attachShadow;
  vi.spyOn(Element.prototype, 'attachShadow').mockImplementation(function (this: Element, options) { const root = attach.call(this, options); if (options.mode === 'closed') shadow = root; return root; });
});
afterEach(() => { for (const ui of controllers.splice(0)) ui.destroy(); vi.restoreAllMocks(); });

describe('isolated inline login picker', () => {
  it('uses a closed shadow root and ignores synthetic activation without reading input values', async () => {
    const fields = form(); fields.password.focus();
    Object.defineProperty(fields.password, 'value', { get() { throw new Error('Typed password must not be read'); } });
    const { mark, request } = setup();
    expect(document.querySelector('[data-boltwarden-inline]')!.shadowRoot).toBeNull();
    expect(mark.hidden).toBe(false); mark.click(); fields.password.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
    expect(request).not.toHaveBeenCalled();
    trusted(mark, 'click'); await settle();
    expect(request).toHaveBeenCalledWith('list', { token: expect.any(String) });
    const row = shadow.querySelector<HTMLButtonElement>('[role=option]')!;
    row.click(); expect(request).toHaveBeenCalledTimes(1);
    trusted(row, 'click'); await settle();
    expect(request).toHaveBeenLastCalledWith('fill', { token: expect.any(String), targetId: 'target-one', itemId: 'first' });
    expect(shadow.textContent).not.toContain('Typed password');
  });
  it('supports account arrows and Enter, while Tab keeps its normal browser action', async () => {
    const fields = form(); fields.username.focus(); const { menu, request } = setup();
    expect(trusted(fields.username, 'keydown', 'ArrowDown').defaultPrevented).toBe(true); await settle();
    trusted(fields.username, 'keydown', 'ArrowDown');
    expect(shadow.querySelector('[aria-selected=true]')!.getAttribute('aria-label')).toBe('Work, bob, master password required');
    trusted(fields.username, 'keydown', 'Enter'); await settle();
    expect(request).toHaveBeenLastCalledWith('fill', { token: expect.any(String), targetId: 'target-one', itemId: 'second' });
    expect(menu.hidden).toBe(true);
    trusted(fields.username, 'keydown', 'ArrowDown'); await settle();
    expect(trusted(fields.username, 'keydown', 'Tab').defaultPrevented).toBe(false); expect(menu.hidden).toBe(true);
  });
  it('discards late list results after focus moves to another form', async () => {
    const first = form(), second = form(); first.username.focus();
    let resolve!: (value: InlineValue) => void;
    const request = vi.fn<InlineOptions['request']>().mockImplementation(action => action === 'list' ? new Promise(done => { resolve = done; }) : Promise.resolve(ready));
    const { menu } = setup(request); trusted(first.username, 'keydown', 'ArrowDown'); second.username.focus();
    resolve(ready); await settle();
    expect(menu.hidden).toBe(true); expect(shadow.querySelectorAll('[role=option]')).toHaveLength(0);
    expect(request.mock.calls.some(([action]) => action === 'fill')).toBe(false);
    expect(request.mock.calls.some(([action]) => action === 'dismiss')).toBe(true);
  });
  it.each(['cross-origin', 'insecure'])('routes %s destinations through toolbar confirmation', async mode => {
    const fields = form(); fields.username.focus();
    const result = structuredClone(ready); if (mode === 'cross-origin') result.frame!.crossOrigin = true; else result.frame!.items[0]!.requires_confirmation = true;
    const { request } = setup(vi.fn<InlineOptions['request']>().mockResolvedValue(result)); trusted(fields.username, 'keydown', 'ArrowDown'); await settle();
    expect(shadow.querySelectorAll('[role=option]')).toHaveLength(0);
    expect(shadow.textContent).toContain('confirm this destination');
    trusted(fields.username, 'keydown', 'Enter'); await settle();
    expect(request).toHaveBeenLastCalledWith('open-popup', { token: expect.any(String), targetId: 'target-one' });
    expect(request.mock.calls.some(([action]) => action === 'fill')).toBe(false);
  });
  it('requires trusted unlock action and retries the same focused pin after connection changes', async () => {
    const fields = form(); fields.username.focus();
    const request = vi.fn<InlineOptions['request']>().mockResolvedValue({ connection: { state: 'locked', epoch: 1 } });
    const { ui } = setup(request); trusted(fields.username, 'keydown', 'ArrowDown'); await settle();
    const unlock = shadow.querySelector<HTMLButtonElement>('.action')!; unlock.click(); expect(request).toHaveBeenCalledTimes(1);
    trusted(unlock, 'click'); await settle(); expect(request.mock.calls[1]![0]).toBe('unlock');
    const original = request.mock.calls[0]![1].token;
    request.mockResolvedValue(ready); ui.state({ state: 'ready', epoch: 2 }); await settle();
    expect(request).toHaveBeenLastCalledWith('list', { token: original }); expect(shadow.querySelectorAll('[role=option]')).toHaveLength(2);
  });
  it.each(['locked', 'unpaired', 'disabled'] as const)('shows known %s state immediately without a matching request', async state => {
    const fields = form(); fields.username.focus(); const { ui, request, menu } = setup();
    ui.state({ state, epoch: 1 });
    trusted(fields.username, 'keydown', 'ArrowDown'); await settle();
    expect(menu.hidden).toBe(false);
    expect(shadow.textContent).not.toMatch(/Working|Loading/);
    expect(request).not.toHaveBeenCalled();
    expect(shadow.querySelector('.action')).not.toBeNull();
    if (state === 'locked') {
      expect(shadow.textContent).toContain('Unlock Boltwarden');
      trusted(shadow.querySelector('.action')!, 'click'); await settle();
      expect(request).toHaveBeenCalledWith('unlock', { token: expect.any(String) });
    }
  });
  it('does not restart an unfinished lookup on repeated matching or page updates', async () => {
    const fields = form(); fields.username.focus();
    let finish!: (value: InlineValue) => void;
    const request = vi.fn<InlineOptions['request']>().mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    const { ui } = setup(request); ui.state(ready.connection);
    trusted(fields.username, 'keydown', 'ArrowDown');
    for (let i = 0; i < 4; i++) { ui.state(ready.connection, 'matches'); ui.state(ready.connection, 'page'); }
    expect(request).toHaveBeenCalledTimes(1);
    finish(ready); await settle();
    expect(shadow.querySelectorAll('[role=option]')).toHaveLength(2);
    expect(shadow.textContent).not.toContain('Loading');
  });
  it('replaces a pending lookup with locked state and ignores its late result', async () => {
    const fields = form(); fields.username.focus();
    let finish!: (value: InlineValue) => void;
    const request = vi.fn<InlineOptions['request']>().mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    const { ui } = setup(request); trusted(fields.username, 'keydown', 'ArrowDown');
    ui.state({ state: 'locked', epoch: 2 });
    expect(shadow.textContent).toContain('Unlock Boltwarden'); expect(request).toHaveBeenCalledTimes(1);
    finish(ready); await settle();
    expect(shadow.querySelectorAll('[role=option]')).toHaveLength(0);
    expect(shadow.textContent).toContain('Unlock Boltwarden');
  });
  it('does not replace a pending protected fill on MatchesChanged', async () => {
    const fields = form(); fields.username.focus();
    let finish!: (value: InlineValue) => void;
    const request = vi.fn<InlineOptions['request']>().mockImplementation(action => action === 'fill' ? new Promise(resolve => { finish = resolve; }) : Promise.resolve(ready));
    const { ui, menu } = setup(request); trusted(fields.username, 'keydown', 'ArrowDown'); await settle();
    trusted(fields.username, 'keydown', 'Enter');
    expect(trusted(fields.username, 'keydown', 'Enter').defaultPrevented).toBe(true);
    ui.state(ready.connection, 'matches'); await settle();
    expect(request.mock.calls.map(([action]) => action)).toEqual(['list', 'fill']);
    finish(ready); await settle(); expect(menu.hidden).toBe(true);
  });
  it('supports open shadow roots and ignores registration, readonly, and disabled fields', () => {
    const host = document.createElement('div'); document.body.append(host);
    const fields = form(host.attachShadow({ mode: 'open' })); fields.username.focus(); const { mark } = setup();
    expect(mark.hidden).toBe(false);
    const registration = form(); registration.password.autocomplete = 'new-password'; registration.username.focus(); expect(mark.hidden).toBe(true);
    registration.password.autocomplete = 'current-password'; registration.username.readOnly = true; registration.password.focus(); registration.username.focus(); expect(mark.hidden).toBe(true);
    registration.username.readOnly = false; registration.username.disabled = true; registration.password.focus(); registration.username.dispatchEvent(new FocusEvent('focusin', { bubbles: true }));
    expect(shadow.querySelectorAll('[role=option]')).toHaveLength(0);
  });
  it('dismisses on Escape and outside input, then removes all UI on destruction', async () => {
    const fields = form(); fields.username.focus(); const { ui, menu, request } = setup();
    trusted(fields.username, 'keydown', 'ArrowDown'); await settle();
    expect(trusted(fields.username, 'keydown', 'Escape').defaultPrevented).toBe(true); expect(menu.hidden).toBe(true);
    trusted(fields.username, 'keydown', 'ArrowDown'); await settle(); trusted(document.body, 'pointerdown'); expect(menu.hidden).toBe(true);
    ui.destroy(); const count = request.mock.calls.length; fields.password.focus(); trusted(fields.password, 'keydown', 'ArrowDown');
    expect(document.querySelector('[data-boltwarden-inline]')).toBeNull(); expect(request).toHaveBeenCalledTimes(count);
  });
});

describe('inline OTP preview', () => {
  it('groups digits, refreshes expired codes, and clears on lock', async () => {
    vi.useFakeTimers();
    try {
      const fields = form(); fields.username.focus();
      const expiresAt = Math.floor(Date.now() / 1000) + 3;
      let previews = 0;
      const page: InlineValue = {...ready, frame: {...ready.frame!, kind: 'totp'}};
      const request = vi.fn<InlineOptions['request']>().mockImplementation(async action => action === 'preview'
        ? {...page, preview: {itemId: 'first', code: ++previews === 1 ? '012345' : '654321', expiresAt: previews === 1 ? expiresAt : expiresAt + 30}}
        : page);
      const {ui, menu} = setup(request);
      trusted(fields.username, 'keydown', 'ArrowDown'); await settle(); await settle();
      expect(menu.querySelector('.otp-code')?.textContent).toBe('012 345');
      expect(menu.querySelector('.otp-expiry')?.textContent).toBe('3s');
      expect(request.mock.calls.filter(([action]) => action === 'fill')).toHaveLength(0);
      await vi.advanceTimersByTimeAsync(3100);
      expect(menu.querySelector('.otp-code')?.textContent).toBe('654 321');
      ui.state({state: 'locked', epoch: 2});
      expect(menu.textContent).not.toContain('654 321');
      expect(menu.textContent).toContain('Unlock Boltwarden');
      const count = request.mock.calls.length;
      await vi.advanceTimersByTimeAsync(30000);
      expect(request.mock.calls).toHaveLength(count);
    } finally { for (const ui of controllers.splice(0)) ui.destroy(); vi.useRealTimers(); }
  });
  it('never requests previews for protected accounts', async () => {
    const fields = form(); fields.username.focus();
    const request = vi.fn<InlineOptions['request']>().mockResolvedValue({...ready, frame: {...ready.frame!, kind: 'totp', items: [ready.frame!.items[1]!]}});
    const {menu} = setup(request);
    trusted(fields.username, 'keydown', 'ArrowDown'); await settle(); await settle();
    expect(menu.textContent).toContain('Locked');
    expect(request.mock.calls.map(([action]) => action)).toEqual(['list']);
  });
});


it('connects from a cold background without opening the toolbar', async () => {
  const fields = form(); fields.username.focus();
  let finish!: (value: InlineValue) => void;
  const request = vi.fn<InlineOptions['request']>().mockImplementation(() => new Promise(resolve => {finish = resolve;}));
  const {ui, menu} = setup(request);
  ui.state({state: 'disconnected', epoch: 0});
  trusted(fields.username, 'keydown', 'ArrowDown');
  expect(request).toHaveBeenCalledWith('list', {token: expect.any(String)});
  ui.state({state: 'connecting', epoch: 0});
  ui.state(ready.connection);
  finish(ready); await settle();
  expect(menu.textContent).toContain('Personal');
  expect(request).toHaveBeenCalledTimes(1);
});

describe('inline password suggestions', () => {
  it('generates and fills both new-password fields without requesting vault access or saving', async () => {
    vi.spyOn(document, 'location', 'get').mockReturnValue({protocol: 'https:'} as Location);
    const fields = form(); fields.password.autocomplete = 'new-password';
    const confirmation = fields.password.cloneNode() as HTMLInputElement;
    confirmation.name = 'confirm-password'; fields.password.form!.append(confirmation);
    confirmation.getBoundingClientRect = fields.password.getBoundingClientRect;
    confirmation.getClientRects = fields.password.getClientRects;
    fields.password.focus();
    const {mark, menu, request, ui} = setup();
    expect(mark.getAttribute('aria-label')).toBe('Suggest a password');
    trusted(fields.password, 'keydown', 'ArrowDown');
    expect(shadow.textContent).toContain('Use suggested password');
    expect(shadow.textContent).toContain('after you submit');
    const suggested = shadow.querySelector('code')!.textContent;
    expect(suggested).toHaveLength(20);
    ui.state({state: 'locked', epoch: 2});
    trusted(fields.password, 'keydown', 'Enter'); await settle();
    expect(fields.password.value).toBe(suggested); expect(confirmation.value).toBe(suggested);
    expect(menu.hidden).toBe(true); expect(shadow.textContent).not.toContain(suggested);
    expect(request).not.toHaveBeenCalled();
  });
});

it('keeps generator controls open while editing and fills the selected PIN', async () => {
  vi.spyOn(document, 'location', 'get').mockReturnValue({protocol: 'https:'} as Location);
  const fields = form(); fields.password.autocomplete = 'new-password'; fields.password.focus();
  const { menu, request } = setup();
  trusted(fields.password, 'keydown', 'ArrowDown');
  let type = shadow.querySelector<HTMLSelectElement>('select')!;
  type.focus(); type.value = 'pin'; trusted(type, 'change'); await settle();
  expect(menu.hidden).toBe(false);
  expect(shadow.querySelector('code')!.textContent).toMatch(/^\d{6}$/);
  const length = shadow.querySelector<HTMLInputElement>('[data-control="length"]')!;
  length.focus(); length.value = '8'; trusted(length, 'input'); await settle();
  const pin = shadow.querySelector('code')!.textContent;
  expect(pin).toMatch(/^\d{8}$/);
  const use = shadow.querySelector<HTMLButtonElement>('.suggested-password')!;
  use.focus(); trusted(use, 'click'); await settle();
  expect(fields.password.value).toBe(pin); expect(menu.hidden).toBe(true); expect(request).not.toHaveBeenCalled();
});
