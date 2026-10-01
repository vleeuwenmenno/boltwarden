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
