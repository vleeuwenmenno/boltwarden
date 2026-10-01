// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { InlineOptions } from '../lib/inline';
import content from '../entrypoints/content';

const harness = vi.hoisted(() => ({ options: undefined as InlineOptions | undefined, message: undefined as ((message: Record<string, unknown>) => void) | undefined,
  disconnected: undefined as (() => void) | undefined, posted: [] as Record<string, unknown>[], stop: undefined as (() => void) | undefined }));
vi.mock('wxt/utils/define-content-script', () => ({ defineContentScript: (definition: unknown) => definition }));
vi.mock('wxt/browser', () => ({ browser: { runtime: { connect: () => ({
  postMessage(message: Record<string, unknown>) { harness.posted.push(message); }, disconnect() { harness.disconnected?.(); },
  onMessage: { addListener(fn: typeof harness.message) { harness.message = fn; } }, onDisconnect: { addListener(fn: typeof harness.disconnected) { harness.disconnected = fn; } },
}) } } }));
vi.mock('../lib/inline', () => ({ createInlineController: (_doc: Document, options: InlineOptions) => { harness.options = options; return {
  reset() { options.release(); }, state() {}, destroy() { options.release(); },
}; } }));
function form() {
  const parent = document.createElement('form'); parent.innerHTML = '<input autocomplete="username"><input type="password">'; document.body.append(parent);
  for (const input of parent.querySelectorAll('input')) {
    input.getBoundingClientRect = () => new DOMRect(20, 30, 240, 32);
    input.getClientRects = () => [input.getBoundingClientRect()] as unknown as DOMRectList;
  }
  return { username: parent.querySelector('input')!, password: parent.querySelector<HTMLInputElement>('input[type=password]')! };
}
const send = (message: Record<string, unknown>) => harness.message!({ generation: 'document-one', ...message });
const inspect = (requestedToken?: string) => { send({ type: 'inspect', id: crypto.randomUUID(), ...(requestedToken ? { requestedToken } : {}) }); return harness.posted.at(-1)!; };
beforeEach(() => {
  document.body.replaceChildren(); harness.posted = [];
  (content as unknown as { main(ctx: unknown): void }).main({ isInvalid: false, setTimeout,
    addEventListener() {}, onInvalidated(fn: () => void) { harness.stop = fn; },
  });
  send({ type: 'generation' });
});
afterEach(() => { harness.stop?.(); vi.restoreAllMocks(); });

describe('inline document token isolation', () => {
  it('keeps popup and inline pins separate and allows OS focus loss during desktop approval', () => {
    const fields = form(); fields.username.focus(); vi.spyOn(document, 'hasFocus').mockReturnValue(false);
    const token = harness.options!.pin(fields.username)!;
    const popup = inspect(); expect(popup.token).not.toBe(token);
    expect(inspect(token)).toMatchObject({ token, focused: true });
    harness.options!.release(); expect(inspect(token)).toMatchObject({ token: null, focused: false });
    send({ type: 'fill', id: 'popup-fill', token: popup.token, username: 'alice', password: 'secret' });
    expect(fields.username.value).toBe('alice'); expect(fields.password.value).toBe('secret');
  });
  it('uses inline pins once and refuses credentials after field focus changes', () => {
    const first = form(), second = form(); first.username.focus();
    const token = harness.options!.pin(first.username)!; second.username.focus();
    send({ type: 'fill', scope: 'inline', id: 'stale', token, username: 'alice', password: 'secret' });
    expect(harness.posted.at(-1)!.type).toBe('failure'); expect(first.password.value).toBe(''); expect(second.password.value).toBe('');
    first.username.focus(); const current = harness.options!.pin(first.username)!;
    send({ type: 'fill', scope: 'inline', id: 'current', token: current, username: 'alice', password: 'secret' });
    expect(harness.posted.at(-1)!.type).toBe('filled'); expect(first.password.value).toBe('secret');
    first.password.value = '';
    send({ type: 'fill', scope: 'inline', id: 'replay', token: current, username: 'alice', password: 'secret' });
    expect(harness.posted.at(-1)!.type).toBe('failure'); expect(first.password.value).toBe('');
  });
  it('does not write a password if username input handlers retarget focus', () => {
    const first = form(), second = form(); first.username.focus(); const token = harness.options!.pin(first.username)!;
    first.username.addEventListener('input', () => second.username.focus());
    send({ type: 'fill', scope: 'inline', id: 'changed-focus', token, username: 'alice', password: 'secret' });
    expect(first.username.value).toBe('alice'); expect(first.password.value).toBe(''); expect(second.password.value).toBe('');
    expect(harness.posted.at(-1)!.type).toBe('failure');
  });
  it('rejects stale pins after generation changes without replacing the new document pin', () => {
    const fields = form(); fields.username.focus(); const token = harness.options!.pin(fields.username)!;
    send({ type: 'generation', generation: 'document-two' });
    send({ type: 'fill', scope: 'inline', id: 'old', token, username: 'alice', password: 'secret' });
    expect(fields.password.value).toBe(''); expect(harness.options!.current(token)).toBe(false);
  });
});
