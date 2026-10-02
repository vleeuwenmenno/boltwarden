// @vitest-environment happy-dom
import { beforeEach, expect, it, vi } from 'vitest';
import { submittedLogin, installPasswordCapture } from '../lib/password-capture';
beforeEach(() => { document.body.innerHTML = ''; });
const visible = (input: HTMLInputElement) => !input.disabled && input.type !== 'hidden';
function form(html: string) { document.body.innerHTML = `<form>${html}</form>`; return document.querySelector('form')!; }
it('captures login and registration credentials only from the submitted form', () => {
  const target = form('<input name="username" value="alice"><input type="password" value="secret">');
  document.body.insertAdjacentHTML('beforeend', '<form><input name="username" value="bob"><input type="password" value="other"></form>');
  expect(submittedLogin(target, visible)).toEqual({username: 'alice', password: 'secret'});
});
it('prefers a new password, requires confirmation fields to agree and excludes OTPs', () => {
  const target = form('<input autocomplete="username" value="alice"><input type="password" autocomplete="current-password" value="old"><input type="password" autocomplete="new-password" value="new"><input type="password" name="confirm" value="new">');
  expect(submittedLogin(target, visible)?.password).toBe('new');
  target.querySelector<HTMLInputElement>('[name=confirm]')!.value = 'different';
  expect(submittedLogin(target, visible)).toBeUndefined();
  expect(submittedLogin(form('<input type="password" autocomplete="one-time-code" value="123456">'), visible)).toBeUndefined();
});
it('does not offer saves for synthetic submissions, blank passwords or oversized values', () => {
  const target = form('<input name="username" value="alice"><input type="password" value="secret">');
  const send = vi.fn(), cleanup = installPasswordCapture(document, send);
  target.dispatchEvent(new Event('submit', {bubbles: true})); expect(send).not.toHaveBeenCalled(); cleanup();
  target.querySelector<HTMLInputElement>('[type=password]')!.value = ''; expect(submittedLogin(target, visible)).toBeUndefined();
  target.querySelector<HTMLInputElement>('[type=password]')!.value = 'a'.repeat(4097); expect(submittedLogin(target, visible)).toBeUndefined();
});
it('never captures payment fields as saved login credentials', () => {
  const target = form('<input name="username" autocomplete="cc-name" value="Alice Example"><input type="password" autocomplete="section-payment CC-CSC" value="123">');
  expect(submittedLogin(target, visible)).toBeUndefined();
  target.insertAdjacentHTML('beforeend', '<input autocomplete="username" value="alice"><input type="password" autocomplete="current-password" value="secret">');
  expect(submittedLogin(target, visible)).toEqual({username: 'alice', password: 'secret'});
});
