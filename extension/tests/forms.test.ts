// @vitest-environment happy-dom
import { beforeEach, describe, expect, it } from 'vitest';
import { activeInput, fillForm, loginForms, selectForm, visibleInput } from '../lib/forms';

const visible = (input: HTMLInputElement) => !input.disabled && !input.readOnly && input.type !== 'hidden' && input.getAttribute('aria-hidden') !== 'true';
beforeEach(() => { document.body.innerHTML = ''; });

describe('form selection', () => {
  it('classifies ordinary and username-first login forms', () => {
    document.body.innerHTML = '<form><input name="username"><input type="password" autocomplete="current-password"></form><form><input autocomplete="username"></form>';
    const forms = loginForms(document, visible);
    expect(forms).toHaveLength(2);
    expect(forms[0]?.password?.type).toBe('password');
    expect(forms[1]?.password).toBeUndefined();
    expect(selectForm(forms, document.body)).toBeNull();
    expect(selectForm(forms, forms[1]!.username!)).toBe(forms[1]);
  });
  it('recognizes email-first and labelled username fields without guessing ambiguous emails', () => {
    document.body.innerHTML = '<form><input type="email"></form><form><label>User name<input></label></form><form><input autocomplete="email"></form><form><input type="email"><input type="email"></form>';
    const forms = loginForms(document, visible);
    expect(forms).toHaveLength(3);
    expect(forms.every(form => form.username && !form.password)).toBe(true);
  });
  it('does not mistake a password or OTP hint for an email login', () => {
    document.body.innerHTML = '<form><input type="email" autocomplete="one-time-code"></form><form><input type="text" autocomplete="new-password" name="username"></form><form><input type="email"><input type="password" autocomplete="new-password"></form>';
    expect(loginForms(document, visible)).toEqual([]);
  });
  it('never selects registration, password-change, OTP, or hidden fields', () => {
    document.body.innerHTML = '<form><input autocomplete="username"><input type="password" autocomplete="new-password"></form><form><input type="password"><input type="password"></form><form><input autocomplete="one-time-code" name="username"></form><form><input name="username" type="hidden"></form>';
    expect(loginForms(document, visible)).toEqual([]);
  });
  it('finds logins and focus inside an open shadow root', () => {
    const host = document.createElement('div'); document.body.append(host);
    const root = host.attachShadow({ mode: 'open' });
    root.innerHTML = '<input autocomplete="username"><input type="password">';
    root.querySelector('input')!.focus();
    const forms = loginForms(document, visible);
    expect(forms).toHaveLength(1);
    expect(activeInput(document)).toBe(forms[0]!.username);
  });
  it('does not guess a username when multiple text fields are ambiguous', () => {
    document.body.innerHTML = '<form><input name="a"><input name="b"><input type="password"></form>';
    expect(loginForms(document, visible)[0]?.username).toBeUndefined();
  });
});

describe('fill safety', () => {
  it('uses the native setter and emits input/change without submitting', () => {
    document.body.innerHTML = '<form><input autocomplete="username"><input type="password"></form>';
    const form = loginForms(document, visible)[0]!;
    const events: string[] = [];
    for (const type of ['input', 'change', 'submit']) document.addEventListener(type, () => events.push(type), { once: false });
    Object.defineProperty(form.password!, 'value', { configurable: true, set() { throw new Error('Overridden setter'); } });
    fillForm(form, 'alice', 'secret', visible);
    const getter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.get!;
    expect(getter.call(form.password)).toBe('secret');
    expect(events).toEqual(['input', 'change', 'input', 'change']);
  });
  it('validates both targets before writing anything', () => {
    document.body.innerHTML = '<form><input autocomplete="username"><input type="password"></form>';
    const form = loginForms(document, visible)[0]!;
    form.password!.disabled = true;
    expect(() => fillForm(form, 'alice', 'secret', visible)).toThrow();
    expect(form.username!.value).toBe('');
  });
  it.each(['remove', 'retype'])('does not write the password after a username handler changes its target (%s)', action => {
    document.body.innerHTML = '<form><input autocomplete="username"><input type="password"></form>';
    const form = loginForms(document, visible)[0]!;
    form.username!.addEventListener('input', () => { if (action === 'remove') form.password!.remove(); else form.password!.type = 'text'; });
    expect(() => fillForm(form, 'alice', 'secret', visible)).toThrow();
    expect(form.password!.value).toBe('');
  });
  it('does not write the password after a username handler changes the route', () => {
    document.body.innerHTML = '<form><input autocomplete="username"><input type="password"></form>';
    const form = loginForms(document, visible)[0]!;
    let current = true;
    form.username!.addEventListener('input', () => { current = false; });
    expect(() => fillForm(form, 'alice', 'secret', visible, () => current)).toThrow();
    expect(form.password!.value).toBe('');
  });
  it('refuses real hidden inputs even with a mocked layout rectangle', () => {
    document.body.innerHTML = '<div aria-hidden="true"><input></div>';
    const input = document.querySelector('input')!;
    input.getClientRects = () => [{ width: 100, height: 20 }] as unknown as DOMRectList;
    expect(visibleInput(input)).toBe(false);
  });
});
