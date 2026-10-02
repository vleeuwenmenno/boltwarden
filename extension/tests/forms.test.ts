// @vitest-environment happy-dom
import { beforeEach, describe, expect, it } from 'vitest';
import { activeInput, fillForm, fillOtp, loginForms, selectForm, visibleInput } from '../lib/forms';

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
  it('keeps OTP separate from registration, password-change, or hidden fields', () => {
    document.body.innerHTML = '<form><input autocomplete="username"><input type="password" autocomplete="new-password"></form><form><input type="password"><input type="password"></form><form><input autocomplete="one-time-code" name="username"></form><form><input name="username" type="hidden"></form>';
    const forms = loginForms(document, visible);
    expect(forms).toHaveLength(1);
    expect(forms[0]?.otp).toHaveLength(1);
    expect(forms[0]?.password).toBeUndefined();
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


describe('verification codes', () => {
  const expires = () => Math.floor(Date.now() / 1000) + 30;
  it.each(['autocomplete="one-time-code"', 'name="passcode"', 'aria-label="Zescijferige code"'])('recognizes and fills single code fields: %s', attributes => {
    document.body.innerHTML = `<form><input ${attributes} maxlength="6"></form>`;
    const form = loginForms(document, visible)[0]!;
    fillOtp(form, '012345', expires(), visible);
    expect(form.otp![0]!.value).toBe('012345');
    expect(form.password).toBeUndefined();
  });
  it('does not guess recovery codes or arbitrary numeric fields', () => {
    document.body.innerHTML = '<form><input name="recovery_code" autocomplete="one-time-code"></form><form><input type="number" maxlength="6"></form>';
    expect(loginForms(document, visible)).toEqual([]);
  });
  it('fills six boxes with auto-advance without submitting', () => {
    document.body.innerHTML = `<form>${Array.from({length: 6}, (_, i) => `<input maxlength="1" ${i === 0 ? 'autocomplete="one-time-code"' : ''}>`).join('')}</form>`;
    const form = loginForms(document, visible)[0]!;
    let submits = 0;
    document.querySelector('form')!.addEventListener('submit', () => submits++);
    form.otp!.forEach((field, i) => field.addEventListener('input', () => form.otp![i + 1]?.focus()));
    fillOtp(form, '012345', expires(), visible);
    expect(form.otp!.map(field => field.value).join('')).toBe('012345');
    expect(submits).toBe(0);
  });
  it.each(['expired', 'length', 'hidden', 'changed'])('refuses unsafe code fills: %s', reason => {
    document.body.innerHTML = '<form><input autocomplete="one-time-code" maxlength="6"></form>';
    const form = loginForms(document, visible)[0]!;
    if (reason === 'hidden') form.otp![0]!.disabled = true;
    expect(() => fillOtp(form, reason === 'length' ? '12345678' : '123456', reason === 'expired' ? 1 : expires(), visible, () => reason !== 'changed')).toThrow();
    expect(form.otp![0]!.value).toBe('');
  });
  it('stops after an input handler replaces a later box', () => {
    document.body.innerHTML = `<form>${'<input maxlength="1" autocomplete="one-time-code">'.repeat(6)}</form>`;
    const form = loginForms(document, visible)[0]!;
    form.otp![0]!.addEventListener('input', () => form.otp![1]!.remove());
    expect(() => fillOtp(form, '123456', expires(), visible)).toThrow();
    expect(form.otp!.slice(1).every(field => field.value === '')).toBe(true);
  });
});

it('fills only the explicit current password on a change form, preserving new passwords and username', () => {
  document.body.innerHTML = '<form><input autocomplete="username" value="chosen-account"><input id="old" type="password" autocomplete="current-password"><input id="new" type="password" autocomplete="new-password" value="new-secret"><input id="confirm" type="password" autocomplete="new-password" value="new-secret"></form>';
  const forms = loginForms(document, visible);
  expect(forms).toHaveLength(1); expect(forms[0]!.username).toBeUndefined();
  fillForm(forms[0]!, 'different-account', 'saved-secret', visible);
  expect(document.querySelector<HTMLInputElement>('#old')!.value).toBe('saved-secret');
  expect(document.querySelector<HTMLInputElement>('#new')!.value).toBe('new-secret');
  expect(document.querySelector<HTMLInputElement>('#confirm')!.value).toBe('new-secret');
  expect(document.querySelector<HTMLInputElement>('[autocomplete=username]')!.value).toBe('chosen-account');
});
it('accepts named old-password fields but rejects ambiguous or conflicting current-password hints', () => {
  document.body.innerHTML = '<form><input type="password" name="old-password"><input type="password" autocomplete="new-password"></form>';
  expect(loginForms(document, visible)).toHaveLength(1);
  document.querySelector('form')!.insertAdjacentHTML('beforeend', '<input type="password" autocomplete="current-password">');
  expect(loginForms(document, visible)).toHaveLength(0);
  document.body.innerHTML = '<form><input type="password" autocomplete="current-password" name="new-password"><input type="password" name="confirm-password"></form>';
  expect(loginForms(document, visible)).toHaveLength(0);
});
