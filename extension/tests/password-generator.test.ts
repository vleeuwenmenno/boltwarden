// @vitest-environment happy-dom
import { beforeEach, expect, it } from 'vitest';
import { fillGeneratedPassword, generatePassword, newPasswordFields } from '../lib/password-generator';
beforeEach(() => { document.body.innerHTML = ''; });
function form(html: string) {
  document.body.innerHTML = `<form>${html}</form>`;
  return [...document.querySelectorAll<HTMLInputElement>('input')];
}
const visible = (field: HTMLInputElement) => !field.hidden && !field.disabled && !field.readOnly;
it('groups new and confirmation fields without including an old password or another form', () => {
  const [old, password, confirmation] = form('<input type="password" autocomplete="current-password"><input type="password" autocomplete="new-password"><input type="password" name="confirm-password">');
  document.body.insertAdjacentHTML('beforeend', '<form><input type="password" autocomplete="new-password"></form>');
  expect(newPasswordFields(old!, visible)).toBeUndefined();
  expect(newPasswordFields(password!, visible)).toEqual([password, confirmation]);
  expect(newPasswordFields(confirmation!, visible)).toEqual([password, confirmation]);
  const [plain, repeat] = form('<input type="password" name="password"><input type="password" name="confirm">');
  expect(newPasswordFields(plain!, visible)).toEqual([plain, repeat]);
});
it('generates bounded passwords with letters, digits and symbols respecting both fields', () => {
  const fields = form('<input type="password" autocomplete="new-password"><input type="password" autocomplete="new-password">');
  const password = generatePassword(fields);
  expect(password).toHaveLength(20);
  expect(password).toMatch(/[A-Z]/); expect(password).toMatch(/[a-z]/); expect(password).toMatch(/[0-9]/); expect(password).toMatch(/[-_]/);
  fields[1]!.maxLength = 16; expect(generatePassword(fields)).toHaveLength(16);
  fields[0]!.minLength = 24; expect(() => generatePassword(fields)).toThrow(/different password length/);
  fields[1]!.maxLength = 32; expect(generatePassword(fields)).toHaveLength(24);
});
it('fills both fields without submitting and rejects retargeting between input events', () => {
  const [old, password, confirmation] = form('<input type="password" autocomplete="current-password" value="old"><input type="password" autocomplete="new-password"><input type="password" autocomplete="new-password">');
  let submits = 0; document.addEventListener('submit', () => submits++, {once: true});
  fillGeneratedPassword(password!, [password!, confirmation!], 'Generated-Password12_', () => true, visible);
  expect(old!.value).toBe('old'); expect(password!.value).toBe(confirmation!.value); expect(submits).toBe(0);
  confirmation!.value = '';
  password!.addEventListener('input', () => { confirmation!.type = 'text'; }, {once: true});
  expect(() => fillGeneratedPassword(password!, [password!, confirmation!], 'Another-Password12_', () => true, visible)).toThrow(/changed/);
  expect(confirmation!.value).toBe(''); expect(old!.value).toBe('old');
});
it('honors random character options and explicit lengths', () => {
  const fields = form('<input type="password" autocomplete="new-password">');
  for (const numbers of [false, true]) for (const symbols of [false, true]) {
    const password = generatePassword(fields, { type: 'random', length: 32, numbers, symbols });
    expect(password).toHaveLength(32);
    expect(/[0-9]/.test(password)).toBe(numbers); expect(/[-_]/.test(password)).toBe(symbols);
  }
});
it('generates memorable phrases and PINs without silently truncating form constraints', () => {
  const fields = form('<input type="password" autocomplete="new-password">');
  expect(generatePassword(fields, { type: 'memorable', length: 6, numbers: false, symbols: false }).split(' ')).toHaveLength(6);
  const phrase = generatePassword(fields, { type: 'memorable', length: 6, numbers: true, symbols: true });
  expect(phrase.split('-')).toHaveLength(6); expect(phrase).toMatch(/[0-9]$/);
  expect(generatePassword(fields, { type: 'pin', length: 6, numbers: false, symbols: true })).toMatch(/^\d{6}$/);
  fields[0]!.maxLength = 8;
  expect(() => generatePassword(fields, { type: 'memorable', length: 6, numbers: false, symbols: false })).toThrow(/requires/);
});
