import { autocompleteOf } from './autocomplete';
/** Generate locally; passwords are never sent to the background or vault here. */
import { passwordWords } from './password-words';
export interface GeneratorOptions { type: 'random' | 'memorable' | 'pin'; length: number; numbers: boolean; symbols: boolean }
export const defaultGeneratorOptions: GeneratorOptions = { type: 'random', length: 20, numbers: true, symbols: true };
function pick(size: number): number {
  const limit = Math.floor(0x100000000 / size) * size;
  const value = new Uint32Array(1);
  do { crypto.getRandomValues(value); } while (value[0]! >= limit);
  const result = value[0]! % size; value.fill(0); return result;
}
const fresh = (input: HTMLInputElement) => autocompleteOf(input).split(/\s+/).includes('new-password')
  || /new[-_ ]?password|confirm|repeat|retype/i.test(`${input.name} ${input.id}`);
const old = (input: HTMLInputElement) => autocompleteOf(input).split(/\s+/).includes('current-password')
  || /current|old[-_ ]?password/i.test(`${input.name} ${input.id}`);

function editable(input: HTMLInputElement): boolean {
  if (!input.isConnected || input.disabled || input.readOnly || !input.getClientRects().length) return false;
  for (let node: Element | null = input; node; node = node.parentElement) {
    const style = getComputedStyle(node);
    if (node.hasAttribute('hidden') || node.hasAttribute('inert') || style.display === 'none' || style.visibility === 'hidden') return false;
  }
  return true;
}

export function newPasswordFields(input: HTMLInputElement, visible = editable): HTMLInputElement[] | undefined {
  const scope = input.form ?? input.closest('[role="form"]');
  if (!scope) return;
  const fields = Array.from(input.form?.elements ?? scope.querySelectorAll('input'))
    .filter((field): field is HTMLInputElement => field instanceof HTMLInputElement && field.type === 'password' && visible(field));
  let selected = fields.filter(field => fresh(field) && !old(field));
  // A plain password plus a confirmation field is a conventional registration form.
  if (fields.length === 2 && fields.every(field => !old(field)) && selected.length === 1
    && /confirm|repeat|retype/i.test(`${selected[0]!.name} ${selected[0]!.id}`)) selected = fields;
  if (!selected.includes(input) || selected.length > 2) return;
  return selected;
}

export function generatePassword(fields: HTMLInputElement[], options?: GeneratorOptions): string {
  const settings = options ?? defaultGeneratorOptions;
  const minimum = Math.max(options ? 1 : 16, ...fields.map(field => field.minLength));
  const maximum = Math.min(1024, ...fields.map(field => field.maxLength < 0 ? 1024 : field.maxLength));
  const length = options ? settings.length : Math.min(maximum, Math.max(20, minimum));
  const lower = settings.type === 'memorable' ? 4 : settings.type === 'pin' ? 4 : 8;
  const upper = settings.type === 'memorable' ? 12 : 128;
  if (!fields.length || maximum < minimum || !Number.isInteger(length) || length < lower || length > upper)
    throw new Error('These fields require a different password length. Adjust the options.');
  for (let attempt = 0; attempt < 128; attempt++) {
    let password: string;
    if (settings.type === 'memorable') {
      password = Array.from({ length }, () => passwordWords[pick(passwordWords.length)]!).join(settings.symbols ? '-' : ' ');
      if (settings.numbers) password += String(pick(10));
    } else {
      const alphabet = settings.type === 'pin' ? '0123456789'
        : 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' + (settings.numbers ? '0123456789' : '') + (settings.symbols ? '-_' : '');
      password = Array.from({ length }, () => alphabet[pick(alphabet.length)]).join('');
      if (settings.type === 'random' && (!/[A-Z]/.test(password) || !/[a-z]/.test(password)
        || (settings.numbers && !/[0-9]/.test(password)) || (settings.symbols && !/[-_]/.test(password)))) continue;
    }
    if (password.length < minimum || password.length > maximum)
      throw new Error(`This form requires ${minimum}–${maximum} characters. Adjust the options.`);
    return password;
  }
  throw new Error('Could not generate a password. Try again.');
}

export function fillGeneratedPassword(input: HTMLInputElement, fields: HTMLInputElement[], password: string,
  stillCurrent: () => boolean, visible = editable) {
  const shapes = fields.map(field => ({ type: field.type, autocomplete: autocompleteOf(field), min: field.minLength, max: field.maxLength }));
  for (const [index, field] of fields.entries()) {
    const current = newPasswordFields(input, visible), shape = shapes[index]!;
    if (!stillCurrent() || !current || current.length !== fields.length || current.some((value, i) => value !== fields[i])
      || !field.isConnected || field.type !== shape.type || autocompleteOf(field) !== shape.autocomplete
      || field.minLength !== shape.min || field.maxLength !== shape.max
      || (field.maxLength >= 0 && password.length > field.maxLength) || password.length < field.minLength) throw new Error('The password form changed. Choose the field again.');
    const setter = Object.getOwnPropertyDescriptor(field.ownerDocument.defaultView!.HTMLInputElement.prototype, 'value')?.set;
    if (!setter) throw new Error('This page does not support filling.');
    setter.call(field, password);
    field.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    field.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
  }
}
