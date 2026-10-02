import { cardForms, sameCard, type CardForm } from './cards';
export interface LoginForm { card?: CardForm; username?: HTMLInputElement; password?: HTMLInputElement; otp?: HTMLInputElement[] }
const LOGIN_NAME = /user(?:[-_ ]?name)?|e-?mail|login|identifier/i;
const NEW_PASSWORD = /new[-_ ]?password|confirm|repeat|retype/i;

/** Includes open shadow roots; closed roots are deliberately outside our support. */
export function inputs(root: Document | ShadowRoot): HTMLInputElement[] {
  const found = Array.from(root.querySelectorAll('input'));
  for (const element of root.querySelectorAll('*')) {
    if (element.shadowRoot) found.push(...inputs(element.shadowRoot));
  }
  return found;
}

export function visibleInput(input: HTMLInputElement | HTMLSelectElement): boolean {
  if (!input.isConnected || input.disabled || ('readOnly' in input && input.readOnly) || input.type === 'hidden' || input.getClientRects().length === 0) return false;
  let element: Element | null = input;
  while (element) {
    if (element.hasAttribute('hidden') || element.hasAttribute('inert') || element.getAttribute('aria-hidden') === 'true' || element.getAttribute('aria-disabled') === 'true') return false;
    const style = getComputedStyle(element);
    if (style.display === 'none' || style.visibility === 'hidden' || style.visibility === 'collapse' || style.opacity === '0') return false;
    element = element.parentElement ?? ((element.getRootNode() as ShadowRoot).host || null);
  }
  const rect = input.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0 && rect.bottom > 0 && rect.right > 0 && rect.top < innerHeight && rect.left < innerWidth;
}

function autocomplete(input: HTMLInputElement): string[] { return input.autocomplete.toLowerCase().split(/\s+/); }
function isUsername(input: HTMLInputElement): boolean {
  return ['text', 'email', 'tel'].includes(input.type) && !autocomplete(input).some(value => value.startsWith('cc-') || value === 'one-time-code' || value === 'new-password');
}

/** OTP fields need an explicit purpose; arbitrary short or numeric fields are not codes. */
function otpHint(input: HTMLInputElement): boolean {
  if (autocomplete(input).some(value => value.startsWith('cc-'))) return false;
  const hint = `${input.name} ${input.id} ${input.getAttribute('aria-label') ?? ''} ${Array.from(input.labels ?? []).map(label => label.textContent ?? '').join(' ')}`;
  if (/recovery|backup|herstel/i.test(hint)) return false;
  return autocomplete(input).includes('one-time-code') || /(?:^|[\s_-])(?:totp|otp|2fa|mfa|passcode)(?:$|[\s_\d-])|(?:verification|security|auth(?:entication)?|two[-_ ]?factor|one[-_ ]?time)[-_ ]?code|zescijferige\s*code/i.test(hint);
}
function otpFields(fields: HTMLInputElement[]): HTMLInputElement[] | undefined {
  const candidates = fields.filter(input => ['text', 'tel', 'number', 'password'].includes(input.type) && !autocomplete(input).includes('new-password'));
  const hinted = candidates.filter(otpHint);
  if (!hinted.length) return;
  const split = candidates.filter(input => input.maxLength === 1);
  if ([6, 8].includes(split.length) && hinted.every(input => split.includes(input))) return split;
  if (hinted.length === 1 && hinted[0]!.maxLength !== 1) return hinted;
}
export function formContains(form: LoginForm, input: Element | null): boolean {
  return !!form.card && Object.values(form.card).includes(input as HTMLInputElement) || form.username === input || form.password === input || !!form.otp?.some(field => field === input);
}
export function formKind(form: LoginForm): 'login' | 'totp' | 'card' { return form.card ? 'card' : form.otp ? 'totp' : 'login'; }

export function loginForms(document: Document, visible: (input: HTMLInputElement) => boolean = visibleInput): LoginForm[] {
  const groups = new Map<Node, HTMLInputElement[]>();
  for (const input of inputs(document).filter(visible)) {
    const group = input.form ?? input.closest('[role="form"]') ?? input.getRootNode();
    groups.set(group, [...(groups.get(group) ?? []), input]);
  }
  const forms: LoginForm[] = [];
  for (const fields of groups.values()) {
    const otp = otpFields(fields);
    if (otp) forms.push({ otp });
    const passwords = fields.filter(input => input.type === 'password' && !otpHint(input) && !autocomplete(input).some(value => value.startsWith('cc-')));
    // A change form may offer the saved password only in one explicitly marked
    // current-password field. Never fill its new password, confirmation, or username.
    const isNew = (input: HTMLInputElement) => autocomplete(input).includes('new-password') || NEW_PASSWORD.test(`${input.name} ${input.id}`);
    if (passwords.length > 1 || passwords.some(isNew)) {
      const current = passwords.filter(input => !isNew(input) && (autocomplete(input).includes('current-password')
        || /(?:^|[\s_-])(?:current|old)[-_ ]?password(?:$|[\s_-])/i.test(`${input.name} ${input.id}`)));
      if (current.length === 1) forms.push({ password: current[0] });
      continue;
    }
    const candidates = fields.filter(input => isUsername(input) && !otpHint(input) && !otp?.includes(input));
    const named = candidates.filter(input => autocomplete(input).includes('username'));
    const likely = candidates.filter(input => input.type === 'email' || autocomplete(input).includes('email') || LOGIN_NAME.test(`${input.name} ${input.id} ${input.getAttribute('aria-label') ?? ''} ${Array.from(input.labels ?? []).map(label => label.textContent ?? '').join(' ')}`));
    const username = named.length === 1 ? named[0] : likely.length === 1 ? likely[0] : passwords.length === 1 && candidates.length === 1 ? candidates[0] : undefined;
    const password = passwords[0];
    if (password || username) forms.push({ username, password });
  }
  return forms;
}

export function autofillForms(document: Document): LoginForm[] {
  return [...loginForms(document), ...cardForms(document).map(card => ({ card }))];
}

export function activeInput(document: Document): Element | null {
  let active = document.activeElement;
  while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  return active;
}

export function selectForm(forms: LoginForm[], active: Element | null): LoginForm | null {
  const focused = forms.filter(form => formContains(form, active));
  if (focused.length === 1) return focused[0]!;
  return forms.length === 1 ? forms[0]! : null;
}

export function sameForm(left: LoginForm, right: LoginForm): boolean {
  return sameCard(left.card, right.card) && left.username === right.username && left.password === right.password
    && (left.otp === undefined ? right.otp === undefined : !!right.otp && left.otp.length === right.otp.length && left.otp.every((field, i) => field === right.otp![i]));
}

export function fillForm(form: LoginForm, username: string, password: string, visible: (input: HTMLInputElement) => boolean = visibleInput, stillCurrent = () => true): void {
  const fields: [HTMLInputElement | undefined, string][] = [[form.username, username], [form.password, password]];
  const expected = fields.map(([input]) => ({ type: input?.type, autocomplete: input?.autocomplete }));
  // Validate every target before changing the first field.
  if (!stillCurrent() || fields.some(([input]) => input && !visible(input))) throw new Error('The login form changed. Select a login field and try again.');
  for (const [index, [input, value]] of fields.entries()) {
    if (!input) continue;
    // Username input handlers run synchronously and may replace or retype the password field.
    if (!stillCurrent() || !input.isConnected || !visible(input) || input.type !== expected[index]!.type || input.autocomplete !== expected[index]!.autocomplete) throw new Error('The login form changed. Select a login field and try again.');
    const prototype = input.ownerDocument.defaultView!.HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set;
    if (!setter) throw new Error('This page does not support filling.');
    setter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    input.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
  }
}

/** Fill only the pinned OTP fields. Revalidate after each input handler and never submit. */
export function fillOtp(form: LoginForm, code: string, expiresAt: number, visible: (input: HTMLInputElement) => boolean = visibleInput, stillCurrent = () => true): void {
  const fields = form.otp;
  if (!fields?.length || !/^\d{6,10}$/.test(code) || !Number.isSafeInteger(expiresAt)
    || (fields.length > 1 && fields.length !== code.length)) throw new Error('The verification code does not fit this field.');
  const shape = fields.map(field => ({ type: field.type, length: field.maxLength, autocomplete: field.autocomplete }));
  const validate = () => {
    if (Date.now() >= expiresAt * 1000 - 1000) throw new Error('Verification code expired. Choose the account again for a fresh code.');
    if (!stillCurrent() || fields.some((field, i) => !field.isConnected || !visible(field) || field.type !== shape[i]!.type
      || field.maxLength !== shape[i]!.length || field.autocomplete !== shape[i]!.autocomplete)) throw new Error('The verification form changed. Try again.');
  };
  validate();
  if (fields.length === 1 && fields[0]!.maxLength > 0 && fields[0]!.maxLength < code.length) throw new Error('The verification code does not fit this field.');
  for (const [index, input] of fields.entries()) {
    validate();
    const setter = Object.getOwnPropertyDescriptor(input.ownerDocument.defaultView!.HTMLInputElement.prototype, 'value')?.set;
    if (!setter) throw new Error('This page does not support filling.');
    setter.call(input, fields.length === 1 ? code : code[index]);
    input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    input.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
  }
}
