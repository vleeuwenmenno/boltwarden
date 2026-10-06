import { autocompleteOf } from './autocomplete';
import { cardPurpose, cardForms, sameCard, type CardForm } from './cards';
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
  const rect = input.getBoundingClientRect();
  // Screen-reader-only and similar 1px fields are not for the user to type into.
  if (rect.width <= 1 || rect.height <= 1) return false;
  // Part of the field that a clipping ancestor still shows. Collapsed steps (height: 0 with
  // overflow: hidden, as in identifier-first logins) hide fields that keep their own size.
  let left = rect.left, top = rect.top, right = rect.right, bottom = rect.bottom;
  let element: Element | null = input, clipping = true;
  while (element) {
    if (element.hasAttribute('hidden') || element.hasAttribute('inert') || element.getAttribute('aria-hidden') === 'true' || element.getAttribute('aria-disabled') === 'true') return false;
    const style = getComputedStyle(element);
    if (style.display === 'none' || style.visibility === 'hidden' || style.visibility === 'collapse' || style.opacity === '0') return false;
    // body/html overflow belongs to the viewport, and fixed elements escape their ancestors' clips.
    if (clipping && element !== input && element !== input.ownerDocument.body && element !== input.ownerDocument.documentElement && style.display !== 'contents') {
      const [overflowX = '', overflowY = overflowX] = (style.overflow || '').split(/\s+/);
      const clipsX = !['', 'visible'].includes(style.overflowX || overflowX), clipsY = !['', 'visible'].includes(style.overflowY || overflowY);
      if (clipsX || clipsY) {
        const box = element.getBoundingClientRect();
        if (clipsX) { left = Math.max(left, box.left); right = Math.min(right, box.right); }
        if (clipsY) { top = Math.max(top, box.top); bottom = Math.min(bottom, box.bottom); }
        if (right - left < 1 || bottom - top < 1) return false;
      }
    }
    if (style.position === 'fixed') clipping = false;
    element = element.parentElement ?? ((element.getRootNode() as ShadowRoot).host || null);
  }
  return rect.bottom > 0 && rect.right > 0 && rect.top < innerHeight && rect.left < innerWidth;
}

function autocomplete(input: HTMLInputElement): string[] { return autocompleteOf(input).toLowerCase().split(/\s+/); }
function isUsername(input: HTMLInputElement): boolean {
  return ['text', 'email', 'tel'].includes(input.type) && !cardPurpose(input) && !autocomplete(input).some(value => value.startsWith('cc-') || value === 'one-time-code' || value === 'new-password');
}

/** OTP fields need an explicit purpose; arbitrary short or numeric fields are not codes. */
function otpHint(input: HTMLInputElement): boolean {
  if (cardPurpose(input)) return false;
  const hint = `${input.name} ${input.id} ${input.getAttribute('aria-label') ?? ''} ${Array.from(input.labels ?? []).map(label => label.textContent ?? '').join(' ')}`;
  if (/recovery|backup|herstel/i.test(hint)) return false;
  return autocomplete(input).includes('one-time-code') || /(?:^|[\s_-])(?:totp|otp|2fa|mfa|passcode)(?:$|[\s_\d-])|(?:verification|security|auth(?:entication)?|two[-_ ]?factor|one[-_ ]?time)[-_ ]?code|zescijferige\s*code|\b[4-8][-\s]?(?:digit|cijferige)\s*code/i.test(hint);
}
function otpFields(fields: HTMLInputElement[]): HTMLInputElement[] | undefined {
  const candidates = fields.filter(input => ['text', 'tel', 'number', 'password'].includes(input.type) && !autocomplete(input).includes('new-password'));
  const hinted = candidates.filter(otpHint);
  // Per-digit boxes often carry no code hint at all ("Digit 1"…). Six or eight single-character
  // inputs that all only accept digits are treated as one code even without a hint.
  const split = candidates.filter(input => input.maxLength === 1);
  const digit = (input: HTMLInputElement) => input.getAttribute('inputmode') === 'numeric' || input.type === 'tel' || input.type === 'number' || /\\d|\[0-9\]/.test(input.pattern);
  if ([6, 8].includes(split.length) && (hinted.length ? hinted.every(input => split.includes(input)) : split.every(digit))) return split;
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
    const passwords = fields.filter(input => input.type === 'password' && !cardPurpose(input) && !otpHint(input) && !autocomplete(input).some(value => value.startsWith('cc-')));
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
  const expected = fields.map(([input]) => ({ type: input?.type, autocomplete: input && autocompleteOf(input) }));
  // Validate every target before changing the first field.
  if (!stillCurrent() || fields.some(([input]) => input && !visible(input))) throw new Error('The login form changed. Select a login field and try again.');
  for (const [index, [input, value]] of fields.entries()) {
    if (!input) continue;
    // Username input handlers run synchronously and may replace or retype the password field.
    if (!stillCurrent() || !input.isConnected || !visible(input) || input.type !== expected[index]!.type || autocompleteOf(input) !== expected[index]!.autocomplete) throw new Error('The login form changed. Select a login field and try again.');
    const prototype = input.ownerDocument.defaultView!.HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set;
    if (!setter) throw new Error('This page does not support filling.');
    setter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    input.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
  }
}

const enabledShown = (element: Element) => element.getClientRects().length > 0 && !(element as HTMLButtonElement).disabled
  && element.getAttribute('aria-disabled') !== 'true';
const isSubmitButton = (element: Element) => (element instanceof HTMLButtonElement && element.type === 'submit')
  || (element instanceof HTMLInputElement && (element.type === 'submit' || element.type === 'image'));
// Language-independent: a text button (not an icon) that is not a toggle such as show-password.
const plainButton = (element: Element) => enabledShown(element) && !element.hasAttribute('aria-pressed')
  && !element.hasAttribute('aria-expanded') && !element.hasAttribute('aria-controls') && !element.hasAttribute('aria-haspopup')
  && !!(element instanceof HTMLInputElement ? element.value : element.textContent ?? '').trim();
// The primary action (Next, Log in, Continue) is drawn as a filled button; helper actions such as
// "Forgot email?" are usually plain text. This works in every language.
const filledButton = (element: Element) => {
  const style = getComputedStyle(element);
  const color = style.backgroundColor.replace(/\s/g, '');
  return (color !== '' && color !== 'transparent' && !/^rgba\(\d+,\d+,\d+,0(?:\.0*)?\)$/.test(color)) || (style.backgroundImage !== '' && style.backgroundImage !== 'none');
};
// Native submission must stay on this origin, in this tab, and never run javascript: URLs.
function sameSiteTarget(owner: HTMLFormElement, button?: HTMLButtonElement | HTMLInputElement) {
  const doc = owner.ownerDocument;
  const action = button?.hasAttribute('formaction') ? button.getAttribute('formaction')! : owner.getAttribute('action') ?? '';
  const target = (button?.hasAttribute('formtarget') ? button.getAttribute('formtarget') : owner.getAttribute('target')) ?? '';
  try {
    const url = new URL(action, doc.baseURI);
    return url.protocol !== 'javascript:' && url.origin === doc.location.origin && ['', '_self'].includes(target.trim().toLowerCase());
  } catch { return false; }
}

/**
 * Submit a just-filled login or verification code the way pressing Enter would, without
 * reading button labels:
 * - a POST form with a submit button is submitted natively, so the browser picks its
 *   default button exactly as Enter does;
 * - GET forms and forms without a submit button never submit natively, because that could
 *   put the credentials in the URL. They get a script-only submit event, which the page's
 *   handler can take but the browser never acts on;
 * - otherwise the filled (primary-looking) text button after the field is clicked, never a
 *   native submit button or a menu/toggle; without one, Enter is sent to the field.
 * Change-password forms (more than one visible password field) are never submitted.
 */
export type SubmitMethod = 'native' | 'script-event' | 'button' | 'enter';
export function submitFilled(form: LoginForm, stillCurrent = () => true): SubmitMethod | false {
  const field = form.password ?? form.otp?.at(-1) ?? form.username;
  if (!field?.value || !field.isConnected || !stillCurrent()) return false;
  const owner = field.form, doc = field.ownerDocument;
  const scope: ParentNode = owner ?? doc;
  if (form.password && Array.from(scope.querySelectorAll('input[type="password"]')).some(input => input !== form.password && visibleInput(input as HTMLInputElement))) return false;
  const password = form.password, type = password?.type;
  // An unmarked show-password toggle got clicked: hide the password again and stop.
  const toggled = () => { if (password && password.type !== type) { password.type = type!; return true; } return false; };
  if (owner) {
    const button = Array.from(owner.elements).find(isSubmitButton) as HTMLButtonElement | HTMLInputElement | undefined;
    // Credentials only ever go to this site: an injected or cross-site form is not submitted.
    if (!sameSiteTarget(owner, button)) return false;
    // Like Enter: click the form's default button (its handlers run and its name is sent).
    if (owner.method === 'post' && button) {
      if (button.disabled) return false;
      button.click();
      return toggled() ? false : 'native';
    }
    if (!owner.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))) return 'script-event';
  }
  const fieldBox = field.getBoundingClientRect();
  // Buttons in a fixed layer or dialog the field is not part of (cookie banners, chat widgets) never count.
  const foreignLayer = (element: Element) => { const layer = element.closest('dialog, [role="dialog"], [aria-modal="true"]'); return !!layer && !layer.contains(field); };
  const fixed = (element: Element) => { for (let node: Element | null = element; node && !node.contains(field); node = node.parentElement) if (getComputedStyle(node).position === 'fixed') return true; return false; };
  let container: Element | null = owner ?? field.parentElement;
  for (let depth = 0; container && depth < 6; depth++, container = owner ? null : container.parentElement) {
    const filled = Array.from(container.querySelectorAll('button, input[type="submit"], [role="button"]'))
      .filter(element => field.compareDocumentPosition(element) & Node.DOCUMENT_POSITION_FOLLOWING && plainButton(element)
        && !(isSubmitButton(element) && (element as HTMLButtonElement).form) && filledButton(element) && !foreignLayer(element) && !fixed(element)
        && element.getBoundingClientRect().top - fieldBox.bottom < 400);
    if (filled.length) {
      // The first filled button after the field is the step's main action.
      (filled[0] as HTMLElement).click();
      return toggled() ? false : 'button';
    }
  }
  for (const type of ['keydown', 'keypress', 'keyup']) {
    field.dispatchEvent(new KeyboardEvent(type, { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true, cancelable: true, composed: true } as KeyboardEventInit));
  }
  return 'enter';
}

/**
 * Identifier-first logins (username, Continue, then password) show the password field only
 * after the first submit. Wait for a visible, empty password field in the same form (or the
 * page's only one, for formless pages and sites that re-render the step), fill it once, and hand it to `filled` for submitting.
 * The password is dropped on fill, timeout, or `stop()`; a full page load ends the watch.
 */
export function watchPasswordStep(document: Document, username: HTMLInputElement, password: string, filled: (form: LoginForm) => void,
  visible: (input: HTMLInputElement) => boolean = visibleInput, timeout = 15_000) {
  let secret: string | undefined = password;
  const owner = username.form;
  // Sites are often still switching steps when the field first shows; fill only once the same
  // field has stayed visible for two checks in a row.
  let seen: HTMLInputElement | undefined;
  const check = () => {
    if (secret === undefined) return;
    // The original form while it exists; once the site replaced it (or had none), the page's
    // only empty password field. The submit that follows still refuses cross-site forms.
    const empty = loginForms(document, visible).filter(candidate => candidate.password && !candidate.password.value);
    const form = owner?.isConnected ? empty.find(candidate => candidate.password!.form === owner) : empty.length === 1 ? empty[0] : undefined;
    if (!form || seen !== form.password) { seen = form?.password; return; }
    const value = secret; stop();
    try { fillForm({ password: form.password }, '', value, visible); filled(form); } catch { /* The page changed again. */ }
  };
  const timer = setInterval(check, 200);
  const limit = setTimeout(() => {
    if (secret !== undefined) console.info('[Boltwarden] Password step: gave up', JSON.stringify({ passwordFields: inputs(document).filter(input => input.type === 'password').length,
      visible: inputs(document).filter(input => input.type === 'password' && visible(input)).length, sameForm: owner?.isConnected ?? false }));
    stop();
  }, timeout);
  function stop() { secret = undefined; clearInterval(timer); clearTimeout(limit); }
  return stop;
}

/** Fill only the pinned OTP fields. Revalidate after each input handler; submitting is the caller's choice. */
export function fillOtp(form: LoginForm, code: string, expiresAt: number, visible: (input: HTMLInputElement) => boolean = visibleInput, stillCurrent = () => true): void {
  const fields = form.otp;
  if (!fields?.length || !/^\d{6,10}$/.test(code) || !Number.isSafeInteger(expiresAt)
    || (fields.length > 1 && fields.length !== code.length)) throw new Error('The verification code does not fit this field.');
  const shape = fields.map(field => ({ type: field.type, length: field.maxLength, autocomplete: autocompleteOf(field) }));
  const validate = () => {
    if (Date.now() >= expiresAt * 1000 - 1000) throw new Error('Verification code expired. Choose the account again for a fresh code.');
    if (!stillCurrent() || fields.some((field, i) => !field.isConnected || !visible(field) || field.type !== shape[i]!.type
      || field.maxLength !== shape[i]!.length || autocompleteOf(field) !== shape[i]!.autocomplete)) throw new Error('The verification form changed. Try again.');
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
