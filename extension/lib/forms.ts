export interface LoginForm { username?: HTMLInputElement; password?: HTMLInputElement }
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

export function visibleInput(input: HTMLInputElement): boolean {
  if (!input.isConnected || input.disabled || input.readOnly || input.type === 'hidden' || input.getClientRects().length === 0) return false;
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
  return ['text', 'email', 'tel'].includes(input.type) && !autocomplete(input).some(value => value === 'one-time-code' || value === 'new-password');
}

export function loginForms(document: Document, visible = visibleInput): LoginForm[] {
  const groups = new Map<Node, HTMLInputElement[]>();
  for (const input of inputs(document).filter(visible)) {
    const group = input.form ?? input.closest('[role="form"]') ?? input.getRootNode();
    groups.set(group, [...(groups.get(group) ?? []), input]);
  }
  const forms: LoginForm[] = [];
  for (const fields of groups.values()) {
    const passwords = fields.filter(input => input.type === 'password');
    // Never put an existing password into registration or change-password forms.
    if (passwords.length > 1 || passwords.some(input => autocomplete(input).includes('new-password') || NEW_PASSWORD.test(`${input.name} ${input.id}`))) continue;
    const candidates = fields.filter(isUsername);
    const named = candidates.filter(input => autocomplete(input).includes('username'));
    const likely = candidates.filter(input => input.type === 'email' || autocomplete(input).includes('email') || LOGIN_NAME.test(`${input.name} ${input.id} ${input.getAttribute('aria-label') ?? ''} ${Array.from(input.labels ?? []).map(label => label.textContent ?? '').join(' ')}`));
    const username = named.length === 1 ? named[0] : likely.length === 1 ? likely[0] : passwords.length === 1 && candidates.length === 1 ? candidates[0] : undefined;
    const password = passwords[0];
    if (password || username) forms.push({ username, password });
  }
  return forms;
}

export function activeInput(document: Document): Element | null {
  let active = document.activeElement;
  while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  return active;
}

export function selectForm(forms: LoginForm[], active: Element | null): LoginForm | null {
  const focused = forms.filter(form => form.username === active || form.password === active);
  if (focused.length === 1) return focused[0]!;
  return forms.length === 1 ? forms[0]! : null;
}

export function sameForm(left: LoginForm, right: LoginForm): boolean {
  return left.username === right.username && left.password === right.password;
}

export function fillForm(form: LoginForm, username: string, password: string, visible = visibleInput, stillCurrent = () => true): void {
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
