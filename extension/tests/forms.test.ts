// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { activeInput, fillForm, type LoginForm, fillOtp, loginForms, submitFilled, watchPasswordStep, selectForm, visibleInput } from '../lib/forms';

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
  it('detects unhinted per-digit boxes only when every box accepts digits', () => {
    document.body.innerHTML = `<form>${Array.from({ length: 6 }, (_, i) => `<input maxlength="1" inputmode="numeric" aria-label="Digit ${i + 1}">`).join('')}</form>`;
    const [form] = loginForms(document, visible);
    expect(form?.otp).toHaveLength(6);
    fillOtp(form!, '012345', expires(), visible);
    expect(form!.otp!.map((field: HTMLInputElement) => field.value).join('')).toBe('012345');
    document.body.innerHTML = `<form>${'<input maxlength="1">'.repeat(6)}</form>`;
    expect(loginForms(document, visible).some(candidate => candidate.otp)).toBe(false);
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

describe('auto-submit after a fill', () => {
  const login = () => loginForms(document, visible)[0]!;
  const expires = () => Math.floor(Date.now() / 1000) + 30;
  const show = () => {
    for (const element of document.querySelectorAll<HTMLElement>('button, input, [role=button]')) {
      element.getBoundingClientRect = () => new DOMRect(0, 0, 40, 20);
      element.getClientRects = () => [element.getBoundingClientRect()] as unknown as DOMRectList;
    }
  };
  const count = (selector: string, type: string) => { const seen = { count: 0 }; document.querySelector(selector)!.addEventListener(type, event => { if (type === 'submit') event.preventDefault(); seen.count++; }); return seen; };
  it('submits a POST form natively, like Enter, whatever the buttons say', () => {
    document.body.innerHTML = '<form method="post"><input autocomplete="username"><input type="password"><button>👁</button><button type="submit">登录</button></form>';
    show(); const form = login(); fillForm(form, 'alice', 'secret', visible);
    const submitted = count('form', 'submit');
    expect(submitFilled(form)).toBeTruthy();
    expect(submitted.count).toBe(1);
  });
  it('never submits a GET form natively and lets its script handle a submit event', () => {
    document.body.innerHTML = '<form><input autocomplete="username"><input type="password"><button>Entrar</button></form>';
    show(); const form = login(); fillForm(form, 'alice', 'secret', visible);
    const seen: boolean[] = [];
    document.querySelector('form')!.addEventListener('submit', event => { event.preventDefault(); seen.push(event.isTrusted === true); });
    const clicked = count('button', 'click');
    submitFilled(form);
    // One untrusted event: the browser never submits it, so nothing reaches the URL.
    expect(seen).toEqual([false]);
    expect(clicked.count).toBe(0);
  });
  it('clicks the filled button on script-driven pages, not a nearer text-only helper (Google)', () => {
    document.body.innerHTML = '<div><div><div><input name="identifier" autocomplete="username webauthn"></div><button type="button">E-mailadres vergeten?</button></div><div><button type="button" aria-haspopup="menu" style="background:#eee">Account maken</button><button type="button" style="background:#0b57d0">Volgende</button></div></div>';
    show(); const form = login(); fillForm(form, 'alice@example.com', 'secret', visible);
    let clicked = '';
    for (const element of document.querySelectorAll('button')) element.addEventListener('click', () => { clicked = element.textContent!; });
    expect(submitFilled(form)).toBe('button');
    expect(clicked).toBe('Volgende');
  });
  it('clicks the filled button after the field on script-driven pages, ignoring toggles', () => {
    document.body.innerHTML = '<div><div><input autocomplete="username"><input type="password" id="pw"><button aria-controls="pw" style="background:#ccc">Toon</button></div><div role="button" style="background:#06c">Inloggen</div></div>';
    show(); const form = login(); fillForm(form, 'alice', 'secret', visible);
    const toggle = count('button', 'click'), login_ = count('[role=button]', 'click');
    submitFilled(form);
    expect([toggle.count, login_.count]).toEqual([0, 1]);
  });
  it('hides the password again if the clicked button turned out to be a show-password toggle', () => {
    document.body.innerHTML = '<div><input autocomplete="username"><input type="password"><button style="background:#ccc">Show</button></div>';
    show(); const form = login(); fillForm(form, 'alice', 'secret', visible);
    document.querySelector('button')!.addEventListener('click', () => { form.password!.type = 'text'; });
    submitFilled(form);
    expect(form.password!.type).toBe('password');
  });
  it('presses Enter when no filled button stands out', () => {
    document.body.innerHTML = '<div><input autocomplete="username"><input type="password"><button>A</button><button>B</button></div>';
    show(); const form = login(); fillForm(form, 'alice', 'secret', visible);
    const keys: string[] = [];
    form.password!.addEventListener('keydown', event => keys.push((event as KeyboardEvent).key));
    submitFilled(form);
    expect(keys).toEqual(['Enter']);
  });
  it('submits verification codes but never change-password forms, empty fields, or stale forms', () => {
    document.body.innerHTML = `<form method="post">${'<input maxlength="1" autocomplete="one-time-code">'.repeat(6)}<button>OK</button></form>`;
    show(); let form = login(); fillOtp(form, '123456', expires(), visible);
    let submitted = count('form', 'submit');
    submitFilled(form);
    expect(submitted.count).toBe(1);
    document.body.innerHTML = '<form method="post"><input type="password" autocomplete="current-password"><input type="password" autocomplete="new-password"><button>Save</button></form>';
    show(); form = login(); fillForm(form, '', 'secret', visible);
    submitted = count('form', 'submit');
    expect(submitFilled(form)).toBe(false);
    document.body.innerHTML = '<form method="post"><input autocomplete="username"><input type="password"><button>Go</button></form>';
    show(); form = login();
    submitted = count('form', 'submit');
    expect(submitFilled(form)).toBe(false);
    fillForm(form, 'alice', 'secret', visible);
    expect(submitFilled(form, () => false)).toBe(false);
    expect(submitted.count).toBe(0);
  });
  it('continues identifier-first logins: submits the username, then fills and submits the password', () => {
    vi.useFakeTimers();
    try {
      document.body.innerHTML = '<form method="post"><input name="username" autocomplete="username"><input type="password" aria-hidden="true"><button type="submit">Continue</button></form>';
      show(); const form = login();
      expect(form.password).toBeUndefined();
      fillForm(form, 'alice', 'secret', visible);
      const submitted = count('form', 'submit');
      const steps: LoginForm[] = [];
      watchPasswordStep(document, form.username!, 'secret', step => { steps.push(step); submitFilled(step); }, visible);
      expect(submitFilled(form)).toBeTruthy();
      vi.advanceTimersByTime(1000);
      expect(steps).toHaveLength(0);
      document.querySelector('input[type=password]')!.removeAttribute('aria-hidden');
      vi.advanceTimersByTime(200);
      // Filled only after the field stayed visible for a second check.
      expect(steps).toHaveLength(0);
      vi.advanceTimersByTime(200);
      expect(steps).toHaveLength(1);
      expect(steps[0]!.password!.value).toBe('secret');
      expect(submitted.count).toBe(2);
      vi.advanceTimersByTime(1000);
      expect(steps).toHaveLength(1);
    } finally { vi.useRealTimers(); }
  });
  it('gives up on the password step after the timeout or when stopped, without filling', () => {
    vi.useFakeTimers();
    try {
      document.body.innerHTML = '<form method="post"><input name="username" autocomplete="username"><input type="password" aria-hidden="true"><button type="submit">Continue</button></form>';
      const form = login(); const filled = vi.fn();
      watchPasswordStep(document, form.username!, 'secret', filled, visible, 5000);
      vi.advanceTimersByTime(5000);
      const stop = watchPasswordStep(document, form.username!, 'secret', filled, visible);
      stop();
      document.querySelector('input[type=password]')!.removeAttribute('aria-hidden');
      vi.advanceTimersByTime(1000);
      expect(filled).not.toHaveBeenCalled();
      expect(document.querySelector<HTMLInputElement>('input[type=password]')!.value).toBe('');
    } finally { vi.useRealTimers(); }
  });
  it('fills and submits a field whose form history Boltwarden is hiding', async () => {
    const { suppressFormHistory } = await import('../lib/autocomplete');
    document.body.innerHTML = '<form method="post"><input autocomplete="username"><input type="password" autocomplete="current-password"><button>Go</button></form>';
    show();
    const restore = suppressFormHistory(document.querySelector('input')!);
    const form = login();
    expect(form.username).toBe(document.querySelector('input'));
    fillForm(form, 'alice', 'secret', visible);
    expect(form.username!.value).toBe('alice');
    restore();
    expect(form.username!.getAttribute('autocomplete')).toBe('username');
  });
  it('detects code fields by attribute even when the browser hides the token from the property', () => {
    // Firefox returns "" from input.autocomplete for one-time-code; Kagi's field has no other hint.
    document.body.innerHTML = '<form method="post"><input type="text" readonly aria-hidden="true" name="username" autocomplete="username"><label><span>6-digit code *</span><input autocomplete="one-time-code" type="text" name="code" inputmode="numeric" maxlength="10"></label><button type="submit">Continue</button></form>';
    const code = document.querySelector<HTMLInputElement>('input[name=code]')!;
    Object.defineProperty(code, 'autocomplete', { get: () => '' });
    expect(loginForms(document, visible).map(form => form.otp)).toEqual([[code]]);
    code.removeAttribute('autocomplete');
    expect(loginForms(document, visible).map(form => form.otp)).toEqual([[code]]);
  });
  it('fills the page\'s only password field when the site re-renders the step in a new form', () => {
    vi.useFakeTimers();
    try {
      document.body.innerHTML = '<form method="post" id="one"><input name="username" autocomplete="username"><button type="submit">Continue</button></form>';
      const form = login(); const filled = vi.fn();
      watchPasswordStep(document, form.username!, 'secret', filled, visible);
      // While the original form exists, a password field elsewhere is not used.
      document.body.insertAdjacentHTML('beforeend', '<form method="post" id="two"><input type="password" autocomplete="current-password"><button type="submit">Log in</button></form>');
      vi.advanceTimersByTime(400);
      expect(filled).not.toHaveBeenCalled();
      document.querySelector('#one')!.remove();
      vi.advanceTimersByTime(400);
      expect(filled).toHaveBeenCalledTimes(1);
      expect(document.querySelector<HTMLInputElement>('#two input')!.value).toBe('secret');
    } finally { vi.useRealTimers(); }
  });
  it('does not guess between several empty password fields outside the original form', () => {
    vi.useFakeTimers();
    try {
      document.body.innerHTML = '<form method="post" id="one"><input name="username" autocomplete="username"></form>';
      const form = login(); const filled = vi.fn();
      watchPasswordStep(document, form.username!, 'secret', filled, visible);
      document.body.insertAdjacentHTML('beforeend', '<form method="post"><input type="password"></form><form method="post"><input type="password"></form>');
      vi.advanceTimersByTime(1000);
      expect(filled).not.toHaveBeenCalled();
    } finally { vi.useRealTimers(); }
  });
  it('treats fields inside a collapsed, clipping step as hidden (Fastmail identifier-first)', () => {
    document.body.innerHTML = '<form method="post"><input name="username" autocomplete="username"><div id="step" style="overflow: hidden"><input type="password" autocomplete="current-password"></div></form>';
    const [username, password] = Array.from(document.querySelectorAll('input'));
    for (const input of [username!, password!]) {
      input.getBoundingClientRect = () => new DOMRect(10, 10, 200, 30);
      input.getClientRects = () => [input.getBoundingClientRect()] as unknown as DOMRectList;
    }
    const step = document.querySelector<HTMLElement>('#step')!;
    step.getBoundingClientRect = () => new DOMRect(10, 50, 200, 0);
    expect(visibleInput(password!)).toBe(false);
    expect(loginForms(document).map(form => [!!form.username, !!form.password])).toEqual([[true, false]]);
    step.getBoundingClientRect = () => new DOMRect(10, 0, 200, 60);
    expect(visibleInput(password!)).toBe(true);
  });
  it('treats 1px screen-reader-only fields as hidden', () => {
    document.body.innerHTML = '<input autocomplete="username">';
    const input = document.querySelector('input')!;
    input.getClientRects = () => [new DOMRect(0, 0, 1, 1)] as unknown as DOMRectList;
    input.getBoundingClientRect = () => new DOMRect(0, 0, 1, 1);
    expect(visibleInput(input)).toBe(false);
  });
  it('never submits a form that posts to another site, another tab, or javascript:', () => {
    for (const attributes of ['action="https://evil.example/collect"', 'target="_blank"', 'action="javascript:void 0"']) {
      document.body.innerHTML = `<form method="post" ${attributes}><input autocomplete="username"><input type="password"><button type="submit">Go</button></form>`;
      show(); const form = login(); fillForm(form, 'alice', 'secret', visible);
      const submitted = count('form', 'submit');
      expect(submitFilled(form)).toBe(false);
      expect(submitted.count).toBe(0);
    }
    document.body.innerHTML = '<form method="post"><input autocomplete="username"><input type="password"><button type="submit" formaction="https://evil.example/">Go</button></form>';
    show(); const form = login(); fillForm(form, 'alice', 'secret', visible);
    expect(submitFilled(form)).toBe(false);
  });
  it('clicks the default button like Enter, and leaves a disabled one alone', () => {
    document.body.innerHTML = '<form method="post"><input autocomplete="username"><input type="password"><button type="submit" name="login" value="1">Go</button></form>';
    show(); let form = login(); fillForm(form, 'alice', 'secret', visible);
    const clicked = count('button', 'click'), submitted = count('form', 'submit');
    expect(submitFilled(form)).toBe('native');
    expect([clicked.count, submitted.count]).toEqual([1, 1]);
    document.body.innerHTML = '<form method="post"><input autocomplete="username"><input type="password"><button type="submit" disabled>Go</button></form>';
    show(); form = login(); fillForm(form, 'alice', 'secret', visible);
    const blocked = count('form', 'submit');
    expect(submitFilled(form)).toBe(false);
    expect(blocked.count).toBe(0);
  });
  it('ignores filled buttons in cookie banners and dialogs, and takes the first filled button', () => {
    document.body.innerHTML = '<div><div><input name="identifier" autocomplete="username"></div><button style="background:#06c">Next</button><button style="background:#06c;width:400px">Sign up</button></div><div style="position:fixed"><button style="background:#0a0">Accept all</button></div><div role="dialog"><button style="background:#0a0">Subscribe</button></div>';
    show(); const form = login(); fillForm(form, 'alice@example.com', 'secret', visible);
    let clicked = '';
    for (const element of document.querySelectorAll('button')) element.addEventListener('click', () => { clicked = element.textContent!; });
    submitFilled(form);
    expect(clicked).toBe('Next');
  });
  it('keeps fields visible under a scroll-locked body or inside a fixed modal, but not in a collapsed step', () => {
    const box = (element: Element, rect: DOMRect) => { (element as HTMLElement).getBoundingClientRect = () => rect; (element as HTMLElement).getClientRects = () => [rect] as unknown as DOMRectList; };
    document.body.innerHTML = '<div id="wrap" style="overflow:hidden"><div id="modal" style="position:fixed"><input id="modal-field"></div></div><div id="step" style="overflow:hidden"><input id="collapsed"></div>';
    document.body.style.overflow = 'hidden';
    box(document.body, new DOMRect(0, 0, 800, 0));
    box(document.querySelector('#wrap')!, new DOMRect(0, 0, 800, 0));
    box(document.querySelector('#modal-field')!, new DOMRect(100, 100, 200, 30));
    box(document.querySelector('#step')!, new DOMRect(0, 300, 800, 0));
    box(document.querySelector('#collapsed')!, new DOMRect(100, 300, 200, 30));
    expect(visibleInput(document.querySelector<HTMLInputElement>('#modal-field')!)).toBe(true);
    expect(visibleInput(document.querySelector<HTMLInputElement>('#collapsed')!)).toBe(false);
    document.body.style.overflow = '';
  });
});
