export interface SubmittedLogin { username: string; password: string }

function displayed(input: HTMLInputElement): boolean {
  if (!input.isConnected || !input.getClientRects().length) return false;
  for (let node: Element | null = input; node; node = node.parentElement) {
    const style = getComputedStyle(node);
    if (node.hasAttribute('hidden') || node.hasAttribute('inert') || style.display === 'none' || style.visibility === 'hidden') return false;
  }
  return true;
}

/** Read only the submitted form. Prefer an explicit new password over the old one. */
export function submittedLogin(form: HTMLFormElement, visible = displayed): SubmittedLogin | undefined {
  const fields = Array.from(form.elements).filter((element): element is HTMLInputElement => element instanceof HTMLInputElement
    && !element.disabled && element.type !== 'hidden' && visible(element));
  const passwords = fields.filter(input => input.type === 'password' && !input.autocomplete.split(/\s+/).includes('one-time-code'));
  const fresh = passwords.filter(input => input.autocomplete.split(/\s+/).includes('new-password') || /new[-_ ]?password|confirm|repeat/i.test(`${input.name} ${input.id}`));
  const selected = fresh.length ? fresh : passwords;
  if (!selected.length || selected.some(input => !input.value || input.value !== selected[0]!.value)) return;
  const usernames = fields.filter(input => ['text', 'email', 'tel'].includes(input.type)
    && (input.autocomplete.split(/\s+/).some(value => ['username', 'email'].includes(value)) || /username|e-?mail|login|identifier/i.test(`${input.name} ${input.id}`)));
  if (usernames.length > 1) return;
  const username = usernames[0]?.value ?? '', password = selected[0]!.value;
  if (username.length > 1024 || password.length > 4096) return;
  return { username, password };
}

export function installPasswordCapture(document: Document, submit: (login: SubmittedLogin) => void) {
  let lastGesture = 0;
  const gesture = (event: Event) => { if (event.isTrusted) lastGesture = Date.now(); };
  const capture = (event: Event) => {
    if (!event.isTrusted || !lastGesture || Date.now() - lastGesture > 5000 || !(event.target instanceof HTMLFormElement)) return;
    lastGesture = 0;
    const login = submittedLogin(event.target);
    if (login) submit(login);
  };
  document.addEventListener('pointerdown', gesture, true);
  document.addEventListener('keydown', gesture, true);
  document.addEventListener('submit', capture, true);
  return () => {
    document.removeEventListener('pointerdown', gesture, true);
    document.removeEventListener('keydown', gesture, true);
    document.removeEventListener('submit', capture, true);
  };
}

/** Reuse the extension palette without exposing password values to the page UI. */
export function saveNotice(document: Document, text: string) {
  const host = document.createElement('div'), root = host.attachShadow({ mode: 'closed' });
  const panel = document.createElement('div'); panel.setAttribute('role', 'status'); panel.textContent = text;
  const style = document.createElement('style');
  style.textContent = ':host{all:initial!important;position:fixed!important;bottom:16px!important;right:16px!important;z-index:2147483647!important}div{max-width:340px;padding:12px 16px;border:1px solid #424557;border-radius:6px;background:#1a1b26;color:#c0caf5;font:14px/1.45 system-ui,sans-serif;box-shadow:0 6px 18px #0005}';
  root.append(style, panel); document.documentElement.append(host); setTimeout(() => host.remove(), 8000);
}
