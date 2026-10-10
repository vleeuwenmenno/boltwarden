import type { Theme } from './settings';
import css from './passkey-dialog.css?inline';
import bolt from '../public/bolt.svg?raw';

export type UnavailableChoice = 'retry' | 'browser' | 'cancel';

const REASONS: Record<string, string> = {
  unpaired: 'This browser is not paired with the Boltwarden desktop app. Open Boltwarden from the toolbar to pair it again.',
  disconnected: 'Boltwarden cannot reach the desktop app. Make sure it is running.',
  'not-responding': 'The Boltwarden desktop app or this extension is not responding. If this keeps happening, reload the extension.',
};

/** Isolated-world dialog in a closed shadow root. Only trusted clicks and keys choose. */
export function showUnavailableDialog(doc: Document, options: { reason: string; site: string; theme: Theme; choose(choice: UnavailableChoice): void }) {
  const host = doc.createElement('div'); host.dataset.boltwardenPasskey = '';
  const root = host.attachShadow({ mode: 'closed' });
  try {
    const sheet = new CSSStyleSheet(); sheet.replaceSync(css); root.adoptedStyleSheets = [sheet];
  } catch {
    // Firefox ESR rejects constructed sheets through content-script Xray wrappers.
    const style = doc.createElement('style'); style.textContent = css; root.append(style);
  }
  const backdrop = doc.createElement('div'); backdrop.className = 'backdrop';
  if (options.theme !== 'system') backdrop.dataset.theme = options.theme;
  const panel = doc.createElement('div'); panel.className = 'panel';
  panel.setAttribute('role', 'alertdialog'); panel.setAttribute('aria-modal', 'true');
  panel.setAttribute('aria-labelledby', 'boltwarden-passkey-title'); panel.setAttribute('aria-describedby', 'boltwarden-passkey-reason');
  const title = doc.createElement('h2'); title.className = 'title'; title.id = 'boltwarden-passkey-title';
  title.append(doc.importNode(new DOMParser().parseFromString(bolt, 'image/svg+xml').documentElement, true), 'Boltwarden can’t use your passkeys right now');
  const reason = doc.createElement('p'); reason.id = 'boltwarden-passkey-reason';
  reason.textContent = REASONS[options.reason] ?? 'Boltwarden cannot take this passkey request right now.';
  const site = doc.createElement('p'); site.className = 'site'; site.textContent = `Requested by ${options.site}`;
  const hint = doc.createElement('p'); hint.className = 'hint';
  hint.textContent = 'You can turn this question off in Boltwarden settings, under Passkeys.';
  const actions = doc.createElement('div'); actions.className = 'actions';
  const button = (label: string, choice: UnavailableChoice, primary = false) => {
    const element = doc.createElement('button'); element.type = 'button'; element.textContent = label;
    if (primary) element.className = 'primary';
    element.addEventListener('click', event => { if (event.isTrusted) pick(choice); });
    return element;
  };
  const retry = button('Try again', 'retry', true);
  actions.append(button('Cancel', 'cancel'), button('Use browser instead', 'browser'), retry);
  panel.append(title, reason, site, actions, hint);
  backdrop.append(panel); root.append(backdrop);
  // Keys stay inside the dialog so the page underneath does not react to them.
  backdrop.addEventListener('keydown', event => {
    event.stopPropagation();
    if (event.isTrusted && event.key === 'Escape') { event.preventDefault(); pick('cancel'); }
  });
  const previous = doc.activeElement instanceof HTMLElement ? doc.activeElement : undefined;
  let open = true;
  function close() {
    if (!open) return;
    open = false; host.remove();
    try { previous?.focus({ preventScroll: true }); } catch { /* element gone */ }
  }
  function pick(choice: UnavailableChoice) {
    if (!open) return;
    close(); options.choose(choice);
  }
  doc.documentElement.append(host);
  retry.focus({ preventScroll: true });
  return { close };
}
