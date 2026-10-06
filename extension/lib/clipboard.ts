import { browser } from 'wxt/browser';

export const OFFSCREEN_COPY = 'offscreen-copy';
// Optional so existing installs are not disabled by a new permission warning.
export const CLIPBOARD_PERMISSION: { permissions: ['clipboardWrite'] } = { permissions: ['clipboardWrite'] };

type Offscreen = {
  createDocument(options: { url: string; reasons: string[]; justification: string }): Promise<void>;
  closeDocument(): Promise<void>;
  hasDocument?(): Promise<boolean>;
};

/** Writes text from the background: Firefox's event page has a DOM, Chrome's worker uses an offscreen page. */
export async function copyFromBackground(text: string) {
  const offscreen = (browser as unknown as { offscreen?: Offscreen }).offscreen;
  if (!offscreen) { await navigator.clipboard.writeText(text); return; }
  if (!await offscreen.hasDocument?.()) {
    await offscreen.createDocument({ url: browser.runtime.getURL('/offscreen.html'), reasons: ['CLIPBOARD'],
      justification: 'Copy the verification code after filling a login, when the user enabled it.' });
  }
  try {
    if (await browser.runtime.sendMessage({ type: OFFSCREEN_COPY, text }) !== true) throw new Error('Clipboard copy failed.');
  } finally { await offscreen.closeDocument().catch(() => {}); }
}
