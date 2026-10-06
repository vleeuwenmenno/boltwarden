import { browser } from 'wxt/browser';
import { OFFSCREEN_COPY } from '../../lib/clipboard';

// Chrome's service worker has no DOM, so the background writes the clipboard through this
// offscreen document. Only the background (no tab, same extension) may ask it to copy.
browser.runtime.onMessage.addListener((message: unknown, sender) => {
  if (sender.id !== browser.runtime.id || sender.tab || !message || typeof message !== 'object') return;
  const data = message as { type?: unknown; text?: unknown };
  if (data.type !== OFFSCREEN_COPY || typeof data.text !== 'string') return;
  // Set the data in the copy event itself: that also works for the empty string that wipes it.
  const text = data.text;
  const write = (event: ClipboardEvent) => { event.clipboardData?.setData('text/plain', text); event.preventDefault(); };
  document.addEventListener('copy', write, { once: true });
  const area = document.getElementById('clipboard') as HTMLTextAreaElement;
  area.value = text || ' '; area.select();
  const copied = document.execCommand('copy');
  document.removeEventListener('copy', write); area.value = '';
  return Promise.resolve(copied);
});
