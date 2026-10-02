import { describe, expect, it } from 'vitest';
import { pairingBrowserLabel } from '../lib/browser-label';

const chromium = { getURL: () => 'chrome-extension://example/' };
const firefox = { getURL: () => 'moz-extension://example/' };

describe('descriptive browser pairing labels', () => {
  it('uses the browser-reported Firefox product name', async () => {
    expect(await pairingBrowserLabel({ ...firefox, getBrowserInfo: async () => ({ name: 'Firefox' }) })).toBe('Firefox');
    expect(await pairingBrowserLabel({ ...firefox, getBrowserInfo: async () => ({ name: 'Zen' }) })).toBe('Zen');
  });
  it('keeps pairing available when browser info is absent or fails', async () => {
    expect(await pairingBrowserLabel(firefox)).toBe('Firefox-based browser');
    expect(await pairingBrowserLabel({ ...firefox, getBrowserInfo: async () => { throw new Error('Unavailable'); } })).toBe('Firefox-based browser');
  });
  it('rejects malformed or oversized browser-reported labels', async () => {
    for (const name of ['', 'Firefox\nTrusted', 'é'.repeat(41)]) {
      expect(await pairingBrowserLabel({ ...firefox, getBrowserInfo: async () => ({ name }) })).toBe('Firefox-based browser');
    }
  });
  it('does not call every Chromium browser Google Chrome', async () => {
    expect(await pairingBrowserLabel(chromium, { userAgentData: { brands: [{ brand: 'Chromium' }, { brand: 'Not A Brand' }] } })).toBe('Chromium-based browser');
    expect(await pairingBrowserLabel(chromium)).toBe('Chromium-based browser');
  });
  it('prefers an explicitly reported derivative over Chrome compatibility', async () => {
    expect(await pairingBrowserLabel(chromium, { userAgentData: { brands: [{ brand: 'Google Chrome' }, { brand: 'Microsoft Edge' }] } })).toBe('Microsoft Edge');
    expect(await pairingBrowserLabel(chromium, { userAgentData: { brands: [{ brand: 'Google Chrome' }] } })).toBe('Google Chrome');
  });
});
