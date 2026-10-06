import { afterEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({ browser: {} as Record<string, any> }));
vi.mock('wxt/browser', () => ({ get browser() { return h.browser; } }));
import { copyFromBackground, OFFSCREEN_COPY } from '../lib/clipboard';

afterEach(() => { vi.unstubAllGlobals(); });

describe('background clipboard', () => {
  it('copies and wipes through a short-lived offscreen page on Chrome', async () => {
    const offscreen = { hasDocument: vi.fn(async () => false), createDocument: vi.fn(async () => {}), closeDocument: vi.fn(async () => {}) };
    const sendMessage = vi.fn(async (_message: unknown) => true);
    h.browser = { offscreen, runtime: { getURL: (path: string) => path, sendMessage } };
    await copyFromBackground('123456');
    await copyFromBackground('');
    expect(sendMessage.mock.calls.map(([message]) => message)).toEqual([{ type: OFFSCREEN_COPY, text: '123456' }, { type: OFFSCREEN_COPY, text: '' }]);
    expect(offscreen.closeDocument).toHaveBeenCalledTimes(2);
  });
  it('writes directly from Firefox’s background page and reports failures', async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    h.browser = { runtime: {} };
    await copyFromBackground('');
    expect(writeText).toHaveBeenCalledWith('');
    h.browser = { offscreen: { hasDocument: async () => true, createDocument: vi.fn(), closeDocument: vi.fn(async () => {}) }, runtime: { getURL: (p: string) => p, sendMessage: async () => false } };
    await expect(copyFromBackground('1')).rejects.toThrow('Clipboard copy failed.');
  });
});
