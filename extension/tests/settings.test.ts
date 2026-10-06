import { describe, expect, it, vi } from 'vitest';
import { DEFAULT_SETTINGS, parseSettings, readSettings, watchSettings, writeSettings } from '../lib/settings';

function fakeStorage(initial?: unknown) {
  const data: Record<string, unknown> = initial === undefined ? {} : { settings: initial };
  const listeners: Array<(changes: Record<string, { newValue?: unknown }>, area: string) => void> = [];
  return {
    local: {
      get: vi.fn(async (key: string) => key in data ? { [key]: data[key] } : {}),
      set: vi.fn(async (items: Record<string, unknown>) => {
        Object.assign(data, items);
        for (const listener of listeners) listener(Object.fromEntries(Object.entries(items).map(([key, newValue]) => [key, { newValue }])), 'local');
      }),
    },
    onChanged: { addListener: vi.fn((listener: typeof listeners[number]) => listeners.push(listener)), removeListener: vi.fn((listener: typeof listeners[number]) => listeners.splice(listeners.indexOf(listener), 1)) },
  };
}

describe('settings', () => {
  it('falls back to defaults for missing or invalid values', () => {
    expect(parseSettings(undefined)).toEqual(DEFAULT_SETTINGS);
    expect(parseSettings({ autoOpen: 'yes', theme: 'purple' })).toEqual(DEFAULT_SETTINGS);
    expect(parseSettings({ autoOpen: false, theme: 'light' })).toEqual({ autoOpen: false, theme: 'light', copyTotp: false, clearClipboardSeconds: 30, autoSubmit: true, suppressFormHistory: true });
  });

  it('reads defaults without storage and merges writes', async () => {
    expect(await readSettings(undefined)).toEqual(DEFAULT_SETTINGS);
    const storage = fakeStorage({ autoOpen: false });
    expect(await writeSettings(storage, { theme: 'dark' })).toEqual({ autoOpen: false, theme: 'dark', copyTotp: false, clearClipboardSeconds: 30, autoSubmit: true, suppressFormHistory: true });
    expect(await readSettings(storage)).toEqual({ autoOpen: false, theme: 'dark', copyTotp: false, clearClipboardSeconds: 30, autoSubmit: true, suppressFormHistory: true });
  });

  it('reports the current value and later changes until unsubscribed', async () => {
    const storage = fakeStorage();
    const seen = vi.fn();
    const stop = watchSettings(storage, seen);
    await vi.waitFor(() => expect(seen).toHaveBeenCalledWith(DEFAULT_SETTINGS));
    await writeSettings(storage, { theme: 'light' });
    expect(seen).toHaveBeenLastCalledWith({ ...DEFAULT_SETTINGS, theme: 'light' });
    stop();
    await writeSettings(storage, { theme: 'dark' });
    expect(seen).toHaveBeenCalledTimes(2);
  });
  it('applies quick writes to different settings one after another without losing any', async () => {
    const storage = fakeStorage();
    await Promise.all([writeSettings(storage, { theme: 'dark' }), writeSettings(storage, { autoOpen: false }), writeSettings(storage, { copyTotp: true })]);
    expect(await readSettings(storage)).toEqual({ ...DEFAULT_SETTINGS, theme: 'dark', autoOpen: false, copyTotp: true });
  });
  it('keeps the clipboard wipe between 30 seconds and 5 minutes', () => {
    expect(parseSettings({ clearClipboardSeconds: 120 }).clearClipboardSeconds).toBe(120);
    for (const value of [5, 301, '60', Number.NaN, undefined]) expect(parseSettings({ clearClipboardSeconds: value }).clearClipboardSeconds).toBe(30);
  });
});
