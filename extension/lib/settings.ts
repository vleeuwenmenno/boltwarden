// User preferences shared by the popup, options page, and content scripts.
// Stored in storage.local so they survive restarts; nothing here is secret.
export type Theme = 'system' | 'light' | 'dark';
export interface Settings {
  /** Open the inline login menu when a login field is clicked. */
  autoOpen: boolean;
  /** `system` follows prefers-color-scheme, which tracks the browser's website appearance. */
  theme: Theme;
  /** After filling a login that has a verification code, copy the current code. Off by default. */
  copyTotp: boolean;
  /** Seconds until a copied code is wiped from the clipboard (30 to 300). */
  clearClipboardSeconds: number;
  /** Submit after filling a password or verification code. */
  autoSubmit: boolean;
  /** Advanced: set autocomplete="off" on the focused login field to hide the browser's typed history. */
  suppressFormHistory: boolean;
}
export const DEFAULT_SETTINGS: Settings = { autoOpen: true, theme: 'system', copyTotp: false, clearClipboardSeconds: 30, autoSubmit: true, suppressFormHistory: true };

type Area = { get(key: string): Promise<Record<string, unknown>>; set(items: Record<string, unknown>): Promise<void> };
type Changes = { addListener(callback: (changes: Record<string, { newValue?: unknown }>, area: string) => void): void;
  removeListener(callback: (changes: Record<string, { newValue?: unknown }>, area: string) => void): void };
export type SettingsStorage = { local?: Area; onChanged?: Changes };

const KEY = 'settings';

export function parseSettings(value: unknown): Settings {
  const stored = value && typeof value === 'object' ? value as Partial<Record<keyof Settings, unknown>> : {};
  return {
    autoOpen: typeof stored.autoOpen === 'boolean' ? stored.autoOpen : DEFAULT_SETTINGS.autoOpen,
    theme: stored.theme === 'light' || stored.theme === 'dark' || stored.theme === 'system' ? stored.theme : DEFAULT_SETTINGS.theme,
    copyTotp: stored.copyTotp === true,
    clearClipboardSeconds: typeof stored.clearClipboardSeconds === 'number' && stored.clearClipboardSeconds >= 30 && stored.clearClipboardSeconds <= 300
      ? Math.round(stored.clearClipboardSeconds) : DEFAULT_SETTINGS.clearClipboardSeconds,
    autoSubmit: typeof stored.autoSubmit === 'boolean' ? stored.autoSubmit : DEFAULT_SETTINGS.autoSubmit,
    suppressFormHistory: typeof stored.suppressFormHistory === 'boolean' ? stored.suppressFormHistory : DEFAULT_SETTINGS.suppressFormHistory,
  };
}

export async function readSettings(storage: SettingsStorage | undefined) {
  try { return parseSettings((await storage?.local?.get(KEY))?.[KEY]); } catch { return { ...DEFAULT_SETTINGS }; }
}

// Writes run one after another so quick changes to different settings cannot overwrite each other.
let writing: Promise<unknown> = Promise.resolve();
export function writeSettings(storage: SettingsStorage | undefined, change: Partial<Settings>): Promise<Settings> {
  const next = writing.catch(() => {}).then(async () => {
    const merged = { ...await readSettings(storage), ...change };
    await storage?.local?.set({ [KEY]: merged });
    return merged;
  });
  writing = next;
  return next;
}

/** Calls back with the current settings now and after every change; returns an unsubscribe function. */
export function watchSettings(storage: SettingsStorage | undefined, callback: (settings: Settings) => void) {
  let live = true;
  const listener = (changes: Record<string, { newValue?: unknown }>, area: string) => {
    if (live && area === 'local' && KEY in changes) callback(parseSettings(changes[KEY]!.newValue));
  };
  storage?.onChanged?.addListener(listener);
  void readSettings(storage).then(settings => { if (live) callback(settings); });
  return () => { live = false; storage?.onChanged?.removeListener(listener); };
}

/** Applies the theme to an extension page; `system` leaves it to prefers-color-scheme. */
export function applyTheme(element: HTMLElement, theme: Theme) {
  if (theme === 'system') delete element.dataset.theme; else element.dataset.theme = theme;
}
