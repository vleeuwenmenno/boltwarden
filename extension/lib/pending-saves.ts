import { expect, NativeError } from './protocol';
import type { NativeClient } from './native';
export interface PendingSaveSummary { id: string; origin: string; username: string; message: string; busy: boolean }
interface PendingSave { id: string; tabId: number; url: string; documentId: string; login: { username: string; password: string }; waiting: boolean; message: string }
interface SessionStorage { get(key: string): Promise<Record<string, any>>; set(values: Record<string, unknown>): Promise<void> }
const key = 'pending_password_saves';
/** Session-only storage survives background suspension, but never persists to disk. */
export function pendingSaves(native: NativeClient, storage: SessionStorage, changed: () => void,
  notice: (entry: { tabId: number; url: string }, message: string) => void) {
  const entries = new Map<string, PendingSave>();
  const busy = new Set<string>();
  const ready = storage.get(key).then(data => {
    for (const entry of data[key] ?? []) entries.set(entry.id, entry);
  }).catch(() => {});
  let writes = Promise.resolve();
  function persist() {
    const snapshot = structuredClone([...entries.values()]);
    const write = writes.catch(() => {}).then(() => storage.set({ [key]: snapshot }));
    writes = write; return write;
  }
  async function retry(id: string) {
    await ready;
    const entry = entries.get(id);
    if (!entry || busy.has(id)) return;
    busy.add(id); entry.message = 'Waiting for Boltwarden…'; changed();
    try {
      await native.connect();
      if (native.snapshot.state === 'locked') {
        entry.waiting = true; entry.message = 'Unlock Boltwarden to finish saving. Password retained for this browser session.';
        await persist(); changed(); notice(entry, entry.message);
        await native.request({ type: 'RequestUnlock' });
        if ((native.snapshot as { state: string }).state !== 'ready') return;
      }
      entry.waiting = false;
      expect(await native.request({ type: 'SaveLogin', top_url: entry.url, frame_url: entry.url,
        document_id: entry.documentId, login: { ...entry.login } }), 'LoginSaved');
      entries.delete(id); await persist(); entry.login.password = ''; entry.login.username = '';
      notice(entry, 'Password saved in Boltwarden.');
    } catch (error) {
      // A lock may race the request. Retain the same credentials for the next unlock.
      entry.waiting = error instanceof NativeError && error.code === 'Locked';
      entry.message = `${error instanceof Error ? error.message : 'Could not save password.'} Password retained; open Boltwarden’s extension to retry or discard.`;
      notice(entry, entry.message);
    } finally {
      busy.delete(id); await persist().catch(() => {}); changed();
    }
  }
  return {
    async add(tabId: number, url: string, documentId: string, login: PendingSave['login']) {
      await ready;
      if ([...entries.values()].some(entry => entry.url === url && entry.login.username === login.username && entry.login.password === login.password)) return;
      const entry: PendingSave = { id: crypto.randomUUID(), tabId, url, documentId, login: { ...login }, waiting: false, message: '' };
      entries.set(entry.id, entry);
      await persist().catch(() => {}); changed();
      await retry(entry.id);
    },
    async list(): Promise<PendingSaveSummary[]> { await ready; return [...entries.values()].map(entry => ({
      id: entry.id, origin: new URL(entry.url).origin, username: entry.login.username, message: entry.message, busy: busy.has(entry.id),
    })); },
    retry,
    async discard(id: string) {
      await ready;
      if (busy.has(id)) throw new Error('Wait for the save request to finish.');
      const entry = entries.get(id); if (!entry) return;
      entries.delete(id); await persist(); entry.login.password = ''; entry.login.username = ''; changed();
    },
    async resume() { await ready; if (native.snapshot.state === 'ready') for (const entry of entries.values()) if (entry.waiting) void retry(entry.id); },
  };
}
