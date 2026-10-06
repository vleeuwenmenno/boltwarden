import { expect, NativeError } from './protocol';
import type { NativeClient } from './native';
export interface PendingSaveSummary { id: string; origin: string; username: string; message: string; busy: boolean }
interface PendingSave { id: string; tabId: number; url: string; documentId: string; login: { username: string; password: string }; waiting: boolean; message: string; saved?: boolean }
interface SessionStorage { get(key: string): Promise<Record<string, any>>; set(values: Record<string, unknown>): Promise<void> }
const key = 'pending_password_saves';
/** Session-only storage survives background suspension, but never persists to disk. */
export function pendingSaves(native: NativeClient, storage: SessionStorage, changed: () => void,
  notice: (entry: { tabId: number; url: string }, message: string) => void) {
  const entries = new Map<string, PendingSave>();
  const busy = new Set<string>();
  let loaded = false, loading: Promise<void> | undefined;
  async function load() {
    if (loaded) return;
    loading ??= storage.get(key).then(data => {
      for (const entry of data[key] ?? []) if (!entries.has(entry.id)) entries.set(entry.id, entry);
      loaded = true;
    });
    try { await loading; } finally { loading = undefined; }
  }
  let writes = Promise.resolve();
  function write(operation: () => Promise<void>) {
    const result = writes.catch(() => {}).then(async () => { await load(); await operation(); });
    writes = result; return result;
  }
  function persist() {
    // Take the snapshot when the queued write runs, not before earlier removals.
    return write(() => storage.set({ [key]: structuredClone([...entries.values()]) }));
  }
  function remove(entry: PendingSave) {
    return write(async () => {
      await storage.set({ [key]: structuredClone([...entries.values()].filter(value => value.id !== entry.id)) });
      // Do not claim deletion or lose the retry handle until storage confirms it.
      entries.delete(entry.id); entry.login.password = ''; entry.login.username = '';
    });
  }
  async function retry(id: string) {
    const entry = entries.get(id);
    if (!entry || busy.has(id)) return;
    busy.add(id); entry.message = 'Waiting for Boltwarden…'; changed();
    try {
      await persist();
      if (entry.saved) { await remove(entry); return; }
      await native.connect();
      if (native.snapshot.state === 'locked') {
        entry.waiting = true; entry.message = 'Unlock Boltwarden to finish saving. Password retained for this browser session.';
        await persist(); changed(); notice(entry, entry.message);
        await native.request({ type: 'RequestUnlock' });
        if ((native.snapshot as { state: string }).state !== 'ready') return;
      }
      entry.waiting = false;
      const result = expect(await native.request({ type: 'SaveLogin', top_url: entry.url, frame_url: entry.url,
        document_id: entry.documentId, login: { ...entry.login } }), 'LoginSaved');
      entry.saved = true;
      await remove(entry);
      // `saved: false` means the vault already had this login (for example right after a fill
      // and submit), so there is nothing to tell the user.
      if (result.saved) notice(entry, 'Password saved in Boltwarden.');
    } catch (error) {
      // A lock may race the request. Retain the same credentials for the next unlock.
      entry.waiting = error instanceof NativeError && error.code === 'Locked';
      entry.message = entry.saved ? 'Password saved, but the temporary copy could not be removed. Retry or discard to finish cleanup.'
        : `${error instanceof Error ? error.message : 'Could not save password.'} Password retained; open Boltwarden’s extension to retry or discard.`;
      notice(entry, entry.message);
    } finally {
      busy.delete(id);
      try { await persist(); } catch { entry.message += ' Session storage unavailable: recovery cannot survive a background restart.'; }
      changed();
    }
  }
  return {
    async add(tabId: number, url: string, documentId: string, login: PendingSave['login']) {
      await load().catch(() => {});
      if ([...entries.values()].some(entry => entry.url === url && entry.login.username === login.username && entry.login.password === login.password)) return;
      const entry: PendingSave = { id: crypto.randomUUID(), tabId, url, documentId, login: { ...login }, waiting: false, message: '' };
      entries.set(entry.id, entry);
      changed();
      await retry(entry.id);
    },
    async list(): Promise<PendingSaveSummary[]> { await load().catch(error => { if (!entries.size) throw error; }); return [...entries.values()].map(entry => ({
      id: entry.id, origin: new URL(entry.url).origin, username: entry.login.username, message: entry.message, busy: busy.has(entry.id),
    })); },
    async retry(id: string) { await load().catch(() => {}); await retry(id); },
    async discard(id: string) {
      await load();
      if (busy.has(id)) throw new Error('Wait for the save request to finish.');
      const entry = entries.get(id); if (!entry) return;
      busy.add(id); changed();
      try { await remove(entry); }
      catch { entry.message = 'Temporary password could not be discarded. Retry discard to remove it.'; throw new Error(entry.message); }
      finally { busy.delete(id); changed(); }
    },
    async resume() { await load(); if (native.snapshot.state === 'ready') for (const entry of entries.values()) if (entry.waiting) void retry(entry.id); },
  };
}
