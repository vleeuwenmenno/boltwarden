import { expect, it, vi } from 'vitest';
import { pendingSaves } from '../lib/pending-saves';
import { NativeError } from '../lib/protocol';
import type { NativeClient } from '../lib/native';
function fixture(state = 'locked') {
  let data: Record<string, any> = {};
  const storage = { get: async () => structuredClone(data), set: async (next: Record<string, unknown>) => { data = structuredClone(next); } };
  const native = { snapshot: { state, epoch: 1 }, connect: vi.fn(async () => {}), request: vi.fn(async (request: any): Promise<any> =>
    request.type === 'SaveLogin' ? { type: 'LoginSaved', saved: true } : { type: 'UnlockRequested' }) };
  const notice = vi.fn();
  const create = () => pendingSaves(native as unknown as NativeClient, storage, vi.fn(), notice);
  return { native, storage, notice, create, queue: create() };
}
const login = { username: 'alice', password: 'generated-test-secret' };
it('retains a submitted password while locked and resumes with identical credentials after unlock', async () => {
  const { queue, native, storage } = fixture();
  await queue.add(1, 'https://example.test/register', 'document', login);
  expect(native.request.mock.calls.map(([request]) => request.type)).toEqual(['RequestUnlock']);
  expect(JSON.stringify(await queue.list())).not.toContain(login.password);
  expect(await queue.list()).toHaveLength(1);
  native.snapshot.state = 'ready'; await queue.resume();
  await vi.waitFor(async () => expect(await queue.list()).toHaveLength(0));
  expect(native.request).toHaveBeenLastCalledWith(expect.objectContaining({ type: 'SaveLogin', login }));
  expect(JSON.stringify(await storage.get())).not.toContain(login.password);
});
it('survives service worker replacement and page navigation during unlock', async () => {
  const { queue, create, native } = fixture();
  await queue.add(1, 'https://example.test/register', 'old-document', login);
  const restored = create(); native.snapshot.state = 'ready'; await restored.resume();
  await vi.waitFor(async () => expect(await restored.list()).toHaveLength(0));
  expect(native.request).toHaveBeenLastCalledWith(expect.objectContaining({ top_url: 'https://example.test/register', document_id: 'old-document', login }));
});
it('retains failures and denied approvals for explicit retry or discard', async () => {
  const { queue, native, storage } = fixture('ready');
  native.request.mockRejectedValueOnce(new NativeError('Cancelled', 'Save cancelled.'));
  await queue.add(1, 'https://example.test/', 'document', login);
  const [pending] = await queue.list(); expect(pending?.message).toContain('retained');
  await queue.retry(pending!.id); expect(await queue.list()).toHaveLength(0);
  native.request.mockRejectedValueOnce(new Error('Offline'));
  await queue.add(1, 'https://example.test/', 'document', login);
  await queue.discard((await queue.list())[0]!.id);
  expect(await queue.list()).toHaveLength(0);
  expect(JSON.stringify(await storage.get())).not.toContain(login.password);
});
it('deduplicates pending captures and never runs duplicate concurrent saves', async () => {
  const { queue, native } = fixture();
  await queue.add(1, 'https://example.test/', 'document', login);
  await queue.add(1, 'https://example.test/', 'document', login);
  expect(await queue.list()).toHaveLength(1);
  let finish!: (value: any) => void;
  native.snapshot.state = 'ready'; native.request.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const id = (await queue.list())[0]!.id;
  const saving = queue.retry(id); await vi.waitFor(() => expect(finish).toBeTypeOf('function'));
  await queue.retry(id);
  await expect(queue.discard(id)).rejects.toThrow(/Wait/);
  finish({ type: 'LoginSaved', saved: true }); await saving;
  expect(native.request).toHaveBeenCalledTimes(2);
});
it('keeps failed discards visible and retryable until session storage confirms removal', async () => {
  const { queue, storage, create } = fixture();
  await queue.add(1, 'https://example.test/', 'document', login);
  const id = (await queue.list())[0]!.id;
  const set = vi.spyOn(storage, 'set').mockRejectedValueOnce(new Error('Storage unavailable'));
  await expect(queue.discard(id)).rejects.toThrow(/could not be discarded/);
  expect((await queue.list())[0]?.id).toBe(id);
  expect(JSON.stringify(await storage.get())).toContain(login.password);
  set.mockRestore(); await queue.discard(id);
  expect(await create().list()).toHaveLength(0);
});
it('retries cleanup after a successful vault save without resubmitting credentials', async () => {
  const { queue, native, storage } = fixture('ready');
  const set = storage.set;
  vi.spyOn(storage, 'set').mockImplementation(async next => {
    if ((next.pending_password_saves as any[]).length === 0) throw new Error('Removal failed');
    await set(next);
  });
  await queue.add(1, 'https://example.test/', 'document', login);
  const [entry] = await queue.list(); expect(entry?.message).toContain('temporary copy');
  vi.restoreAllMocks(); await queue.retry(entry!.id);
  expect(native.request).toHaveBeenCalledTimes(1); expect(await queue.list()).toHaveLength(0);
});
it('does not overwrite unread session data when loading fails', async () => {
  const { queue, create, storage, native } = fixture();
  await queue.add(1, 'https://example.test/first', 'document', login);
  const restored = create();
  const get = vi.spyOn(storage, 'get').mockRejectedValue(new Error('Read failed'));
  const set = vi.spyOn(storage, 'set');
  await restored.add(2, 'https://example.test/second', 'second', { username: 'bob', password: 'second-secret' });
  expect(set).not.toHaveBeenCalled(); expect(native.request).toHaveBeenCalledTimes(1);
  const [entry] = await restored.list(); expect(entry?.message).toContain('background restart');
  get.mockRestore(); await restored.retry(entry!.id);
  expect(await restored.list()).toHaveLength(2);
});
it('does not resurrect discarded credentials during a concurrent save', async () => {
  const { queue, storage, create } = fixture();
  await queue.add(1, 'https://example.test/first', 'document', login);
  const id = (await queue.list())[0]!.id;
  const set = storage.set;
  let finish!: () => void;
  vi.spyOn(storage, 'set').mockImplementationOnce(async next => { await new Promise<void>(resolve => { finish = resolve; }); await set(next); });
  const discard = queue.discard(id);
  await vi.waitFor(() => expect(finish).toBeTypeOf('function'));
  const add = queue.add(2, 'https://example.test/second', 'second', { username: 'bob', password: 'second-secret' });
  finish(); await Promise.all([discard, add]);
  expect(await create().list()).toHaveLength(1);
  expect(JSON.stringify(await storage.get())).not.toContain(login.password);
});
it('says nothing when the vault already had the submitted login', async () => {
  const { queue, native, notice } = fixture('ready');
  native.request.mockResolvedValueOnce({ type: 'LoginSaved', saved: false });
  await queue.add(1, 'https://example.test/login', 'document', login);
  await vi.waitFor(async () => expect(await queue.list()).toHaveLength(0));
  expect(notice).not.toHaveBeenCalledWith(expect.anything(), 'Password saved in Boltwarden.');
});
it('confirms a real save', async () => {
  const { queue, notice } = fixture('ready');
  await queue.add(1, 'https://example.test/login', 'document', login);
  await vi.waitFor(() => expect(notice).toHaveBeenCalledWith(expect.anything(), 'Password saved in Boltwarden.'));
});
