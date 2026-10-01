import 'fake-indexeddb/auto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NativeClient, type NativePort } from '../lib/native';
import type { Request, Response } from '../lib/protocol';

class MockPort implements NativePort {
  messages: Array<Request & { id: string }> = [];
  listeners: Array<(message: unknown) => void> = [];
  disconnects: Array<() => void> = [];
  onMessage = { addListener: (callback: (message: unknown) => void) => { this.listeners.push(callback); } };
  onDisconnect = { addListener: (callback: () => void) => { this.disconnects.push(callback); } };
  hold = false;
  postMessage(message: Request & { id: string }) {
    this.messages.push(message);
    const pairing_id = '11111111-1111-4111-8111-111111111111';
    let reply: Response | undefined;
    if (message.type === 'Hello') reply = { type: 'Challenge', paired: false, pairing_id, nonce: 'A'.repeat(43) };
    if (message.type === 'RequestPairing') reply = { type: 'Paired', pairing_id };
    if (message.type === 'Status') reply = { type: 'Status', enabled: true, unlocked: true, epoch: 1 };
    if (message.type === 'ListMatches' && !this.hold) reply = { type: 'Matches', items: [], epoch: 1, next_offset: null };
    if (message.type === 'Cancel') reply = { type: 'Cancelled', request_id: message.request_id };
    if (reply) queueMicrotask(() => this.emit({ version: 1, id: message.id, ...reply }));
  }
  emit(message: unknown) { for (const listener of this.listeners) listener(message); }
  disconnect() { for (const callback of this.disconnects) callback(); }
}
beforeEach(() => vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] }));
afterEach(() => vi.useRealTimers());
function setup() {
  const ports: MockPort[] = [];
  const storage = { read: vi.fn(async () => undefined), write: vi.fn(async (_id: string) => {}) };
  const client = new NativeClient(() => {
    const port = new MockPort(); ports.push(port);
    queueMicrotask(() => port.emit({ version: 1, type: 'HostContext', host_pid: 321 }));
    return port;
  }, storage);
  return { client, ports, storage };
}
const list: Request = { type: 'ListMatches', top_url: 'https://example.com', frame_url: 'https://example.com', document_id: 'doc' };

describe('native port lifecycle', () => {
  it('shares one handshake and pairs only after an explicit action', async () => {
    const { client, ports, storage } = setup();
    await Promise.all([client.connect(), client.connect(), client.connect()]);
    expect(ports).toHaveLength(1);
    expect(client.snapshot.state).toBe('unpaired');
    expect(ports.at(-1)!.messages.map(value => value.type)).toEqual(['Hello']);
    await client.pair('Test browser');
    expect(client.snapshot.state).toBe('ready');
    expect(storage.write).toHaveBeenCalledOnce();
    const proof = ports.at(-1)!.messages.find(value => value.type === 'RequestPairing');
    expect(proof).toMatchObject({ host_pid: 321 });
  });
  it('rejects every inflight request on disconnect without replaying it', async () => {
    const { client, ports } = setup(); await client.pair('Test');
    ports.at(-1)!.hold = true;
    const request = client.request(list);
    const rejected = expect(request).rejects.toMatchObject({ code: 'Disconnected' });
    await Promise.resolve(); await Promise.resolve();
    ports.at(-1)!.disconnect(); await rejected;
    await vi.advanceTimersByTimeAsync(1000);
    expect(ports).toHaveLength(3);
    expect(ports.at(-1)!.messages.some(value => value.type === 'ListMatches')).toBe(false);
  });
  it('cancels a daemon request on abort and ignores its late response', async () => {
    const { client, ports } = setup(); await client.pair('Test'); ports.at(-1)!.hold = true;
    const controller = new AbortController();
    const request = client.request(list, controller.signal);
    const rejected = expect(request).rejects.toMatchObject({ code: 'Cancelled' });
    await Promise.resolve(); await Promise.resolve(); controller.abort(); await rejected;
    expect(ports.at(-1)!.messages.at(-1)?.type).toBe('Cancel');
    const original = ports.at(-1)!.messages.find(value => value.type === 'ListMatches')!;
    ports.at(-1)!.emit({ version: 1, id: original.id, type: 'Matches', items: [], epoch: 1, next_offset: null });
    expect(client.snapshot.state).toBe('ready');
  });
  it('allows a 30 second match refresh and cancels on timeout', async () => {
    const { client, ports } = setup(); await client.pair('Test'); ports.at(-1)!.hold = true;
    const request = client.request(list);
    const rejected = expect(request).rejects.toMatchObject({ code: 'Timeout' });
    await vi.advanceTimersByTimeAsync(29999);
    expect(ports.at(-1)!.messages.at(-1)?.type).toBe('ListMatches');
    await vi.advanceTimersByTimeAsync(1); await rejected;
    expect(ports.at(-1)!.messages.at(-1)?.type).toBe('Cancel');
  });
  it('reports cache invalidation without dropping authentication', async () => {
    const { client, ports } = setup(); await client.pair('Test');
    const changed = vi.fn(); client.onChange = changed;
    ports.at(-1)!.emit({ version: 1, type: 'MatchesChanged', epoch: 2 });
    expect(client.snapshot).toMatchObject({ state: 'ready', epoch: 2 });
    expect(changed).toHaveBeenCalledWith(client.snapshot, { version: 1, type: 'MatchesChanged', epoch: 2 });
  });
  it('does not turn an unpaired connection into ready when the vault unlocks', async () => {
    const { client, ports } = setup(); await client.connect();
    ports.at(-1)!.emit({ version: 1, type: 'Unlocked', epoch: 2 });
    expect(client.snapshot).toMatchObject({ state: 'unpaired', epoch: 2 });
    await expect(client.request(list)).rejects.toMatchObject({ code: 'Unpaired' });
  });
});
