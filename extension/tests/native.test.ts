import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
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
  /** Status requests wait here until a test answers them. */
  heldStatus: Array<Request & { id: string }> | undefined;
  status: Record<string, unknown> = {};
  postMessage(message: Request & { id: string }) {
    this.messages.push(message);
    const pairing_id = '11111111-1111-4111-8111-111111111111';
    let reply: Response | undefined;
    if (message.type === 'Hello') reply = { type: 'Challenge', paired: false, pairing_id, nonce: 'A'.repeat(43) };
    if (message.type === 'RequestPairing') reply = { type: 'Paired', pairing_id };
    if (message.type === 'Status' && this.heldStatus) { this.heldStatus.push(message); return; }
    if (message.type === 'Status') reply = { type: 'Status', enabled: true, unlocked: true, epoch: 1, ...this.status } as Response;
    if (message.type === 'ListMatches' && !this.hold) reply = { type: 'Matches', items: [], epoch: 1, next_offset: null };
    if (message.type === 'Cancel') reply = { type: 'Cancelled', request_id: message.request_id };
    if (reply) queueMicrotask(() => this.emit({ version: 1, id: message.id, ...reply }));
  }
  emit(message: unknown) { for (const listener of this.listeners) listener(message); }
  disconnect() { for (const callback of this.disconnects) callback(); }
}
beforeEach(() => vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] }));
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

const releases = JSON.parse(readFileSync(new URL('../protocol/fixtures/status-releases.json', import.meta.url), 'utf8')).releases;
describe('release metadata on the native connection', () => {
  it('keeps validated release metadata across lock and unlock, and clears it on disconnect', async () => {
    const { client, ports } = setup(); await client.pair('Test');
    expect(client.releases).toEqual({ receivedAt: expect.any(Number), revision: 1 });
    ports.at(-1)!.status = { desktop_version: '1.0.0-rc.5', releases };
    await client.refreshStatus();
    const metadata = client.releases;
    expect(metadata?.releases?.desktop.offer?.version).toBe('1.0.0');
    ports.at(-1)!.emit({ version: 1, type: 'Locked', epoch: 2 });
    ports.at(-1)!.emit({ version: 1, type: 'Unlocked', epoch: 3 });
    expect(client.releases).toBe(metadata);
    // An unchanged answer keeps the same object, so listeners see no change.
    await client.refreshStatus(); expect(client.releases).toBe(metadata);
    ports.at(-1)!.disconnect();
    expect(client.releases).toBeUndefined();
  });
  it('clears release metadata when pairing is revoked and does not read it while unpaired', async () => {
    const { client, ports } = setup(); await client.pair('Test');
    ports.at(-1)!.status = { releases }; await client.refreshStatus();
    expect(client.releases?.releases).toBeDefined();
    ports.at(-1)!.emit({ version: 1, type: 'PairingRevoked' });
    expect(client.releases).toBeUndefined();
    await client.refreshStatus(true);
    expect(client.releases).toBeUndefined();
    expect(ports.at(-1)!.messages.filter(value => value.type === 'Status')).toHaveLength(2);
  });
  it('keeps the connection usable when release metadata is malformed', async () => {
    const { client, ports } = setup(); await client.pair('Test');
    ports.at(-1)!.status = { desktop_version: 7, releases: { state: 'fresh', desktop: 'bad' } };
    await client.refreshStatus();
    expect(client.snapshot.state).toBe('ready');
    expect(client.releases).toEqual({ invalid: true, receivedAt: expect.any(Number), revision: expect.any(Number) });
  });
  it('sends check_updates only for an explicit check', async () => {
    const { client, ports } = setup(); await client.pair('Test');
    await client.refreshStatus(); await client.refreshStatus(true);
    const statuses = ports.at(-1)!.messages.filter(value => value.type === 'Status');
    expect(statuses.map(value => 'check_updates' in value ? value.check_updates : undefined)).toEqual([undefined, undefined, true]);
  });
});

describe('serialized Status requests', () => {
  const fresh = { ...releases, state: 'fresh' };
  const answer = (port: MockPort, extra: Record<string, unknown>) => {
    const request = port.heldStatus!.shift()!;
    port.emit({ version: 1, id: request.id, type: 'Status', enabled: true, unlocked: true, epoch: 1, ...extra });
  };
  const settle = async () => { for (let i = 0; i < 5; i++) await Promise.resolve(); };
  it('bounds the queue and expires unsent requests instead of replaying a backlog', async () => {
    const { client, ports } = setup(); await client.pair('Test');
    const port = ports.at(-1)!; port.heldStatus = [];
    const results = Promise.all(Array.from({ length: 40 }, (_, index) => client.refreshStatus(index === 1)
      .then(() => 'answered', error => error.code)));
    await settle();
    expect(port.heldStatus).toHaveLength(1);
    // Status waiting does not block unrelated requests, such as listing matching logins.
    await expect(client.request(list)).resolves.toMatchObject({ type: 'Matches' });
    await vi.advanceTimersByTimeAsync(10_000);
    const errors = await results;
    expect(errors.filter(code => code === 'Busy')).toHaveLength(8);
    expect(errors.filter(code => code === 'Timeout')).toHaveLength(32);
    expect(port.heldStatus).toHaveLength(1);
    expect(port.messages.some(value => value.type === 'Status' && 'check_updates' in value)).toBe(false);
    expect(client.snapshot.state).toBe('ready');
    // Neither a late timed-out answer nor its queued manual check may change the state.
    answer(port, { unlocked: false, epoch: 99, releases: fresh });
    expect(client.snapshot).toMatchObject({ state: 'ready', epoch: 1 });
    expect(client.releases?.failed).toBe(true);
    port.heldStatus = undefined;
    await client.refreshStatus(true);
    expect(client.releases?.failed).toBeUndefined();
    expect(port.messages.at(-1)).toMatchObject({ type: 'Status', check_updates: true });
  });
  it('includes queue time in the timeout of a manual check sent after a passive read', async () => {
    const { client, ports } = setup(); await client.pair('Test');
    const port = ports.at(-1)!; port.heldStatus = [];
    const passive = client.refreshStatus();
    await vi.advanceTimersByTimeAsync(1000);
    let finished = false;
    const manual = expect(client.refreshStatus(true).finally(() => { finished = true; }))
      .rejects.toMatchObject({ code: 'Timeout' });
    await vi.advanceTimersByTimeAsync(8000);
    answer(port, { releases: fresh }); await passive; await settle();
    expect(port.heldStatus).toHaveLength(1);
    expect(port.heldStatus[0]).toMatchObject({ type: 'Status', check_updates: true });
    await vi.advanceTimersByTimeAsync(1999);
    expect(finished).toBe(false);
    await vi.advanceTimersByTimeAsync(1); await manual;
    expect(finished).toBe(true);
  });
  it('sends a manual check only after an earlier passive Status was answered', async () => {
    const { client, ports } = setup(); await client.pair('Test');
    const port = ports.at(-1)!; port.heldStatus = [];
    const passive = client.refreshStatus();
    const manual = client.refreshStatus(true);
    await settle();
    expect(port.heldStatus.map(value => 'check_updates' in value)).toEqual([false]);
    // The older passive answer still says fresh; the manual check has not been sent yet.
    answer(port, { releases: fresh }); await passive; await settle();
    expect(client.releases?.releases?.state).toBe('fresh');
    expect(port.heldStatus.map(value => (value as { check_updates?: boolean }).check_updates)).toEqual([true]);
    answer(port, { releases: { ...releases, state: 'checking' } }); await manual;
    expect(client.releases?.releases?.state).toBe('checking');
    // A later poll sees the completed check.
    const poll = client.refreshStatus(); await settle();
    answer(port, { releases: fresh }); await poll;
    expect(client.releases?.releases?.state).toBe('fresh');
  });
  it('drops queued requests when the connection closes and never sends them to a new host', async () => {
    const { client, ports } = setup(); await client.pair('Test');
    const port = ports.at(-1)!; port.heldStatus = [];
    const passive = expect(client.refreshStatus()).rejects.toMatchObject({ code: 'Disconnected' });
    const manual = expect(client.refreshStatus(true)).rejects.toMatchObject({ code: 'Disconnected' });
    await settle();
    port.disconnect(); await passive; await manual;
    // A late answer from the old port changes nothing.
    port.emit({ version: 1, id: 'late', type: 'Status', enabled: true, unlocked: false, epoch: 9, releases: fresh });
    expect(client.releases).toBeUndefined(); expect(client.snapshot.state).toBe('disconnected');
    await vi.advanceTimersByTimeAsync(1000);
    expect(ports.length).toBeGreaterThan(2);
    for (const later of ports.slice(ports.indexOf(port) + 1)) {
      expect(later.messages.some(value => value.type === 'Status' && 'check_updates' in value)).toBe(false);
    }
  });
  it('withdraws currentness when a Status request fails, keeps known releases, and recovers', async () => {
    const { client, ports } = setup(); await client.pair('Test');
    const port = ports.at(-1)!;
    port.status = { releases: fresh }; await client.refreshStatus();
    const before = client.releases!;
    const changed = vi.fn(); client.onChange = changed;
    port.heldStatus = [];
    const failing = expect(client.refreshStatus(true)).rejects.toMatchObject({ code: 'Busy' });
    await settle();
    const request = port.heldStatus.shift()!;
    port.emit({ version: 1, id: request.id, type: 'Error', code: 'Busy', message: 'Busy.' });
    await failing;
    expect(client.snapshot.state).toBe('ready');
    expect(client.releases).toMatchObject({ failed: true, receivedAt: before.receivedAt, releases: before.releases });
    expect(client.releases!.revision).toBeGreaterThan(before.revision);
    expect(changed).toHaveBeenCalledWith(client.snapshot);
    // A timeout counts as a failure too, and the next answer clears it.
    const timeout = expect(client.refreshStatus()).rejects.toMatchObject({ code: 'Timeout' });
    await settle(); await vi.advanceTimersByTimeAsync(10_000); await timeout;
    expect(client.releases?.failed).toBe(true);
    port.heldStatus = undefined;
    await client.refreshStatus();
    expect(client.releases?.failed).toBeUndefined();
    expect(client.snapshot.state).toBe('ready');
  });
});
