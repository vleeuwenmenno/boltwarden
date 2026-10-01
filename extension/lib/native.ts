import { identity, publicIdentity, signChallenge } from './pairing';
import { expect, NativeError, parseWire, type Push, type Request, type Response } from './protocol';

export interface NativePort {
  postMessage(message: unknown): void;
  disconnect(): void;
  onMessage: { addListener(callback: (message: unknown) => void): void };
  onDisconnect: { addListener(callback: () => void): void };
}
export interface PairingStorage { read(): Promise<string | undefined>; write(id: string): Promise<void> }
export type ConnectionState = 'disconnected' | 'connecting' | 'unpaired' | 'locked' | 'ready' | 'disabled';
export interface NativeSnapshot { state: ConnectionState; error?: string; epoch: number }
interface Pending { resolve(value: Response): void; reject(error: Error): void; timer: ReturnType<typeof setTimeout>; cleanup(): void }

/** One authenticated port; outstanding requests are never replayed after disconnect. */
export class NativeClient {
  snapshot: NativeSnapshot = { state: 'disconnected', epoch: 0 };
  private port?: NativePort;
  private connecting?: Promise<void>;
  private pairing?: Promise<void>;
  private pending = new Map<string, Pending>();
  private hostPid?: number;
  private hostReady?: { resolve(pid: number): void; reject(error: Error): void };
  private reconnectTimer?: ReturnType<typeof setTimeout>;
  private retries = 0;
  private authenticated = false;
  onChange: (snapshot: NativeSnapshot, event?: Push) => void = () => {};

  constructor(private createPort: () => NativePort, private storage: PairingStorage) {}

  private update(state: ConnectionState, error?: string, epoch = this.snapshot.epoch, event?: Push) {
    this.snapshot = { state, epoch, ...(error ? { error } : {}) };
    this.onChange(this.snapshot, event);
  }

  async connect(): Promise<void> {
    if (this.connecting) return this.connecting;
    if (this.port && this.hostPid) return;
    clearTimeout(this.reconnectTimer);
    const attempt = this.open();
    this.connecting = attempt;
    try { await attempt; } finally { if (this.connecting === attempt) this.connecting = undefined; }
  }

  private async open(): Promise<void> {
    this.update('connecting');
    try {
      const host = new Promise<number>((resolve, reject) => { this.hostReady = { resolve, reject }; });
      const timer = setTimeout(() => this.hostReady?.reject(new NativeError('Timeout', 'Native host did not identify itself.')), 5000);
      try {
        const port = this.createPort();
        this.port = port;
        port.onMessage.addListener(message => { if (this.port === port) this.receive(message); });
        port.onDisconnect.addListener(() => { if (this.port === port) this.disconnected('Cannot reach Boltwarden. Start the desktop app and check browser integration.'); });
        this.hostPid = await host;
      } finally { clearTimeout(timer); this.hostReady = undefined; }
      const pairingId = await this.storage.read();
      const challenge = expect(await this.raw({ type: 'Hello', ...(pairingId ? { pairing_id: pairingId } : {}) }), 'Challenge');
      if (!pairingId || !challenge.paired || challenge.pairing_id !== pairingId) { this.update('unpaired'); return; }
      const sig = await signChallenge(await identity(), challenge.nonce, challenge.pairing_id, this.hostPid);
      const reply = await this.raw({ type: 'Authenticate', pairing_id: pairingId, sig, host_pid: this.hostPid });
      if (reply.type !== 'Authenticated' || reply.pairing_id !== pairingId) throw new NativeError('ProtocolError', 'Invalid authentication response.');
      this.authenticated = true;
      this.retries = 0;
      await this.refreshStatus();
    } catch (error) {
      if (error instanceof NativeError && ['Unpaired', 'Unauthorized'].includes(error.code) && this.port) {
        this.update('unpaired', 'Pairing was revoked or changed. Pair this browser again.');
        return;
      }
      this.disconnected(error instanceof Error ? error.message : 'Native connection failed.');
      throw error;
    }
  }

  async pair(label: string): Promise<void> {
    if (this.pairing) return this.pairing;
    const attempt = this.pairOnce(label);
    this.pairing = attempt;
    try { await attempt; } finally { this.pairing = undefined; }
  }

  private async pairOnce(label: string): Promise<void> {
    await this.connect();
    if (this.authenticated) { await this.refreshStatus(); return; }
    // Unauthenticated daemon connections have a short lifetime. A user may have
    // spent longer reading the fingerprint, so begin approval on a fresh port.
    this.disconnected('Starting a new pairing connection.');
    await this.connect();
    const challenge = expect(await this.raw({ type: 'Hello' }), 'Challenge');
    const keys = await identity();
    const publicKey = await publicIdentity();
    if (!this.hostPid) throw new NativeError('Disconnected', 'Native host disconnected.');
    const sig = await signChallenge(keys, challenge.nonce, challenge.pairing_id, this.hostPid);
    const result = await this.raw({ type: 'RequestPairing', pairing_id: challenge.pairing_id, sig, host_pid: this.hostPid, public_key_spki: publicKey.spki, label: label.slice(0, 80) }, undefined, 65000);
    if (result.type !== 'Paired' || result.pairing_id !== challenge.pairing_id) throw new NativeError('ProtocolError', 'Invalid pairing response.');
    await this.storage.write(result.pairing_id);
    this.authenticated = true;
    this.retries = 0;
    await this.refreshStatus();
  }

  async refreshStatus(): Promise<NativeSnapshot> {
    if (!this.authenticated) return this.snapshot;
    const status = expect(await this.raw({ type: 'Status' }), 'Status');
    this.update(!status.enabled ? 'disabled' : status.unlocked ? 'ready' : 'locked', undefined, status.epoch);
    return this.snapshot;
  }

  async request(request: Request, signal?: AbortSignal): Promise<Response> {
    await this.connect();
    if (!this.authenticated) throw new NativeError('Unpaired', 'Pair this browser with Boltwarden first.');
    return this.raw(request, signal, request.type === 'PasskeyGet' || request.type === 'PasskeyCreate'
      ? request.options.timeout_ms + 1000 : request.type === 'FillLogin' ? 65000 : request.type === 'ListMatches' ? 30000 : 10000);
  }

  private raw(request: Request, signal?: AbortSignal, timeout = 10000): Promise<Response> {
    if (signal?.aborted) return Promise.reject(new NativeError('Cancelled', 'The page changed. Try again.'));
    if (!this.port) return Promise.reject(new NativeError('Disconnected', 'Native host disconnected.'));
    if (this.pending.size >= 32) return Promise.reject(new NativeError('Busy', 'Too many pending browser requests.'));
    const id = crypto.randomUUID();
    return new Promise<Response>((resolve, reject) => {
      const cancel = () => {
        const pending = this.pending.get(id);
        if (!pending) return;
        this.pending.delete(id); clearTimeout(pending.timer); pending.cleanup();
        reject(new NativeError('Cancelled', 'The page changed. Try again.'));
        // Cancellation is best effort; a response from an old document is still discarded locally.
        try { this.port?.postMessage({ version: 1, id: crypto.randomUUID(), type: 'Cancel', request_id: id }); } catch { /* disconnected */ }
      };
      const timer = setTimeout(() => {
        const pending = this.pending.get(id);
        if (!pending) return;
        this.pending.delete(id); pending.cleanup();
        reject(new NativeError('Timeout', 'Boltwarden did not respond in time.'));
        try { this.port?.postMessage({ version: 1, id: crypto.randomUUID(), type: 'Cancel', request_id: id }); } catch { /* disconnected */ }
      }, timeout);
      this.pending.set(id, { resolve, reject, timer, cleanup: () => signal?.removeEventListener('abort', cancel) });
      signal?.addEventListener('abort', cancel, { once: true });
      try { this.port!.postMessage({ version: 1, id, ...request }); }
      catch { cancel(); }
    });
  }

  private receive(value: unknown) {
    try {
      const message = parseWire(value);
      if (message.type === 'HostContext') {
        if (this.hostPid || !this.hostReady) throw new NativeError('ProtocolError', 'Unexpected native host identity.');
        this.hostReady.resolve(message.host_pid); return;
      }
      if (message.id) {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        this.pending.delete(message.id); clearTimeout(pending.timer); pending.cleanup();
        if (message.type === 'Error') pending.reject(new NativeError(message.code, message.message));
        else pending.resolve(message as Response);
        return;
      }
      switch (message.type) {
        case 'Locked': this.update(this.authenticated ? 'locked' : this.snapshot.state, undefined, message.epoch, message); break;
        case 'Unlocked': this.update(this.authenticated ? 'ready' : this.snapshot.state, undefined, message.epoch, message); break;
        case 'MatchesChanged': this.update(this.snapshot.state, undefined, message.epoch, message); break;
        case 'Disabled': this.update('disabled', undefined, this.snapshot.epoch, message); break;
        case 'PairingRevoked': this.authenticated = false; this.update('unpaired', 'Pairing was revoked. Pair again to reconnect.', this.snapshot.epoch, message); break;
        case 'Error': throw new NativeError(message.code, message.message);
        default: throw new NativeError('ProtocolError', 'Unexpected native event.');
      }
    } catch (error) { this.disconnected(error instanceof Error ? error.message : 'Invalid native message.'); }
  }

  private disconnected(message: string) {
    const wasUnpaired = this.snapshot.state === 'unpaired';
    const port = this.port;
    this.port = undefined; this.hostPid = undefined; this.authenticated = false;
    this.hostReady?.reject(new NativeError('Disconnected', message)); this.hostReady = undefined;
    try { port?.disconnect(); } catch { /* already closed */ }
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer); pending.cleanup(); pending.reject(new NativeError('Disconnected', message));
    }
    this.pending.clear(); this.update(wasUnpaired ? 'unpaired' : 'disconnected', wasUnpaired ? 'Select Pair with Boltwarden to start a fresh pairing request.' : message);
    clearTimeout(this.reconnectTimer);
    if (this.retries < 5) {
      const delay = Math.min(1000 * 2 ** this.retries++, 30000);
      this.reconnectTimer = setTimeout(() => { void this.connect().catch(() => {}); }, delay);
    }
  }
}
