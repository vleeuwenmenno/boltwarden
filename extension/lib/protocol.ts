import identities from './browser-identities.json';
import { isPasskeyResult, type GetOptions, type CreateOptions, type PasskeyResult } from './passkey-types';
export const HOST_NAME = identities.host_name;
export const PROTOCOL_VERSION = 1;

export interface Match {
  id: string;
  name: string;
  username: string | null;
  reprompt: boolean;
  requires_confirmation: boolean;
  revision: string;
}

export interface PageContext {
  top_url: string;
  frame_url: string;
  document_id: string;
}

export type Request =
  | { type: 'Hello'; pairing_id?: string }
  | { type: 'Authenticate'; pairing_id: string; sig: string; host_pid: number }
  | { type: 'RequestPairing'; pairing_id: string; sig: string; host_pid: number; public_key_spki: string; label: string }
  | { type: 'Status' }
  | { type: 'RequestUnlock' }
  | ({ type: 'ListMatches' | 'ListTotpMatches'; offset?: number } & PageContext)
  | ({ type: 'FillLogin' | 'FillTotp'; item_id: string; revision: string; interaction: 'shortcut' | 'popup'; confirm_insecure: boolean; confirm_cross_origin: boolean } & PageContext)
  | ({ type: 'SaveLogin'; login: { username: string; password: string } } & PageContext)
  | ({ type: 'PasskeyGet'; options: GetOptions } & PageContext)
  | ({ type: 'PasskeyCreate'; options: CreateOptions } & PageContext)
  | { type: 'Cancel'; request_id: string };

export type Response =
  | PasskeyResult
  | { type: 'Challenge'; nonce: string; pairing_id: string; paired: boolean }
  | { type: 'Authenticated' | 'Paired'; pairing_id: string }
  | { type: 'Status'; enabled: boolean; unlocked: boolean; epoch: number }
  | { type: 'UnlockRequested' }
  | { type: 'LoginSaved'; saved: boolean }
  | { type: 'Matches'; items: Match[]; epoch: number; next_offset: number | null; warning?: string | null }
  | { type: 'Cancelled'; request_id: string }
  | { type: 'Totp'; code: string; expires_at: number; document_id: string; epoch: number }
  | { type: 'Credentials'; username: string; password: string; document_id: string; epoch: number }
  | { type: 'Error'; code: string; message: string };

export type Push =
  | { type: 'HostContext'; host_pid: number }
  | { type: 'Locked' | 'Unlocked' | 'MatchesChanged'; epoch: number }
  | { type: 'Disabled' | 'PairingRevoked' };
export type WireMessage = (Response | Push) & { version: 1; id?: string };

export class NativeError extends Error {
  constructor(public code: string, message: string) { super(message); this.name = 'NativeError'; }
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function text(value: unknown): value is string { return typeof value === 'string'; }
function epoch(value: unknown): value is number { return Number.isSafeInteger(value) && Number(value) >= 0; }
export function isMatch(value: unknown): value is Match {
  return record(value) && text(value.id) && text(value.name) && (value.username === null || text(value.username))
    && typeof value.reprompt === 'boolean' && typeof value.requires_confirmation === 'boolean' && text(value.revision);
}

/** Reject malformed daemon messages before they can become UI or DOM operations. */
export function parseWire(value: unknown): WireMessage {
  if (!record(value) || value.version !== 1 || !text(value.type)
    || (value.id !== undefined && (!text(value.id) || value.id.length > 64))) {
    throw new NativeError('ProtocolError', 'Unsupported or malformed native message.');
  }
  let valid = false;
  switch (value.type) {
    case 'HostContext': valid = epoch(value.host_pid) && Number(value.host_pid) > 0 && value.id === undefined; break;
    case 'Challenge': valid = text(value.nonce) && /^[A-Za-z0-9_-]{43}$/.test(value.nonce) && text(value.pairing_id) && typeof value.paired === 'boolean'; break;
    case 'Authenticated': case 'Paired': valid = text(value.pairing_id); break;
    case 'Status': valid = typeof value.enabled === 'boolean' && typeof value.unlocked === 'boolean' && epoch(value.epoch); break;
    case 'UnlockRequested': valid = true; break;
    case 'LoginSaved': valid = typeof value.saved === 'boolean'; break;
    case 'Matches': valid = Array.isArray(value.items) && value.items.length <= 1000 && value.items.every(isMatch) && epoch(value.epoch) && (value.next_offset === null || epoch(value.next_offset)) && (value.warning === undefined || value.warning === null || text(value.warning)); break;
    case 'Cancelled': valid = text(value.request_id); break;
    case 'Totp': valid = text(value.code) && /^\d{6,10}$/.test(value.code) && epoch(value.expires_at) && text(value.document_id) && epoch(value.epoch); break;
    case 'Credentials': valid = text(value.username) && text(value.password) && text(value.document_id) && epoch(value.epoch); break;
    case 'PasskeyResult': valid = isPasskeyResult(value); break;
    case 'Error': valid = text(value.code) && text(value.message); break;
    case 'Locked': case 'Unlocked': case 'MatchesChanged': valid = epoch(value.epoch) && value.id === undefined; break;
    case 'Disabled': case 'PairingRevoked': valid = value.id === undefined; break;
  }
  if (!valid) throw new NativeError('ProtocolError', 'Invalid native response.');
  return value as WireMessage;
}

export function expect<T extends Response['type']>(response: Response, type: T): Extract<Response, { type: T }> {
  if (response.type !== type) throw new NativeError('ProtocolError', `Expected ${type}.`);
  return response as Extract<Response, { type: T }>;
}

export function webUrl(raw: string): URL | null {
  try {
    const url = new URL(raw);
    return (url.protocol === 'https:' || url.protocol === 'http:') && !url.username && !url.password ? url : null;
  } catch { return null; }
}
