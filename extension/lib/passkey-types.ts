export type Verification = 'required' | 'preferred' | 'discouraged';
export interface Descriptor { type: 'public-key'; id: string; transports?: string[] }
export interface GetOptions {
  challenge: string; rp_id?: string; allow_credentials: Descriptor[];
  user_verification: Verification; timeout_ms: number;
}
export interface CreateOptions {
  challenge: string; rp: { id?: string; name: string }; user: { id: string; name: string; display_name: string };
  pub_key_cred_params: { type: 'public-key'; alg: number }[]; exclude_credentials: Descriptor[];
  resident_key: Verification; user_verification: Verification; cred_props: boolean; timeout_ms: number;
}
export type PasskeyOperation = { kind: 'get'; options: GetOptions } | { kind: 'create'; options: CreateOptions };
export interface PasskeyResult {
  type: 'PasskeyResult'; kind: 'get' | 'create'; credential_id: string; client_data_json: string;
  authenticator_data: string; signature?: string; user_handle?: string | null;
  attestation_object?: string; public_key?: string; public_key_algorithm?: number;
  transports?: string[]; cred_props?: boolean; document_id: string; epoch: number;
}
export const PASSKEY_CHANNEL = 'boltwarden-webauthn-v1';
export const PASSKEY_PORT = 'boltwarden-passkeys-v1';
// Keep synchronized with src/passkeys.rs; leave room in the 256 KiB native frame.
export const MAX_CHALLENGE_BYTES = 65_536;
export const MAX_CHALLENGE_ENCODED = Math.ceil(MAX_CHALLENGE_BYTES * 4 / 3);
export const MAX_CLIENT_DATA_ENCODED = 131_072;
export const MAX_TIMEOUT = 60_000;
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = (value: unknown, limit = 1024): value is string => typeof value === 'string' && value.length <= limit;
const verification = (value: unknown): value is Verification => ['required', 'preferred', 'discouraged'].includes(String(value));
export const binary = (value: unknown, maximum = 131_072, minimum = 1): value is string => text(value, maximum)
  && value.length >= minimum && value.length % 4 !== 1 && /^[A-Za-z0-9_-]*$/.test(value);
const descriptor = (value: unknown): value is Descriptor => object(value) && value.type === 'public-key' && binary(value.id, 1400)
  && (value.transports === undefined || (Array.isArray(value.transports) && value.transports.length <= 8 && value.transports.every(item => text(item, 32))));
const descriptors = (value: unknown) => Array.isArray(value) && value.length <= 64 && value.every(descriptor);

/** Main-world input is untrusted even after its first serialization. */
export function isOperation(value: unknown): value is PasskeyOperation {
  if (!object(value) || !object(value.options)) return false;
  const options = value.options;
  if (!binary(options.challenge, MAX_CHALLENGE_ENCODED) || !verification(options.user_verification)
    || !Number.isSafeInteger(options.timeout_ms) || Number(options.timeout_ms) < 1000 || Number(options.timeout_ms) > MAX_TIMEOUT) return false;
  if (value.kind === 'get') return (options.rp_id === undefined || text(options.rp_id, 253)) && descriptors(options.allow_credentials);
  return value.kind === 'create' && object(options.rp) && text(options.rp.name)
    && (options.rp.id === undefined || text(options.rp.id, 253)) && object(options.user)
    && binary(options.user.id, 86) && text(options.user.name) && text(options.user.display_name)
    && Array.isArray(options.pub_key_cred_params) && options.pub_key_cred_params.length > 0 && options.pub_key_cred_params.length <= 32
    && options.pub_key_cred_params.every(param => object(param) && param.type === 'public-key' && Number.isSafeInteger(param.alg))
    && options.pub_key_cred_params.some(param => param.alg === -7)
    && descriptors(options.exclude_credentials) && verification(options.resident_key) && typeof options.cred_props === 'boolean';
}

export function isPasskeyResult(value: unknown): value is PasskeyResult {
  if (!object(value) || value.type !== 'PasskeyResult' || !binary(value.credential_id, 1400)
    || !binary(value.client_data_json, MAX_CLIENT_DATA_ENCODED) || !binary(value.authenticator_data, 16_384)
    || !text(value.document_id, 128) || !Number.isSafeInteger(value.epoch) || Number(value.epoch) < 0) return false;
  if (value.kind === 'get') return binary(value.signature, 512)
    && (value.user_handle === null || value.user_handle === undefined || binary(value.user_handle, 86));
  return value.kind === 'create' && binary(value.attestation_object, 32_768) && binary(value.public_key, 1400)
    && value.public_key_algorithm === -7 && Array.isArray(value.transports)
    && value.transports.length <= 8 && value.transports.every(item => text(item, 32))
    && (value.cred_props === undefined || typeof value.cred_props === 'boolean');
}

export function encode(bytes: Uint8Array): string {
  let value = '';
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
export function decode(value: string): ArrayBuffer {
  const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), character => character.charCodeAt(0));
  return bytes.buffer;
}
