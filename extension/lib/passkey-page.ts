import { decode, encode, isOperation, isPasskeyResult, MAX_CHALLENGE_BYTES, MAX_TIMEOUT, PASSKEY_CHANNEL, type Descriptor, type PasskeyOperation, type PasskeyResult, type Verification } from './passkey-types';

function buffer(value: BufferSource, maximum: number): string {
  // instanceof rejects genuine ArrayBuffers created in another same-origin realm.
  if (!ArrayBuffer.isView(value)) {
    try { Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength')!.get!.call(value); }
    catch { throw new TypeError('Expected BufferSource'); }
  }
  const bytes = ArrayBuffer.isView(value)
    ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
    : new Uint8Array(value);
  if (!bytes.byteLength || bytes.byteLength > maximum) throw new TypeError(`Unsupported byte length: ${bytes.byteLength} (expected 1..${maximum})`);
  return encode(bytes);
}
function descriptors(values: PublicKeyCredentialDescriptor[] | undefined): Descriptor[] {
  if (values !== undefined && !Array.isArray(values)) throw new TypeError('Expected credential descriptors');
  if ((values?.length ?? 0) > 64) throw new TypeError('Too many credential descriptors');
  return (values ?? []).map(value => ({ type: value.type, id: buffer(value.id, 1023), ...(value.transports ? { transports: [...value.transports] } : {}) }));
}
const verification = (value: string | undefined): Verification => (value ?? 'preferred') as Verification;

/** Unsupported options retain the original native call, including its validation. */
export function normalize(kind: 'get' | 'create', options: CredentialRequestOptions | CredentialCreationOptions | undefined, rejected: (reason: string) => void = () => {}): PasskeyOperation | null {
  const reject = (reason: string) => { rejected(reason); return null; };
  let stage = 'request';
  try {
    if (!options?.publicKey) return reject('no-public-key-options');
    if ('mediation' in options && options.mediation !== undefined && !['optional', 'required'].includes(options.mediation)) return reject('mediation');
    const publicKey = options.publicKey;
    // Hints guide browser UI; they are not authenticator requirements.
    if ('hints' in publicKey && publicKey.hints !== undefined
      && (!Array.isArray(publicKey.hints) || publicKey.hints.some(hint => typeof hint !== 'string'))) return reject('hints');
    const timeout = publicKey.timeout ?? 60_000;
    if (typeof timeout !== 'number' || !Number.isFinite(timeout) || timeout < 0) return reject('timeout');
    stage = 'challenge';
    const common = { challenge: buffer(publicKey.challenge, MAX_CHALLENGE_BYTES), timeout_ms: Math.max(1000, Math.min(Math.floor(timeout), MAX_TIMEOUT)) };
    let operation: PasskeyOperation;
    if (kind === 'get') {
      const request = publicKey as PublicKeyCredentialRequestOptions;
      // Ignore the optional legacy AppID extension for RP-scoped WebAuthn keys.
      // Never substitute AppID for rpId or claim legacy U2F support in the result.
      // If no ordinary credential matches, the original request goes to the browser.
      if (request.extensions && (Object.keys(request.extensions).some(key => key !== 'appid')
        || (request.extensions.appid !== undefined && typeof request.extensions.appid !== 'string'))) return reject('extensions');
      stage = 'allow-credentials';
      operation = { kind, options: { ...common, ...(request.rpId === undefined ? {} : { rp_id: request.rpId }),
        allow_credentials: descriptors(request.allowCredentials), user_verification: verification(request.userVerification) } };
    } else {
      const request = publicKey as PublicKeyCredentialCreationOptions;
      if ((request.attestation !== undefined && request.attestation !== 'none')
        || (request.authenticatorSelection?.authenticatorAttachment !== undefined && request.authenticatorSelection.authenticatorAttachment !== 'platform')
        || (request.extensions && Object.keys(request.extensions).some(key => key !== 'credProps'))) return null;
      const selection = request.authenticatorSelection;
      operation = { kind, options: { ...common, rp: { name: request.rp.name, ...(request.rp.id === undefined ? {} : { id: request.rp.id }) },
        user: { id: buffer(request.user.id, 64), name: request.user.name, display_name: request.user.displayName },
        pub_key_cred_params: request.pubKeyCredParams.map(value => ({ type: value.type, alg: value.alg })),
        exclude_credentials: descriptors(request.excludeCredentials),
        resident_key: selection?.residentKey ?? (selection?.requireResidentKey ? 'required' : 'discouraged'),
        user_verification: verification(selection?.userVerification), cred_props: request.extensions?.credProps === true } };
    }
    return isOperation(operation) ? operation : reject('normalized-options');
  } catch (error) { return reject(`${stage}: ${error instanceof TypeError ? error.message : 'invalid-value'}`); }
}

/** Own methods support normal WebAuthn consumers. Native internal slots cannot
 * be synthesized: native prototype methods called explicitly are unsupported. */
export function credential(result: PasskeyResult): PublicKeyCredential {
  if (!isPasskeyResult(result)) throw new DOMException('Invalid passkey response.', 'UnknownError');
  const rawId = decode(result.credential_id), clientDataJSON = decode(result.client_data_json);
  const authenticatorData = decode(result.authenticator_data);
  const extensions = () => result.kind === 'create' && result.cred_props !== undefined ? { credProps: { rk: result.cred_props } } : {};
  const response = result.kind === 'get'
    ? { clientDataJSON, authenticatorData, signature: decode(result.signature!), userHandle: result.user_handle ? decode(result.user_handle) : null }
    : { clientDataJSON, attestationObject: decode(result.attestation_object!),
      getAuthenticatorData: () => authenticatorData.slice(0), getPublicKey: () => decode(result.public_key!),
      getPublicKeyAlgorithm: () => result.public_key_algorithm!, getTransports: () => [...result.transports!] };
  Object.setPrototypeOf(response, result.kind === 'get' ? AuthenticatorAssertionResponse.prototype : AuthenticatorAttestationResponse.prototype);
  const value = { id: result.credential_id, rawId, type: 'public-key', authenticatorAttachment: 'platform', response,
    getClientExtensionResults: extensions,
    toJSON: () => ({ id: result.credential_id, rawId: encode(new Uint8Array(rawId)), type: 'public-key', authenticatorAttachment: 'platform',
      clientExtensionResults: extensions(), response: result.kind === 'get'
        ? { clientDataJSON: encode(new Uint8Array(clientDataJSON)), authenticatorData: encode(new Uint8Array(authenticatorData)),
          signature: encode(new Uint8Array((response as AuthenticatorAssertionResponse).signature)),
          userHandle: (response as AuthenticatorAssertionResponse).userHandle ? encode(new Uint8Array((response as AuthenticatorAssertionResponse).userHandle!)) : null }
        : { clientDataJSON: encode(new Uint8Array(clientDataJSON)), attestationObject: encode(new Uint8Array((response as AuthenticatorAttestationResponse).attestationObject)),
          authenticatorData: encode(new Uint8Array(authenticatorData)), publicKey: result.public_key, publicKeyAlgorithm: result.public_key_algorithm,
          transports: [...result.transports!] } }),
  };
  return Object.setPrototypeOf(value, PublicKeyCredential.prototype) as PublicKeyCredential;
}

export function installPageBridge() {
  if (!globalThis.isSecureContext || location.protocol !== 'https:' || window.top !== window
    || !globalThis.PublicKeyCredential || !navigator.credentials) return;
  const container = navigator.credentials;
  const native = { get: container.get, create: container.create };
  const request = async (operation: PasskeyOperation, original: CredentialRequestOptions | CredentialCreationOptions): Promise<PublicKeyCredential | null> => {
    if (original.signal?.aborted) throw original.signal.reason ?? new DOMException('The request was aborted.', 'AbortError');
    const channel = new MessageChannel();
    const id = crypto.randomUUID();
    let timer: ReturnType<typeof setTimeout> | undefined, startup: ReturnType<typeof setTimeout> | undefined;
    let abort = () => {};
    try {
      const result = await new Promise<PasskeyResult | 'fallback'>((resolve, reject) => {
        let settled = false;
        const finish = (value: PasskeyResult | 'fallback' | Error, error = false) => {
          if (settled) return;
          settled = true; clearTimeout(timer); clearTimeout(startup);
          if (error) reject(value); else resolve(value as PasskeyResult | 'fallback');
        };
        const cancel = () => { try { channel.port1.postMessage({ type: 'cancel', id }); } catch { /* page gone */ } };
        abort = () => { cancel(); finish(original.signal?.reason ?? new DOMException('The request was aborted.', 'AbortError'), true); };
        original.signal?.addEventListener('abort', abort, { once: true });
        channel.port1.onmessage = ({ data }) => {
          if (!data || data.id !== id) return;
          if (data.type === 'ack') { clearTimeout(startup); return; }
          if (data.type === 'fallback') { console.info('[Boltwarden] Passkey fallback:', typeof data.reason === 'string' ? data.reason : 'bridge-fallback'); finish('fallback'); return; }
          if (data.type === 'result' && isPasskeyResult(data.result) && data.result.kind === operation.kind) { finish(data.result); return; }
          if (data.type === 'error') {
            const name = ['AbortError', 'NotAllowedError', 'SecurityError', 'InvalidStateError', 'NotSupportedError', 'DataError', 'OperationError'].includes(data.name) ? data.name : 'UnknownError';
            finish(new DOMException(typeof data.message === 'string' ? data.message : 'Passkey request failed.', name), true);
          }
        };
        // No relay after extension reload must not permanently replace native WebAuthn.
        startup = setTimeout(() => { console.info('[Boltwarden] Passkey fallback: relay-unavailable'); cancel(); finish('fallback'); }, 1000);
        timer = setTimeout(() => { cancel(); finish(new DOMException('The passkey request timed out.', 'NotAllowedError'), true); }, operation.options.timeout_ms);
        window.postMessage({ source: PASSKEY_CHANNEL, type: 'request', id, ...operation }, location.origin, [channel.port2]);
      });
      if (result === 'fallback') return Reflect.apply(native[operation.kind], container, [original]) as Promise<PublicKeyCredential | null>;
      if (original.signal?.aborted) throw original.signal.reason ?? new DOMException('The request was aborted.', 'AbortError');
      return credential(result);
    } finally {
      clearTimeout(timer); clearTimeout(startup); original.signal?.removeEventListener('abort', abort);
      channel.port1.close(); channel.port2.close();
    }
  };
  function reportUnsupported(kind: 'get' | 'create', options: CredentialRequestOptions | CredentialCreationOptions | undefined, reason: string) {
    if (!options?.publicKey) return;
    // Log option names only. Never log challenges, credential IDs, users, or payloads.
    console.info('[Boltwarden] Passkey fallback: unsupported-options', JSON.stringify({
      kind, reason, mediation: 'mediation' in options ? options.mediation : undefined,
      optionNames: Object.keys(options.publicKey), extensionNames: Object.keys(options.publicKey.extensions ?? {}),
      allowCredentialCount: 'allowCredentials' in options.publicKey ? options.publicKey.allowCredentials?.length : undefined,
      appidType: typeof options.publicKey.extensions?.appid,
      userVerification: 'userVerification' in options.publicKey ? options.publicKey.userVerification : undefined,
    }));
  }
  container.get = function(options) {
    let reason = 'receiver';
    const operation = this === container ? normalize('get', options, value => { reason = value; }) : null;
    if (!operation) reportUnsupported('get', options, reason);
    return operation && options ? request(operation, options) : Reflect.apply(native.get, this, [options]);
  };
  container.create = function(options) {
    let reason = 'receiver';
    const operation = this === container ? normalize('create', options, value => { reason = value; }) : null;
    if (!operation) reportUnsupported('create', options, reason);
    return operation && options ? request(operation, options) : Reflect.apply(native.create, this, [options]);
  };
}
