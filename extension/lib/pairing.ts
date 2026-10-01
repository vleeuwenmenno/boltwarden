export interface Identity { privateKey: CryptoKey; publicKey: CryptoKey }
const DATABASE = 'boltwarden-pairing';

export function base64url(data: ArrayBuffer | Uint8Array): string {
  return btoa(String.fromCharCode(...new Uint8Array(data instanceof Uint8Array ? data : new Uint8Array(data))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => request.result.createObjectStore('keys');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('Cannot open pairing key storage.'));
  });
}

let pendingIdentity: Promise<Identity> | undefined;
export function identity(): Promise<Identity> {
  pendingIdentity ??= loadIdentity().catch(error => { pendingIdentity = undefined; throw error; });
  return pendingIdentity;
}

async function loadIdentity(): Promise<Identity> {
  const db = await database();
  try {
    const existing = await new Promise<Identity | undefined>((resolve, reject) => {
      const request = db.transaction('keys').objectStore('keys').get('identity');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error('Cannot read pairing key.'));
    });
    if (existing) return existing;
    const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction('keys', 'readwrite');
      transaction.objectStore('keys').put(keys, 'identity');
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(new Error('Cannot store pairing key.'));
      transaction.onabort = () => reject(new Error('Pairing key storage was interrupted.'));
    });
    return keys;
  } finally { db.close(); }
}

export function authenticationBytes(nonce: string, pairingId: string, hostPid: number): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`boltwarden-browser-v1\n${nonce}\n${pairingId}\n${hostPid}`);
}

export async function signChallenge(keys: Identity, nonce: string, pairingId: string, hostPid: number): Promise<string> {
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey,
    authenticationBytes(nonce, pairingId, hostPid));
  return base64url(signature);
}

export async function publicIdentity(): Promise<{ spki: string; fingerprint: string }> {
  const keys = await identity();
  const spki = await crypto.subtle.exportKey('spki', keys.publicKey);
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', spki));
  const fingerprint = Array.from(hash, byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase().match(/.{1,4}/g)!.join(':');
  return { spki: base64url(spki), fingerprint };
}
