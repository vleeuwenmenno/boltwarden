#!/usr/bin/env node
/**
 * Independent verifier for the public synthetic Rust WebAuthn test artifact.
 * Uses only Node's OpenSSL-backed crypto and a small CBOR reader, not Boltwarden
 * encoders or verification code. No vault, browser profile, or network access.
 *
 * BOLTWARDEN_PASSKEY_TEST_OUTPUT=/tmp/boltwarden-passkey-interop.json \
 *   cargo test passkeys::tests::generated_credential_registers_and_signs_with_verifiable_public_key
 * node scripts/test-passkey-interop.mjs /tmp/boltwarden-passkey-interop.json
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPrivateKey, createPublicKey, verify, webcrypto } from 'node:crypto';

const artifact = JSON.parse(readFileSync(process.argv[2] ?? '/tmp/boltwarden-passkey-interop.json', 'utf8'));
const hash = bytes => createHash('sha256').update(bytes).digest();
function binary(value) {
  assert.equal(typeof value, 'string');
  assert.match(value, /^[A-Za-z0-9_-]+$/);
  const bytes = Buffer.from(value, 'base64url');
  assert.equal(bytes.toString('base64url'), value, 'canonical unpadded base64url');
  return bytes;
}

/** Return one CBOR value plus its ending offset; reject indefinite lengths/tags. */
function cbor(bytes, start = 0) {
  let offset = start;
  const take = length => {
    assert.ok(offset + length <= bytes.length, 'CBOR does not run beyond input');
    const value = bytes.subarray(offset, offset + length);
    offset += length;
    return value;
  };
  const byte = take(1)[0];
  const major = byte >> 5;
  const additional = byte & 31;
  let length;
  if (additional < 24) length = additional;
  else if (additional === 24) length = take(1)[0];
  else if (additional === 25) length = take(2).readUInt16BE();
  else if (additional === 26) length = take(4).readUInt32BE();
  else throw new Error('Unsupported CBOR length or indefinite item');
  assert.ok(length <= 65536, 'bounded synthetic CBOR');
  let value;
  if (major === 0) value = length;
  else if (major === 1) value = -1 - length;
  else if (major === 2) value = take(length);
  else if (major === 3) value = new TextDecoder('utf-8', { fatal: true }).decode(take(length));
  else if (major === 5) {
    value = new Map();
    for (let index = 0; index < length; index++) {
      const [key, keyEnd] = cbor(bytes, offset);
      const [entry, entryEnd] = cbor(bytes, keyEnd);
      assert.ok(!value.has(key), 'duplicate CBOR map key');
      value.set(key, entry);
      offset = entryEnd;
    }
  } else throw new Error(`Unexpected CBOR major type ${major}`);
  return [value, offset];
}

function clientData(response, type) {
  const bytes = binary(response.client_data_json);
  const data = JSON.parse(bytes.toString('utf8'));
  assert.equal(data.type, type);
  assert.equal(data.origin, 'https://example.com');
  assert.equal(data.crossOrigin, false);
  assert.ok(!Object.hasOwn(data, 'topOrigin'));
  assert.ok(binary(data.challenge).length > 0);
  return { bytes, data };
}

async function verifyCeremony(artifact, userVerified) {
  const { registration, assertion } = artifact;
  const createClient = clientData(registration, 'webauthn.create');
  assert.equal(registration.kind, 'create');
  assert.equal(registration.public_key_algorithm, -7);
  assert.equal(registration.cred_props, true);
  assert.deepEqual(registration.transports, ['internal']);
  const id = binary(registration.credential_id);
  assert.equal(id.length, 16);
  assert.equal(id[6] >> 4, 4, 'random UUID version');
  assert.equal(id[8] & 0xc0, 0x80, 'UUID variant');
  const auth = binary(registration.authenticator_data);
  assert.deepEqual(auth.subarray(0, 32), hash(Buffer.from('example.com')));
  assert.equal(auth[32], 0x59 | (userVerified ? 0x04 : 0), 'creation: UP, BE, BS, AT, plus UV only after verification');
  assert.equal(auth.readUInt32BE(33), 0, 'new credential uses the zero-counter profile');
  assert.deepEqual(auth.subarray(37, 53), Buffer.alloc(16), 'none-attestation AAGUID');
  const credentialLength = auth.readUInt16BE(53);
  assert.deepEqual(auth.subarray(55, 55 + credentialLength), id);
  const [cose, coseEnd] = cbor(auth, 55 + credentialLength);
  assert.equal(coseEnd, auth.length, 'no unparsed authenticator data');
  assert.equal(cose.size, 5);
  assert.equal(cose.get(1), 2, 'EC2');
  assert.equal(cose.get(3), -7, 'ES256');
  assert.equal(cose.get(-1), 1, 'P-256');
  assert.equal(cose.get(-2).length, 32);
  assert.equal(cose.get(-3).length, 32);
  const fromCose = createPublicKey({
    format: 'jwk',
    key: { kty: 'EC', crv: 'P-256', x: cose.get(-2).toString('base64url'), y: cose.get(-3).toString('base64url') },
  });
  const spki = binary(registration.public_key);
  assert.deepEqual(fromCose.export({ format: 'der', type: 'spki' }), spki, 'COSE and SPKI describe the same public key');
  const publicKey = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  assert.equal(publicKey.asymmetricKeyDetails.namedCurve, 'prime256v1');
  const attestationBytes = binary(registration.attestation_object);
  const [attestation, attestationEnd] = cbor(attestationBytes);
  assert.equal(attestationEnd, attestationBytes.length);
  assert.equal(attestation.size, 3);
  assert.equal(attestation.get('fmt'), 'none');
  assert.equal(attestation.get('attStmt').size, 0);
  assert.deepEqual(attestation.get('authData'), auth);

  assert.equal(assertion.kind, 'get');
  assert.deepEqual(binary(assertion.credential_id), id);
  assert.deepEqual(binary(assertion.user_handle), Buffer.from('account id'));
  const getClient = clientData(assertion, 'webauthn.get');
  assert.equal(getClient.data.challenge, createClient.data.challenge, 'the synthetic test reuses its challenge');
  const getAuth = binary(assertion.authenticator_data);
  assert.equal(getAuth.length, 37);
  assert.deepEqual(getAuth.subarray(0, 32), hash(Buffer.from('example.com')));
  assert.equal(getAuth[32], 0x19 | (userVerified ? 0x04 : 0), 'assertion: UP, BE, BS, plus UV only after verification');
  assert.equal(getAuth.readUInt32BE(33), 0);
  const signed = Buffer.concat([getAuth, hash(getClient.bytes)]);
  const signature = binary(assertion.signature);
  assert.equal(signature[0], 0x30, 'ASN.1 DER ECDSA sequence, not raw r||s');
  assert.equal(signature[1], signature.length - 2);
  assert.ok(verify('sha256', signed, publicKey, signature), 'OpenSSL verifies Rust assertion DER');
  const tampered = Buffer.from(signed);
  tampered[0] ^= 1;
  assert.equal(verify('sha256', tampered, publicKey, signature), false, 'changed RP hash fails');
  const changedVerification = Buffer.from(signed);
  changedVerification[32] ^= 0x04;
  assert.equal(verify('sha256', changedVerification, publicKey, signature), false, 'changed UV flag fails');
  const changedChallenge = Buffer.from(JSON.stringify({ ...getClient.data, challenge: 'dGFtcGVyZWQ' }));
  assert.equal(verify('sha256', Buffer.concat([getAuth, hash(changedChallenge)]), publicKey, signature), false, 'changed challenge fails');

  // Optional test-only synthetic private material proves the reverse storage path:
  // WebCrypto, as used by the official Bitwarden client, imports Rust's PKCS#8.
  if (artifact.pkcs8_der !== undefined) {
    assert.equal(artifact.synthetic_test_fixture, true, 'private material is explicitly marked synthetic');
    const der = binary(artifact.pkcs8_der);
    const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    assert.deepEqual(createPublicKey(privateKey).export({ format: 'der', type: 'spki' }), spki);
    const webKey = await webcrypto.subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const p1363 = Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, webKey, signed));
    assert.equal(p1363.length, 64);
    assert.ok(verify('sha256', signed, { key: publicKey, dsaEncoding: 'ieee-p1363' }, p1363));
    console.log('PASS: Rust PKCS#8 imports in OpenSSL and WebCrypto; public key and signatures agree.');
  }
  console.log(`PASS (${userVerified ? 'verified' : 'approval only'}): none attestation, CBOR/COSE, SPKI, RP/client binding, flags, zero counter, DER signature, and tamper rejection.`);
}

await verifyCeremony(artifact, true);
assert.ok(artifact.approval_only_registration && artifact.approval_only_assertion, 'approval-only fixture is present');
await verifyCeremony({
  registration: artifact.approval_only_registration,
  assertion: artifact.approval_only_assertion,
}, false);
