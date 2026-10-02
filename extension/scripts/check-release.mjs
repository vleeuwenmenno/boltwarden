// Validate built store artifacts rather than trusting source configuration alone.
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import { createHash } from 'node:crypto';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = async path => JSON.parse(await readFile(resolve(root, path), 'utf8'));
const pkg = await read('package.json');
const ids = await read('lib/browser-identities.json');
const chromeId = createHash('sha256').update(Buffer.from(ids.chrome_public_key, 'base64')).digest('hex')
  .slice(0, 32).replace(/[0-9a-f]/g, char => String.fromCharCode(97 + parseInt(char, 16)));
assert.equal(chromeId, ids.chrome_id, 'Chrome public key and native-host allowlist must agree');
for (const browser of ['chrome', 'firefox']) {
  for (const file of ['LICENSE', 'privacy.html', 'THIRD_PARTY_NOTICES.txt']) {
    assert((await readFile(resolve(root, `.output/${browser}-mv3/${file}`))).length > 0, `Missing or empty ${browser} ${file}`);
  }
  const manifest = await read(`.output/${browser}-mv3/manifest.json`);
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.version, pkg.version);
  assert.deepEqual([...manifest.permissions].sort(), ['nativeMessaging', 'storage', 'webNavigation', 'webRequest'].sort());
  assert.deepEqual([...manifest.host_permissions].sort(), ['http://*/*', 'https://*/*'].sort());
  assert.equal(manifest.externally_connectable, undefined, 'No external privileged messaging');
  assert.equal(manifest.update_url, undefined, 'Store manages updates');
  assert(!JSON.stringify(manifest.content_security_policy ?? {}).includes('unsafe-eval'));
  if (browser === 'firefox') {
    const gecko = manifest.browser_specific_settings.gecko;
    assert.equal(gecko.id, ids.firefox_id);
    assert(Number.parseInt(gecko.strict_min_version) >= 140);
    assert.deepEqual([...gecko.data_collection_permissions.required].sort(),
      ['authenticationInfo', 'personallyIdentifyingInfo', 'browsingActivity', 'websiteContent'].sort());
  } else assert.equal(manifest.key, ids.chrome_public_key);
}
const files = await readdir(resolve(root, '.output'));
for (const kind of ['chrome', 'firefox', 'sources']) {
  assert(files.includes(`${pkg.name}-${pkg.version}-${kind}.zip`), `Missing ${kind} archive`);
}
console.log('Store manifest versions, identities, permissions, consent, and ZIPs: passed');
