import { defineConfig } from 'wxt';

// This public key fixes the unpacked development ID. It is not an authentication key.
import identities from "./lib/browser-identities.json";
import packageJson from './package.json';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** A stable hash of the extension code, so pages and content scripts can tell when the
 * browser still runs an older background. It depends only on source files, which keeps
 * builds from the source archive reproducible. */
function sourceDigest() {
  const root = fileURLToPath(new URL('.', import.meta.url));
  const hash = createHash('sha256');
  const walk = (directory: string) => {
    for (const entry of readdirSync(resolve(root, directory), { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else hash.update(path.replaceAll('\\', '/')).update('\0').update(readFileSync(resolve(root, path))).update('\0');
    }
  };
  walk('entrypoints'); walk('lib');
  hash.update(packageJson.version);
  return hash.digest('hex').slice(0, 16);
}

let unpackedManifest: string | undefined;

export default defineConfig({
  manifestVersion: 3,
  imports: false,
  hooks: {
    async 'zip:extension:start'(wxt) {
      if (wxt.config.browser !== 'chrome') return;
      const path = resolve(wxt.config.outDir, 'manifest.json');
      unpackedManifest = await readFile(path, 'utf8');
      const manifest = JSON.parse(unpackedManifest);
      // Chrome Web Store rejects the key used for unpacked development builds.
      delete manifest.key;
      await writeFile(path, JSON.stringify(manifest));
    },
    async 'zip:extension:done'(wxt) {
      if (wxt.config.browser !== 'chrome' || unpackedManifest === undefined) return;
      await writeFile(resolve(wxt.config.outDir, 'manifest.json'), unpackedManifest);
      unpackedManifest = undefined;
    },
    'config:resolved'(wxt) {
      // AMO reviewers must be able to run the documented tests from the source ZIP.
      wxt.config.zip.excludeSources = wxt.config.zip.excludeSources.filter(pattern =>
        pattern !== '**/__tests__/**' && pattern !== '**/*.+(test|spec).?(c|m)+(j|t)s?(x)');
    },
  },
  manifest: ({ browser }) => ({
    name: 'Boltwarden',
    description: 'Fill logins and use passkeys with your Boltwarden desktop vault.',
    version: packageJson.version,
    icons: { 16: 'icon/16.png', 32: 'icon/32.png', 48: 'icon/48.png', 128: 'icon/128.png' },
    // Chrome's service worker writes the clipboard through an offscreen page; `offscreen` has no install warning.
    // `alarms` (no warning either) wipes a copied 2FA code later, even after the background was suspended.
    permissions: ['nativeMessaging', 'storage', 'webNavigation', 'webRequest', 'alarms', ...(browser === 'firefox' ? [] : ['offscreen'])],
    // Requested from the options page: `privacy` to switch off the browser's own autofill,
    // `clipboardWrite` to copy verification codes after a fill.
    optional_permissions: ['privacy', 'clipboardWrite'],
    host_permissions: ['http://*/*', 'https://*/*'],
    ...(browser === 'firefox'
      ? { browser_specific_settings: { gecko: { id: identities.firefox_id, strict_min_version: '140.0',
        data_collection_permissions: { required: ['financialAndPaymentInfo', 'authenticationInfo', 'personallyIdentifyingInfo', 'browsingActivity', 'websiteContent'] } } } }
      : { key: identities.chrome_public_key, minimum_chrome_version: '127' }),
    commands: {
      autofill: { suggested_key: { default: 'Ctrl+Shift+L' }, description: 'Fill a login or select a matching login' },
      _execute_action: { description: 'Open Boltwarden' },
    },
    action: {
      default_title: 'Boltwarden',
      default_icon: { 16: 'icon/16.png', 24: 'icon/24.png', 32: 'icon/32.png' },
      ...(browser === 'firefox' ? {
        theme_icons: [16, 32].map(size => ({
          light: `icon/light-${size}.png`, dark: `icon/dark-${size}.png`, size,
        })),
      } : {}),
    },
    options_ui: { open_in_tab: true },
  }),
  vite: () => ({ oxc: { jsx: { runtime: 'automatic' as const, importSource: 'preact' } },
    define: { 'import.meta.env.BOLTWARDEN_BUILD': JSON.stringify(sourceDigest()) } }),
});
