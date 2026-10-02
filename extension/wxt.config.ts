import { defineConfig } from 'wxt';

// This public key fixes the unpacked development ID. It is not an authentication key.
import identities from "./lib/browser-identities.json";
import packageJson from './package.json';

export default defineConfig({
  manifestVersion: 3,
  imports: false,
  hooks: {
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
    permissions: ['nativeMessaging', 'storage', 'webNavigation', 'webRequest'],
    host_permissions: ['http://*/*', 'https://*/*'],
    ...(browser === 'firefox'
      ? { browser_specific_settings: { gecko: { id: identities.firefox_id, strict_min_version: '140.0',
        data_collection_permissions: { required: ['authenticationInfo', 'personallyIdentifyingInfo', 'browsingActivity', 'websiteContent'] } } } }
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
  vite: () => ({ oxc: { jsx: { runtime: 'automatic' as const, importSource: 'preact' } } }),
});
