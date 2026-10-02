/** Descriptive pairing label, never an authentication or authorization identity. */
interface BrowserRuntime {
  getURL(path: string): string;
  getBrowserInfo?: () => Promise<{ name: string }>;
}
interface BrowserNavigator {
  userAgent?: string;
  userAgentData?: { brands: readonly { brand: string }[] };
}

export async function pairingBrowserLabel(runtime: BrowserRuntime, agent: BrowserNavigator = {}): Promise<string> {
  const firefox = runtime.getURL('/').startsWith('moz-extension://');
  if (firefox && runtime.getBrowserInfo) {
    try {
      const name = (await runtime.getBrowserInfo()).name;
      if (typeof name === 'string' && name.trim() && !/[\u0000-\u001f\u007f-\u009f]/u.test(name)
          && new TextEncoder().encode(name.trim()).length <= 80) return name.trim();
    } catch { /* A missing browser-info API must not prevent pairing. */ }
  }
  if (firefox) return 'Firefox-based browser';
  const brands = new Set(agent.userAgentData?.brands.map(value => value.brand));
  // Chromium derivatives can also advertise Google Chrome. Prefer an explicitly
  // reported derivative; do not infer a product name from its rendering engine.
  for (const brand of ['Microsoft Edge', 'Brave', 'Opera', 'Vivaldi', 'Google Chrome']) {
    if (brands.has(brand)) return brand;
  }
  return 'Chromium-based browser';
}
