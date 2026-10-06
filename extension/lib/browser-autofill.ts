// The browser's own password manager and autofill compete with Boltwarden for the same
// fields. The privacy API lets an extension switch them off for the profile; browsers
// revert extension-controlled settings when the extension is removed or disabled.
// `privacy` is optional so existing installs are not disabled by a new permission prompt.
export const AUTOFILL_PERMISSION = { permissions: ['privacy'] };

export const AUTOFILL_SETTINGS = [
  { key: 'passwordSavingEnabled', label: 'Password saving and filling' },
  { key: 'autofillAddressEnabled', label: 'Address autofill' },
  { key: 'autofillCreditCardEnabled', label: 'Credit card autofill' },
] as const;

export type AutofillSettingKey = typeof AUTOFILL_SETTINGS[number]['key'];
export type LevelOfControl = 'not_controllable' | 'controlled_by_other_extensions' | 'controllable_by_this_extension' | 'controlled_by_this_extension';
type Setting = {
  get(details: object): Promise<{ value: unknown; levelOfControl: LevelOfControl }>;
  set(details: { value: boolean }): Promise<void>;
  clear(details: object): Promise<void>;
};
type Permissions = {
  contains(permissions: typeof AUTOFILL_PERMISSION): Promise<boolean>;
  request(permissions: typeof AUTOFILL_PERMISSION): Promise<boolean>;
  remove(permissions: typeof AUTOFILL_PERMISSION): Promise<boolean>;
};
// The browser namespace; `privacy` only appears once the optional permission is granted.
export type AutofillApi = { permissions?: Permissions; privacy?: { services?: Partial<Record<AutofillSettingKey, Setting>> } };

export type AutofillSettingState = { key: AutofillSettingKey; label: string; enabled: boolean; control: LevelOfControl };
export type AutofillState =
  | { kind: 'unsupported' }
  | { kind: 'not-granted' }
  | { kind: 'granted'; settings: AutofillSettingState[] };

// Firefox only exposes passwordSavingEnabled; skip settings this browser lacks.
function available(api: AutofillApi) {
  const services = api.privacy?.services ?? {};
  return AUTOFILL_SETTINGS.flatMap(({ key, label }) => services[key] ? [{ key, label, setting: services[key]! }] : []);
}

export async function autofillState(api: AutofillApi): Promise<AutofillState> {
  if (!api.permissions) return { kind: 'unsupported' };
  if (!await api.permissions.contains(AUTOFILL_PERMISSION)) return { kind: 'not-granted' };
  const settings = await Promise.all(available(api).map(async ({ key, label, setting }) => {
    const { value, levelOfControl } = await setting.get({});
    return { key, label, enabled: value !== false, control: levelOfControl };
  }));
  return { kind: 'granted', settings };
}

// Must be the first call in a click handler: permission requests need the user gesture.
export async function suppressBrowserAutofill(api: AutofillApi) {
  if (!api.permissions || !await api.permissions.request(AUTOFILL_PERMISSION)) return false;
  for (const { setting } of available(api)) {
    const { levelOfControl } = await setting.get({});
    if (levelOfControl === 'controllable_by_this_extension' || levelOfControl === 'controlled_by_this_extension') {
      await setting.set({ value: false });
    }
  }
  return true;
}

export async function restoreBrowserAutofill(api: AutofillApi) {
  for (const { setting } of available(api)) {
    const { levelOfControl } = await setting.get({});
    if (levelOfControl === 'controlled_by_this_extension') await setting.clear({});
  }
  await api.permissions?.remove(AUTOFILL_PERMISSION);
}
