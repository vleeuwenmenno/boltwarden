import { describe, expect, it, vi } from 'vitest';
import { autofillState, restoreBrowserAutofill, suppressBrowserAutofill, type AutofillApi, type LevelOfControl } from '../lib/browser-autofill';

function setting(value: boolean, levelOfControl: LevelOfControl = 'controllable_by_this_extension') {
  const state = { value, levelOfControl };
  return {
    state,
    get: vi.fn(async () => ({ ...state })),
    set: vi.fn(async ({ value }: { value: boolean }) => { state.value = value; state.levelOfControl = 'controlled_by_this_extension'; }),
    clear: vi.fn(async () => { state.value = true; state.levelOfControl = 'controllable_by_this_extension'; }),
  };
}

function fakeApi(granted: boolean, services: Record<string, ReturnType<typeof setting>>) {
  const api: AutofillApi & { grant: boolean } = {
    grant: granted,
    permissions: {
      contains: vi.fn(async () => api.grant),
      request: vi.fn(async () => { api.grant = true; return true; }),
      remove: vi.fn(async () => { api.grant = false; return true; }),
    },
    privacy: { services },
  };
  return api;
}

describe('browser autofill', () => {
  it('reports unsupported browsers and missing permission', async () => {
    expect(await autofillState({})).toEqual({ kind: 'unsupported' });
    expect(await autofillState(fakeApi(false, {}))).toEqual({ kind: 'not-granted' });
  });

  it('turns off every controllable setting and skips ones the browser lacks', async () => {
    // Firefox only has passwordSavingEnabled.
    const passwords = setting(true);
    const api = fakeApi(false, { passwordSavingEnabled: passwords });
    expect(await suppressBrowserAutofill(api)).toBe(true);
    expect(passwords.set).toHaveBeenCalledWith({ value: false });
    expect(await autofillState(api)).toEqual({ kind: 'granted', settings: [
      { key: 'passwordSavingEnabled', label: 'Password saving and filling', enabled: false, control: 'controlled_by_this_extension' },
    ] });
  });

  it('leaves policy and other-extension settings alone', async () => {
    const policy = setting(true, 'not_controllable'), other = setting(true, 'controlled_by_other_extensions'), cards = setting(true);
    const api = fakeApi(false, { passwordSavingEnabled: policy, autofillAddressEnabled: other, autofillCreditCardEnabled: cards });
    await suppressBrowserAutofill(api);
    expect(policy.set).not.toHaveBeenCalled();
    expect(other.set).not.toHaveBeenCalled();
    expect(cards.set).toHaveBeenCalledWith({ value: false });
  });

  it('does nothing when the permission request is declined', async () => {
    const passwords = setting(true);
    const api = fakeApi(false, { passwordSavingEnabled: passwords });
    vi.mocked(api.permissions!.request).mockResolvedValueOnce(false);
    expect(await suppressBrowserAutofill(api)).toBe(false);
    expect(passwords.set).not.toHaveBeenCalled();
  });

  it('restores only settings it controls, then drops the permission', async () => {
    const ours = setting(false, 'controlled_by_this_extension'), other = setting(false, 'controlled_by_other_extensions');
    const api = fakeApi(true, { passwordSavingEnabled: ours, autofillAddressEnabled: other });
    await restoreBrowserAutofill(api);
    expect(ours.clear).toHaveBeenCalled();
    expect(other.clear).not.toHaveBeenCalled();
    expect(api.permissions!.remove).toHaveBeenCalledWith({ permissions: ['privacy'] });
    expect(await autofillState(api)).toEqual({ kind: 'not-granted' });
  });
});
