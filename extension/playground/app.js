const element = id => document.getElementById(id);
let controller;
const bytes = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), character => character.charCodeAt(0));
const encode = value => {
  let text = ''; for (const byte of new Uint8Array(value)) text += String.fromCharCode(byte);
  return btoa(text).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
};
function serialize(value) {
  const response = value.response;
  return { id: value.id, rawId: encode(value.rawId), type: value.type,
    clientExtensionResults: value.getClientExtensionResults(),
    response: { clientDataJSON: encode(response.clientDataJSON),
      ...(response.attestationObject ? { attestationObject: encode(response.attestationObject), transports: response.getTransports?.() ?? [] }
        : { authenticatorData: encode(response.authenticatorData), signature: encode(response.signature), userHandle: response.userHandle ? encode(response.userHandle) : null }) } };
}
async function api(path, body = {}) {
  const response = await fetch(`/api/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const value = await response.json(); if (!response.ok) throw new Error(value.error); return value;
}
function status(message, state = '') { element('status').textContent = message; element('status').dataset.state = state; }
async function refresh() {
  const { accounts } = await api('state');
  element('accounts').replaceChildren(...accounts.filter(account => account.passkeys || account.password).map(account => {
    const item = document.createElement('li'); item.textContent = `${account.name} · ${account.passkeys} passkey${account.passkeys === 1 ? '' : 's'}${account.password ? ' · password account' : ''}`; return item;
  }));
  if (!element('accounts').children.length) { const item = document.createElement('li'); item.textContent = 'No registered passkeys yet.'; element('accounts').append(item); }
}
async function run(kind, discoverable = false) {
  if (controller) return;
  controller = new AbortController();
  for (const node of document.querySelectorAll('button, input, select')) node.disabled = node.id !== 'cancel';
  element('cancel').hidden = false;
  status('Waiting for passkey approval…');
  try {
    const { requestId, options } = await api('options', { kind, discoverable, name: element('account').value.trim(),
      verification: element('verification').value, challengeBytes: Number(element('challenge').value) });
    options.challenge = bytes(options.challenge);
    if (options.user) options.user.id = bytes(options.user.id);
    for (const field of ['allowCredentials', 'excludeCredentials']) {
      if (options[field]) options[field] = options[field].map(key => ({ ...key, id: bytes(key.id) }));
    }
    const credential = await navigator.credentials[kind]({ publicKey: options, signal: controller.signal });
    if (!credential) throw new Error('No passkey returned.');
    const result = await api('verify', { requestId, response: serialize(credential) });
    status(`${result.account}: ${result.message} User verification: ${result.userVerified ? 'yes' : 'no'}.`, 'success');
    await refresh();
  } catch (error) { status(`${error.name}: ${error.message}`, 'error'); }
  finally {
    controller = undefined;
    for (const node of document.querySelectorAll('button, input, select')) node.disabled = false;
    element('cancel').hidden = true;
    element('password-action').onchange();
  }
}
element('create').onclick = () => run('create');
element('get').onclick = () => run('get');
element('discover').onclick = () => run('get', true);
element('cancel').onclick = () => controller?.abort();
const syncUsername = () => { element('test-username').value = `boltwarden-test-${element('account').value}`; };
element('account').addEventListener('input', syncUsername);
element('new-account').onclick = () => { element('account').value = `test-${crypto.randomUUID().slice(0, 8)}`; syncUsername(); element('account').focus(); };
const validateConfirmation = () => {
  const confirmation = element('confirm-password');
  confirmation.setCustomValidity(!confirmation.disabled && confirmation.value && confirmation.value !== element('test-password').value ? 'Passwords do not match.' : '');
};
element('test-password').addEventListener('input', validateConfirmation);
element('confirm-password').addEventListener('input', validateConfirmation);
element('password-action').onchange = () => {
  const action = element('password-action').value;
  element('old-password-row').hidden = action !== 'change';
  element('old-password').disabled = action !== 'change';
  element('old-password').required = action === 'change';
  element('test-password').autocomplete = action === 'login' ? 'current-password' : 'new-password';
  element('password-label').textContent = action === 'login' ? 'Password' : 'New password';
  element('confirm-password-row').hidden = action === 'login';
  element('confirm-password').disabled = action === 'login';
  element('confirm-password').required = action !== 'login';
  element('password-suggestion-hint').hidden = action === 'login';
  validateConfirmation();
};
element('password-form').onsubmit = async event => {
  event.preventDefault();
  const output = element('password-status');
  try {
    const result = await api('password', { action: element('password-action').value,
      username: element('test-username').value, password: element('test-password').value, oldPassword: element('old-password').value, confirmation: element('confirm-password').value });
    output.textContent = `${result.message} Boltwarden's save prompt is separate from this server check.`; output.dataset.state = 'success';
    await refresh();
  } catch (error) { output.textContent = error.message; output.dataset.state = 'error'; }
  finally { element('test-password').value = ''; element('old-password').value = ''; element('confirm-password').value = ''; validateConfirmation(); }
};
element('reset').onclick = async () => {
  if (!confirm('Forget all playground accounts? Passkeys saved in your vault will remain.')) return;
  try { await api('reset'); await refresh(); status('Test data reset. Vault items were not deleted.'); }
  catch (error) { status(error.message, 'error'); }
};
refresh().catch(error => status(error.message, 'error'));
