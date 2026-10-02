import type { PendingSaveSummary } from './pending-saves';
import { render } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import { browser } from 'wxt/browser';
import type { UiFrame, UiPage, UiResult, UiState, UiStateChange } from './ui-types';
import type { Match } from './protocol';
import './ui.css';

async function call<T>(type: string, fields: Record<string, unknown> = {}): Promise<T> {
  const result = await browser.runtime.sendMessage({ type, ...fields }) as UiResult<T> | undefined;
  if (!result) throw new Error('Reload the extension and try again.');
  if (!result.ok) throw new Error(result.error);
  return result.value;
}

type Selection = { frame: UiFrame; item: Match };
type Operation = 'idle' | 'loading' | 'filling' | 'action';
const selectionKey = ({ frame, item }: Selection) => `${frame.targetId}:${item.id}`;
const errorMessage = (error: unknown) => error instanceof Error ? error.message : 'Request failed. Try again.';

function Symbol({ name }: { name: 'key' | 'refresh' | 'settings' | 'lock' | 'warning' | 'check' }) {
  const paths = {
    key: <><circle cx="8" cy="8" r="4" /><path d="m11 11 9 9m-5-5 3-3m-1 5 3-3" /></>,
    refresh: <><path d="M20 7v5h-5M4 17v-5h5" /><path d="M6 7a7 7 0 0 1 12-1l2 3M4 15l2 3a7 7 0 0 0 12-1" /></>,
    settings: <><path d="m9 3-1 3-3 1-2 3 2 2-1 3 2 3 3-1 2 2h3l1-3 3-1 2-3-2-2 1-3-2-3-3 1-2-2Z" /><circle cx="11.5" cy="11" r="3" /></>,
    lock: <><rect x="5" y="10" width="14" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2" /></>,
    warning: <><path d="m12 3 10 18H2L12 3Z" /><path d="M12 9v5m0 3v.1" /></>,
    check: <path d="m5 12 4 4L19 6" />,
  };
  return <svg class="symbol" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{paths[name]}</svg>;
}

function App({ options }: { options: boolean }) {
  const [pending, setPending] = useState<PendingSaveSummary[]>([]);
  const [state, setState] = useState<UiState>();
  const [page, setPage] = useState<UiPage>();
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [operation, setOperation] = useState<Operation>('loading');
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState('');
  const [confirmation, setConfirmation] = useState<Selection>();
  const [filled, setFilled] = useState(false);
  const search = useRef<HTMLInputElement>(null);
  const dialog = useRef<HTMLElement>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  const mounted = useRef(false);
  const currentState = useRef<UiState | undefined>(undefined);
  const currentOperation = useRef<Operation>('idle');
  const generation = useRef(0);
  const refreshPending = useRef(false);
  const refreshAfterFill = useRef(false);
  const live = () => mounted.current;

  function updateState(next: UiState) { currentState.current = next; setState(next); }
  function invalidate() {
    generation.current++;
    setPage(undefined); setConfirmation(undefined); setSelected(''); setFilled(false);
  }
  function start(next: Operation) {
    if (!live() || currentOperation.current !== 'idle') return false;
    currentOperation.current = next; setOperation(next); setError(''); setMessage('');
    return true;
  }
  function finish() {
    currentOperation.current = 'idle';
    if (!live()) return;
    setOperation('idle');
    if (refreshPending.current) {
      refreshPending.current = false;
      queueMicrotask(() => { if (live()) void refresh(); });
    }
  }
  async function refresh(retry = false) {
    if (!start('loading')) { refreshPending.current = true; return; }
    invalidate();
    const version = generation.current;
    try {
      if (retry) await call('retry');
      const next = await call<UiState>('state');
      void call<PendingSaveSummary[]>('pending-saves').then(items => { if (live()) setPending(items ?? []); }).catch(() => {});
      if (!live()) return;
      // Retain the public fingerprint even when a newer connection event has
      // superseded this response during the native handshake.
      if (version !== generation.current) {
        if (currentState.current) updateState({ ...currentState.current, fingerprint: next.fingerprint });
        return;
      }
      updateState(next);
      if (!options && next.connection.state === 'ready') {
        const matches = await call<UiPage>('list');
        if (live() && version === generation.current && currentState.current?.connection.state === 'ready') setPage(matches);
      }
    } catch (error) {
      if (live() && version === generation.current) setError(errorMessage(error));
    } finally { finish(); }
  }
  function connectionChanged(event: UiStateChange) {
    if (!live() || event.type !== 'state-changed') return;
    const previous = currentState.current?.connection;
    void call<PendingSaveSummary[]>('pending-saves').then(items => setPending(items ?? [])).catch(() => {});
    updateState({ fingerprint: currentState.current?.fingerprint ?? '', connection: event.connection });
    const changed = !previous || previous.state !== event.connection.state;
    const invalid = event.reason !== 'state' || (changed && event.connection.state !== 'ready');
    if (invalid) { invalidate(); setError(''); }
    if (event.connection.state !== 'ready') {
      refreshPending.current = false;
      setMessage('');
      return;
    }
    if (options || (!changed && event.reason === 'state')) return;
    if (currentOperation.current === 'filling') {
      // Match changes can come from the sync preceding this very fill. Never
      // start discovery while desktop approval is still pending.
      refreshAfterFill.current ||= event.reason === 'page' || changed;
      return;
    }
    if (currentOperation.current !== 'idle') refreshPending.current = true;
    else void refresh();
  }
  useEffect(() => {
    mounted.current = true;
    const port = browser.runtime.connect({ name: 'boltwarden-ui-v1' });
    port.onMessage.addListener(connectionChanged);
    port.onDisconnect.addListener(() => {
      if (!live()) return;
      invalidate(); refreshPending.current = false;
      updateState({ fingerprint: currentState.current?.fingerprint ?? '', connection: { state: 'disconnected', epoch: 0, error: 'Connection interrupted. Reopen this popup to reconnect.' } });
    });
    void refresh();
    return () => { mounted.current = false; generation.current++; port.disconnect(); };
  }, []);

  const terms = query.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
  const groups = (page?.frames ?? []).map(frame => ({ frame, items: frame.items.filter(item => {
    const text = `${item.name}\n${item.username ?? ''}`.toLocaleLowerCase();
    return terms.every(term => text.includes(term));
  }) }));
  const rows = groups.flatMap(({ frame, items }) => items.map(item => ({ frame, item })));
  const active = rows.find(row => selectionKey(row) === selected) ?? rows[0];
  const activeKey = active ? selectionKey(active) : '';
  const connection = state?.connection;
  const ready = connection?.state === 'ready';
  const busy = operation !== 'idle';
  const filteringLoadedMatches = query.trim().length > 0
    && (page?.frames.some(frame => frame.items.length > 0) ?? false);

  useEffect(() => {
    if (confirmation) cancel.current?.focus();
    else if (page && !options) search.current?.focus();
  }, [Boolean(page), Boolean(confirmation)]);
  useEffect(() => {
    if (activeKey) document.getElementById(`login-${encodeURIComponent(activeKey)}`)?.scrollIntoView?.({ block: 'nearest' });
  }, [activeKey]);

  async function action(type: 'pair' | 'unlock') {
    if (!start('action')) return;
    invalidate();
    setMessage(type === 'pair' ? 'Approve pairing in Boltwarden desktop.' : 'Unlock Boltwarden in the desktop app.');
    try {
      await call(type);
      if (type === 'pair') refreshPending.current = true;
    } catch (error) { if (live()) { setError(errorMessage(error)); setMessage(''); } }
    finally { finish(); }
  }
  async function fill(selection: Selection, confirmed = false) {
    if (currentOperation.current !== 'idle') return;
    const { frame, item } = selection;
    if (!confirmed && (frame.crossOrigin || item.requires_confirmation)) { setConfirmation(selection); return; }
    if (!start('filling')) return;
    setConfirmation(undefined); setFilled(false);
    const version = generation.current;
    setMessage(item.reprompt ? 'Verify your master password in Boltwarden desktop.' : 'Filling login…');
    try {
      await call('fill', { targetId: frame.targetId, itemId: item.id,
        confirmCrossOrigin: confirmed && frame.crossOrigin, confirmInsecure: confirmed && item.requires_confirmation });
      if (live() && currentState.current?.connection.state === 'ready' && !refreshAfterFill.current) {
        setPage(undefined); setFilled(true); setMessage('Login filled.');
      }
    } catch (error) {
      if (live() && currentState.current?.connection.state === 'ready') {
        setError(errorMessage(error)); setMessage('');
        // A failed fill can mean the document or item changed. Require a fresh
        // lookup and selection rather than retaining the stale rows.
        invalidate();
      }
    } finally {
      if (refreshAfterFill.current || (version !== generation.current && currentState.current?.connection.state !== 'ready')) {
        refreshPending.current = refreshAfterFill.current && currentState.current?.connection.state === 'ready';
      }
      refreshAfterFill.current = false;
      finish();
    }
  }
  async function more(frame: UiFrame) {
    if (!start('loading')) return;
    const version = generation.current;
    try {
      const updated = await call<UiFrame>('more', { targetId: frame.targetId });
      if (live() && version === generation.current) setPage(current => current && ({ ...current, frames: current.frames.map(value => value.targetId === updated.targetId ? updated : value) }));
    } catch (error) {
      if (live() && version === generation.current) { invalidate(); setError(errorMessage(error)); }
    } finally { finish(); }
  }
  function keyboard(event: KeyboardEvent) {
    if (confirmation) {
      if (event.key === 'Escape') { event.preventDefault(); setConfirmation(undefined); }
      if (event.key === 'Tab') {
        const buttons = Array.from(dialog.current?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)') ?? []);
        const first = buttons[0], last = buttons.at(-1);
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      }
      return;
    }
    if (options || event.altKey || event.ctrlKey || event.metaKey || event.isComposing) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      if (query) { setQuery(''); setSelected(''); search.current?.focus(); }
      else window.close();
      return;
    }
    const inPicker = event.target === search.current || (event.target instanceof Element && Boolean(event.target.closest('.login')));
    if (!inPicker || busy) return;
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      const index = rows.findIndex(row => selectionKey(row) === activeKey);
      const next = Math.max(0, Math.min(rows.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
      if (rows[next]) { setSelected(selectionKey(rows[next])); search.current?.focus(); }
    } else if (event.key === 'Enter' && active) {
      event.preventDefault(); void fill(active);
    }
  }
  const status = connection?.state === 'ready' ? 'Connected' : connection?.state === 'locked' ? 'Locked'
    : connection?.state === 'unpaired' ? 'Not paired' : connection?.state === 'disabled' ? 'Disabled'
      : connection?.state === 'disconnected' ? 'Unavailable' : 'Connecting';

  const codePage = !!page?.frames.length && page.frames.every(frame => frame.kind === 'totp');
  const searchLabel = codePage ? 'Filter verification accounts' : 'Filter this page’s logins';

  return <main class={options ? 'options' : 'popup'} onKeyDown={keyboard}>
    <header class="header">
      <span class="brand-mark" aria-hidden="true" />
      {ready && !options && !confirmation ? <>
        <h1 class="visually-hidden">Boltwarden</h1>
        <label class="visually-hidden" for="search">{searchLabel}</label>
        <input ref={search} id="search" class="search" type="search" placeholder={searchLabel} autoComplete="off" spellcheck={false}
          value={query} disabled={busy && !page} onInput={event => { setQuery(event.currentTarget.value); setSelected(''); }}
          aria-controls="matching-logins" aria-describedby="search-scope" />
        <span id="search-scope" class="visually-hidden">Filters names and usernames among loaded matches for this page.</span>
        <span class="count" aria-label={`${rows.length} matching logins`}>{busy ? <span class="spinner" /> : page ? rows.length : ''}</span>
      </> : <h1>{options ? 'Browser connection' : 'Boltwarden'}</h1>}
    </header>

    <div class="body" aria-busy={busy}>
      {confirmation ? <section ref={dialog} class="confirmation" role="alertdialog" aria-modal="true" aria-labelledby="confirmation-title" aria-describedby="confirmation-details">
        <div class="state-icon caution"><Symbol name="warning" /></div>
        <h2 id="confirmation-title">Fill {confirmation.item.name || 'this login'}?</h2>
        <div id="confirmation-details"><p class="destination-label">Destination</p><strong class="destination">{confirmation.frame.origin}</strong>
          {confirmation.frame.crossOrigin && <p>This embedded page belongs to a different origin from the page you opened.</p>}
          {confirmation.item.requires_confirmation && <p>This page uses HTTP. Your password may be visible to others on the network.</p>}
        </div>
        <div class="buttons"><button ref={cancel} class="secondary" onClick={() => setConfirmation(undefined)}>Cancel</button><button onClick={() => void fill(confirmation, true)}>Confirm and fill</button></div>
      </section> : <>
        {pending.map(entry => <section class="notice" key={entry.id}>
          <strong>Password awaiting save · {entry.origin}</strong>
          <p>{entry.username}</p><p role="status">{entry.message}</p>
          <p class="detail">Kept only until saved, discarded, or this browser session ends.</p>
          <div class="buttons"><button disabled={entry.busy} onClick={() => void call('retry-save', { id: entry.id }).catch(error => setError(errorMessage(error)))}>Retry save</button>
          <button class="secondary" disabled={entry.busy} onClick={() => void call('discard-save', { id: entry.id }).catch(error => setError(errorMessage(error)))}>Discard</button></div>
        </section>)}
        {error && <p role="alert" class="notice error">{error}</p>}
        {message && !filled && <p role="status" class="notice">{message}</p>}
        {(!connection || connection.state === 'connecting') && <section class="empty-state"><span class="spinner large" /><h2>Connecting to Boltwarden…</h2></section>}
        {connection?.state === 'disconnected' && <section class="empty-state"><div class="state-icon"><span class="brand-mark" /></div><h2>Connect to Boltwarden</h2><p>Open Boltwarden desktop and enable this browser in Settings → Browser setup, then try again.</p><button disabled={busy} onClick={() => void refresh(true)}>Try again</button>{options && <p class="detail">{connection.error}</p>}</section>}
        {connection?.state === 'disabled' && <section class="empty-state"><div class="state-icon"><Symbol name="lock" /></div><h2>Browser integration is off</h2><p>Enable it in Boltwarden desktop settings.</p><button disabled={busy} onClick={() => void refresh(true)}>Try again</button></section>}
        {connection?.state === 'unpaired' && <section class="empty-state pairing"><div class="state-icon"><span class="brand-mark" /></div><h2>Pair this browser</h2><p>Compare this fingerprint with the request in Boltwarden desktop.</p><code class="fingerprint">{state?.fingerprint || 'Loading fingerprint…'}</code>
          <button disabled={busy || !state?.fingerprint} onClick={() => void action('pair')}>Pair with Boltwarden</button></section>}
        {connection?.state === 'locked' && <section class="empty-state"><div class="state-icon"><Symbol name="lock" /></div><h2>Vault locked</h2><p>Unlock in Boltwarden desktop to see matching logins.</p><button disabled={busy} onClick={() => void action('unlock')}>Unlock desktop vault</button></section>}
        {ready && options && <section class="connection-details"><h2>This browser is paired</h2><p>Press <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>L</kbd> on a login form. If more than one login matches, choose it from the toolbar popup.</p><p>Manage or revoke paired browsers in Boltwarden desktop settings.</p><h3>Browser fingerprint</h3><code class="fingerprint">{state?.fingerprint}</code></section>}
        {ready && !options && filled && <section class="empty-state" role="status"><div class="state-icon success"><Symbol name="check" /></div><h2>Login filled</h2><p>You can return to the page.</p></section>}
        {ready && !options && !page && !filled && <section class="empty-state">{operation === 'loading' ? <><span class="spinner large" /><h2>Finding matching logins…</h2></> : operation === 'filling' ? <div class="state-icon"><Symbol name="lock" /></div> : <><div class="state-icon"><Symbol name="key" /></div><h2>Choose a login to fill</h2><p>Refresh to check this page again.</p></>}</section>}
        {page && ready && <section id="matching-logins" aria-label="Matching logins">
          <span class="visually-hidden" role="status">{active ? `${active.item.name || 'Unnamed login'}, ${active.item.username || 'No username'}` : 'No matching logins'}</span>
          {page.warning && <p class="notice warning" role="status">{page.warning}</p>}
          {rows.length === 0 && <section class="empty-state no-matches"><div class="state-icon"><Symbol name="key" /></div><h2>{filteringLoadedMatches ? 'No matching logins' : 'No logins for this page'}</h2><p>{filteringLoadedMatches ? 'Try another name or username.' : page.message || 'Open a login form, then refresh.'}</p></section>}
          {groups.filter(({ frame, items }) => items.length || frame.more).map(({ frame, items }) => <section key={frame.targetId} class="frame">
            <h2 class="frame-heading"><span title={frame.origin}>{frame.origin}{frame.kind === 'totp' ? ' · Verification codes' : ''}</span>{frame.crossOrigin && <span class="frame-warning" title="This embedded page has a different origin">Embedded page</span>}</h2>
            {items.map(item => {
              const row = { frame, item }, key = selectionKey(row), selected = key === activeKey;
              return <button id={`login-${encodeURIComponent(key)}`} class={`login${selected ? ' selected' : ''}`} key={item.id} disabled={busy}
                aria-label={`${item.name || 'Unnamed login'}, ${item.username || 'No username'}${item.reprompt ? ', master password required' : ''}${item.requires_confirmation ? ', insecure page, confirmation required' : ''}`}
                onFocus={() => setSelected(key)} onMouseEnter={() => setSelected(key)} onClick={() => void fill(row)}>
                <Symbol name="key" /><span class="item-text"><strong>{item.name || 'Unnamed login'}</strong><span class="username">{item.username || 'No username'}</span></span>
                {item.reprompt && <span class="row-hint" title="Master password required"><Symbol name="lock" /></span>}
                {(item.requires_confirmation || frame.crossOrigin) && <span class="row-hint caution" title="Destination confirmation required"><Symbol name="warning" /></span>}
                {selected && <span class="enter-hint" aria-hidden="true">↵</span>}
              </button>;
            })}
            {frame.more && <button class="more secondary" disabled={busy} onClick={() => void more(frame)}>Load more matching logins</button>}
          </section>)}
        </section>}
        {options && <section class="connection-details help"><h2>Using this extension</h2><p>The popup only shows logins that match the current page. Filtering narrows loaded matches; it does not search the whole vault.</p><p>Passwords are sent only when you choose to fill. No vault is stored in this extension.</p><h3>Desktop setup</h3><p>Run <code>boltwarden install-browser</code>, start Boltwarden, and enable browser integration in desktop settings.</p></section>}
      </>}
    </div>

    <footer class="footer" aria-hidden={confirmation ? 'true' : undefined}>
      <span class={`connection-status ${connection?.state ?? 'connecting'}`}><span class="status-dot" />{status}</span>
      {!options && <span class="keyboard-hints">{page ? <><kbd>↑↓</kbd> Navigate <kbd>Enter</kbd> Fill</> : <><kbd>Esc</kbd> Close</>}</span>}
      <div class="footer-actions"><button class="icon-button" disabled={busy || Boolean(confirmation)} title="Refresh matching logins" aria-label="Refresh" onClick={() => void refresh(true)}><Symbol name="refresh" /></button>
        {!options && <button class="icon-button" disabled={Boolean(confirmation)} title="Connection settings" aria-label="Connection settings" onClick={() => void browser.runtime.openOptionsPage()}><Symbol name="settings" /></button>}</div>
    </footer>
  </main>;
}

export function mount(options = false) { render(<App options={options} />, document.getElementById('app')!); }
