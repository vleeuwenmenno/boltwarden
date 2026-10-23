import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { parseWire } from '../lib/protocol';
import {
  compareVersions, DEFAULT_RELEASE_PREFERENCES, dismissRelease, extensionStatus, parseDesktopVersion, parseExtensionVersion, parseReleaseInfo,
  parseReleasePreferences, parseReleases, readReleasePreferences, releaseNotices, releaseSummary, retryAfter, sameReleases, setReleaseNotices, statusReleases,
  type ReleaseMetadata, type ReleasePreferences,
} from '../lib/releases';

const fixture = (name: string) => JSON.parse(readFileSync(new URL(`../protocol/fixtures/${name}`, import.meta.url), 'utf8'));
const NOW = 1_790_000_000;
const info = (tag: string, published_at = NOW) => ({ version: tag.replace(/^(extension-)?v/, ''), tag, url: `https://github.com/vleeuwenmenno/boltwarden/releases/tag/${tag}`, published_at });
function snapshot(overrides: Record<string, unknown> = {}, desktop: Record<string, unknown> = {}) {
  return { state: 'fresh', auto_check: true, checked_at: NOW, complete: true,
    desktop: { installed: '1.0.0-rc.5', update: 'available', offer: info('v1.0.0'), dismissed: false, stable: info('v1.0.0'), preview: info('v1.0.0'), ...desktop },
    extension: info('extension-v0.5.10'), ...overrides };
}
const metadata = (releases: unknown): ReleaseMetadata => ({ releases: parseReleases(releases)!, receivedAt: NOW * 1000, revision: 1 });

describe('release versions', () => {
  it('parses desktop and extension versions strictly', () => {
    expect(parseDesktopVersion('1.0.0-rc.5')).toEqual({ major: 1, minor: 0, patch: 0, rc: 5 });
    expect(parseDesktopVersion('10.20.30')).toEqual({ major: 10, minor: 20, patch: 30 });
    for (const bad of ['1.0', '1.0.0.0', '01.0.0', '1.0.0-rc.0', '1.0.0-rc.01', '1.0.0-beta.1', 'v1.0.0', ' 1.0.0', '1.0.0+dev', '1234567890.0.0', 1, null]) {
      expect(parseDesktopVersion(bad)).toBeUndefined();
    }
    expect(parseExtensionVersion('0.5.10')).toEqual({ major: 0, minor: 5, patch: 10 });
    expect(parseExtensionVersion('0.5.10-rc.1')).toBeUndefined();
  });
  it('compares numerically and sorts final releases after their candidates', () => {
    const v = (text: string) => parseDesktopVersion(text)!;
    expect(compareVersions(v('0.5.10'), v('0.5.9'))).toBeGreaterThan(0);
    expect(compareVersions(v('1.0.0'), v('1.0.0-rc.5'))).toBeGreaterThan(0);
    expect(compareVersions(v('1.0.0-rc.10'), v('1.0.0-rc.9'))).toBeGreaterThan(0);
    expect(compareVersions(v('1.0.1-rc.1'), v('1.0.0'))).toBeGreaterThan(0);
    expect(compareVersions(v('2.0.0'), v('2.0.0'))).toBe(0);
  });
});

describe('release metadata validation', () => {
  it('accepts the shared desktop fixture and keeps Status valid', () => {
    const status = parseWire(fixture('status-releases.json'));
    expect(status).toMatchObject({ type: 'Status', enabled: true, unlocked: false, epoch: 3 });
    const parsed = statusReleases(status as never, 5);
    expect(parsed).toEqual({ desktopVersion: '1.0.0-rc.5', releases: fixture('status-releases.json').releases, receivedAt: 5, revision: 0 });
  });
  it('reports an older desktop without release fields as unsupported, not invalid', () => {
    const status = parseWire({ version: 1, id: 'old', type: 'Status', enabled: true, unlocked: true, epoch: 1 });
    expect(statusReleases(status as never, 5)).toEqual({ receivedAt: 5, revision: 0 });
  });
  it('discards malformed release metadata without rejecting the core Status', () => {
    for (const releases of ['bad', [], { state: 'fresh' }, snapshot({ state: 'done' }), snapshot({ auto_check: 'yes' }),
      snapshot({ desktop: null }), snapshot({}, { installed: 5 }), snapshot({}, { installed: 'x'.repeat(65) }), snapshot({}, { update: 'later' })]) {
      const status = parseWire({ version: 1, id: 's', type: 'Status', enabled: true, unlocked: true, epoch: 1, desktop_version: { evil: true }, releases });
      expect(status.type).toBe('Status');
      expect(statusReleases(status as never, 5)).toEqual({ invalid: true, receivedAt: 5, revision: 0 });
    }
  });
  it('drops individual malformed release fields', () => {
    const parsed = parseReleases(snapshot({ checked_at: -1, error: 'boom', retry_after_seconds: 1.5, extension: info('v0.5.10') },
      { stable: info('v1.0.0-rc.6'), preview: { ...info('v1.0.0'), url: 'https://example.com' } }))!;
    expect(parsed.checked_at).toBeUndefined(); expect(parsed.error).toBeUndefined(); expect(parsed.retry_after_seconds).toBeUndefined();
    expect(parsed.extension).toBeUndefined(); expect(parsed.desktop.stable).toBeUndefined(); expect(parsed.desktop.preview).toBeUndefined();
    expect(parsed.desktop.offer?.version).toBe('1.0.0');
  });
  it('rebuilds release links only from an exact tag and fixed repository URL', () => {
    expect(parseReleaseInfo(info('v1.0.0'), 'desktop')?.url).toBe('https://github.com/vleeuwenmenno/boltwarden/releases/tag/v1.0.0');
    const good = info('v1.0.0');
    for (const bad of [
      { ...good, url: 'https://github.com/vleeuwenmenno/boltwarden/releases/tag/v1.0.0/../../evil' },
      { ...good, url: 'https://github.com/vleeuwenmenno/boltwarden/releases/tag/v1.0.0?x=1' },
      { ...good, url: 'http://github.com/vleeuwenmenno/boltwarden/releases/tag/v1.0.0' },
      { ...good, url: 'javascript:alert(1)' },
      { ...good, tag: 'v1.0.1' }, { ...good, version: '1.0.1' }, { ...good, tag: 'extension-v1.0.0' },
      { ...good, published_at: 5 }, { ...good, published_at: '1790000000' }, { ...good, version: '<b>1</b>' },
    ]) expect(parseReleaseInfo(bad, 'desktop')).toBeUndefined();
    // Component mix-ups are rejected in both directions.
    expect(parseReleaseInfo(info('extension-v0.5.10'), 'desktop')).toBeUndefined();
    expect(parseReleaseInfo(info('v0.5.10'), 'extension')).toBeUndefined();
    expect(parseReleaseInfo(info('extension-v0.5.10'), 'extension')?.tag).toBe('extension-v0.5.10');
  });
  it('accepts an offer only when it is newer on the installed channel', () => {
    const offerFor = (installed: string, offer: string) => parseReleases(snapshot({}, { installed, offer: info(offer) }))!.desktop;
    expect(offerFor('1.0.0-rc.5', 'v1.0.0-rc.6')).toMatchObject({ update: 'available', offer: { version: '1.0.0-rc.6' } });
    // A stable installation is never offered a release candidate.
    expect(offerFor('1.0.0', 'v1.0.1-rc.1')).toEqual(expect.objectContaining({ update: 'unknown' }));
    expect(offerFor('1.0.0', 'v1.0.1-rc.1').offer).toBeUndefined();
    expect(offerFor('1.0.0', 'v1.0.0').offer).toBeUndefined();
    expect(offerFor('1.1.0', 'v1.0.9').update).toBe('unknown');
    expect(offerFor('garbage', 'v1.0.9').update).toBe('unknown');
    // Development builds never get an automatic claim.
    expect(offerFor('1.0.0+3.gabc1234.dirty', 'v2.0.0')).toEqual(expect.objectContaining({ update: 'development' }));
    expect(offerFor('1.0.0+3.gabc1234.dirty', 'v2.0.0').offer).toBeUndefined();
    expect(parseReleases(snapshot({}, { offer: { ...info('v1.0.0'), tag: 'extension-v1.0.0' } }))!.desktop.update).toBe('unknown');
  });
  it.each([['checking', true], ['empty', true], ['unsupported', true], ['error', true], ['stale', true], ['fresh', false]] as const)(
    'claims desktop up to date only for a fresh complete check: %s, complete %s', (state, complete) => {
      expect(parseReleases(snapshot({ state, complete }, { update: 'up_to_date', offer: undefined }))!.desktop.update).toBe('unknown');
    });
  it('does not keep an up-to-date claim from a failed or old check', () => {
    expect(parseReleases(snapshot({ state: 'error', error: 'network' }, { update: 'up_to_date', offer: undefined }))!.desktop.update).toBe('unknown');
    expect(parseReleases(snapshot({ state: 'stale' }, { update: 'up_to_date', offer: undefined }))!.desktop.update).toBe('unknown');
    expect(parseReleases(snapshot({}, { update: 'up_to_date', offer: undefined }))!.desktop.update).toBe('up_to_date');
  });
  it('bounds the reported retry wait and counts it down locally', () => {
    expect(parseReleases(snapshot({ retry_after_seconds: 10 ** 9 }))!.retry_after_seconds).toBe(7 * 86_400);
    expect(parseReleases(snapshot({ retry_after_seconds: 0 }))!.retry_after_seconds).toBeUndefined();
    const value = { ...metadata(snapshot({ retry_after_seconds: 60 })), receivedAt: 1_000_000 };
    expect(retryAfter(value, 1_000_000)).toBe(60);
    expect(retryAfter(value, 1_030_500)).toBe(30);
    expect(retryAfter(value, 1_061_000)).toBe(0);
    expect(retryAfter(undefined, 0)).toBe(0);
  });
  it('compares metadata without its arrival time', () => {
    expect(sameReleases(metadata(snapshot()), { ...metadata(snapshot()), receivedAt: 1 })).toBe(true);
    expect(sameReleases(metadata(snapshot()), metadata(snapshot({ state: 'checking' })))).toBe(false);
    expect(sameReleases(undefined, undefined)).toBe(true);
    const waiting = metadata(snapshot({ retry_after_seconds: 30 }));
    expect(sameReleases(waiting, { ...waiting })).toBe(false);
  });
});

describe('release notices', () => {
  const show: ReleasePreferences = { notices: true, dismissed: {} };
  it('shows a newer desktop release and a newer extension release with store-lag wording', () => {
    const notices = releaseNotices(metadata(snapshot({ extension: info('extension-v0.6.0') })), '0.5.10', show);
    expect(notices.map(notice => notice.component)).toEqual(['desktop', 'extension']);
    expect(notices[0]!.title).toBe('Boltwarden desktop 1.0.0 is available');
    expect(notices[1]!.title).toBe('Boltwarden extension 0.6.0 was published on GitHub');
    expect(notices[1]!.detail).toContain('Browser store updates may still be pending');
    expect(notices[1]!.release.url).toBe('https://github.com/vleeuwenmenno/boltwarden/releases/tag/extension-v0.6.0');
  });
  it('compares the extension numerically with the running version', () => {
    const releases = parseReleases(snapshot({ extension: info('extension-v0.5.10') }))!;
    expect(extensionStatus(releases, '0.5.9')).toBe('available');
    expect(extensionStatus(releases, '0.5.10')).toBe('up_to_date');
    expect(extensionStatus(releases, '0.6.0')).toBe('up_to_date');
    expect(extensionStatus(releases, 'dev')).toBe('unknown');
    // Only a fresh and complete list proves nothing newer exists.
    expect(extensionStatus({ ...releases, complete: false }, '0.5.10')).toBe('unknown');
    expect(extensionStatus({ ...releases, state: 'stale' }, '0.5.10')).toBe('unknown');
    expect(extensionStatus({ ...releases, state: 'error' }, '0.5.9')).toBe('available');
    expect(extensionStatus({ ...releases, extension: undefined }, '0.5.10')).toBe('unknown');
  });
  it('honors per-component dismissals and the notice switch', () => {
    const value = metadata(snapshot({ extension: info('extension-v0.6.0') }));
    expect(releaseNotices(value, '0.5.10', { notices: true, dismissed: { desktop: '1.0.0' } }).map(notice => notice.component)).toEqual(['extension']);
    expect(releaseNotices(value, '0.5.10', { notices: true, dismissed: { extension: '0.6.0' } }).map(notice => notice.component)).toEqual(['desktop']);
    // A dismissal is per version: a later version shows again.
    expect(releaseNotices(metadata(snapshot({ extension: info('extension-v0.6.1') })), '0.5.10', { notices: true, dismissed: { extension: '0.6.0' } })).toHaveLength(2);
    expect(releaseNotices(value, '0.5.10', { notices: false, dismissed: {} })).toEqual([]);
    expect(releaseNotices({ receivedAt: 0, revision: 1 }, '0.5.10', show)).toEqual([]);
    expect(releaseNotices(undefined, '0.5.10', show)).toEqual([]);
  });
  it('shows a desktop notice independently of a dismissal on the desktop', () => {
    expect(releaseNotices(metadata(snapshot({}, { dismissed: true })), '0.5.10', show).map(notice => notice.component)).toEqual(['desktop']);
  });
});

function fakeStorage() {
  const data: Record<string, unknown> = {};
  return { data, local: { get: vi.fn(async (key: string) => key in data ? { [key]: data[key] } : {}), set: vi.fn(async (items: Record<string, unknown>) => { Object.assign(data, items); }) } };
}

describe('release preferences', () => {
  it('keeps one valid dismissed version per component', () => {
    expect(parseReleasePreferences(undefined)).toEqual(DEFAULT_RELEASE_PREFERENCES);
    expect(parseReleasePreferences({ notices: 'no', dismissed: { desktop: 'v1', extension: '0.5.10-rc.1', other: '1.0.0' } })).toEqual(DEFAULT_RELEASE_PREFERENCES);
    expect(parseReleasePreferences({ notices: false, dismissed: { desktop: '1.0.0-rc.6', extension: '0.6.0' } }))
      .toEqual({ notices: false, dismissed: { desktop: '1.0.0-rc.6', extension: '0.6.0' } });
  });
  it('persists dismissals per component and replaces older ones', async () => {
    const storage = fakeStorage();
    await Promise.all([dismissRelease(storage, 'desktop', '1.0.0'), dismissRelease(storage, 'extension', '0.6.0'), setReleaseNotices(storage, false)]);
    expect(await readReleasePreferences(storage)).toEqual({ notices: false, dismissed: { desktop: '1.0.0', extension: '0.6.0' } });
    await dismissRelease(storage, 'extension', '0.6.1');
    expect((await readReleasePreferences(storage)).dismissed).toEqual({ desktop: '1.0.0', extension: '0.6.1' });
    expect(Object.keys(storage.data)).toEqual(['release-notices']);
  });
});

describe('release summary', () => {
  const NOW_MS = NOW * 1000;
  const current = (overrides: Record<string, unknown> = {}, extra: Partial<ReleaseMetadata> = {}) =>
    ({ releases: parseReleases(snapshot({ extension: info('extension-v0.5.10'), ...overrides }, { update: 'up_to_date', offer: undefined }))!, receivedAt: NOW_MS, revision: 1, ...extra });
  it('claims both components current only after a fresh, complete, answered check', () => {
    expect(releaseSummary(current(), '0.5.10')).toEqual({ desktop: 'up_to_date', extension: 'up_to_date', checking: false });
    for (const value of [current({ state: 'checking' }), current({ state: 'empty' }), current({ state: 'unsupported' }), current({ state: 'error', error: 'network' }),
      current({ state: 'stale' }), current({ complete: false }), current({}, { failed: true })]) {
      const summary = releaseSummary(value, '0.5.10');
      expect(summary.desktop).toBe('unknown'); expect(summary.extension).toBe('unknown');
    }
    expect(releaseSummary(current(), '0.5.10', true)).toMatchObject({ desktop: 'unknown', extension: 'unknown' });
  });
  it('keeps known newer releases when currentness is withdrawn', () => {
    const value = { releases: parseReleases(snapshot({ state: 'error', error: 'network', extension: info('extension-v0.6.0') }))!, receivedAt: NOW_MS, revision: 1, failed: true as const };
    expect(releaseSummary(value, '0.5.10', true)).toEqual({ desktop: 'available', extension: 'available', checking: false });
    expect(releaseNotices(value, '0.5.10', { notices: true, dismissed: {} })).toHaveLength(2);
  });
  it('stops reporting a check in progress once the page gave up waiting', () => {
    expect(releaseSummary(current({ state: 'checking' }), '0.5.10').checking).toBe(true);
    expect(releaseSummary(current({ state: 'checking' }), '0.5.10', true).checking).toBe(false);
  });
});
