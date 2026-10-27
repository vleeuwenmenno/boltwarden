// Public release information that the paired desktop app caches from GitHub. The extension
// never contacts GitHub itself: it only reads what the desktop sends in Status responses.
// Everything here is untrusted input, so each field is validated on its own and a malformed
// field is dropped without affecting the vault connection.

export const REPOSITORY_RELEASES = 'https://github.com/vleeuwenmenno/boltwarden/releases/tag/';
/** Publish and check times outside 2015..2200 are treated as corrupt (as on the desktop). */
const MIN_TIMESTAMP = 1_420_070_400;
const MAX_TIMESTAMP = 7_258_118_400;
const MAX_TAG_LENGTH = 40;
const MAX_INSTALLED_LENGTH = 64;
/** A rate-limit wait longer than this is shown as this. */
const MAX_RETRY_AFTER = 7 * 86_400;

export type CheckState = 'unsupported' | 'empty' | 'checking' | 'fresh' | 'stale' | 'error';
export type ReleaseError = 'network' | 'rate_limited' | 'http_status' | 'too_large' | 'invalid_response';
export type DesktopUpdate = 'available' | 'up_to_date' | 'unknown' | 'development';
export type Component = 'desktop' | 'extension';

export interface ReleaseInfo { version: string; tag: string; url: string; published_at: number }
export interface DesktopReleases {
  installed: string; update: DesktopUpdate; offer?: ReleaseInfo; dismissed: boolean;
  stable?: ReleaseInfo; preview?: ReleaseInfo;
}
export interface Releases {
  state: CheckState; auto_check: boolean; checked_at?: number; complete: boolean; error?: ReleaseError;
  retry_after_seconds?: number; desktop: DesktopReleases; extension?: ReleaseInfo;
}
/** What one authenticated Status response said about releases. `releases` is missing when the
 * desktop predates release checks; `invalid` when it sent release data that did not validate;
 * `failed` when the latest Status request failed, so the earlier data can no longer prove that
 * nothing newer exists. `revision` increases with every change on this background, so pages
 * can ignore answers older than what they already show. */
export interface ReleaseMetadata { desktopVersion?: string; releases?: Releases; invalid?: true; failed?: true; receivedAt: number; revision: number }

export interface DesktopVersion { major: number; minor: number; patch: number; rc?: number }
export type ExtensionVersion = Omit<DesktopVersion, 'rc'>;

const NUMBER = '(0|[1-9]\\d{0,8})';
const DESKTOP = new RegExp(`^${NUMBER}\\.${NUMBER}\\.${NUMBER}(?:-rc\\.([1-9]\\d{0,8}))?$`);
const EXTENSION = new RegExp(`^${NUMBER}\\.${NUMBER}\\.${NUMBER}$`);

/** `X.Y.Z` or `X.Y.Z-rc.N`: numeric parts without leading zeros, N from 1. */
export function parseDesktopVersion(text: unknown): DesktopVersion | undefined {
  const match = typeof text === 'string' ? DESKTOP.exec(text) : null;
  if (!match) return undefined;
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]), ...(match[4] ? { rc: Number(match[4]) } : {}) };
}
/** Browser stores only accept numeric `X.Y.Z` extension versions. */
export function parseExtensionVersion(text: unknown): ExtensionVersion | undefined {
  const match = typeof text === 'string' ? EXTENSION.exec(text) : null;
  return match ? { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) } : undefined;
}
/** A final release sorts after all of its release candidates. */
export function compareVersions(left: DesktopVersion, right: DesktopVersion): number {
  return left.major - right.major || left.minor - right.minor || left.patch - right.patch
    || (left.rc === right.rc ? 0 : left.rc === undefined ? 1 : right.rc === undefined ? -1 : left.rc - right.rc);
}

const record = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const timestamp = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= MIN_TIMESTAMP && (value as number) <= MAX_TIMESTAMP;
const optional = <T>(value: T | undefined, key: string) => value === undefined ? {} : { [key]: value };

/** A release of one component, or nothing. The link is rebuilt from the validated tag rather
 * than trusted, and must match what the desktop sent exactly. */
export function parseReleaseInfo(value: unknown, component: Component): ReleaseInfo | undefined {
  if (!record(value) || typeof value.version !== 'string' || typeof value.tag !== 'string'
    || typeof value.url !== 'string' || !timestamp(value.published_at) || value.tag.length > MAX_TAG_LENGTH) return undefined;
  const version = component === 'desktop' ? parseDesktopVersion(value.version) : parseExtensionVersion(value.version);
  const tag = `${component === 'desktop' ? 'v' : 'extension-v'}${value.version}`;
  const url = REPOSITORY_RELEASES + tag;
  if (!version || value.tag !== tag || value.url !== url) return undefined;
  return { version: value.version, tag, url, published_at: value.published_at };
}

const CHECK_STATES: readonly CheckState[] = ['unsupported', 'empty', 'checking', 'fresh', 'stale', 'error'];
const ERRORS: readonly ReleaseError[] = ['network', 'rate_limited', 'http_status', 'too_large', 'invalid_response'];
const UPDATES: readonly DesktopUpdate[] = ['available', 'up_to_date', 'unknown', 'development'];
const printable = (value: unknown, max: number): value is string => typeof value === 'string' && value.length > 0 && value.length <= max && /^[\x21-\x7e]+$/.test(value);

/** Installed desktop builds with `+metadata` come from a source checkout and are never offered updates. */
export function installedDesktop(text: string) {
  const [base, metadata] = text.split('+', 2);
  return { version: parseDesktopVersion(base), development: metadata !== undefined };
}

function parseDesktop(value: unknown, state: CheckState, complete: boolean): DesktopReleases | undefined {
  if (!record(value) || !printable(value.installed, MAX_INSTALLED_LENGTH) || typeof value.dismissed !== 'boolean'
    || !UPDATES.includes(value.update as DesktopUpdate)) return undefined;
  const installed = installedDesktop(value.installed);
  const stable = parseReleaseInfo(value.stable, 'desktop');
  let update = value.update as DesktopUpdate;
  let offer = parseReleaseInfo(value.offer, 'desktop');
  if (installed.development) update = 'development';
  // Only a recent, successful and complete check proves there is nothing newer.
  if (update === 'up_to_date' && !(state === 'fresh' && complete)) update = 'unknown';
  // Offer only a release that is newer than this installation, on its channel: stable
  // installations never see release candidates.
  const offered = offer && parseDesktopVersion(offer.version)!;
  if (update !== 'available' || !offered || !installed.version || compareVersions(offered, installed.version) <= 0
    || (installed.version.rc === undefined && offered.rc !== undefined)) {
    offer = undefined;
    if (update === 'available') update = 'unknown';
  }
  return { installed: value.installed, update, dismissed: value.dismissed, ...optional(offer, 'offer'),
    ...optional(stable && parseDesktopVersion(stable.version)!.rc === undefined ? stable : undefined, 'stable'),
    ...optional(parseReleaseInfo(value.preview, 'desktop'), 'preview') };
}

/** Validated release state, or undefined when its required fields are malformed. */
export function parseReleases(value: unknown): Releases | undefined {
  if (!record(value) || !CHECK_STATES.includes(value.state as CheckState) || typeof value.auto_check !== 'boolean'
    || typeof value.complete !== 'boolean') return undefined;
  const desktop = parseDesktop(value.desktop, value.state as CheckState, value.complete);
  if (!desktop) return undefined;
  const retry = value.retry_after_seconds;
  return {
    state: value.state as CheckState, auto_check: value.auto_check, complete: value.complete, desktop,
    ...optional(timestamp(value.checked_at) ? value.checked_at : undefined, 'checked_at'),
    ...optional(ERRORS.includes(value.error as ReleaseError) ? value.error as ReleaseError : undefined, 'error'),
    ...optional(Number.isSafeInteger(retry) && (retry as number) > 0 ? Math.min(retry as number, MAX_RETRY_AFTER) : undefined, 'retry_after_seconds'),
    ...optional(parseReleaseInfo(value.extension, 'extension'), 'extension'),
  };
}

/** Release metadata from a Status response that already passed core validation. */
export function statusReleases(status: { desktop_version?: unknown; releases?: unknown }, now: number, revision = 0): ReleaseMetadata {
  const releases = status.releases === undefined || status.releases === null ? undefined : parseReleases(status.releases);
  return {
    ...optional(printable(status.desktop_version, MAX_INSTALLED_LENGTH) ? status.desktop_version : undefined, 'desktopVersion'),
    ...optional(releases, 'releases'),
    ...(releases === undefined && status.releases !== undefined && status.releases !== null ? { invalid: true as const } : {}),
    receivedAt: now, revision,
  };
}

/** Same release information, ignoring when it arrived. A reported wait counts from its
 * arrival, so metadata with one is always treated as new. */
export function sameReleases(left: ReleaseMetadata | undefined, right: ReleaseMetadata | undefined) {
  if (left?.releases?.retry_after_seconds !== undefined || right?.releases?.retry_after_seconds !== undefined) return false;
  const strip = (value?: ReleaseMetadata) => value && JSON.stringify({ ...value, receivedAt: 0, revision: 0 });
  return strip(left) === strip(right);
}

/** Seconds left before a manual check is worth trying again, if the desktop said to wait. */
export function retryAfter(metadata: ReleaseMetadata | undefined, now: number) {
  const seconds = metadata?.releases?.retry_after_seconds;
  return seconds === undefined ? 0 : Math.max(0, Math.ceil(metadata!.receivedAt / 1000 + seconds - now / 1000));
}

// ---------------------------------------------------------------------------------------
// What to tell the user.

export type ExtensionStatus = 'available' | 'up_to_date' | 'unknown';
/** Compares the newest published extension release with the running extension's own version.
 * A newer release is always worth showing; "up to date" needs a fresh and complete list. */
export function extensionStatus(releases: Releases, running: string): ExtensionStatus {
  const current = parseExtensionVersion(running);
  const published = releases.extension && parseExtensionVersion(releases.extension.version);
  if (!current) return 'unknown';
  if (published && compareVersions(published, current) > 0) return 'available';
  return published && releases.complete && releases.state === 'fresh' ? 'up_to_date' : 'unknown';
}

/** What the options page may claim. "Up to date" needs a fresh, complete check, a successful
 * latest Status, and no check that ran out of time; known newer releases are always kept. */
export interface ReleaseSummary { desktop: DesktopUpdate; extension: ExtensionStatus; checking: boolean }
export function releaseSummary(metadata: ReleaseMetadata & { releases: Releases }, running: string, timedOut = false): ReleaseSummary {
  const { releases } = metadata;
  const certain = releases.state === 'fresh' && releases.complete && !metadata.failed && !timedOut;
  const extension = extensionStatus(releases, running);
  return {
    desktop: releases.desktop.update === 'up_to_date' && !certain ? 'unknown' : releases.desktop.update,
    extension: extension === 'up_to_date' && !certain ? 'unknown' : extension,
    checking: releases.state === 'checking' && !timedOut,
  };
}

export interface ReleaseNotice { component: Component; release: ReleaseInfo; title: string; detail: string }
/** Compact notices for newer releases that this browser has not dismissed. */
export function releaseNotices(metadata: ReleaseMetadata | undefined, running: string, preferences: ReleasePreferences): ReleaseNotice[] {
  const releases = metadata?.releases;
  if (!releases || !preferences.notices) return [];
  const notices: ReleaseNotice[] = [];
  const offer = releases.desktop.offer;
  if (releases.desktop.update === 'available' && offer && preferences.dismissed.desktop !== offer.version) {
    notices.push({ component: 'desktop', release: offer, title: `Boltwarden desktop ${offer.version} is available`,
      detail: `You have ${releases.desktop.installed}. Update the desktop app to get it.` });
  }
  const extension = releases.extension;
  if (extension && extensionStatus(releases, running) === 'available' && preferences.dismissed.extension !== extension.version) {
    notices.push({ component: 'extension', release: extension, title: `Boltwarden extension ${extension.version} was published on GitHub`,
      detail: `You have ${running}. Browser store updates may still be pending; your browser installs it once the store has it.` });
  }
  return notices;
}

export const ERROR_TEXT: Record<ReleaseError, string> = {
  network: 'GitHub could not be reached',
  rate_limited: 'GitHub asked to retry later',
  http_status: 'GitHub returned an error',
  too_large: 'the release list was too large',
  invalid_response: 'the release list could not be read',
};

// ---------------------------------------------------------------------------------------
// Preferences: whether to show notices, and one dismissed version per component. These only
// change what this browser displays; automatic checks are controlled in the desktop app.

export interface ReleasePreferences { notices: boolean; dismissed: Partial<Record<Component, string>> }
export const DEFAULT_RELEASE_PREFERENCES: ReleasePreferences = { notices: true, dismissed: {} };
const KEY = 'release-notices';

type Area = { get(key: string): Promise<Record<string, unknown>>; set(items: Record<string, unknown>): Promise<void> };
type Changes = { addListener(callback: (changes: Record<string, { newValue?: unknown }>, area: string) => void): void;
  removeListener(callback: (changes: Record<string, { newValue?: unknown }>, area: string) => void): void };
export type ReleaseStorage = { local?: Area; onChanged?: Changes };

export function parseReleasePreferences(value: unknown): ReleasePreferences {
  const stored = record(value) ? value : {};
  const dismissed = record(stored.dismissed) ? stored.dismissed : {};
  return {
    notices: typeof stored.notices === 'boolean' ? stored.notices : DEFAULT_RELEASE_PREFERENCES.notices,
    dismissed: {
      ...optional(parseDesktopVersion(dismissed.desktop) ? dismissed.desktop as string : undefined, 'desktop'),
      ...optional(parseExtensionVersion(dismissed.extension) ? dismissed.extension as string : undefined, 'extension'),
    },
  };
}

export async function readReleasePreferences(storage: ReleaseStorage | undefined) {
  try { return parseReleasePreferences((await storage?.local?.get(KEY))?.[KEY]); }
  catch { return structuredClone(DEFAULT_RELEASE_PREFERENCES); }
}

let writing: Promise<unknown> = Promise.resolve();
function writeReleasePreferences(storage: ReleaseStorage | undefined, change: (current: ReleasePreferences) => ReleasePreferences) {
  const next = writing.catch(() => {}).then(async () => {
    const value = parseReleasePreferences(change(await readReleasePreferences(storage)));
    await storage?.local?.set({ [KEY]: value });
    return value;
  });
  writing = next;
  return next;
}
export const setReleaseNotices = (storage: ReleaseStorage | undefined, notices: boolean) =>
  writeReleasePreferences(storage, current => ({ ...current, notices }));
/** Replaces any earlier dismissal for the component, so a later version shows again. */
export const dismissRelease = (storage: ReleaseStorage | undefined, component: Component, version: string) =>
  writeReleasePreferences(storage, current => ({ ...current, dismissed: { ...current.dismissed, [component]: version } }));

export function watchReleasePreferences(storage: ReleaseStorage | undefined, callback: (preferences: ReleasePreferences) => void) {
  let live = true;
  const listener = (changes: Record<string, { newValue?: unknown }>, area: string) => {
    if (live && area === 'local' && KEY in changes) callback(parseReleasePreferences(changes[KEY]!.newValue));
  };
  storage?.onChanged?.addListener(listener);
  void readReleasePreferences(storage).then(preferences => { if (live) callback(preferences); });
  return () => { live = false; storage?.onChanged?.removeListener(listener); };
}
