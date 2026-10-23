import type { NativeSnapshot } from './native';
import type { Match } from './protocol';
import type { ReleaseMetadata } from './releases';

export interface UiFrame { kind?: 'login' | 'totp' | 'card'; targetId: string; origin: string; crossOrigin: boolean; items: Match[]; more: boolean }
export interface UiPage { frames: UiFrame[]; message?: string; warning?: string }
/** `build` is missing when the background predates build checks. */
export interface UiState { connection: NativeSnapshot; fingerprint: string; build?: string; releases?: ReleaseMetadata }
/** `releases` is only sent to the extension's own pages, never to content scripts. A `releases`
 * reason means only the release information changed. */
export interface UiStateChange { type: 'state-changed'; connection: NativeSnapshot; reason: 'state' | 'matches' | 'page' | 'releases'; releases?: ReleaseMetadata }
/** Answer to the `releases` action. */
export interface UiReleases { connection: NativeSnapshot; releases?: ReleaseMetadata }
export type UiResult<T> = { ok: true; value: T } | { ok: false; error: string };
