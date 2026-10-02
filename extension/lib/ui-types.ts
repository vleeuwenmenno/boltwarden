import type { NativeSnapshot } from './native';
import type { Match } from './protocol';

export interface UiFrame { kind?: 'login' | 'totp' | 'card'; targetId: string; origin: string; crossOrigin: boolean; items: Match[]; more: boolean }
export interface UiPage { frames: UiFrame[]; message?: string; warning?: string }
export interface UiState { connection: NativeSnapshot; fingerprint: string }
export interface UiStateChange { type: 'state-changed'; connection: NativeSnapshot; reason: 'state' | 'matches' | 'page' }
export type UiResult<T> = { ok: true; value: T } | { ok: false; error: string };
