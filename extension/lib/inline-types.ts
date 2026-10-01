import type { NativeSnapshot } from './native';
import type { UiFrame } from './ui-types';

export type InlineAction = 'list' | 'fill' | 'more' | 'unlock' | 'dismiss' | 'open-popup';
export interface InlineValue { connection: NativeSnapshot; frame?: UiFrame; message?: string; warning?: string }
export interface InlineRequest {
  type: 'inline-request'; id: string; generation: string; action: InlineAction;
  token?: string; targetId?: string; itemId?: string;
}
export interface InlineResponse {
  type: 'inline-response'; id: string; generation: string; ok: boolean;
  value?: InlineValue; error?: string;
}
export interface InlineState {
  type: 'inline-state'; generation: string; connection: NativeSnapshot;
  reason: 'state' | 'matches' | 'page';
}
