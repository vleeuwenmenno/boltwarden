import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseWire, webUrl, type Request } from '../lib/protocol';

describe('wire contract', () => {
  it('uses the shared Rust request fixture', () => {
    const fixture = JSON.parse(readFileSync(new URL('../protocol/fixtures/list-matches.json', import.meta.url), 'utf8'));
    const request: Request & { version: number; id: string } = { version: 1, id: 'match-1', type: 'ListMatches', top_url: 'https://example.com/login', frame_url: 'https://example.com/login', document_id: 'document-1', offset: 0 };
    expect(fixture).toEqual(request);
  });
  it('validates credentials and metadata without accepting unknown response types', () => {
    expect(parseWire({ version: 1, id: '1', type: 'Credentials', username: 'user', password: 'secret', document_id: 'doc', epoch: 1 }).type).toBe('Credentials');
    expect(() => parseWire({ version: 2, type: 'Locked', epoch: 1 })).toThrow();
    expect(() => parseWire({ version: 1, type: 'Credentials', username: [], password: 'secret', document_id: 'doc', epoch: 1 })).toThrow();
    expect(() => parseWire({ version: 1, type: 'Eval', code: 'bad' })).toThrow();
    expect(() => parseWire({ version: 1, type: 'Matches', items: [{}], epoch: 1, next_offset: null })).toThrow();
  });
  it('accepts invalidation events without a request id', () => {
    expect(parseWire({ version: 1, type: 'MatchesChanged', epoch: 4 })).toEqual({ version: 1, type: 'MatchesChanged', epoch: 4 });
    expect(() => parseWire({ version: 1, type: 'Locked', epoch: 4, id: 'request' })).toThrow();
    expect(parseWire({ version: 1, id: 'matches', type: 'Matches', items: [], epoch: 1, next_offset: null, warning: null }).type).toBe('Matches');
  });
  it('rejects URLs outside the supported website boundary', () => {
    for (const url of ['file:///etc/passwd', 'about:blank', 'data:text/html,x', 'https://good.com@evil.com/', 'http://u:p@example.com/']) expect(webUrl(url)).toBeNull();
    expect(webUrl('https://example.com:8443/login')?.origin).toBe('https://example.com:8443');
  });
});


describe('verification code wire contract', () => {
  it('validates code, expiry, and document metadata', () => {
    const response = {version: 1, id: 'code', type: 'Totp', code: '012345', expires_at: 123456789, document_id: 'doc', epoch: 1};
    expect(parseWire(response).type).toBe('Totp');
    for (const invalid of [{code: 'secret'}, {code: '123'}, {expires_at: -1}, {expires_at: 1.5}, {document_id: null}]) {
      expect(() => parseWire({...response, ...invalid})).toThrow();
    }
  });
});
