import { describe, it, expect, afterEach } from 'vitest';
import { resolveConnectUrl } from '../cli/commands/connect';

describe('resolveConnectUrl', () => {
  const prev = process.env.NODE9_API_URL;
  afterEach(() => {
    if (prev === undefined) delete process.env.NODE9_API_URL;
    else process.env.NODE9_API_URL = prev;
  });

  it('uses --api-url when given (wins over env + default)', () => {
    process.env.NODE9_API_URL = 'https://x/api/v1/intercept';
    expect(resolveConnectUrl('http://localhost:9/cli/connect')).toBe(
      'http://localhost:9/cli/connect'
    );
  });

  it('derives from NODE9_API_URL by swapping /intercept → /cli/connect', () => {
    process.env.NODE9_API_URL = 'https://dev-api.node9.ai/api/v1/intercept';
    expect(resolveConnectUrl()).toBe('https://dev-api.node9.ai/api/v1/cli/connect');
  });

  it('tolerates a trailing slash on NODE9_API_URL', () => {
    process.env.NODE9_API_URL = 'https://dev-api.node9.ai/api/v1/intercept/';
    expect(resolveConnectUrl()).toBe('https://dev-api.node9.ai/api/v1/cli/connect');
  });

  it('falls back to the prod default when nothing is set', () => {
    delete process.env.NODE9_API_URL;
    expect(resolveConnectUrl()).toBe('https://api.node9.ai/api/v1/cli/connect');
  });
});
