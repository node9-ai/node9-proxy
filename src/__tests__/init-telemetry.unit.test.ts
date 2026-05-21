import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { buildTelemetryPayload } from '../cli/commands/init.js';
import { node9Version } from '../setup.js';

describe('init telemetry payload', () => {
  // Prior bug: telemetry sent `node9_version: 'unknown'` for every global
  // install because `process.env.npm_package_version` is only populated by
  // npm-script invocations. Fix replaces that read with `node9Version()`,
  // which reads the shipped package.json relative to the CLI binary.
  describe('node9_version', () => {
    it('returns a real version string, not the literal "unknown"', () => {
      expect(node9Version()).not.toBe('unknown');
    });

    it('matches the version field in the shipped package.json', () => {
      const pkg = JSON.parse(
        fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf-8')
      ) as { version: string };
      expect(node9Version()).toBe(pkg.version);
    });

    it('matches semver shape (X.Y.Z optional prerelease)', () => {
      expect(node9Version()).toMatch(/^\d+\.\d+\.\d+(-[\w.]+)?$/);
    });
  });

  describe('buildTelemetryPayload', () => {
    it('returns the expected event name', () => {
      expect(buildTelemetryPayload([], true).event).toBe('init_completed');
    });

    it('includes detected agents verbatim', () => {
      expect(buildTelemetryPayload(['claude', 'gemini'], true).agents_detected).toEqual([
        'claude',
        'gemini',
      ]);
    });

    it('uses process.platform for os', () => {
      expect(buildTelemetryPayload([], true).os).toBe(process.platform);
    });

    it('resolves node9_version via node9Version() (no env-var fallback)', () => {
      // Regression: if someone reintroduces process.env.npm_package_version,
      // this assertion catches the regression because the env var is
      // undefined when running tests via `npm test` (vitest is the active
      // script, not the package).
      expect(buildTelemetryPayload([], true).node9_version).toBe(node9Version());
      expect(buildTelemetryPayload([], true).node9_version).not.toBe('unknown');
    });

    it('threads first_install through to the payload', () => {
      expect(buildTelemetryPayload([], true).first_install).toBe(true);
      expect(buildTelemetryPayload([], false).first_install).toBe(false);
    });
  });
});
