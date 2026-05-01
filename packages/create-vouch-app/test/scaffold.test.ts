/**
 * Unit tests for the scaffolder — uses fixture template trees in tmpdir
 * to avoid coupling to the shipped templates' contents. The actual
 * shipped templates are exercised end-to-end by running the CLI binary.
 */
import { afterEach, describe, expect, it } from 'vitest';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scaffold } from '../src/scaffold.js';

interface Trial {
  template: string;
  target: string;
  cleanup: () => void;
}

function makeTrial(): Trial {
  const root = mkdtempSync(join(tmpdir(), 'create-vouch-app-test-'));
  const template = join(root, 'template');
  const target = join(root, 'target');
  mkdirSync(template, { recursive: true });
  return {
    template,
    target,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

describe('scaffold()', () => {
  let trial: Trial | null = null;
  afterEach(() => {
    trial?.cleanup();
    trial = null;
  });

  it('copies plain files and substitutes {{name}} / {{description}}', () => {
    trial = makeTrial();
    writeFileSync(
      join(trial.template, 'package.json'),
      JSON.stringify({ name: '{{name}}', description: '{{description}}' }),
    );
    writeFileSync(join(trial.template, 'README.md'), '# {{name}}\n\n{{description}}');

    scaffold({
      name: 'my-saas',
      description: 'A test app',
      template_dir: trial.template,
      target_dir: trial.target,
    });

    const pkg = JSON.parse(readFileSync(join(trial.target, 'package.json'), 'utf8'));
    expect(pkg.name).toBe('my-saas');
    expect(pkg.description).toBe('A test app');

    const readme = readFileSync(join(trial.target, 'README.md'), 'utf8');
    expect(readme).toContain('# my-saas');
    expect(readme).toContain('A test app');
  });

  it('renames _gitignore -> .gitignore and _env.example -> .env.example', () => {
    trial = makeTrial();
    writeFileSync(join(trial.template, '_gitignore'), 'node_modules\n');
    writeFileSync(join(trial.template, '_env.example'), 'PORT=8080\n');

    scaffold({
      name: 'x',
      template_dir: trial.template,
      target_dir: trial.target,
    });

    const entries = readdirSync(trial.target);
    expect(entries).toContain('.gitignore');
    expect(entries).toContain('.env.example');
    expect(entries).not.toContain('_gitignore');
  });

  it('preserves nested directory structure', () => {
    trial = makeTrial();
    mkdirSync(join(trial.template, 'src', 'lib'), { recursive: true });
    writeFileSync(join(trial.template, 'src', 'index.ts'), 'export {};');
    writeFileSync(join(trial.template, 'src', 'lib', 'util.ts'), 'export const x = 1;');

    scaffold({
      name: 'x',
      template_dir: trial.template,
      target_dir: trial.target,
    });

    expect(readFileSync(join(trial.target, 'src', 'index.ts'), 'utf8')).toBe('export {};');
    expect(readFileSync(join(trial.target, 'src', 'lib', 'util.ts'), 'utf8')).toBe(
      'export const x = 1;',
    );
  });

  it('throws when template directory does not exist', () => {
    trial = makeTrial();
    expect(() =>
      scaffold({
        name: 'x',
        template_dir: '/no/such/path/' + Date.now(),
        target_dir: trial!.target,
      }),
    ).toThrow(/Template not found/);
  });

  it('refuses to scaffold into a non-empty target by default', () => {
    trial = makeTrial();
    writeFileSync(join(trial.template, 'a.txt'), 'hi');
    mkdirSync(trial.target, { recursive: true });
    writeFileSync(join(trial.target, 'existing.txt'), 'pre-existing');

    expect(() =>
      scaffold({
        name: 'x',
        template_dir: trial!.template,
        target_dir: trial!.target,
      }),
    ).toThrow(/not empty/);
  });

  it('overwrites a non-empty target when fail_if_non_empty is false', () => {
    trial = makeTrial();
    writeFileSync(join(trial.template, 'a.txt'), 'fresh');
    mkdirSync(trial.target, { recursive: true });
    writeFileSync(join(trial.target, 'existing.txt'), 'pre-existing');

    const out = scaffold({
      name: 'x',
      template_dir: trial.template,
      target_dir: trial.target,
      fail_if_non_empty: false,
    });

    expect(out.files_written).toBe(1);
    // The existing file is left untouched (we don't delete; we add).
    expect(readFileSync(join(trial.target, 'existing.txt'), 'utf8')).toBe('pre-existing');
    expect(readFileSync(join(trial.target, 'a.txt'), 'utf8')).toBe('fresh');
  });

  it('does not corrupt binary files (here: a tiny PNG-ish blob)', () => {
    trial = makeTrial();
    const binary = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    writeFileSync(join(trial.template, 'logo.png'), binary);

    scaffold({
      name: 'x',
      template_dir: trial.template,
      target_dir: trial.target,
    });

    const written = readFileSync(join(trial.target, 'logo.png'));
    expect(Buffer.compare(written, binary)).toBe(0);
  });
});
