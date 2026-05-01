/**
 * Scaffolder logic — copies a template directory to a target, replacing
 * placeholders inline. Pure functions; the CLI shell wraps these.
 *
 * Templates live under `packages/create-vouch-app/templates/<name>/`. Files
 * may use the `{{name}}` and `{{description}}` placeholders, which are
 * substituted at copy time.
 */
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';

export interface ScaffoldOptions {
  /** Project name — substituted for `{{name}}`. */
  readonly name: string;
  /** Project description — substituted for `{{description}}`. */
  readonly description?: string;
  /** Absolute path to the template's root directory. */
  readonly template_dir: string;
  /** Absolute path to the target. Created if it doesn't exist. */
  readonly target_dir: string;
  /** If true, fail when target_dir is non-empty. Default true. */
  readonly fail_if_non_empty?: boolean;
  /** Optional logger; defaults to stderr. */
  readonly logger?: (line: string) => void;
}

export interface ScaffoldResult {
  readonly files_written: number;
  readonly target_dir: string;
}

const TEXT_FILE_EXTS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.json',
  '.md',
  '.yml',
  '.yaml',
  '.env',
  '.gitignore',
  '.gitattributes',
  '.npmrc',
  '.dockerignore',
  '.editorconfig',
  '.eslintrc',
  '.prettierrc',
  '',
]);

const PLACEHOLDER_NAME = /\{\{\s*name\s*\}\}/g;
const PLACEHOLDER_DESC = /\{\{\s*description\s*\}\}/g;

export function scaffold(opts: ScaffoldOptions): ScaffoldResult {
  const log = opts.logger ?? ((line: string) => process.stderr.write(line + '\n'));
  const description = opts.description ?? `A Vouch app called ${opts.name}.`;

  if (!isDirectory(opts.template_dir)) {
    throw new Error(`Template not found: ${opts.template_dir}`);
  }

  if (existsSync(opts.target_dir) && !isEmptyDir(opts.target_dir)) {
    if (opts.fail_if_non_empty !== false) {
      throw new Error(
        `Target directory ${opts.target_dir} is not empty. Pass --force to overwrite.`,
      );
    }
  }
  mkdirSync(opts.target_dir, { recursive: true });

  let count = 0;
  walk(opts.template_dir, (sourceFile) => {
    const rel = relative(opts.template_dir, sourceFile);
    // Templates ship `_gitignore` etc. instead of `.gitignore` so npm
    // doesn't strip them from the published tarball. Rename on copy.
    const targetRel = rel
      .split('/')
      .map((part) => (part.startsWith('_') ? '.' + part.slice(1) : part))
      .join('/');
    const targetFile = join(opts.target_dir, targetRel);
    mkdirSync(dirname(targetFile), { recursive: true });

    if (isTextFile(sourceFile)) {
      const raw = readFileSync(sourceFile, 'utf8');
      const rendered = raw
        .replace(PLACEHOLDER_NAME, opts.name)
        .replace(PLACEHOLDER_DESC, description);
      writeFileSync(targetFile, rendered);
    } else {
      // Binary copy via Buffer
      writeFileSync(targetFile, readFileSync(sourceFile));
    }
    count++;
  });

  log(`Wrote ${count} files to ${opts.target_dir}`);
  return { files_written: count, target_dir: opts.target_dir };
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function isDirectory(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function existsSync(p: string): boolean {
  try {
    statSync(p);
    return true;
  } catch {
    return false;
  }
}

function isEmptyDir(p: string): boolean {
  try {
    return readdirSync(p).length === 0;
  } catch {
    return true;
  }
}

function isTextFile(path: string): boolean {
  const lastDot = path.lastIndexOf('.');
  const lastSlash = path.lastIndexOf('/');
  const ext = lastDot > lastSlash ? path.slice(lastDot).toLowerCase() : '';
  return TEXT_FILE_EXTS.has(ext);
}

function walk(dir: string, fn: (file: string) => void): void {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      walk(full, fn);
    } else {
      fn(full);
    }
  }
}
