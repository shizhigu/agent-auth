#!/usr/bin/env node
/**
 * `create-vouch-app` — scaffold a new Vouch project.
 *
 *   npx create-vouch-app my-saas
 *   npx create-vouch-app my-agent --template agent
 *
 * Templates ship inside this package under `templates/`. The CLI is
 * deliberately small (parseArgs + the `scaffold` helper) so the same
 * logic is reusable from a Node import.
 */
import { parseArgs } from 'node:util';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scaffold } from './scaffold.js';

export { scaffold } from './scaffold.js';
export type { ScaffoldOptions, ScaffoldResult } from './scaffold.js';

const VERSION = '0.0.0-dev';

const HELP = `create-vouch-app — scaffold a new Vouch project

USAGE
  npx create-vouch-app <name> [options]

OPTIONS
  --template <name>   Template to scaffold. One of:
                        saas-express  (default) Express SaaS using vouch()
                        agent                   Node script using @vouch/client
  --force             Overwrite a non-empty target directory
  --description <text>  One-line description (used in package.json + README)
  --version           Print the scaffolder version
  --help              Show this help

EXAMPLES
  npx create-vouch-app my-saas
  npx create-vouch-app my-agent --template agent
  npx create-vouch-app my-saas --description "Acme SaaS using Vouch"
`;

function main(argv: string[]): number {
  if (argv.length === 0) {
    process.stdout.write(HELP);
    return 0;
  }
  if (argv[0] === '--version' || argv[0] === '-v') {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (argv[0] === '--help' || argv[0] === '-h') {
    process.stdout.write(HELP);
    return 0;
  }

  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        template: { type: 'string', default: 'saas-express' },
        force: { type: 'boolean', default: false },
        description: { type: 'string' },
      },
      allowPositionals: true,
      strict: true,
    });
  } catch (err) {
    process.stderr.write(`Bad flags: ${(err as Error).message}\n`);
    return 64;
  }

  const positionals = parsed.positionals;
  if (positionals.length === 0) {
    process.stderr.write('Missing project name. Run `npx create-vouch-app <name>`.\n');
    return 64;
  }
  if (positionals.length > 1) {
    process.stderr.write(`Too many positional args: ${positionals.join(', ')}\n`);
    return 64;
  }
  const projectName = positionals[0]!;
  if (!/^[a-z0-9_-][a-z0-9_.-]*$/.test(projectName)) {
    process.stderr.write(
      `Invalid project name "${projectName}". Use lowercase letters, digits, dot, dash, underscore.\n`,
    );
    return 64;
  }

  const template =
    typeof parsed.values.template === 'string' ? parsed.values.template : 'saas-express';
  const force = parsed.values.force === true;
  const descFlag =
    typeof parsed.values.description === 'string' ? parsed.values.description : undefined;

  const here = dirname(fileURLToPath(import.meta.url));
  // dist is one level under the package root, so templates/ is at ../templates.
  const templateDir = resolve(here, '..', 'templates', template);
  const targetDir = isAbsolute(projectName) ? projectName : join(process.cwd(), projectName);

  try {
    scaffold({
      name: projectName,
      template_dir: templateDir,
      target_dir: targetDir,
      fail_if_non_empty: !force,
      ...(descFlag !== undefined ? { description: descFlag } : {}),
    });
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 1;
  }

  process.stdout.write(`
Scaffolded ${projectName} in ${targetDir} from template "${template}".

Next:
  cd ${projectName}
  cp .env.example .env
  npm install
  docker compose up -d        # if you scaffolded a SaaS
  npx vouch migrate up        # apply the schema
  npm run dev                 # start the SaaS

See ${projectName}/README.md for the full walkthrough.
`);
  return 0;
}

const code = main(process.argv.slice(2));
process.exit(code);
