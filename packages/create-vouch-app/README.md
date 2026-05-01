# create-vouch-app

Scaffold a working [Vouch](https://github.com/shizhigu/agent-auth) project in one command.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

## Usage

```bash
npx create-vouch-app my-saas
```

That creates `my-saas/` with a working Express SaaS template wired up to Vouch — Postgres + Redis docker-compose, .env scaffolding, migrate scripts, the lib's middleware mounted on `/agent-auth`, and an example protected route.

```bash
cd my-saas
cp .env.example .env
npm install
docker compose up -d
npx vouch migrate up
npm run dev
# -> my-saas listening on http://localhost:8080
```

## Templates

```bash
npx create-vouch-app my-saas                    # default: saas-express
npx create-vouch-app my-agent --template agent  # Node script using @vouch/client
```

| Template       | What you get                                                                  |
|----------------|-------------------------------------------------------------------------------|
| `saas-express` | Express SaaS using `vouch()` + `auth.express.mount(app)`. Includes docker-compose for local Postgres/Redis, `.env.example`, npm scripts wired to `@vouch/cli` for migrations. |
| `agent`        | Node script using `@vouch/client`'s one-shot `register()` flow. Includes `.env.example` with the SaaS URL.                                                                  |

## Options

```
--template <name>     Default: saas-express
--description <text>  Used in the generated package.json + README
--force               Overwrite a non-empty target directory
--version             Print the scaffolder version
--help                Show usage
```

## Programmatic use

```ts
import { scaffold } from 'create-vouch-app';

scaffold({
  name: 'my-saas',
  template_dir: '/abs/path/to/template',
  target_dir: '/abs/path/to/output',
});
```

## License

[MIT](../../LICENSE) © 2026 Agentic Flow LLC
