<div align="center">

# warden

**Security controls as decorators — for Fetch-API servers and the browser.**

[![ci](https://github.com/SanaAfshani/warden/actions/workflows/ci.yml/badge.svg)](https://github.com/SanaAfshani/warden/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![node](https://img.shields.io/badge/node-%E2%89%A522.12-brightgreen.svg)](#requirements)

[English](README.md) · [فارسی](README.fa.md)

</div>

---

Install a track's core plus only the plugins you need. Nothing is configured
globally, nothing reads an environment variable, and nothing runs unless you
put it in a chain.

```bash
# server
npm i @sanaafshani/warden-ssr @sanaafshani/warden-ssr-headers @sanaafshani/warden-ssr-authn

# browser
npm i @sanaafshani/warden-csr @sanaafshani/warden-csr-storage

# the rules that keep the unsafe APIs out of your code
npm i -D @sanaafshani/warden-csr-eslint-plugin
```

```ts
export const POST = chain()
  .use(secureHeaders())
  .use(limiter.limit({ scope: 'posts', limit: 30, windowSeconds: 60 }))
  .use(session.required())
  .use(access.require('post:create'))
  .use(body(PostSchema))
  .handle(async (_request, { principal, body }) =>
    Response.json(await createPost(principal.id, body)),
  );
```

`principal` and `body` exist on that context because the decorators above added
them. Remove `session.required()` and the line below it stops compiling — the
error names the missing key.

---

## Why decorators

A security layer usually arrives as middleware: a list in a config file, far
from the route it protects, applied by a framework you now depend on. You
cannot see from the route what guards it, the order is global, and "is this
endpoint rate-limited?" is answered by reading two files and guessing.

Here a control is an object that wraps a handler and returns the same shape.
That buys three things a middleware list cannot:

- **The order is the nesting, and it is local.** The chain is written next to
  the handler. What protects this route is what you can see.
- **The type system carries the context.** A decorator declares what it needs
  and what it adds. Asking for a permission check with no authentication above
  it is a compile error, not a 3am pager.
- **No framework.** A chain is a function `(Request) => Promise<Response>`.
  It runs on Next.js route handlers, Hono, Bun, Deno, Workers and Node,
  because that signature is all it uses.

## The two tracks

*SSR* and *CSR* here mean **server side** and **client side**: where the code
runs, not how pages are rendered. Neither track renders anything.

| Track | Core | Runs on | Plugins |
| --- | --- | --- | --- |
| **SSR** | `@sanaafshani/warden-ssr` | Any Fetch-API server | `headers` `ratelimit` `authn` `csrf` `access` `validate` `logging` `crypto` `ssrf` `upload` |
| **CSR** | `@sanaafshani/warden-csr` | The browser | `storage` `sanitize` `access` `sso` `eslint-plugin` |

Both cores have **zero dependencies** and contain no control of their own —
they are the contract, and every control is a plugin built on it.

The tracks share no code. An SSR plugin never pulls in browser code and vice
versa; a lint rule in this repo fails the build if one imports the other.
Every package name starts with its track, so `npm ls '@sanaafshani/warden-ssr*'`
shows exactly what a server installed.

### Browser composition

```ts
const store = decorate(
  webStorage('local'),
  namespaced('app'),              // outermost: key prefix
  expiring({ ttlSeconds: 3600 }), // deadline goes inside the ciphertext
  encrypted({ keyring }),
);
```

What is inside `encrypted` is what gets encrypted. With `expiring` outside it,
the deadline is part of the ciphertext and cannot be edited.

## The lint plugin

The library can make the safe thing easy. It cannot make the unsafe thing
impossible — `localStorage.setItem` and `dangerouslySetInnerHTML` are still one
line away, and they are shorter.

Five rules close that gap, and each declares its own **tier**:

| tier | rules | means |
| --- | --- | --- |
| **`required`** | `no-dangerous-html`, `no-dom-html-sink`, `require-safe-url` | guards an injection class nothing here mitigates at runtime |
| `recommended` | `no-raw-web-storage`, `no-unsafe-target-blank` | defence in depth — a second failure is needed before it becomes an incident |

```js
export default warden.enforce(            // outermost: it sees only what it is given
  { ...warden.configs.recommended, files: ['src/**/*.ts'] },

  warden.waive({
    rule: 'no-dangerous-html',
    files: ['src/components/SafeHtml.tsx'],
    reason: 'The one sink; DOMPurify runs on the line above it.',
  }),
);
```

ESLint gives a plugin no way to forbid an override — a flat config is an array
and the last entry wins. So `enforce()` reads the config and **refuses** one
that lowers a `required` rule, rather than silently re-enabling it and sending
you hunting for why your `'off'` did nothing. `waive()` is not a loophole: it
is the price list — a scope and a sentence, both greppable, both in the diff.

## Documentation

| | |
| --- | --- |
| [docs/getting-started.md](docs/getting-started.md) | Install, a first chain, a first store |
| [docs/ssr.md](docs/ssr.md) | The server contract, recommended order, writing a plugin |
| [docs/csr.md](docs/csr.md) | The browser contract, composition, writing a plugin |
| [packages/csr/eslint-plugin](packages/csr/eslint-plugin#readme) | The five rules, the tiers, `enforce` and `waive` |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability, and what this library does not cover |

Every package has its own README with the reasoning behind its control.

## What this does not do

Stated so nobody assumes coverage: MFA, a password-reset flow, a database, a
WAF, TLS, secrets-manager integration, and alerting are all out of scope.

Nothing in the CSR track is a trust boundary. It runs on a machine the user
controls: `access` decides what the UI shows, never what is allowed, and every
permission must be checked again by the server.

## Requirements

Node **≥ 22.12** (Node 20 is end-of-life, and `require(esm)` is what lets CJS
consumers load these packages). TypeScript is optional but the types are where
most of the value is.

## Repository

```
packages/ssr/<core|plugin>   server track
packages/csr/<core|plugin>   browser track (the lint rules are a CSR plugin)
docs/                        one document per track
tests/                       release checks: versions, peer ranges, LICENSE
```

```bash
npm ci
npm run build       # tsc -b, every package under its own tsconfig
npm run typecheck   # sources and tests, resolved to src (no build needed)
npm run lint        # needs build: ESLint loads the plugin from dist
npm test            # SSR in Node, CSR in jsdom
npm run release     # clean build, every check above, then npm publish --workspaces
```

Each package's `src` is reachable through the `@sanaafshani/source` export
condition, which TypeScript (`customConditions`) and Vitest use, so tests and
typechecking never run against stale `dist` output. Published consumers never
see that condition.

## Contributing

Both track documents end with a "writing a plugin" checklist, which is the
short version of the house style: take options rather than reading the
environment, keep no module-level state, fail closed, and report through
`emit(options.onEvent, …)`.

Changes need `npm run lint`, `npm run typecheck` and `npm test` to pass. A new
lint rule will not compile without choosing a tier.

## License

[MIT](LICENSE) © Sana Afshani
