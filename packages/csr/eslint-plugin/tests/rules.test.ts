/**
 * Every case below is a real pattern from real code, not a synthetic string.
 *
 * The `valid` cases matter as much as the `invalid` ones: a security lint rule
 * that cries wolf gets disabled wholesale, and a disabled rule protects nothing.
 */
import { RuleTester } from 'eslint';
import { parser as tsParser } from 'typescript-eslint';
import { noDangerousHtml } from '../src/rules/no-dangerous-html.js';
import { noDomHtmlSink } from '../src/rules/no-dom-html-sink.js';
import { noRawWebStorage } from '../src/rules/no-raw-web-storage.js';
import { requireSafeUrl } from '../src/rules/require-safe-url.js';
import { noUnsafeTargetBlank } from '../src/rules/no-unsafe-target-blank.js';

const ruleTester = new RuleTester({
  languageOptions: {
    parser: tsParser,
    ecmaVersion: 2022,
    sourceType: 'module',
    parserOptions: { ecmaFeatures: { jsx: true } },
  },
});

ruleTester.run('no-dangerous-html', noDangerousHtml, {
  valid: [
    '<SafeHtml html={comment.body} />;',
    '<div>{comment.body}</div>;',
    'const x = { dangerouslySetInnerHTML: 1 };',   // an object key, not JSX
  ],
  invalid: [
    {
      code: '<div dangerouslySetInnerHTML={{ __html: body }} />;',
      errors: [{ messageId: 'dangerous' }],
    },
    {
      // Even a "safe-looking" constant: the parser rewrites markup regardless.
      code: '<div dangerouslySetInnerHTML={{ __html: "<b>hi</b>" }} />;',
      errors: [{ messageId: 'dangerous' }],
    },
    {
      code: '<article dangerouslySetInnerHTML={{ __html: post.html }} />;',
      options: [{ component: 'Markup' }],
      errors: [{ message: /<Markup html=/ }],
    },
  ],
});

ruleTester.run('no-dom-html-sink', noDomHtmlSink, {
  valid: [
    'el.textContent = value;',
    'el.append(node);',
    'el.innerText = value;',
    'const html = el.innerHTML;',            // reading is not a sink
    'logger.write(line);',                   // not document.write
    'stream.writeln(line);',
  ],
  invalid: [
    { code: 'el.innerHTML = value;', errors: [{ messageId: 'assignment' }] },
    { code: 'el.outerHTML = "<b>" + name + "</b>";', errors: [{ messageId: 'assignment' }] },
    { code: 'document.body.innerHTML = "";', errors: [{ messageId: 'assignment' }] },
    { code: 'el.insertAdjacentHTML("beforeend", markup);', errors: [{ messageId: 'call' }] },
    { code: 'document.write(markup);', errors: [{ messageId: 'call' }] },
    { code: 'window.document.writeln(markup);', errors: [{ messageId: 'call' }] },
  ],
});

ruleTester.run('no-raw-web-storage', noRawWebStorage, {
  valid: [
    'await storage.set("auth.tokens", tokens);',
    'const localStorage = makeFake();',          // a declaration, not the global
    'const obj = { localStorage: 1 };',          // an object KEY
    { code: 'localStorage.getItem("theme");', options: [{ allowReads: true }] },
    { code: 'sessionStorage.length;', options: [{ allowReads: true }] },
    // Availability guards. Web Storage THROWS on access in a sandboxed iframe
    // and is absent during SSR, so these are the correct thing to write — and
    // flagging them was a false positive found by dogfooding the plugin.
    "const driver = typeof localStorage === 'undefined' ? memory() : local();",
    "if (typeof window.sessionStorage !== 'undefined') { use(); }",
    "const ok = typeof document.cookie === 'string';",
    { code: 'const c = document.cookie;', options: [{ allowReads: true }] },
  ],
  invalid: [
    { code: 'localStorage.setItem("token", token);', errors: [{ messageId: 'storage' }] },
    { code: 'window.localStorage.setItem("token", token);', errors: [{ messageId: 'storage' }] },
    { code: 'sessionStorage.getItem("user");', errors: [{ messageId: 'storage' }] },
    {
      // The rule's real target: a persist adapter pointed at plaintext storage.
      code: 'persist(fn, { name: "app", storage: localStorage });',
      errors: [{ messageId: 'storage' }],
    },
    {
      code: 'document.cookie = "session=" + token;',
      errors: [{ messageId: 'cookie' }],
    },
    {
      // Reads allowed, writes still not: plaintext on disk is the harm.
      code: 'localStorage.setItem("token", token);',
      options: [{ allowReads: true }],
      errors: [{ messageId: 'storage' }],
    },
    {
      code: 'localStorage.setItem("x", y);',
      options: [{ replacement: 'ourStore' }],
      errors: [{ message: /ourStore/ }],
    },
    {
      // Regression: the message named the METHOD (`getItem`) instead of the
      // storage, which read as nonsense — "`getItem` stores plaintext".
      code: 'localStorage.getItem("x");',
      errors: [{ message: /`localStorage` stores PLAINTEXT/ }],
    },
    {
      // Regression: `allowReads` treated every call as a write, so it exempted
      // nothing. A direct property write is still a write.
      code: 'localStorage.token = t;',
      options: [{ allowReads: true }],
      errors: [{ messageId: 'storage' }],
    },
    {
      code: 'delete localStorage.token;',
      options: [{ allowReads: true }],
      errors: [{ messageId: 'storage' }],
    },
    {
      // Handing the raw object to a library gives it write access, so the
      // read-only exemption must not apply here.
      code: 'persist(fn, { storage: localStorage });',
      options: [{ allowReads: true }],
      errors: [{ messageId: 'storage' }],
    },
    {
      code: 'const x = document.cookie;',
      errors: [{ messageId: 'cookie' }],
    },
  ],
});

ruleTester.run('require-safe-url', requireSafeUrl, {
  valid: [
    '<a href="/about">about</a>;',                       // static
    '<a href={`/users/1`}>x</a>;',                       // template, no interpolation
    '<a href={safeUrl(user.site) ?? "#"}>x</a>;',
    '<img src={safeUrl(u)} />;',
    '<a href={ok ? safeUrl(a) : "#"}>x</a>;',
    { code: '<a href={checkUrl(u)}>x</a>;', options: [{ validators: ['checkUrl'] }] },
    '<div data-href={u} />;',                            // not a URL sink
  ],
  invalid: [
    { code: '<a href={user.website}>site</a>;', errors: [{ messageId: 'unchecked' }] },
    { code: '<iframe src={props.src} />;', errors: [{ messageId: 'unchecked' }] },
    { code: '<form action={endpoint} />;', errors: [{ messageId: 'unchecked' }] },
    {
      // A template literal WITH interpolation is dynamic; `${scheme}` can be
      // `javascript:`.
      code: '<a href={`${base}/x`}>x</a>;',
      errors: [{ messageId: 'unchecked' }],
    },
    {
      // Only one branch validated is not validated.
      code: '<a href={ok ? safeUrl(a) : raw}>x</a>;',
      errors: [{ messageId: 'unchecked' }],
    },
    {
      code: '<a href={safeUrl(u)}>x</a>;',
      options: [{ validators: ['checkUrl'] }],
      errors: [{ messageId: 'unchecked' }],
    },
  ],
});

ruleTester.run('no-unsafe-target-blank', noUnsafeTargetBlank, {
  valid: [
    '<a href="/x" target="_blank" rel="noopener noreferrer">x</a>;',
    '<a href="/x" target="_blank" rel="noopener">x</a>;',
    '<a href="/x">x</a>;',
    '<a href="/x" target="_self">x</a>;',
    '<a href="/x" target="_blank" rel={computed}>x</a>;',   // undecidable, not guessed
  ],
  invalid: [
    {
      code: '<a href="/x" target="_blank">x</a>;',
      output: '<a href="/x" target="_blank" rel="noopener noreferrer">x</a>;',
      errors: [{ messageId: 'missing' }],
    },
    {
      code: '<a href={safeUrl(u)} target={"_blank"}>x</a>;',
      output: '<a href={safeUrl(u)} target={"_blank"} rel="noopener noreferrer">x</a>;',
      errors: [{ messageId: 'missing' }],
    },
    {
      // `rel` present but wrong — NOT auto-fixed, because amending someone's
      // existing rel is a judgement call.
      code: '<a href="/x" target="_blank" rel="nofollow">x</a>;',
      errors: [{ messageId: 'missing' }],
    },
  ],
});
