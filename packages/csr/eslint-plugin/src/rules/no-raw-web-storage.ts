/**
 * ============================================================================
 * no-raw-web-storage
 * ============================================================================
 *
 * Ban direct `localStorage`, `sessionStorage` and `document.cookie` access.
 *
 * ---------------------------------------------------------------------------
 * What this is actually protecting against
 * ---------------------------------------------------------------------------
 * Not XSS. Encrypted browser storage does not stop XSS, and this rule does not
 * pretend to. It protects against the three things that DO happen:
 *
 *  1. **Blind exfiltration.** The commodity stealer script does not read your
 *     code; it dumps every key in `localStorage` and posts it. A value written
 *     through the encrypted store is ciphertext to that script, and the key is
 *     non-extractable so it cannot be taken either.
 *
 *  2. **At-rest exposure.** A browser profile backup, a synced device, a shared
 *     machine, a screen-share with devtools open. Plaintext in `localStorage`
 *     survives all of them; the user never signed up for that.
 *
 *  3. **Drift.** One module uses the encrypted store, the next uses
 *     `localStorage` directly because it was quicker, and now half the app's
 *     state is plaintext and nobody knows which half. This rule is what keeps
 *     the answer to "is our storage encrypted?" from being "some of it".
 *
 * ---------------------------------------------------------------------------
 * Why `document.cookie` is in the same rule
 * ---------------------------------------------------------------------------
 * Because a cookie written from JavaScript can never be `httpOnly` — that flag
 * can only come from a `Set-Cookie` header. So every `document.cookie = ...` is
 * a value readable by any script on the origin, by construction. If it holds a
 * session token, the strongest control available to you has been given up in
 * one line, silently.
 */

import type { Rule } from 'eslint';
import type { Node } from 'estree';
import { createRule, docs, memberPath, lastSegment, type WardenRule } from '../shared.js';

const STORAGES = new Set(['localStorage', 'sessionStorage']);
const READ_METHODS = new Set(['getItem', 'key', 'length']);

export const noRawWebStorage: WardenRule = createRule(
  {
    type: 'problem',
    docs: {
      description:
        'Disallow direct localStorage/sessionStorage/document.cookie access; use an encrypted store.',
      url: docs('no-raw-web-storage'),
      /**
       * Defence in depth, by this rule's own admission: the encrypted store
       * does not stop XSS — nothing in a browser does — it stops blind
       * exfiltration and at-rest exposure. Reaching the plaintext still needs a
       * second failure (script execution, a stolen profile, a shared machine),
       * which is the definition of the `recommended` tier here.
       *
       * It relaxes by OPTION rather than severity: `allowReads` lets a team
       * move writes first, which is the order that matters, since an
       * unencrypted read of an encrypted value just returns null while an
       * unencrypted write leaves plaintext on disk.
       */
      tier: 'recommended',
    },
    schema: [
      {
        type: 'object',
        properties: {
          /** Reported name of the replacement, so this works for any wrapper. */
          replacement: { type: 'string' },
          /** Allow reads but not writes. For a codebase mid-migration. */
          allowReads: { type: 'boolean' },
        },
        additionalProperties: false,
      },
    ],
    messages: {
      storage:
        '`{{name}}` stores PLAINTEXT that any script on this origin can read, and that survives in profile backups and on shared machines. Use `{{replacement}}`, which encrypts with a non-extractable key. (It does not stop XSS — nothing in a browser does — it stops blind exfiltration and at-rest exposure.)',
      cookie:
        'A cookie written from JavaScript can never be httpOnly — only a Set-Cookie header can do that — so this value is readable by any script on the origin. For a session token, have the SERVER set the cookie. For anything else, use `{{replacement}}`.',
    },
  },
  (context) => {
    const options = (context.options[0] ?? {}) as { replacement?: string; allowReads?: boolean };
    const replacement = options.replacement ?? 'encrypted() from @sanaafshani/warden-csr-storage';
    const allowReads = options.allowReads ?? false;

    /**
     * Web Storage methods that CHANGE what is on disk.
     *
     * The read/write split is what makes `allowReads` useful during a
     * migration: an unencrypted read of a value that was written encrypted
     * simply returns null, while an unencrypted WRITE leaves plaintext behind
     * that outlives the migration.
     */
    const WRITE_METHODS = new Set(['setItem', 'removeItem', 'clear']);

    /**
     * `typeof localStorage === 'undefined'` is the standard availability guard,
     * not a storage access — Web Storage throws on access in a sandboxed iframe
     * and is absent during SSR, so this check is the CORRECT thing to write.
     *
     * Reporting it was a false positive found by running this plugin on the
     * library it protects. False positives are how a security rule gets
     * disabled wholesale, so they cost more than they look.
     */
    function isTypeofGuard(node: Rule.Node): boolean {
      const parent = node.parent as Node | undefined;
      return parent?.type === 'UnaryExpression' && parent.operator === 'typeof';
    }

    /** Does this access modify storage? Unknown access counts as a write. */
    function isWrite(node: Rule.Node, path: string): boolean {
      const parent = node.parent as Node | undefined;

      // `localStorage.token = x` / `delete localStorage.token`
      if (parent?.type === 'AssignmentExpression' && (parent.left as Node) === (node as unknown as Node)) return true;
      if (parent?.type === 'UnaryExpression' && parent.operator === 'delete') return true;
      if (parent?.type === 'UpdateExpression') return true;

      const method = lastSegment(path);
      if (WRITE_METHODS.has(method)) return true;
      if (READ_METHODS.has(method)) return false;

      // Something we cannot classify — a destructure, an alias, a pass to a
      // helper. Treated as a write, because the pessimistic answer is the one
      // that fails safely.
      return true;
    }

    return {
      MemberExpression(node) {
        const path = memberPath(node);
        if (path === null) return;

        if (isTypeofGuard(node)) return;

        // `document.cookie`, `window.document.cookie`
        if (/(^|\.)document\.cookie$/.test(path)) {
          // `document.cookie = x` is the write; reading it is the getter.
          const writing =
            ((node as Rule.Node).parent as Node | undefined)?.type === 'AssignmentExpression';
          if (allowReads && !writing) return;
          context.report({ node, messageId: 'cookie', data: { replacement } });
          return;
        }

        // `localStorage.getItem(...)`, `window.sessionStorage.setItem(...)`
        const parts = path.split('.');
        const storage = parts.find((part) => STORAGES.has(part));
        if (storage === undefined) return;

        // Report the OUTERMOST member expression only, so
        // `window.localStorage.setItem` produces one message, not three.
        const parent = (node as Rule.Node).parent as Node | undefined;
        if (parent?.type === 'MemberExpression' && !parent.computed) return;

        if (allowReads && !isWrite(node, path)) return;
        context.report({ node, messageId: 'storage', data: { name: storage, replacement } });
      },

      /**
       * A bare `localStorage` passed somewhere, e.g.
       * `persist({ storage: localStorage })`.
       *
       * `allowReads` deliberately does NOT exempt this: handing the raw object
       * to another library gives it write access too, and this exact line is
       * how a whole redux store ends up in plaintext.
       */
      Identifier(node) {
        if (!STORAGES.has(node.name)) return;
        if (isTypeofGuard(node)) return;
        const parent = (node as Rule.Node).parent as Node | undefined;
        if (parent?.type === 'MemberExpression') return;       // handled above
        if (parent?.type === 'Property' && (parent.key as Node) === (node as unknown as Node)) return;
        if (parent?.type === 'VariableDeclarator' && (parent.id as Node) === (node as unknown as Node)) return;
        context.report({ node, messageId: 'storage', data: { name: node.name, replacement } });
      },
    };
  },
);
