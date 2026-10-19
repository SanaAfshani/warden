/**
 * ============================================================================
 * Rule tiers
 * ============================================================================
 *
 * ---------------------------------------------------------------------------
 * The problem this solves
 * ---------------------------------------------------------------------------
 * Before this file, severity lived only in the shipped configs: `recommended`
 * set every rule to `error`, `migrating` set one of them to `warn`. The rules
 * themselves said nothing. Every rule declared `type: 'problem'`, which is
 * ESLint's coarsest category and therefore carried no information at all.
 *
 * That leaves the most important question unanswered for anyone who writes
 * their own config — which is everyone, eventually: *which of these may I turn
 * off, and which one is holding a vulnerability class shut?* With no answer in
 * the metadata, the question gets settled by whoever is unblocking a build at
 * 6pm, and it gets settled the same way every time.
 *
 * ---------------------------------------------------------------------------
 * Why two tiers and not a 1-10 scale
 * ---------------------------------------------------------------------------
 * A tier has to drive a decision or it is decoration. The only decision here is
 * binary: may this rule be downgraded, or not. A finer scale would invite
 * argument about whether something is a 6 or a 7 without changing what anyone
 * does, and a number nobody acts on is a number nobody maintains.
 */

/**
 * `required` — the rule stands for a vulnerability class that nothing else in
 * this library can mitigate at runtime. Turning it off does not degrade a
 * defence, it removes one. These stay `error` in every config we ship, and
 * {@link enforce} refuses a config that lowers them.
 *
 * `recommended` — a real control, but defence in depth: the failure it prevents
 * needs a second failure to become an incident, or the rule carries an autofix
 * so the cost of keeping it on is close to zero. A team may switch these off
 * knowingly; we would rather they did not.
 */
export type Tier = 'required' | 'recommended';
