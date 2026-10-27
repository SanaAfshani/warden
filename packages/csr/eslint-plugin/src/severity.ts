/**
 * Rule tiers. A tier answers the one question anyone writing their own config
 * has: may this rule be switched off? It is binary because that decision is
 * binary; a finer scale would invite argument without changing what anyone does.
 *
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
