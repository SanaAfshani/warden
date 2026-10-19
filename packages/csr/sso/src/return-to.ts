/**
 * Where to go after login, as a RELATIVE path or the fallback. An
 * unvalidated `?returnTo=` is an open redirect: the link is on your domain,
 * passes every filter, and lands the freshly signed-in user on a clone.
 * "Same origin" comparisons are easy to get wrong (`https://you@evil/`,
 * `//evil`); a single leading `/` with no scheme and no authority cannot
 * leave the origin.
 */
export function safeReturnTo(value: string | null | undefined, fallback = '/'): string {
  if (typeof value !== 'string' || value.length === 0) return fallback;
  const trimmed = stripIgnorable(value);
  if (!trimmed.startsWith('/')) return fallback;

  // Checked decoded: the browser decodes, and `%2f%2fevil` is `//evil` by then.
  let decoded: string;
  try {
    decoded = stripIgnorable(decodeURIComponent(trimmed));
  } catch {
    return fallback;
  }
  if (!decoded.startsWith('/')) return fallback;
  // Browsers treat `/\host` as `//host`.
  if (decoded.startsWith('//') || decoded.startsWith('/\\')) return fallback;
  if (/^[a-z][a-z0-9+.-]*:/i.test(decoded.replace(/^[/\\]+/, ''))) return fallback;
  return trimmed;
}

/** The current location as a return target. */
export function currentReturnTo(location: { pathname: string; search: string; hash: string }): string {
  return safeReturnTo(`${location.pathname}${location.search}${location.hash}`);
}

/** Browsers drop C0 controls, DEL and whitespace inside URLs; a string check must too. */
function stripIgnorable(value: string): string {
  let out = '';
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code <= 0x1f || code === 0x7f || character.trim().length === 0) continue;
    out += character;
  }
  return out;
}
