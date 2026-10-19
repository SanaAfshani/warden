/**
 * NIST SP 800-63B: length plus a known-bad check, no composition rules (they
 * produce `Password1!`) and no forced rotation (it produces `Autumn2024!`).
 */
export interface PasswordCheckResult {
  ok: boolean;
  /** Every problem at once, phrased for the user. */
  problems: string[];
}

export interface PasswordCheckOptions {
  /** Default 12. */
  minLength?: number;
  /** Default 128. A hashing-cost (DoS) limit, not a strength rule. */
  maxLength?: number;
  /** Rejected when contained in the password: the first things a targeted attacker tries. */
  userInputs?: readonly (string | undefined)[];
}

// A floor for zero-configuration use, not a breach corpus: pair with `checkPasswordAgainstBreaches`.
const COMMON = new Set([
  '123456', '123456789', '12345678', 'password', 'qwerty', 'qwerty123', '1234567890',
  '000000', '111111', 'iloveyou', 'admin', 'welcome', 'monkey', 'dragon', 'letmein',
  'football', 'abc123', 'password1', 'password123', 'passw0rd', 'p@ssw0rd', 'qwertyuiop',
  'sunshine', 'princess', 'azerty', 'trustno1', 'baseball', 'superman', 'starwars',
  'whatever', 'changeme', 'secret', 'letmein123', 'welcome123', 'admin123', 'root', 'toor',
  'test', 'test123', 'guest',
]);

const SEQUENCES = [
  'abcdefghijklmnopqrstuvwxyz', '01234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
  'qazwsxedc', '!@#$%^&*()',
];

// Every cracking tool applies these substitutions first.
const deLeet = (value: string) =>
  value
    .toLowerCase()
    .replace(/[4@]/g, 'a')
    .replace(/[3€]/g, 'e')
    .replace(/[1!|]/g, 'i')
    .replace(/0/g, 'o')
    .replace(/[5$]/g, 's')
    .replace(/7/g, 't')
    .replace(/8/g, 'b')
    .replace(/9/g, 'g');

/** Exact, with digits/symbols stripped from the ends (`password1234`), or a common word making up half of it. */
function isCommonVariant(value: string): boolean {
  if (COMMON.has(value)) return true;
  const core = value.replace(/^[^a-z]+/, '').replace(/[^a-z]+$/, '');
  if (core.length >= 4 && COMMON.has(core)) return true;
  for (const word of COMMON) {
    if (word.length >= 6 && value.includes(word) && word.length / value.length >= 0.5) return true;
  }
  return false;
}

function hasSequence(value: string, run = 5): boolean {
  for (const sequence of SEQUENCES) {
    for (let i = 0; i + run <= sequence.length; i++) {
      const slice = sequence.slice(i, i + run);
      if (value.includes(slice) || value.includes([...slice].reverse().join(''))) return true;
    }
  }
  return false;
}

const hasRepetition = (value: string) =>
  /(.)\1{3,}/u.test(value) || new Set(value).size < Math.min(5, Math.ceil(value.length / 3));

export function checkPasswordStrength(
  password: string,
  options: PasswordCheckOptions = {},
): PasswordCheckResult {
  const min = options.minLength ?? 12;
  const max = options.maxLength ?? 128;
  const problems: string[] = [];
  if (password.length < min) problems.push(`Use at least ${min} characters.`);
  if (password.length > max) problems.push(`Use at most ${max} characters.`);

  const normalised = deLeet(password.trim());
  if (isCommonVariant(normalised) || isCommonVariant(password.toLowerCase())) {
    problems.push('This password appears in lists of commonly used passwords.');
  }
  if (hasSequence(normalised)) problems.push('Avoid keyboard patterns and simple sequences.');
  if (hasRepetition(password)) problems.push('Avoid repeated characters.');

  // Compared on letters and digits only, and per name part: `mary.jones@…` must catch `maryjones-2024`.
  const alnum = (value: string) => value.toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');
  const candidate = alnum(normalised);
  const inputs = (options.userInputs ?? [])
    .filter((value): value is string => typeof value === 'string')
    .flatMap((value) => {
      const local = value.split('@')[0] ?? value;
      return [value, local, ...local.split(/[^\p{L}\p{N}]+/u).filter((part) => part.length >= 4)];
    })
    .map(alnum)
    .filter((value) => value.length >= 3);
  if (inputs.some((value) => candidate.includes(value) || (candidate.length >= 3 && value.includes(candidate)))) {
    problems.push('Do not use your name or email address in your password.');
  }

  return { ok: problems.length === 0, problems };
}

/**
 * Have I Been Pwned range lookup (k-anonymity: only 5 hex characters of the
 * SHA-1 leave the process). SHA-1 is the API's lookup key, not a password
 * hash. Fails open with `checked: false`: a third-party outage must not stop
 * signups. Pass an SSRF-safe fetch.
 */
export async function checkPasswordAgainstBreaches(
  password: string,
  fetchImpl: (url: string) => Promise<Response>,
): Promise<{ breached: boolean; count: number; checked: boolean }> {
  try {
    const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
    const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
    const response = await fetchImpl(`https://api.pwnedpasswords.com/range/${hex.slice(0, 5)}`);
    if (!response.ok) return { breached: false, count: 0, checked: false };
    const suffix = hex.slice(5);
    for (const line of (await response.text()).split('\n')) {
      const [candidate, count] = line.trim().split(':');
      if (candidate === suffix) return { breached: true, count: Number(count ?? 0), checked: true };
    }
    return { breached: false, count: 0, checked: true };
  } catch {
    return { breached: false, count: 0, checked: false };
  }
}
