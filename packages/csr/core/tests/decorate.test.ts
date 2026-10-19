import { describe, expect, it } from 'vitest';
import { decorate, emit, type Decorator } from '../src/index.js';

type Greeter = { greet(name: string): string };

const wrap = (tag: string): Decorator<Greeter> => (inner) => ({ greet: (name) => `${tag}(${inner.greet(name)})` });

describe('decorate', () => {
  it('applies decorators with the first listed outermost, and leaves the original untouched', () => {
    const base: Greeter = { greet: (name) => name };
    const decorated = decorate(base, wrap('a'), wrap('b'));
    expect(decorated.greet('x')).toBe('a(b(x))');
    expect(base.greet('x')).toBe('x');
  });

  it('returns the base when there is nothing to apply', () => {
    const base: Greeter = { greet: (name) => name };
    expect(decorate(base)).toBe(base);
  });
});

describe('emit', () => {
  it('swallows a throwing handler, so reporting can never break the control', () => {
    expect(() =>
      emit(() => {
        throw new Error('telemetry down');
      }, { type: 'x' }),
    ).not.toThrow();
  });
});
