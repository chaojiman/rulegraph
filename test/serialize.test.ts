import { describe, expect, it } from 'vitest';
import { compile } from '../src/compiler.js';
import { RuleEngine } from '../src/engine.js';
import { parseRuleset } from '../src/parser.js';
import { deserialize, serialize } from '../src/serialize.js';
import { generateCorpus } from '../src/bench/generate.js';

const corpus = generateCorpus({ rules: 800, queries: 1200, seed: 11 });
const compiled = compile(parseRuleset(corpus.text, { strict: true }));

describe('binary image', () => {
  it('round-trips rules and answers identically', () => {
    const image = serialize(compiled);
    expect(image.byteLength).toBeGreaterThan(0);

    const restored = deserialize(image);
    expect(restored.rules).toEqual(compiled.rules);
    expect(restored.stats).toEqual(compiled.stats);
    expect(restored.matchIndex).toBe(compiled.matchIndex);

    const original = new RuleEngine(compiled);
    const copy = new RuleEngine(restored);
    for (const query of corpus.queries) {
      const left = original.match(query)?.index ?? -1;
      const right = copy.match(query)?.index ?? -1;
      expect(right, JSON.stringify(query)).toBe(left);
    }
  });

  it('is deterministic for the same input', () => {
    const first = serialize(compiled);
    const second = serialize(compile(parseRuleset(corpus.text, { strict: true })));
    expect(Buffer.from(second).equals(Buffer.from(first))).toBe(true);
  });

  it('rejects a corrupted image', () => {
    const image = serialize(compiled);
    const corrupted = Uint8Array.from(image);
    corrupted[20] = (corrupted[20] as number) ^ 0xff;
    expect(() => deserialize(corrupted)).toThrow(/checksum/);
  });

  it('rejects a truncated image', () => {
    const image = serialize(compiled);
    const truncated = image.subarray(0, Math.floor(image.length / 2));
    expect(() => deserialize(truncated)).toThrow();
  });

  it('rejects a foreign file', () => {
    expect(() => deserialize(new Uint8Array(32))).toThrow();
  });
});