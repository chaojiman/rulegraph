/**
 * Differential test: for randomised rule sets the compiled engine must return
 * exactly the index a linear first-match scan returns. This is the property
 * that lets the indexes be trusted at all.
 */

import { describe, expect, it } from 'vitest';
import { compile, naiveMatch } from '../src/compiler.js';
import { RuleEngine } from '../src/engine.js';
import { parseRuleset } from '../src/parser.js';
import { generateCorpus } from '../src/bench/generate.js';

describe('differential: compiled indexes vs linear scan', () => {
  for (const seed of [1, 2, 3, 17]) {
    it(`agrees on seed ${seed}`, () => {
      const corpus = generateCorpus({ rules: 400, queries: 1500, seed });
      const parsed = parseRuleset(corpus.text, { strict: true });
      expect(parsed.errors).toEqual([]);

      const engine = new RuleEngine(compile(parsed));
      const failures: string[] = [];
      for (const query of corpus.queries) {
        const expected = naiveMatch(parsed.rules, query);
        const actual = engine.match(query)?.index ?? -1;
        if (actual !== expected) failures.push(`${JSON.stringify(query)}: expected ${expected}, got ${actual}`);
      }
      expect(failures.slice(0, 5)).toEqual([]);
      expect(failures).toHaveLength(0);
    });
  }
});