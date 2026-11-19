/**
 * Query engine.
 *
 * `match` normalizes the input once, asks every index for candidate rule
 * positions, and returns the rule with the smallest position. That is exactly
 * the result of a linear first-match scan over the source rules, at a cost of
 * O(host length + address bits) instead of O(rules).
 */

import { normalizeHost } from './domain.js';
import { bitsOf, parseIp } from './ip.js';
import type { CompiledRuleset } from './compiler.js';
import type { MatchInput, MatchResult, Rule } from './types.js';

export class RuleEngine {
  private readonly compiled: CompiledRuleset;

  constructor(compiled: CompiledRuleset) {
    this.compiled = compiled;
  }

  get stats(): CompiledRuleset['stats'] {
    return this.compiled.stats;
  }

  match(input: MatchInput): MatchResult | null {
    const { rules, domains, keywords, ipv4, ipv6, matchIndex } = this.compiled;

    let best = -1;
    let host: string | null = null;
    if (input.host !== undefined) host = normalizeHost(input.host);

    if (host !== null) {
      const hits = domains.match(host);
      for (const index of hits.exact) if (best < 0 || index < best) best = index;
      for (const index of hits.suffix) if (best < 0 || index < best) best = index;
      if (best !== 0) {
        const keywordHits = keywords.match(host);
        for (const index of keywordHits) {
          if (best < 0 || index < best) best = index;
          if (best === 0) break;
        }
      }
    }

    if (best !== 0) {
      const parsed = input.ip !== undefined ? parseIp(input.ip) : host === null && input.host !== undefined ? parseIp(input.host) : null;
      if (parsed !== null) {
        const trie = parsed.family === 4 ? ipv4 : ipv6;
        const hits = trie.match(parsed.words, bitsOf(parsed.family));
        for (const index of hits) {
          if (best < 0 || index < best) best = index;
          if (best === 0) break;
        }
      }
    }

    if (best < 0 && matchIndex !== null) best = matchIndex;
    if (best < 0) return null;

    const rule = rules[best];
    if (rule === undefined) return null;
    return { index: best, rule: rule as Rule };
  }

  /** Batch entry point that keeps the allocation profile of the benchmark honest. */
  matchAll(inputs: readonly MatchInput[]): number {
    let matched = 0;
    for (const input of inputs) {
      if (this.match(input) !== null) matched += 1;
    }
    return matched;
  }
}