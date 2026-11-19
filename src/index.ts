/**
 * Public surface of rulegraph.
 */

export { normalizeHost } from './domain.js';
export { DomainTrie, type DomainHit, type DomainNode } from './domain-trie.js';
export { CidrTrie, type CidrNode } from './cidr-trie.js';
export { Automaton, type AutomatonState } from './aho-corasick.js';
export { parseRuleset, type ParseOptions } from './parser.js';
export { compile, naiveMatch, type CompiledRuleset } from './compiler.js';
export { RuleEngine } from './engine.js';
export { serialize, deserialize, recount } from './serialize.js';
export { parseIp, parseCidr, bitsOf, maskWords, bitAt } from './ip.js';
export type {
  CompileStats,
  MatchInput,
  MatchResult,
  ParseError,
  Rule,
  Ruleset,
  RuleType,
} from './types.js';