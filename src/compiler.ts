/**
 * Compiles a parsed ruleset into the query structures.
 *
 * Each rule type gets a dedicated index, and every index records the rule's
 * position in the source list. The engine then takes the smallest position
 * across all hits, which reproduces the linear "first match wins" scan exactly.
 */

import { Automaton } from './aho-corasick.js';
import { CidrTrie } from './cidr-trie.js';
import { normalizeHost } from './domain.js';
import { DomainTrie } from './domain-trie.js';
import { bitsOf, maskWords, parseCidr, parseIp, type ParsedCidr, type ParsedIp } from './ip.js';
import type { CompileStats, Rule, Ruleset } from './types.js';

export interface CompiledRuleset {
  readonly rules: readonly Rule[];
  readonly domains: DomainTrie;
  readonly ipv4: CidrTrie;
  readonly ipv6: CidrTrie;
  readonly keywords: Automaton;
  /** Index of the first `MATCH` rule, or `null` when the ruleset has none. */
  readonly matchIndex: number | null;
  readonly stats: CompileStats;
}

export function compile(ruleset: Ruleset): CompiledRuleset {
  const domains = new DomainTrie();
  const ipv4 = new CidrTrie();
  const ipv6 = new CidrTrie();
  const keywords = new Automaton();

  let domainExact = 0;
  let domainSuffix = 0;
  let domainKeyword = 0;
  let ipv4Cidr = 0;
  let ipv6Cidr = 0;
  let matchIndex: number | null = null;
  let unreachable = 0;

  for (let index = 0; index < ruleset.rules.length; index += 1) {
    const rule = ruleset.rules[index] as Rule;
    if (matchIndex !== null) unreachable += 1;

    switch (rule.type) {
      case 'DOMAIN':
        domains.insertExact(rule.payload, index);
        domainExact += 1;
        break;
      case 'DOMAIN-SUFFIX':
        domains.insertSuffix(rule.payload, index);
        domainSuffix += 1;
        break;
      case 'DOMAIN-KEYWORD':
        keywords.addPattern(rule.payload, index);
        domainKeyword += 1;
        break;
      case 'IP-CIDR':
      case 'IP-CIDR6': {
        const cidr = parseCidr(rule.payload);
        if (cidr === null) break;
        const trie = cidr.family === 4 ? ipv4 : ipv6;
        trie.insert(maskWords(cidr.words, cidr.prefix), cidr.prefix, index);
        if (cidr.family === 4) ipv4Cidr += 1;
        else ipv6Cidr += 1;
        break;
      }
      case 'MATCH':
        if (matchIndex === null) matchIndex = index;
        break;
    }
  }

  keywords.build();

  const stats: CompileStats = {
    rules: ruleset.rules.length,
    domainExact,
    domainSuffix,
    domainKeyword,
    ipv4Cidr,
    ipv6Cidr,
    domainNodes: domains.size,
    ipv4Nodes: ipv4.size,
    ipv6Nodes: ipv6.size,
    automatonStates: keywords.stateCount,
    fallback: matchIndex !== null,
    unreachable,
  };

  return { rules: ruleset.rules, domains, ipv4, ipv6, keywords, matchIndex, stats };
}

/** Reference implementation: the plain first-match scan the indexes must emulate. */
export function naiveMatch(rules: readonly Rule[], input: { host?: string; ip?: string }): number {
  let host: string | null = null;
  let ipText: string | null = null;
  if (input.host !== undefined) {
    host = normalizeHost(input.host);
    if (host === null) ipText = input.host;
  }
  if (input.ip !== undefined) ipText = input.ip;

  const ip = ipText === null ? null : parseIp(ipText);

  for (let index = 0; index < rules.length; index += 1) {
    const rule = rules[index] as Rule;
    if (matches(rule, host, ip)) return index;
  }
  return -1;
}

function matches(rule: Rule, host: string | null, ip: ParsedIp | null): boolean {
  switch (rule.type) {
    case 'MATCH':
      return true;
    case 'DOMAIN':
      return host !== null && host === rule.payload;
    case 'DOMAIN-SUFFIX':
      return host !== null && (host === rule.payload || host.endsWith(`.${rule.payload}`));
    case 'DOMAIN-KEYWORD':
      return host !== null && host.includes(rule.payload);
    case 'IP-CIDR':
    case 'IP-CIDR6': {
      if (ip === null) return false;
      const cidr = parseCidr(rule.payload);
      return cidr !== null && ipInCidr(ip, cidr);
    }
    default:
      return false;
  }
}

function ipInCidr(ip: ParsedIp, cidr: ParsedCidr): boolean {
  if (ip.family !== cidr.family) return false;
  const total = bitsOf(cidr.family);
  const limit = Math.min(cidr.prefix, total);
  for (let i = 0; i < limit; i += 1) {
    const word = i >>> 5;
    const mask = 1 << (31 - (i & 31));
    if (((ip.words[word] as number) & mask) !== ((cidr.words[word] as number) & mask)) return false;
  }
  return true;
}