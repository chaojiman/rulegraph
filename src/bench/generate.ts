/**
 * Deterministic corpus generator for the benchmark and the differential test.
 *
 * Rules and queries are derived from the same vocabulary so that a realistic
 * share of queries hits a rule: a corpus where every query misses would let a
 * broken index look fast.
 */

import type { MatchInput, Rule, Ruleset } from '../types.js';

const TLDS = ['com', 'net', 'org', 'io', 'cn', 'xyz', 'dev', 'app', 'co', 'me'];
const WORDS = [
  'api', 'cdn', 'static', 'img', 'mail', 'auth', 'admin', 'edge', 'node', 'cache',
  'track', 'metrics', 'search', 'video', 'pay', 'user', 'sso', 'assets', 'upload', 'stream',
  'gateway', 'relay', 'proxy', 'mirror', 'bucket', 'queue', 'worker', 'build', 'deploy', 'status',
];
const KEYWORDS = ['analytics', 'doubleclick', 'adservice', 'tracker', 'banner', 'pixel'];

type Random = () => number;

function mulberry32(seed: number): Random {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(random: Random, items: readonly T[]): T {
  return items[Math.floor(random() * items.length)] as T;
}

function randomLabel(random: Random): string {
  const word = pick(random, WORDS);
  const suffix = Math.floor(random() * 1000);
  return random() < 0.5 ? word : `${word}${suffix}`;
}

function randomDomain(random: Random): string {
  const parts = [randomLabel(random), pick(random, WORDS)];
  if (random() < 0.35) parts.push(pick(random, WORDS));
  return `${parts.join('.')}.${pick(random, TLDS)}`;
}

function randomIpv4(random: Random): string {
  const a = 1 + Math.floor(random() * 223);
  const b = Math.floor(random() * 256);
  const c = Math.floor(random() * 256);
  const d = Math.floor(random() * 256);
  return `${a}.${b}.${c}.${d}`;
}

function randomIpv6(random: Random): string {
  const hextet = () => Math.floor(random() * 0x10000).toString(16);
  return `${hextet()}:${hextet()}:${hextet()}:${hextet()}::${Math.floor(random() * 8)}`;
}

export interface BenchCorpus {
  text: string;
  ruleset: Ruleset;
  queries: MatchInput[];
  /** `true` when the corpus contains a trailing MATCH rule. */
  hasFallback: boolean;
}

export interface GenerateOptions {
  rules: number;
  queries: number;
  seed?: number;
  /** Emit a trailing MATCH rule; 60% of generated rule sets include one. */
  fallback?: boolean;
}

export function generateCorpus(options: GenerateOptions): BenchCorpus {
  const random = mulberry32(options.seed ?? 1);
  const total = Math.max(1, options.rules);
  const fallback = options.fallback ?? true;
  const lines: string[] = [];
  const domains: string[] = [];
  const ipv4s: string[] = [];
  const ipv6s: string[] = [];
  const keywords: string[] = KEYWORDS.slice();

  const body = fallback ? total - 1 : total;
  for (let i = 0; i < body; i += 1) {
    const roll = random();
    if (roll < 0.55) {
      const domain = randomDomain(random);
      domains.push(domain);
      lines.push(`DOMAIN-SUFFIX,${domain},POLICY-${i % 24}`);
    } else if (roll < 0.75) {
      const domain = randomDomain(random);
      domains.push(domain);
      lines.push(`DOMAIN,${domain},POLICY-${i % 24}`);
    } else if (roll < 0.85) {
      const keyword = pick(random, keywords);
      lines.push(`DOMAIN-KEYWORD,${keyword},POLICY-${i % 24}`);
    } else if (roll < 0.95) {
      const ip = randomIpv4(random);
      ipv4s.push(ip);
      const prefix = 8 + Math.floor(random() * 16);
      lines.push(`IP-CIDR,${ip}/${prefix},POLICY-${i % 24},no-resolve`);
    } else {
      const ip = randomIpv6(random);
      ipv6s.push(ip);
      const prefix = 16 + Math.floor(random() * 64);
      lines.push(`IP-CIDR6,${ip}/${prefix},POLICY-${i % 24}`);
    }
  }
  if (fallback) lines.push(`MATCH,POLICY-${total % 24}`);

  const queries: MatchInput[] = [];
  for (let i = 0; i < options.queries; i += 1) {
    const roll = random();
    if (roll < 0.45 && domains.length > 0) {
      const domain = pick(random, domains);
      queries.push({ host: random() < 0.5 ? domain : `${randomLabel(random)}.${domain}` });
    } else if (roll < 0.7) {
      queries.push({ host: randomDomain(random) });
    } else if (roll < 0.85 && ipv4s.length > 0) {
      queries.push({ ip: pick(random, ipv4s) });
    } else if (roll < 0.95 && ipv6s.length > 0) {
      queries.push({ ip: pick(random, ipv6s) });
    } else {
      queries.push({ host: randomDomain(random), ip: randomIpv4(random) });
    }
  }

  const text = lines.join('\n');
  return { text, ruleset: { rules: lines.map(toRule), errors: [] }, queries, hasFallback: fallback };
}

function toRule(line: string): Rule {
  const parts = line.split(',');
  const type = (parts[0] ?? 'MATCH') as Rule['type'];
  const policy = parts[2] ?? parts[1] ?? 'DIRECT';
  return {
    type,
    payload: type === 'MATCH' ? '' : (parts[1] ?? ''),
    policy: type === 'MATCH' ? (parts[1] ?? 'DIRECT') : policy,
    noResolve: parts.includes('no-resolve'),
    line: 0,
  };
}