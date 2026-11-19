import { describe, expect, it } from 'vitest';
import { compile, naiveMatch } from '../src/compiler.js';
import { RuleEngine } from '../src/engine.js';
import { parseRuleset } from '../src/parser.js';

const SOURCE = [
  'DOMAIN,ads.example.com,Reject',
  'DOMAIN-KEYWORD,track,Track',
  'DOMAIN-SUFFIX,example.com,Proxy',
  'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
  'IP-CIDR6,2001:db8::/32,Proxy',
  'MATCH,Fallback',
].join('\n');

const parsed = parseRuleset(SOURCE);
const engine = new RuleEngine(compile(parsed));

describe('RuleEngine', () => {
  it('honours source order across rule types', () => {
    expect(engine.match({ host: 'ads.example.com' })?.index).toBe(0);
    expect(engine.match({ host: 'api.example.com' })?.index).toBe(2);
    expect(engine.match({ host: 'tracking.example.com' })?.index).toBe(1);
  });

  it('lets a broader rule shadow a later exact rule, like a linear scan', () => {
    const shadowed = new RuleEngine(
      compile(parseRuleset('DOMAIN-SUFFIX,example.com,Proxy\nDOMAIN,ads.example.com,Reject')),
    );
    expect(shadowed.match({ host: 'ads.example.com' })?.rule.policy).toBe('Proxy');
  });

  it('routes IP literals present in --host through the CIDR index', () => {
    expect(engine.match({ host: '10.1.2.3' })?.rule.policy).toBe('DIRECT');
    expect(engine.match({ ip: '10.1.2.3' })?.index).toBe(3);
    expect(engine.match({ ip: '2001:db8::5' })?.index).toBe(4);
  });

  it('falls back to MATCH only when nothing else hits', () => {
    expect(engine.match({ host: 'unknown.other' })?.index).toBe(5);
    expect(engine.match({ ip: '203.0.113.1' })?.index).toBe(5);
  });

  it('returns null when there is no MATCH rule and nothing hits', () => {
    const bare = new RuleEngine(compile(parseRuleset('DOMAIN,only.example.com,Proxy')));
    expect(bare.match({ host: 'nope.example.com' })).toBeNull();
  });

  it('agrees with the reference scan for every query', () => {
    const queries = [
      { host: 'ads.example.com' },
      { host: 'example.com' },
      { host: 'sub.deep.example.com' },
      { host: 'tracker.io' },
      { ip: '10.255.0.1' },
      { ip: '2001:db8:1::1' },
      { host: 'unrelated.dev', ip: '10.0.0.9' },
    ];
    for (const query of queries) {
      const expected = naiveMatch(parsed.rules, query);
      const actual = engine.match(query);
      expect(actual?.index ?? -1, JSON.stringify(query)).toBe(expected);
    }
  });
});