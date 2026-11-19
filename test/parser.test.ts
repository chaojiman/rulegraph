import { describe, expect, it } from 'vitest';
import { parseRuleset } from '../src/parser.js';

describe('parseRuleset', () => {
  it('parses a plain rule list', () => {
    const { rules, errors } = parseRuleset(`
      DOMAIN-SUFFIX,example.com,Proxy
      DOMAIN,ads.example.com,REJECT
      IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
      MATCH,DIRECT
    `);
    expect(errors).toEqual([]);
    expect(rules.map((rule) => rule.type)).toEqual(['DOMAIN-SUFFIX', 'DOMAIN', 'IP-CIDR', 'MATCH']);
    expect(rules[2]?.noResolve).toBe(true);
    expect(rules[3]?.payload).toBe('');
  });

  it('extracts the rules block from a Clash config and keeps line numbers', () => {
    const config = [
      'port: 7890',
      'rules:',
      '  - "DOMAIN-SUFFIX,example.com,Proxy"',
      "  - DOMAIN,cdn.example.net,DIRECT # inline comment",
      '  - IP-CIDR6,2001:db8::/32,Proxy',
      'proxies:',
      '  - name: node',
    ].join('\n');
    const { rules, errors } = parseRuleset(config);
    expect(errors).toEqual([]);
    expect(rules).toHaveLength(3);
    expect(rules[0]).toMatchObject({ type: 'DOMAIN-SUFFIX', payload: 'example.com', policy: 'Proxy', line: 3 });
    expect(rules[1]).toMatchObject({ type: 'DOMAIN', payload: 'cdn.example.net', line: 4 });
    expect(rules[2]).toMatchObject({ type: 'IP-CIDR6', payload: '2001:db8::/32', line: 5 });
  });

  it('normalizes hosts and keywords', () => {
    const { rules } = parseRuleset('DOMAIN-SUFFIX,Example.COM.,Proxy\nDOMAIN-KEYWORD,Tracker,Track');
    expect(rules[0]?.payload).toBe('example.com');
    expect(rules[1]?.payload).toBe('tracker');
  });

  it('reports unsupported types instead of dropping them silently', () => {
    const { rules, errors } = parseRuleset('RULE-SET,reject,DIRECT\nDOMAIN,ok.example.com,Proxy');
    expect(rules).toHaveLength(1);
    expect(errors).toHaveLength(1);
    expect(errors[0]?.line).toBe(1);
    expect(errors[0]?.message).toContain('unsupported rule type');
  });

  it('validates payloads and policies', () => {
    const { errors } = parseRuleset(
      ['DOMAIN-KEYWORD,,DIRECT', 'IP-CIDR,2001:db8::/32,DIRECT', 'DOMAIN,a..b,DIRECT', 'MATCH'].join('\n'),
    );
    expect(errors).toHaveLength(4);
    expect(errors.map((error) => error.line)).toEqual([1, 2, 3, 4]);
  });

  it('rejects unknown flags only in strict mode', () => {
    const lenient = parseRuleset('DOMAIN,a.example.com,DIRECT,src');
    expect(lenient.errors).toEqual([]);
    const strict = parseRuleset('DOMAIN,a.example.com,DIRECT,src', { strict: true });
    expect(strict.errors).toHaveLength(1);
    expect(strict.errors[0]?.message).toContain('unknown rule flag');
  });
});