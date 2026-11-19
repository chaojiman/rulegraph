import { describe, expect, it } from 'vitest';
import { normalizeHost } from '../src/domain.js';

describe('normalizeHost', () => {
  it('lower-cases and strips one trailing dot', () => {
    expect(normalizeHost('Example.COM.')).toBe('example.com');
    expect(normalizeHost('  API.Example.Com  ')).toBe('api.example.com');
  });

  it('converts IDN labels to punycode', () => {
    expect(normalizeHost('例子.测试')).toBe('xn--fsqu00a.xn--0zwm56d');
  });

  it('keeps single-label hosts', () => {
    expect(normalizeHost('localhost')).toBe('localhost');
  });

  it('rejects IP literals so they reach the CIDR index', () => {
    expect(normalizeHost('1.2.3.4')).toBeNull();
    expect(normalizeHost('::1')).toBeNull();
  });

  it('rejects wildcards, empty labels and over-long names', () => {
    expect(normalizeHost('*.example.com')).toBeNull();
    expect(normalizeHost('a..b')).toBeNull();
    expect(normalizeHost('')).toBeNull();
    expect(normalizeHost(`${'a'.repeat(64)}.com`)).toBeNull();
    expect(normalizeHost(`${'a.'.repeat(130)}com`)).toBeNull();
  });

  it('accepts underscores used by service records', () => {
    expect(normalizeHost('_service._tcp.example.com')).toBe('_service._tcp.example.com');
  });
});