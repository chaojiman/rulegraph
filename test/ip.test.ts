import { describe, expect, it } from 'vitest';
import { bitAt, maskWords, parseCidr, parseIp } from '../src/ip.js';

describe('parseIp', () => {
  it('parses IPv4 literals', () => {
    const ip = parseIp('192.168.1.1');
    expect(ip?.family).toBe(4);
    expect(ip?.text).toBe('192.168.1.1');
    expect(ip?.words[0]).toBe(0xc0a80101);
  });

  it('rejects malformed IPv4', () => {
    for (const text of ['256.1.1.1', '01.2.3.4', '1.2.3', '1.2.3.4.5', '1.2.3.-1', 'a.b.c.d', '']) {
      expect(parseIp(text), text).toBeNull();
    }
  });

  it('compresses IPv6 to RFC 5952 form', () => {
    expect(parseIp('2001:0db8:0000:0000:0000:0000:0000:0001')?.text).toBe('2001:db8::1');
    expect(parseIp('::1')?.text).toBe('::1');
    expect(parseIp('::')?.text).toBe('::');
    expect(parseIp('2001:db8:0:1:0:0:0:1')?.text).toBe('2001:db8:0:1::1');
  });

  it('accepts a zone id and embedded IPv4', () => {
    expect(parseIp('fe80::1%eth0')?.text).toBe('fe80::1');
    const mapped = parseIp('::ffff:192.168.1.1');
    expect(mapped?.family).toBe(6);
    expect(mapped?.words[3]).toBe(0xc0a80101);
  });

  it('rejects malformed IPv6', () => {
    for (const text of ['1::2::3', '1:2:3', '1:2:3:4:5:6:7:8:9', 'gggg::1', ':']) {
      expect(parseIp(text), text).toBeNull();
    }
  });
});

describe('parseCidr', () => {
  it('parses IPv4 and IPv6 prefixes', () => {
    expect(parseCidr('10.0.0.0/8')).toMatchObject({ family: 4, prefix: 8 });
    expect(parseCidr('2001:db8::/32')).toMatchObject({ family: 6, prefix: 32 });
  });

  it('rejects out-of-range prefixes and missing addresses', () => {
    for (const text of ['10.0.0.0/33', '2001:db8::/129', '10.0.0.0', '/8', '10.0.0.0/x']) {
      expect(parseCidr(text), text).toBeNull();
    }
  });
});

describe('bit helpers', () => {
  it('masks bits past the prefix', () => {
    const words = parseIp('192.168.200.5')?.words as Uint32Array;
    expect(maskWords(words, 16)[0]).toBe(0xc0a80000);
    expect(maskWords(words, 24)[0]).toBe(0xc0a8c800);
  });

  it('reads bits from the most significant end', () => {
    const words = parseIp('128.0.0.0')?.words as Uint32Array;
    expect(bitAt(words, 0)).toBe(1);
    expect(bitAt(words, 1)).toBe(0);
  });
});