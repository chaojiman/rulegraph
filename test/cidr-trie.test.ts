import { describe, expect, it } from 'vitest';
import { CidrTrie } from '../src/cidr-trie.js';
import { maskWords, parseIp } from '../src/ip.js';

const words = (address: string): Uint32Array => parseIp(address)?.words as Uint32Array;

describe('CidrTrie', () => {
  it('returns every covering prefix', () => {
    const trie = new CidrTrie();
    trie.insert(maskWords(words('10.0.0.0'), 8), 8, 0);
    trie.insert(maskWords(words('10.1.0.0'), 16), 16, 1);
    expect(trie.match(words('10.1.2.3'), 32).sort()).toEqual([0, 1]);
    expect(trie.match(words('10.2.2.3'), 32)).toEqual([0]);
    expect(trie.match(words('11.0.0.1'), 32)).toEqual([]);
  });

  it('supports the default route', () => {
    const trie = new CidrTrie();
    trie.insert(maskWords(words('0.0.0.0'), 0), 0, 7);
    expect(trie.match(words('203.0.113.9'), 32)).toEqual([7]);
  });

  it('handles IPv6 prefixes', () => {
    const trie = new CidrTrie();
    trie.insert(maskWords(words('2001:db8::'), 32), 32, 0);
    trie.insert(maskWords(words('2001:db8:0:1::'), 64), 64, 1);
    expect(trie.match(words('2001:db8:0:1::5'), 128).sort()).toEqual([0, 1]);
    expect(trie.match(words('2001:db8:0:2::5'), 128)).toEqual([0]);
    expect(trie.match(words('2001:db9::1'), 128)).toEqual([]);
  });

  it('survives a dump/restore cycle', () => {
    const trie = new CidrTrie();
    trie.insert(maskWords(words('192.168.0.0'), 16), 16, 3);
    const restored = CidrTrie.fromNodes(trie.dump());
    expect(restored.size).toBe(trie.size);
    expect(restored.match(words('192.168.9.9'), 32)).toEqual([3]);
  });
});