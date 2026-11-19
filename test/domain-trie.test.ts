import { describe, expect, it } from 'vitest';
import { DomainTrie } from '../src/domain-trie.js';

describe('DomainTrie', () => {
  it('matches a suffix rule on the bare domain and on subdomains', () => {
    const trie = new DomainTrie();
    trie.insertSuffix('example.com', 0);
    expect(trie.match('example.com').suffix).toEqual([0]);
    expect(trie.match('a.example.com').suffix).toEqual([0]);
    expect(trie.match('a.b.example.com').suffix).toEqual([0]);
    expect(trie.match('notexample.com').suffix).toEqual([]);
    expect(trie.match('com').suffix).toEqual([]);
  });

  it('keeps exact rules separate from suffix rules', () => {
    const trie = new DomainTrie();
    trie.insertSuffix('example.com', 0);
    trie.insertExact('www.example.com', 1);
    expect(trie.match('www.example.com')).toEqual({ exact: [1], suffix: [0] });
    expect(trie.match('api.example.com')).toEqual({ exact: [], suffix: [0] });
  });

  it('returns every nested suffix in source order', () => {
    const trie = new DomainTrie();
    trie.insertSuffix('com', 0);
    trie.insertSuffix('example.com', 1);
    trie.insertSuffix('deep.example.com', 2);
    expect(trie.match('a.deep.example.com').suffix).toEqual([0, 1, 2]);
  });

  it('survives a dump/restore cycle', () => {
    const trie = new DomainTrie();
    trie.insertSuffix('example.com', 0);
    trie.insertExact('only.example.com', 1);
    const restored = DomainTrie.fromNodes(trie.dump());
    expect(restored.size).toBe(trie.size);
    expect(restored.match('only.example.com')).toEqual({ exact: [1], suffix: [0] });
  });
});