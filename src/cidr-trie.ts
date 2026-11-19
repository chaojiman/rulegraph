/**
 * Binary prefix trie over `Uint32Array` words.
 *
 * Every node on the path from the root to the queried address owns the rule
 * indexes whose network covers that address, so a single 32-bit (IPv4) or
 * 128-bit (IPv6) descent returns every candidate rule. Rule order is resolved
 * by the engine (minimum index wins), which is what makes this structure
 * semantically equivalent to a linear first-match scan.
 */

import { bitAt } from './ip.js';

export interface CidrNode {
  id: number;
  zero: CidrNode | null;
  one: CidrNode | null;
  bucket: number[] | null;
}

const emptyNode = (id: number): CidrNode => ({ id, zero: null, one: null, bucket: null });

export class CidrTrie {
  private root: CidrNode = emptyNode(0);
  private nextId = 1;
  private nodeCount = 1;

  get size(): number {
    return this.nodeCount;
  }

  /** `words` must already be masked to `prefix`. */
  insert(words: Uint32Array, prefix: number, index: number): void {
    let node = this.root;
    for (let i = 0; i < prefix; i += 1) {
      const slot: 'zero' | 'one' = bitAt(words, i) === 0 ? 'zero' : 'one';
      let child = node[slot];
      if (child === null) {
        child = emptyNode(this.nextId);
        this.nextId += 1;
        this.nodeCount += 1;
        node[slot] = child;
      }
      node = child;
    }
    if (node.bucket === null) node.bucket = [];
    node.bucket.push(index);
  }

  match(words: Uint32Array, bits: number): number[] {
    const out: number[] = [];
    let node: CidrNode | null = this.root;
    if (node.bucket !== null) for (const index of node.bucket) out.push(index);
    for (let i = 0; i < bits; i += 1) {
      node = bitAt(words, i) === 0 ? node.zero : node.one;
      if (node === null) return out;
      if (node.bucket !== null) for (const index of node.bucket) out.push(index);
    }
    return out;
  }

  dump(): CidrNode[] {
    const nodes: CidrNode[] = new Array<CidrNode>(this.nextId);
    const stack: CidrNode[] = [this.root];
    while (stack.length > 0) {
      const node = stack.pop() as CidrNode;
      nodes[node.id] = node;
      if (node.zero !== null) stack.push(node.zero);
      if (node.one !== null) stack.push(node.one);
    }
    return nodes;
  }

  static fromNodes(nodes: CidrNode[]): CidrTrie {
    const trie = new CidrTrie();
    trie.root = nodes[0] as CidrNode;
    trie.nextId = nodes.length;
    trie.nodeCount = nodes.length;
    return trie;
  }
}