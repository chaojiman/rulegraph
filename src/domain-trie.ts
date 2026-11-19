/**
 * Domain index: exact matches and suffix matches share one trie built on
 * reversed labels (`a.b.example.com` → `com` → `example` → `b` → `a`).
 *
 * A suffix rule `DOMAIN-SUFFIX,example.com` matches both `example.com` and
 * `*.example.com`; walking from the TLD inwards means every visited node can
 * contribute its suffix buckets without allocating a label array per query.
 */

export interface DomainNode {
  id: number;
  children: Map<string, DomainNode> | null;
  exact: number[] | null;
  suffix: number[] | null;
}

export interface DomainHit {
  readonly exact: readonly number[];
  readonly suffix: readonly number[];
}

const emptyNode = (id: number): DomainNode => ({ id, children: null, exact: null, suffix: null });

export class DomainTrie {
  private root: DomainNode = emptyNode(0);
  private nextId = 1;
  private nodeCount = 1;

  get size(): number {
    return this.nodeCount;
  }

  private insertAt(labelsRightToLeft: readonly string[], index: number, suffix: boolean): void {
    let node = this.root;
    for (const label of labelsRightToLeft) {
      if (node.children === null) node.children = new Map();
      let child = node.children.get(label);
      if (child === undefined) {
        child = emptyNode(this.nextId);
        this.nextId += 1;
        this.nodeCount += 1;
        node.children.set(label, child);
      }
      node = child;
    }
    const bucket = suffix ? 'suffix' : 'exact';
    if (node[bucket] === null) node[bucket] = [];
    (node[bucket] as number[]).push(index);
  }

  insertExact(host: string, index: number): void {
    this.insertAt(host.split('.').reverse(), index, false);
  }

  insertSuffix(host: string, index: number): void {
    this.insertAt(host.split('.').reverse(), index, true);
  }

  /** Match a host that has already been normalized by `normalizeHost`. */
  match(host: string): DomainHit {
    const exact: number[] = [];
    const suffix: number[] = [];
    let node: DomainNode | null = this.root;
    let end = host.length;
    while (end > 0 && node !== null) {
      const dot = host.lastIndexOf('.', end - 1);
      const start = dot + 1;
      node = node.children === null ? null : (node.children.get(host.slice(start, end)) ?? null);
      if (node !== null && node.suffix !== null) {
        for (const index of node.suffix) suffix.push(index);
      }
      end = dot;
    }
    if (node !== null && node.exact !== null) {
      for (const index of node.exact) exact.push(index);
    }
    return { exact, suffix };
  }

  /** Nodes indexed by id; the serializer walks them in that order. */
  dump(): DomainNode[] {
    const nodes: DomainNode[] = new Array<DomainNode>(this.nextId);
    const stack: DomainNode[] = [this.root];
    while (stack.length > 0) {
      const node = stack.pop() as DomainNode;
      nodes[node.id] = node;
      if (node.children !== null) {
        for (const child of node.children.values()) stack.push(child);
      }
    }
    return nodes;
  }

  static fromNodes(nodes: DomainNode[]): DomainTrie {
    const trie = new DomainTrie();
    trie.root = nodes[0] as DomainNode;
    trie.nextId = nodes.length;
    trie.nodeCount = nodes.length;
    return trie;
  }
}