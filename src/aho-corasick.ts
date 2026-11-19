/**
 * Aho-Corasick automaton for `DOMAIN-KEYWORD` rules.
 *
 * Keyword rules are substring tests over the host, so the only way to avoid an
 * O(rules) scan is a multi-pattern automaton. Build is O(total pattern length);
 * a query is O(host length + hits).
 */

export interface AutomatonState {
  fail: number;
  out: number[] | null;
  next: Map<number, number> | null;
}

const emptyState = (): AutomatonState => ({ fail: 0, out: null, next: null });

export class Automaton {
  private readonly states: AutomatonState[];
  private built: boolean;

  constructor(states?: AutomatonState[]) {
    if (states === undefined) {
      this.states = [emptyState()];
      this.built = false;
    } else {
      this.states = states;
      this.built = true;
    }
  }

  get stateCount(): number {
    return this.states.length;
  }

  addPattern(pattern: string, index: number): void {
    if (this.built) throw new Error('automaton already built');
    let state = 0;
    for (let i = 0; i < pattern.length; i += 1) {
      const code = pattern.charCodeAt(i);
      const current = this.states[state] as AutomatonState;
      if (current.next === null) current.next = new Map();
      let next = current.next.get(code);
      if (next === undefined) {
        next = this.states.length;
        this.states.push(emptyState());
        current.next.set(code, next);
      }
      state = next;
    }
    const final = this.states[state] as AutomatonState;
    if (final.out === null) final.out = [];
    final.out.push(index);
  }

  build(): void {
    if (this.built) return;
    const root = this.states[0] as AutomatonState;
    const queue: number[] = [];
    if (root.next !== null) {
      for (const child of root.next.values()) {
        (this.states[child] as AutomatonState).fail = 0;
        queue.push(child);
      }
    }
    let head = 0;
    while (head < queue.length) {
      const state = queue[head++] as number;
      const current = this.states[state] as AutomatonState;
      if (current.next === null) continue;
      for (const [code, child] of current.next) {
        let fallback = current.fail;
        for (;;) {
          const candidate = this.states[fallback] as AutomatonState;
          const target = candidate.next === null ? undefined : candidate.next.get(code);
          if (target !== undefined && target !== child) {
            fallback = target;
            break;
          }
          if (fallback === 0) break;
          fallback = candidate.fail;
        }
        const node = this.states[child] as AutomatonState;
        node.fail = fallback;
        const inherited = (this.states[fallback] as AutomatonState).out;
        if (inherited !== null && inherited.length > 0) {
          node.out = node.out === null ? [...inherited] : node.out.concat(inherited);
        }
        queue.push(child);
      }
    }
    this.built = true;
  }

  /** Returns matched pattern indexes (unsorted, may contain duplicates). */
  match(text: string): number[] {
    if (!this.built) this.build();
    const out: number[] = [];
    let state = 0;
    for (let i = 0; i < text.length; i += 1) {
      const code = text.charCodeAt(i);
      for (;;) {
        const current = this.states[state] as AutomatonState;
        const next = current.next === null ? undefined : current.next.get(code);
        if (next !== undefined) {
          state = next;
          break;
        }
        if (state === 0) break;
        state = current.fail;
      }
      const hits = (this.states[state] as AutomatonState).out;
      if (hits !== null) for (const index of hits) out.push(index);
    }
    return out;
  }

  dump(): AutomatonState[] {
    this.build();
    return this.states;
  }

  static fromStates(states: AutomatonState[]): Automaton {
    return new Automaton(states);
  }
}