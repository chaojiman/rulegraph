import { describe, expect, it } from 'vitest';
import { Automaton } from '../src/aho-corasick.js';

describe('Automaton', () => {
  it('finds every overlapping pattern', () => {
    const automaton = new Automaton();
    automaton.addPattern('aa', 0);
    automaton.addPattern('aaa', 1);
    automaton.build();
    expect(automaton.match('aaaa').sort()).toEqual([0, 0, 0, 1, 1]);
  });

  it('matches keywords inside a hostname', () => {
    const automaton = new Automaton();
    automaton.addPattern('analytics', 0);
    automaton.addPattern('tracker', 1);
    automaton.build();
    expect(automaton.match('secure-tracker.example').sort()).toEqual([1]);
    expect(automaton.match('nothing-here.example')).toEqual([]);
  });

  it('inherits output from failure links', () => {
    const automaton = new Automaton();
    automaton.addPattern('he', 0);
    automaton.addPattern('she', 1);
    automaton.addPattern('hers', 2);
    automaton.build();
    expect(automaton.match('ushers').sort()).toEqual([0, 1, 2]);
  });

  it('restores from dumped states', () => {
    const automaton = new Automaton();
    automaton.addPattern('ab', 0);
    automaton.build();
    const restored = Automaton.fromStates(automaton.dump());
    expect(restored.match('zzabzz').sort()).toEqual([0]);
    expect(restored.stateCount).toBe(automaton.stateCount);
  });
});