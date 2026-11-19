/**
 * Benchmark: compiled engine vs linear first-match scan, across rule-set sizes.
 *
 * Two properties are enforced before any number is reported:
 *   1. the engine must agree with the reference scan on every sampled query;
 *   2. the reloaded image must agree with the freshly compiled one.
 *
 * The naive scan is intentionally expensive (O(rules) per query), so it runs on
 * a fixed sample while the engine is timed on the full query set — otherwise a
 * 100k-rule run would take hours and tell us nothing new.
 */

import { compile, naiveMatch } from '../compiler.js';
import { RuleEngine } from '../engine.js';
import { parseRuleset } from '../parser.js';
import { deserialize, serialize } from '../serialize.js';
import type { MatchInput, Rule } from '../types.js';
import { generateCorpus } from './generate.js';

export interface Timing {
  qps: number;
  p50Us: number;
  p95Us: number;
  p99Us: number;
}

export interface SizeResult {
  rules: number;
  queries: number;
  sample: number;
  parseMs: number;
  compileMs: number;
  serializeMs: number;
  deserializeMs: number;
  imageBytes: number;
  heapMiB: number;
  engine: Timing;
  naive: Timing;
  speedup: number;
  mismatches: number;
}

export interface BenchResult {
  seed: number;
  sizes: SizeResult[];
}

const now = (): number => Number(process.hrtime.bigint()) / 1e6;

function percentile(sorted: readonly number[], ratio: number): number {
  if (sorted.length === 0) return 0;
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * ratio))] as number;
}

function summarize(samples: number[], elapsedMs: number): Timing {
  const sorted = samples.sort((a, b) => a - b);
  return {
    qps: Math.round((samples.length / elapsedMs) * 1000),
    p50Us: Number(percentile(sorted, 0.5).toFixed(2)),
    p95Us: Number(percentile(sorted, 0.95).toFixed(2)),
    p99Us: Number(percentile(sorted, 0.99).toFixed(2)),
  };
}

function timeEngine(engine: RuleEngine, queries: readonly MatchInput[]): Timing {
  const samples: number[] = new Array<number>(queries.length);
  const start = now();
  for (let i = 0; i < queries.length; i += 1) {
    const begin = now();
    engine.match(queries[i] as MatchInput);
    samples[i] = (now() - begin) * 1000;
  }
  return summarize(samples, now() - start);
}

function timeNaive(rules: readonly Rule[], queries: readonly MatchInput[]): Timing {
  const samples: number[] = new Array<number>(queries.length);
  const start = now();
  for (let i = 0; i < queries.length; i += 1) {
    const begin = now();
    naiveMatch(rules, queries[i] as MatchInput);
    samples[i] = (now() - begin) * 1000;
  }
  return summarize(samples, now() - start);
}

export interface BenchOptions {
  sizes: number[];
  queries: number;
  seed: number;
  sample: number;
}

export function runBenchmark(options: BenchOptions): BenchResult {
  const sizes: SizeResult[] = [];

  for (const ruleCount of options.sizes) {
    const corpus = generateCorpus({ rules: ruleCount, queries: options.queries, seed: options.seed });

    const parseStart = now();
    const parsed = parseRuleset(corpus.text, { strict: true });
    const parseMs = now() - parseStart;
    const firstError = parsed.errors[0];
    if (firstError !== undefined) throw new Error(`generated corpus failed to parse: ${firstError.message}`);

    const compileStart = now();
    const compiled = compile(parsed);
    const compileMs = now() - compileStart;

    const serializeStart = now();
    const image = serialize(compiled);
    const serializeMs = now() - serializeStart;

    const deserializeStart = now();
    const restored = deserialize(image);
    const deserializeMs = now() - deserializeStart;

    const engine = new RuleEngine(compiled);
    const restoredEngine = new RuleEngine(restored);
    const sampleSize = Math.min(options.sample, corpus.queries.length);
    const sample = corpus.queries.slice(0, sampleSize);

    let mismatches = 0;
    for (const query of sample) {
      const expected = naiveMatch(parsed.rules, query);
      if ((engine.match(query)?.index ?? -1) !== expected) mismatches += 1;
      if ((restoredEngine.match(query)?.index ?? -1) !== expected) mismatches += 1;
    }
    if (mismatches > 0) throw new Error(`${mismatches} mismatches between the reference scan and the compiled index`);

    // Warm up both paths before timing.
    for (const query of sample) {
      engine.match(query);
      naiveMatch(parsed.rules, query);
    }

    const engineTiming = timeEngine(engine, corpus.queries);
    const naiveTiming = timeNaive(parsed.rules, sample);
    const heapMiB = Number((process.memoryUsage().heapUsed / 1048576).toFixed(1));

    sizes.push({
      rules: ruleCount,
      queries: corpus.queries.length,
      sample: sampleSize,
      parseMs: Number(parseMs.toFixed(1)),
      compileMs: Number(compileMs.toFixed(1)),
      serializeMs: Number(serializeMs.toFixed(1)),
      deserializeMs: Number(deserializeMs.toFixed(1)),
      imageBytes: image.length,
      heapMiB,
      engine: engineTiming,
      naive: naiveTiming,
      speedup: Number((engineTiming.qps / Math.max(1, naiveTiming.qps)).toFixed(2)),
      mismatches: 0,
    });
  }

  return { seed: options.seed, sizes };
}

export function formatReport(result: BenchResult): string {
  const lines: string[] = [];
  lines.push(`seed ${result.seed} — engine timed on the full query set, naive scan on a sample`);
  lines.push('');
  lines.push(
    ['rules'.padStart(8), 'compile', 'image', 'engine qps', 'engine p50', 'naive qps', 'naive p50', 'speedup'].join('  '),
  );
  for (const size of result.sizes) {
    lines.push(
      [
        String(size.rules).padStart(8),
        `${size.compileMs} ms`.padEnd(9),
        `${(size.imageBytes / 1048576).toFixed(2)} MiB`.padEnd(9),
        String(size.engine.qps).padStart(10),
        `${size.engine.p50Us} µs`.padEnd(9),
        String(size.naive.qps).padStart(9),
        `${size.naive.p50Us} µs`.padEnd(9),
        `${size.speedup}x`,
      ].join('  '),
    );
  }
  lines.push('');
  for (const size of result.sizes) {
    lines.push(
      `${size.rules} rules: ${size.queries} queries, ${size.sample} verified against the linear scan, ` +
        `p95 ${size.engine.p95Us} µs, p99 ${size.engine.p99Us} µs, heap ${size.heapMiB} MiB`,
    );
  }
  return lines.join('\n');
}