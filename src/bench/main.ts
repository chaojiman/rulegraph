/**
 * Standalone benchmark entry point (`npm run bench`).
 *
 *   tsx src/bench/main.ts [--sizes 1000,10000,100000] [--queries 20000]
 *                         [--seed 7] [--sample 2000] [--json]
 */

import { formatReport, runBenchmark } from './run.js';

function flag(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  return index < 0 ? undefined : argv[index + 1];
}

function numberList(argv: readonly string[], name: string, fallback: number[]): number[] {
  const raw = flag(argv, name);
  if (raw === undefined) return fallback;
  const values = raw.split(',').map(Number).filter((value) => Number.isFinite(value) && value > 0);
  return values.length > 0 ? values : fallback;
}

function number(argv: readonly string[], name: string, fallback: number): number {
  const raw = flag(argv, name);
  const value = Number(raw);
  return raw !== undefined && Number.isFinite(value) && value > 0 ? value : fallback;
}

const argv = process.argv.slice(2);
const result = runBenchmark({
  sizes: numberList(argv, '--sizes', [1_000, 10_000, 100_000]),
  queries: number(argv, '--queries', 20_000),
  seed: number(argv, '--seed', 7),
  sample: number(argv, '--sample', 2_000),
});

process.stdout.write(argv.includes('--json') ? `${JSON.stringify(result, null, 2)}\n` : `${formatReport(result)}\n`);