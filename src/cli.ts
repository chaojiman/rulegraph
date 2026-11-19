#!/usr/bin/env node
/**
 * rulegraph CLI.
 *
 *   rulegraph compile <rules|config.yaml> -o <file.rgp> [--strict]
 *   rulegraph match <file.rgp|rules> (--host <host> | --ip <addr>) [--json]
 *   rulegraph stats <file.rgp>
 *   rulegraph bench [--rules N] [--queries M] [--seed S] [--json]
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { compile, naiveMatch } from './compiler.js';
import { RuleEngine } from './engine.js';
import { parseRuleset } from './parser.js';
import { deserialize, serialize } from './serialize.js';
import { runBenchmark, formatReport } from './bench/run.js';
import type { CompiledRuleset } from './compiler.js';
import type { Ruleset, MatchInput } from './types.js';

const HELP = `rulegraph — compile Clash/mihomo rule sets into prefix indexes

Usage:
  rulegraph compile <rules|config.yaml> -o <out.rgp> [--strict] [--json]
  rulegraph match <rules|out.rgp> (--host <host> | --ip <addr>) [--json]
  rulegraph stats <rules|out.rgp> [--json]
  rulegraph bench [--rules N] [--queries M] [--seed S] [--json]
  rulegraph --help

Notes:
  compile  refuses to drop unknown rule types silently; pass --strict to also
           reject unknown flags (e.g. src, uid).
  match    reports the first matching rule exactly like a linear scan would.
`;

function load(source: string): CompiledRuleset {
  const text = readFileSync(source);
  if (source.endsWith('.rgp')) return deserialize(new Uint8Array(text));
  const ruleset: Ruleset = parseRuleset(text.toString('utf8'), { strict: true });
  if (ruleset.errors.length > 0) {
    const detail = ruleset.errors.map((error) => `  line ${error.line}: ${error.message}`).join('\n');
    throw new Error(`parse errors:\n${detail}`);
  }
  return compile(ruleset);
}

function reportParseErrors(ruleset: Ruleset): void {
  for (const error of ruleset.errors) {
    process.stderr.write(`warning: line ${error.line}: ${error.message} — rule ignored\n`);
  }
}

function fmtNumber(value: number): string {
  return value.toLocaleString('en-US');
}

function printStats(compiled: CompiledRuleset): void {
  for (const [key, value] of Object.entries(compiled.stats)) {
    process.stdout.write(`${key.padEnd(16)} ${fmtNumber(typeof value === 'number' ? value : Number(value))}\n`);
  }
}

function main(argv: readonly string[]): number {
  const [command, ...rest] = argv;
  if (command === undefined || command === '--help' || command === '-h') {
    process.stdout.write(HELP);
    return 0;
  }

  if (command === 'compile') {
    const parsed = parseArgs({
      args: rest as string[],
      options: { output: { type: 'string', short: 'o' }, strict: { type: 'boolean' }, json: { type: 'boolean' } },
      allowPositionals: true,
    });
    const input = parsed.positionals[0];
    if (input === undefined) throw new Error('compile: missing input file');
    const ruleset = parseRuleset(readFileSync(input, 'utf8'), { strict: parsed.values.strict ?? false });
    reportParseErrors(ruleset);
    if (ruleset.rules.length === 0) throw new Error('compile: no rules parsed');
    const compiled = compile(ruleset);
    const image = serialize(compiled);
    const output = parsed.values.output ?? `${input}.rgp`;
    writeFileSync(output, image);
    if (parsed.values.json) {
      process.stdout.write(`${JSON.stringify({ output, bytes: image.length, stats: compiled.stats })}\n`);
    } else {
      process.stdout.write(`compiled ${ruleset.rules.length} rules → ${output} (${fmtNumber(image.length)} bytes)\n`);
      printStats(compiled);
    }
    return ruleset.errors.length > 0 ? 1 : 0;
  }

  if (command === 'match') {
    const parsed = parseArgs({
      args: rest as string[],
      options: { host: { type: 'string' }, ip: { type: 'string' }, json: { type: 'boolean' } },
      allowPositionals: true,
    });
    const source = parsed.positionals[0];
    if (source === undefined) throw new Error('match: missing rules file');
    if (parsed.values.host === undefined && parsed.values.ip === undefined) {
      throw new Error('match: pass --host and/or --ip');
    }
    const compiled = load(source);
    const input: MatchInput = {};
    if (parsed.values.host !== undefined) input.host = parsed.values.host;
    if (parsed.values.ip !== undefined) input.ip = parsed.values.ip;
    const index = compiled.rules.length > 0 ? naiveMatch(compiled.rules, input) : -1;
    const result = new RuleEngine(compiled).match(input);
    if (parsed.values.json) {
      process.stdout.write(`${JSON.stringify({ input, match: result, referenceIndex: index })}\n`);
    } else if (result === null) {
      process.stdout.write('no rule matched\n');
    } else {
      const rule = result.rule;
      const text = rule.type === 'MATCH' ? `MATCH,${rule.policy}` : `${rule.type},${rule.payload},${rule.policy}`;
      process.stdout.write(`${text}  (index ${result.index}, source line ${rule.line})\n`);
    }
    return 0;
  }

  if (command === 'stats') {
    const source = rest.find((arg) => !arg.startsWith('-'));
    if (source === undefined) throw new Error('stats: missing rules file');
    const compiled = load(source);
    if (rest.includes('--json')) process.stdout.write(`${JSON.stringify(compiled.stats, null, 2)}\n`);
    else printStats(compiled);
    return 0;
  }

  if (command === 'bench') {
    const sizesIndex = rest.indexOf('--sizes');
    const sizeText = sizesIndex >= 0 ? rest[sizesIndex + 1] : undefined;
    const parsedSizes = sizeText === undefined
      ? []
      : sizeText.split(',').map(Number).filter((value) => Number.isFinite(value) && value > 0);
    const result = runBenchmark({
      sizes: parsedSizes.length > 0 ? parsedSizes : [1_000, 10_000, 100_000],
      queries: numericFlag(rest, '--queries', 20_000),
      seed: numericFlag(rest, '--seed', 7),
      sample: numericFlag(rest, '--sample', 2_000),
    });
    process.stdout.write(rest.includes('--json') ? `${JSON.stringify(result, null, 2)}\n` : `${formatReport(result)}\n`);
    return 0;
  }

  process.stderr.write(`unknown command "${command}"\n\n${HELP}`);
  return 2;
}

function numericFlag(argv: readonly string[], name: string, fallback: number): number {
  const index = argv.indexOf(name);
  if (index < 0) return fallback;
  const value = Number(argv[index + 1] ?? '');
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 2;
}