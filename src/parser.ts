/**
 * Rule text parser.
 *
 * Two input shapes are accepted:
 *   1. a plain rule list, one rule per line;
 *   2. a Clash / mihomo `config.yaml` document — only the `rules:` block is
 *      consumed (the YAML reader is deliberately a scanner for that one block,
 *      so the package keeps zero runtime dependencies).
 *
 * Anything the engine cannot evaluate without extra context (RULE-SET, GEOIP,
 * AND/OR/SRC-IP) is reported as a `ParseError` instead of being dropped
 * silently — a compiled ruleset must never differ from its source without
 * a diagnostic.
 */

import { normalizeHost } from './domain.js';
import { parseCidr } from './ip.js';
import type { ParseError, Rule, Ruleset, RuleType } from './types.js';

const SUPPORTED: Record<string, true> = {
  DOMAIN: true,
  'DOMAIN-SUFFIX': true,
  'DOMAIN-KEYWORD': true,
  'IP-CIDR': true,
  'IP-CIDR6': true,
  MATCH: true,
};

const SUPPORTED_LIST = Object.keys(SUPPORTED).join(', ');

export interface ParseOptions {
  /** Treat unsupported rule types as errors rather than keeping them as text. */
  strict?: boolean;
  /** Xor-relative origin line, used when parsing embedded lists. */
  lineOffset?: number;
}

interface RuleEntry {
  raw: string;
  line: number;
}

function stripComment(line: string): string {
  const hash = line.indexOf('#');
  return hash >= 0 ? line.slice(0, hash) : line;
}

function unquote(value: string): string {
  const text = value.trim();
  if (text.length >= 2) {
    const first = text[0];
    const last = text[text.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return text.slice(1, -1);
    }
  }
  return text;
}

/** Collect rule entries from a `rules:` YAML block, or treat the whole file as a list. */
function collectEntries(text: string): RuleEntry[] {
  const lines = text.split(/\r?\n/);
  const hasRulesBlock = lines.some((line) => /^rules:\s*$/.test(line));
  const entries: RuleEntry[] = [];

  if (!hasRulesBlock) {
    for (let i = 0; i < lines.length; i += 1) {
      const raw = stripComment(lines[i] as string).trim();
      if (raw.length > 0) entries.push({ raw, line: i + 1 });
    }
    return entries;
  }

  let inside = false;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] as string;
    if (!inside) {
      if (/^rules:\s*$/.test(line)) inside = true;
      continue;
    }
    const trimmed = stripComment(line).trim();
    if (trimmed.length === 0) continue;
    const indent = (line.match(/^\s*/)?.[0] ?? '').length;
    if (indent === 0) {
      inside = false;
      continue;
    }
    if (!trimmed.startsWith('-')) continue;
    const raw = unquote(trimmed.replace(/^-\s*/, ''));
    if (raw.length > 0) entries.push({ raw, line: i + 1 });
  }
  return entries;
}

function parseEntry(entry: RuleEntry, strict: boolean): Rule | ParseError {
  const parts = entry.raw.split(',').map((part) => part.trim());
  const typeText = (parts[0] ?? '').toUpperCase();

  if (SUPPORTED[typeText] !== true) {
    return {
      line: entry.line,
      message: `unsupported rule type "${typeText}" (supported: ${SUPPORTED_LIST})`,
      raw: entry.raw,
    };
  }

  const type = typeText as RuleType;
  if (type === 'MATCH') {
    const policy = parts[1] ?? '';
    if (policy.length === 0) {
      return { line: entry.line, message: 'MATCH requires a policy name', raw: entry.raw };
    }
    return { type, payload: '', policy, noResolve: false, line: entry.line };
  }

  const payload = parts[1] ?? '';
  const policy = parts[2] ?? '';
  if (payload.length === 0) {
    return { line: entry.line, message: `${type} requires a payload`, raw: entry.raw };
  }
  if (policy.length === 0) {
    return { line: entry.line, message: `${type} requires a policy name`, raw: entry.raw };
  }

  const flags = parts.slice(3).filter((flag) => flag.length > 0);
  const noResolve = flags.includes('no-resolve');
  const unknown = flags.filter((flag) => flag !== 'no-resolve');
  if (unknown.length > 0 && strict) {
    return {
      line: entry.line,
      message: `unknown rule flag(s): ${unknown.join(', ')}`,
      raw: entry.raw,
    };
  }

  if (type === 'DOMAIN' || type === 'DOMAIN-SUFFIX') {
    const host = normalizeHost(payload);
    if (host === null) {
      return { line: entry.line, message: `invalid hostname "${payload}"`, raw: entry.raw };
    }
    return { type, payload: host, policy, noResolve, line: entry.line };
  }

  if (type === 'DOMAIN-KEYWORD') {
    const keyword = payload.toLowerCase();
    if (keyword.length === 0 || keyword.length > 253) {
      return { line: entry.line, message: `invalid keyword length`, raw: entry.raw };
    }
    return { type, payload: keyword, policy, noResolve, line: entry.line };
  }

  const cidr = parseCidr(payload);
  if (cidr === null) {
    return { line: entry.line, message: `invalid CIDR "${payload}"`, raw: entry.raw };
  }
  if (type === 'IP-CIDR' && cidr.family !== 4) {
    return { line: entry.line, message: `IP-CIDR only accepts IPv4 networks`, raw: entry.raw };
  }
  if (type === 'IP-CIDR6' && cidr.family !== 6) {
    return { line: entry.line, message: `IP-CIDR6 only accepts IPv6 networks`, raw: entry.raw };
  }
  return { type, payload, policy, noResolve, line: entry.line };
}

export function parseRuleset(text: string, options: ParseOptions = {}): Ruleset {
  const strict = options.strict ?? false;
  const offset = options.lineOffset ?? 0;
  const rules: Rule[] = [];
  const errors: ParseError[] = [];

  for (const entry of collectEntries(text)) {
    const shifted: RuleEntry = { raw: entry.raw, line: entry.line + offset };
    const result = parseEntry(shifted, strict);
    if ('message' in result) {
      errors.push(result);
    } else {
      rules.push(result);
    }
  }

  return { rules, errors };
}