/**
 * Shared types for rulegraph.
 *
 * The rule model follows the subset of the Clash / mihomo rule grammar that can
 * be evaluated purely on the connection tuple (host + destination IP). Rules
 * that require extra context (RULE-SET, GEOIP lookups, AND/OR logic) are
 * rejected by the parser instead of being silently dropped, so a compiled
 * ruleset never diverges from the source file without a diagnostic.
 */

export type RuleType =
  | 'DOMAIN'
  | 'DOMAIN-SUFFIX'
  | 'DOMAIN-KEYWORD'
  | 'IP-CIDR'
  | 'IP-CIDR6'
  | 'MATCH';

export interface Rule {
  readonly type: RuleType;
  readonly payload: string;
  readonly policy: string;
  readonly noResolve: boolean;
  /** 1-based line in the source document, for diagnostics. */
  readonly line: number;
}

export interface ParseError {
  readonly line: number;
  readonly message: string;
  readonly raw: string;
}

export interface Ruleset {
  readonly rules: readonly Rule[];
  readonly errors: readonly ParseError[];
}

export interface MatchInput {
  /** Destination host as seen by the proxy(usually SNI or the parsed CONNECT target). */
  host?: string;
  /** Destination IP, when already known (A/AAAA answer or literal target). */
  ip?: string;
}

export interface MatchResult {
  /** 0-based index into `CompiledRuleset.rules`. */
  index: number;
  rule: Rule;
}

export interface CompileStats {
  rules: number;
  domainExact: number;
  domainSuffix: number;
  domainKeyword: number;
  ipv4Cidr: number;
  ipv6Cidr: number;
  domainNodes: number;
  ipv4Nodes: number;
  ipv6Nodes: number;
  automatonStates: number;
  fallback: boolean;
  /** Rules positioned after the first MATCH; a first-match scan never reaches them. */
  unreachable: number;
}