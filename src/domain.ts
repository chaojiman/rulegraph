/**
 * Host normalization shared by the compiler and the query path.
 *
 * The query path must be exactly as forgiving as the compile path, otherwise a
 * rule written as `DOMAIN-SUFFIX,example.com` would silently miss queries for
 * `EXAMPLE.com.` — so both sides go through this single function.
 */

import { domainToASCII } from 'node:url';
import { parseIp } from './ip.js';

const LABEL = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;

/**
 * Normalize a host to lower-case ASCII (IDN → punycode), strip a single
 * trailing dot, and reject anything that is not a hostname.
 *
 * Returns `null` for IP literals — callers route those through the CIDR index.
 */
export function normalizeHost(input: string): string | null {
  let text = input.trim().toLowerCase();
  if (text.length === 0) return null;
  if (text.endsWith('.')) text = text.slice(0, -1);
  if (text.length === 0 || text.length > 253) return null;
  if (parseIp(text) !== null) return null;

  const ascii = domainToASCII(text);
  if (ascii === '') return null;
  if (ascii.length === 0 || ascii.length > 253) return null;
  if (ascii.includes('*')) return null;

  const labels = ascii.split('.');
  for (const label of labels) {
    if (!LABEL.test(label)) return null;
  }
  return ascii;
}

/** Human-readable reason a host was rejected, used by the CLI. */
export function describeHost(input: string): string {
  if (parseIp(input) !== null) return 'IP literal';
  const normalized = normalizeHost(input);
  return normalized === null ? 'not a valid hostname' : `normalized: ${normalized}`;
}