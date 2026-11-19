/**
 * Compact binary format for compiled rulesets (".rgp").
 *
 * Motivation: compiling 500k Clash rules takes seconds and produces far more
 * memory than a proxy wants to rebuild on every restart. The compiler therefore
 * emits a flat, self-describing image that the engine can load directly:
 *
 *   magic "RGP1" | u32 version | u32 ruleCount | rules[] |
 *   domain trie (nodes, edges, buckets) | IPv4 trie | IPv6 trie |
 *   Aho-Corasick states | u32 firstMatchIndex+1 | u32 FNV-1a checksum
 *
 * All integers are little-endian. Strings are u16-length-prefixed UTF-8.
 * A checksum trailer makes truncated or patched images fail loudly.
 */

import { Automaton, type AutomatonState } from './aho-corasick.js';
import { CidrTrie, type CidrNode } from './cidr-trie.js';
import { compile, type CompiledRuleset } from './compiler.js';
import { DomainTrie, type DomainNode } from './domain-trie.js';
import type { CompileStats, Rule, RuleType } from './types.js';

const MAGIC = [0x52, 0x47, 0x50, 0x31] as const; // "RGP1"
const VERSION = 1;
const NONE = 0xffffffff;

const TYPE_CODES: Record<RuleType, number> = {
  DOMAIN: 0,
  'DOMAIN-SUFFIX': 1,
  'DOMAIN-KEYWORD': 2,
  'IP-CIDR': 3,
  'IP-CIDR6': 4,
  MATCH: 5,
};

const CODE_TYPES: readonly RuleType[] = ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6', 'MATCH'];

const encoder = new TextEncoder();
const decoder = new TextDecoder();

class ByteWriter {
  private buffer = new Uint8Array(8192);
  private view = new DataView(this.buffer.buffer);
  private length = 0;

  private reserve(count: number): void {
    if (this.length + count <= this.buffer.length) return;
    let size = this.buffer.length * 2;
    while (size < this.length + count) size *= 2;
    const next = new Uint8Array(size);
    next.set(this.buffer.subarray(0, this.length));
    this.buffer = next;
    this.view = new DataView(next.buffer);
  }

  u8(value: number): void {
    this.reserve(1);
    this.view.setUint8(this.length, value);
    this.length += 1;
  }

  u16(value: number): void {
    this.reserve(2);
    this.view.setUint16(this.length, value, true);
    this.length += 2;
  }

  u32(value: number): void {
    this.reserve(4);
    this.view.setUint32(this.length, value, true);
    this.length += 4;
  }

  str(value: string): void {
    const bytes = encoder.encode(value);
    if (bytes.length > 0xffff) throw new RangeError('string too long for the image format');
    this.u16(bytes.length);
    this.reserve(bytes.length);
    this.buffer.set(bytes, this.length);
    this.length += bytes.length;
  }

  finish(): Uint8Array {
    return this.buffer.slice(0, this.length);
  }
}

class ByteReader {
  private position = 0;
  private readonly view: DataView;
  private readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get offset(): number {
    return this.position;
  }

  u8(): number {
    this.need(1);
    const value = this.view.getUint8(this.position);
    this.position += 1;
    return value;
  }

  u16(): number {
    this.need(2);
    const value = this.view.getUint16(this.position, true);
    this.position += 2;
    return value;
  }

  u32(): number {
    this.need(4);
    const value = this.view.getUint32(this.position, true);
    this.position += 4;
    return value;
  }

  str(): string {
    const length = this.u16();
    this.need(length);
    const value = decoder.decode(this.bytes.subarray(this.position, this.position + length));
    this.position += length;
    return value;
  }

  private need(count: number): void {
    if (this.position + count > this.bytes.length) {
      throw new RangeError(`truncated image: wanted ${count} bytes at offset ${this.position}`);
    }
  }
}

function checksum(bytes: Uint8Array): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i += 1) {
    hash ^= bytes[i] as number;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

export function serialize(compiled: CompiledRuleset): Uint8Array {
  const writer = new ByteWriter();
  for (const byte of MAGIC) writer.u8(byte);
  writer.u32(VERSION);
  writer.u32(compiled.rules.length);
  for (const rule of compiled.rules) {
    writer.u8(TYPE_CODES[rule.type]);
    writer.u8(rule.noResolve ? 1 : 0);
    writer.u32(rule.line);
    writer.str(rule.policy);
    writer.str(rule.payload);
  }

  writeDomainTrie(writer, compiled.domains);
  writeCidrTrie(writer, compiled.ipv4);
  writeCidrTrie(writer, compiled.ipv6);
  writeAutomaton(writer, compiled.keywords);
  writer.u32(compiled.matchIndex === null ? NONE : compiled.matchIndex);

  const body = writer.finish();
  const footer = new Uint8Array(4);
  new DataView(footer.buffer).setUint32(0, checksum(body), true);
  const image = new Uint8Array(body.length + 4);
  image.set(body, 0);
  image.set(footer, body.length);
  return image;
}

export function deserialize(image: Uint8Array): CompiledRuleset {
  if (image.length < 16) throw new RangeError('image too short');
  const bodyLength = image.length - 4;
  const expected = new DataView(image.buffer, image.byteOffset + bodyLength, 4).getUint32(0, true);
  if (checksum(image.subarray(0, bodyLength)) !== expected) {
    throw new Error('image checksum mismatch — file is corrupted or was edited');
  }

  const reader = new ByteReader(image.subarray(0, bodyLength));
  for (const byte of MAGIC) {
    if (reader.u8() !== byte) throw new Error('not a rulegraph image (bad magic)');
  }
  const version = reader.u32();
  if (version !== VERSION) throw new Error(`unsupported image version ${version}`);

  const ruleCount = reader.u32();
  const rules: Rule[] = [];
  for (let i = 0; i < ruleCount; i += 1) {
    const typeCode = reader.u8();
    const type = CODE_TYPES[typeCode];
    if (type === undefined) throw new Error(`unknown rule type code ${typeCode}`);
    const flags = reader.u8();
    const line = reader.u32();
    const policy = reader.str();
    const payload = reader.str();
    rules.push({ type, payload, policy, noResolve: (flags & 1) !== 0, line });
  }

  const domains = readDomainTrie(reader);
  const ipv4 = readCidrTrie(reader);
  const ipv6 = readCidrTrie(reader);
  const keywords = readAutomaton(reader);
  const matchRaw = reader.u32();
  const matchIndex = matchRaw === NONE ? null : matchRaw;

  const compiled: Omit<CompiledRuleset, 'stats'> = { rules, domains, ipv4, ipv6, keywords, matchIndex };
  return { ...compiled, stats: recount(rules, compiled) };
}

function writeDomainTrie(writer: ByteWriter, trie: DomainTrie): void {
  const nodes = trie.dump();
  writer.u32(nodes.length);
  for (const node of nodes) {
    writer.u32(node.children === null ? 0 : node.children.size);
    writer.u32(node.exact === null ? 0 : node.exact.length);
    writer.u32(node.suffix === null ? 0 : node.suffix.length);
  }
  for (const node of nodes) {
    if (node.children === null) continue;
    for (const [label, child] of node.children) {
      writer.str(label);
      writer.u32(child.id);
    }
  }
  for (const node of nodes) {
    if (node.exact !== null) for (const index of node.exact) writer.u32(index);
    if (node.suffix !== null) for (const index of node.suffix) writer.u32(index);
  }
}

function readDomainTrie(reader: ByteReader): DomainTrie {
  const count = reader.u32();
  const nodes: DomainNode[] = new Array<DomainNode>(count);
  const childCounts = new Uint32Array(count);
  const exactCounts = new Uint32Array(count);
  const suffixCounts = new Uint32Array(count);
  for (let i = 0; i < count; i += 1) {
    childCounts[i] = reader.u32();
    exactCounts[i] = reader.u32();
    suffixCounts[i] = reader.u32();
    nodes[i] = { id: i, children: null, exact: null, suffix: null };
  }
  for (let i = 0; i < count; i += 1) {
    const children = childCounts[i] as number;
    if (children === 0) continue;
    const node = nodes[i] as DomainNode;
    const map = new Map<string, DomainNode>();
    for (let c = 0; c < children; c += 1) {
      const label = reader.str();
      const child = nodes[reader.u32()] as DomainNode;
      map.set(label, child);
    }
    node.children = map;
  }
  for (let i = 0; i < count; i += 1) {
    const node = nodes[i] as DomainNode;
    const exact = exactCounts[i] as number;
    if (exact > 0) {
      const bucket: number[] = new Array<number>(exact);
      for (let k = 0; k < exact; k += 1) bucket[k] = reader.u32();
      node.exact = bucket;
    }
    const suffix = suffixCounts[i] as number;
    if (suffix > 0) {
      const bucket: number[] = new Array<number>(suffix);
      for (let k = 0; k < suffix; k += 1) bucket[k] = reader.u32();
      node.suffix = bucket;
    }
  }
  return DomainTrie.fromNodes(nodes);
}

function writeCidrTrie(writer: ByteWriter, trie: CidrTrie): void {
  const nodes = trie.dump();
  writer.u32(nodes.length);
  for (const node of nodes) {
    const flags = (node.zero === null ? 0 : 1) | (node.one === null ? 0 : 2);
    writer.u8(flags);
    writer.u32(node.bucket === null ? 0 : node.bucket.length);
  }
  for (const node of nodes) {
    if (node.zero !== null) writer.u32(node.zero.id);
    if (node.one !== null) writer.u32(node.one.id);
  }
  for (const node of nodes) {
    if (node.bucket !== null) for (const index of node.bucket) writer.u32(index);
  }
}

function readCidrTrie(reader: ByteReader): CidrTrie {
  const count = reader.u32();
  const nodes: CidrNode[] = new Array<CidrNode>(count);
  const flags = new Uint8Array(count);
  const bucketCounts = new Uint32Array(count);
  for (let i = 0; i < count; i += 1) {
    flags[i] = reader.u8();
    bucketCounts[i] = reader.u32();
    nodes[i] = { id: i, zero: null, one: null, bucket: null };
  }
  for (let i = 0; i < count; i += 1) {
    const node = nodes[i] as CidrNode;
    const flag = flags[i] as number;
    if ((flag & 1) !== 0) node.zero = nodes[reader.u32()] as CidrNode;
    if ((flag & 2) !== 0) node.one = nodes[reader.u32()] as CidrNode;
  }
  for (let i = 0; i < count; i += 1) {
    const size = bucketCounts[i] as number;
    if (size === 0) continue;
    const node = nodes[i] as CidrNode;
    const bucket: number[] = new Array<number>(size);
    for (let k = 0; k < size; k += 1) bucket[k] = reader.u32();
    node.bucket = bucket;
  }
  return CidrTrie.fromNodes(nodes);
}

function writeAutomaton(writer: ByteWriter, automaton: Automaton): void {
  const states = automaton.dump();
  writer.u32(states.length);
  for (const state of states) {
    writer.u32(state.fail);
    writer.u32(state.out === null ? 0 : state.out.length);
    for (const index of state.out ?? []) writer.u32(index);
    writer.u32(state.next === null ? 0 : state.next.size);
    if (state.next !== null) {
      for (const [code, target] of state.next) {
        writer.u16(code);
        writer.u32(target);
      }
    }
  }
}

function readAutomaton(reader: ByteReader): Automaton {
  const count = reader.u32();
  const states: AutomatonState[] = new Array<AutomatonState>(count);
  for (let i = 0; i < count; i += 1) {
    const fail = reader.u32();
    const outCount = reader.u32();
    const out = outCount === 0 ? null : new Array<number>(outCount);
    for (let k = 0; k < outCount; k += 1) (out as number[])[k] = reader.u32();
    const gotoCount = reader.u32();
    const next = gotoCount === 0 ? null : new Map<number, number>();
    for (let g = 0; g < gotoCount; g += 1) {
      const code = reader.u16();
      (next as Map<number, number>).set(code, reader.u32());
    }
    states[i] = { fail, out, next };
  }
  return Automaton.fromStates(states);
}

/** Recompute every counter from the structures — used after loading an image. */
export function recount(rules: readonly Rule[], compiled: Omit<CompiledRuleset, 'stats'>): CompileStats {
  let domainExact = 0;
  let domainSuffix = 0;
  let domainKeyword = 0;
  let ipv4Cidr = 0;
  let ipv6Cidr = 0;
  let unreachable = 0;
  for (let i = 0; i < rules.length; i += 1) {
    const rule = rules[i] as Rule;
    if (compiled.matchIndex !== null && i > compiled.matchIndex) unreachable += 1;
    switch (rule.type) {
      case 'DOMAIN':
        domainExact += 1;
        break;
      case 'DOMAIN-SUFFIX':
        domainSuffix += 1;
        break;
      case 'DOMAIN-KEYWORD':
        domainKeyword += 1;
        break;
      case 'IP-CIDR':
        ipv4Cidr += 1;
        break;
      case 'IP-CIDR6':
        ipv6Cidr += 1;
        break;
      case 'MATCH':
        break;
    }
  }
  return {
    rules: rules.length,
    domainExact,
    domainSuffix,
    domainKeyword,
    ipv4Cidr,
    ipv6Cidr,
    domainNodes: compiled.domains.size,
    ipv4Nodes: compiled.ipv4.size,
    ipv6Nodes: compiled.ipv6.size,
    automatonStates: compiled.keywords.stateCount,
    fallback: compiled.matchIndex !== null,
    unreachable,
  };
}

/** Convenience: parse + compile in one step (used by tests and the CLI). */
export { compile };