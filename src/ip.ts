/**
 * IPv4 / IPv6 parsing helpers.
 *
 * Addresses are carried around as `Uint32Array` words (most significant word
 * first) so the CIDR index can walk bits with plain integer shifts instead of
 * allocating BigInt values per bit — this matters at 10^6 lookups/s.
 */

export type IpFamily = 4 | 6;

export interface ParsedIp {
  readonly family: IpFamily;
  /** One 32-bit word for IPv4, four words for IPv6. */
  readonly words: Uint32Array;
  /** Canonical text form (lower-case, zero-compressed IPv6). */
  readonly text: string;
}

export interface ParsedCidr {
  readonly family: IpFamily;
  readonly words: Uint32Array;
  readonly prefix: number;
}

const V4_CHUNK = /^(?:0|[1-9]\d{0,2})$/;

function parseIPv4Words(input: string): Uint32Array | null {
  const chunks = input.split('.');
  if (chunks.length !== 4) return null;
  let value = 0;
  for (const chunk of chunks) {
    if (!V4_CHUNK.test(chunk)) return null;
    const octet = Number(chunk);
    if (octet > 255) return null;
    value = (value * 256 + octet) >>> 0;
  }
  return Uint32Array.of(value);
}

function parseIPv6Words(input: string): Uint32Array | null {
  let text = input;
  const zone = text.indexOf('%');
  if (zone >= 0) text = text.slice(0, zone);
  if (!/^[0-9a-fA-F:.]+$/.test(text)) return null;
  if (!text.includes(':')) return null;

  const doubleColon = text.indexOf('::');
  if (doubleColon >= 0 && text.indexOf('::', doubleColon + 1) >= 0) return null;

  const splitGroups = (segment: string): number[] | null => {
    if (segment === '') return [];
    const out: number[] = [];
    const parts = segment.split(':');
    for (let i = 0; i < parts.length; i += 1) {
      const part = parts[i] as string;
      if (part.includes('.')) {
        // Embedded IPv4 is only legal as the final group of the address.
        if (i !== parts.length - 1) return null;
        const v4 = parseIPv4Words(part);
        if (!v4) return null;
        const word = v4[0] as number;
        out.push(word >>> 16, word & 0xffff);
        continue;
      }
      if (part.length === 0 || part.length > 4 || !/^[0-9a-fA-F]+$/.test(part)) return null;
      out.push(Number.parseInt(part, 16));
    }
    return out;
  };

  let groups: number[];
  if (doubleColon >= 0) {
    const head = splitGroups(text.slice(0, doubleColon));
    const tail = splitGroups(text.slice(doubleColon + 2));
    if (!head || !tail) return null;
    const zeros = 8 - head.length - tail.length;
    if (zeros < 1) return null;
    groups = [...head, ...new Array<number>(zeros).fill(0), ...tail];
  } else {
    const all = splitGroups(text);
    if (!all || all.length !== 8) return null;
    groups = all;
  }

  const words = new Uint32Array(4);
  for (let i = 0; i < 8; i += 1) {
    const group = groups[i] as number;
    const wordIndex = i >> 1;
    if ((i & 1) === 0) {
      words[wordIndex] = group << 16;
    } else {
      words[wordIndex] = (words[wordIndex] as number) | group;
    }
  }
  return words;
}

function formatIPv6(words: Uint32Array): string {
  const groups: number[] = [];
  for (let i = 0; i < 4; i += 1) {
    const word = words[i] as number;
    groups.push(word >>> 16, word & 0xffff);
  }
  // RFC 5952: compress the longest run (>= 2) of zero groups.
  let bestStart = -1;
  let bestLength = 0;
  let runStart = -1;
  for (let i = 0; i <= 8; i += 1) {
    const isZero = i < 8 && groups[i] === 0;
    if (isZero && runStart < 0) runStart = i;
    if (!isZero && runStart >= 0) {
      const length = i - runStart;
      if (length > bestLength && length >= 2) {
        bestStart = runStart;
        bestLength = length;
      }
      runStart = -1;
    }
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart < 0) return hex.join(':');
  const head = hex.slice(0, bestStart).join(':');
  const tail = hex.slice(bestStart + bestLength).join(':');
  return `${head}::${tail}`;
}

export function parseIp(input: string): ParsedIp | null {
  const text = input.trim();
  if (text.length === 0) return null;
  if (text.includes(':')) {
    const words = parseIPv6Words(text);
    return words ? { family: 6, words, text: formatIPv6(words) } : null;
  }
  const words = parseIPv4Words(text);
  if (!words) return null;
  const v = words[0] as number;
  return {
    family: 4,
    words,
    text: `${(v >>> 24) & 0xff}.${(v >>> 16) & 0xff}.${(v >>> 8) & 0xff}.${v & 0xff}`,
  };
}

export function parseCidr(input: string): ParsedCidr | null {
  const text = input.trim();
  const slash = text.lastIndexOf('/');
  if (slash <= 0) return null;
  const address = parseIp(text.slice(0, slash));
  if (!address) return null;
  const prefixText = text.slice(slash + 1);
  if (!/^\d{1,3}$/.test(prefixText)) return null;
  const prefix = Number(prefixText);
  const bits = address.family === 4 ? 32 : 128;
  if (prefix > bits) return null;
  return { family: address.family, words: address.words, prefix };
}

export function bitsOf(family: IpFamily): number {
  return family === 4 ? 32 : 128;
}

/** True when the address belongs to a family that a rule of `family` can match. */
export function sameFamily(left: IpFamily, right: IpFamily): boolean {
  return left === right;
}

/** Bit at `index` (0 = most significant) inside a word array. */
export function bitAt(words: Uint32Array, index: number): number {
  const word = words[index >>> 5] as number;
  return (word >>> (31 - (index & 31))) & 1;
}

/** Mask an address down to its prefix: bits past `prefix` become zero. */
export function maskWords(words: Uint32Array, prefix: number): Uint32Array {
  const out = Uint32Array.from(words);
  for (let i = prefix; i < out.length * 32; i += 1) {
    const wordIndex = i >>> 5;
    out[wordIndex] = (out[wordIndex] as number) & ~(1 << (31 - (i & 31)));
  }
  return out;
}