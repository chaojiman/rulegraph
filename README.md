# rulegraph

Compile a [Clash](https://github.com/Dreamacro/clash) / [mihomo](https://github.com/MetaCubeX/mihomo) rule set into prefix indexes so a per-connection lookup no longer costs a linear scan over every rule.

A mid-size rule listing has ~30k entries; big curated sets run into hundreds of thousands, and every proxied connection pays for a scan from the first rule until a match. `rulegraph` keeps the exact same **first-match-wins** semantics, but answers in time proportional to the query (host labels + address bits) instead of the rule count.

```
1,000 rules     447,745 qps      naive scan     15,587 qps     28.7x
100,000 rules   244,921 qps      naive scan        175 qps   1,399x
```

## Why not just sort the rules?

Because order *is* the semantics. `DOMAIN-SUFFIX,example.com,Proxy` placed before `DOMAIN,ads.example.com,REJECT` **must** route `ads.example.com` through `Proxy` — a "most specific rule wins" index would silently break the config. So this project does not re-interpret the ruleset; it indexes it and resolves the original position.

The model is simple and testable:

1. Every index stores the rule's original index.
2. A query collects every rule that *could* match.
3. The smallest index wins.
4. That is, by construction, what the reference linear scan returns.

Step 4 is checked by a differential test: generated rule sets (mixed `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `IP-CIDR`, `IP-CIDR6`, `MATCH`) are queried through both implementations, and any divergence fails the suite. The benchmark refuses to print numbers if the two disagree.

## How it works

```
                 rules: parse            compile
Clash YAML ──► rule list ──┬─► reversed-label trie   (DOMAIN, DOMAIN-SUFFIX)
                           ├─► binary prefix trie    (IP-CIDR, IP-CIDR6)
                           ├─► Aho-Corasick automaton (DOMAIN-KEYWORD)
                           └─► MATCH position        (fallback)
                                     │
                                     ▼
                              .rgp image ──► mmap-free load at startup
                                     │
   (host, ip) ──────────────────────►┼──► smallest rule index ──► policy
```

| Stage   | Cost                                                                 |
| ------- | -------------------------------------------------------------------- |
| parse   | O(document size)                                                     |
| compile | O(total payload length); one trie node per host label, one automaton state per keyword character |
| query   | O(labels + 32 or 128 address bits + host length) — independent of rule count |
| memory  | one node per label prefix; 100k rules ≈ 7 MiB image, ~150 MiB heap after load (Node object graph) |

`DOMAIN` and `DOMAIN-SUFFIX` share a single trie: labels are walked from the TLD inwards, so `a.b.example.com` visits `com → example → b → a` and picks up suffix buckets on the way while exact matches are read at the final node. Suffix matching therefore costs the number of labels, not the number of rules.

## Install

```bash
npm install -g rulegraph        # or: npx rulegraph --help
```

Node.js 20 or newer. Zero runtime dependencies — the Clash `rules:` block is read by a small purpose-built scanner, not a YAML parser.

## CLI

```bash
# compile a Clash config (or a plain rule list) into a binary image
rulegraph compile config.yaml -o config.rgp

# inspect what a connection would match
rulegraph match config.rgp --host ads.doubleclick.net
# DOMAIN-SUFFIX,doubleclick.net,AdBlock  (index 7, source line 51)

rulegraph match config.rgp --ip 10.5.5.5
# IP-CIDR,10.0.0.0/8,DIRECT  (index 3, source line 46)

rulegraph stats config.rgp
rulegraph bench --sizes 1000,10000,100000 --queries 20000
```

Exit codes: `0` success, `1` the ruleset had diagnostics (unparsed lines), `2` usage error or unusable input.

Diagnostics are never silent: an unsupported rule type (`RULE-SET`, `GEOIP`, `AND`, `SRC-IP`, ...) is reported with its line number and excluded, because the alternative — dropping a `REJECT` rule quietly — changes behaviour without telling anyone.

## Library

```ts
import { readFile } from 'node:fs/promises';
import { parseRuleset, compile, RuleEngine, serialize, deserialize } from 'rulegraph';

const ruleset = parseRuleset(await readFile('config.yaml', 'utf8'));
const compiled = compile(ruleset);
const engine = new RuleEngine(compiled);

const hit = engine.match({ host: 'ads.example.com', ip: '10.0.0.9' });
hit?.rule.policy;  // 'REJECT'
hit?.index;        // position in the source list

const image = serialize(compiled); // Uint8Array, checksummed
const restored = new RuleEngine(deserialize(image));
```

The image is a flat, little-endian layout with an FNV-1a trailer: a truncated or hand-edited file fails loudly instead of loading garbage.

## Benchmark

Measured on 2026-11-19, Intel i5-12600KF (16 threads), 31.8 GiB RAM, Windows 11, Node v25.1.0. Engine timed on 20,000 queries; the naive scan is timed on the first 2,000 of them (it is O(rules) per query — a full run at 100k rules would take hours). Every sampled query is verified against the reference scan before the numbers are printed.

| rules      | compile | image   | engine qps | engine p50 | naive qps | naive p50 | speedup |
| ---------- | ------- | ------- | ---------- | ---------- | --------- | --------- | ------- |
| 1,000      | 2 ms    | 0.10 MiB | 447,745   | 1.9 µs     | 15,587    | 43.6 µs   | 28.7x   |
| 10,000     | 16 ms   | 0.82 MiB | 194,279   | 4.3 µs     | 476       | 1.11 ms   | 408x    |
| 100,000    | 399 ms  | 7.15 MiB | 244,921   | 3.6 µs     | 175       | 3.80 ms   | 1,399x  |

p95/p99 at 100k rules: 6.3 µs / 8.0 µs. Reproduce with `npm run bench`.

The engine's cost is dominated by host normalization and Map walks, so it barely moves with rule count; the naive scan grows linearly and becomes unusable around a few hundred thousand rules (≈4 ms per connection at 100k).

## Supported rules

| Rule           | Status                                                       |
| -------------- | ------------------------------------------------------------ |
| `DOMAIN`       | ✅ exact host match                                          |
| `DOMAIN-SUFFIX`| ✅ bare domain and subdomains                                |
| `DOMAIN-KEYWORD`| ✅ substring, case-insensitive                               |
| `IP-CIDR`      | ✅ IPv4, bit-trie, `no-resolve` flag recorded                |
| `IP-CIDR6`     | ✅ IPv6 (32-bit word trie)                                   |
| `MATCH`        | ✅ fallback; it must be last or later rules are marked unreachable |
| `RULE-SET`, `GEOIP`, `IP-ASN`, `SRC-*`, `AND`, `OR`, `NOT` | ❌ reported as diagnostics, not implemented |

The engine does not perform DNS resolution: it takes the host and/or IP the proxy already knows. `no-resolve` is preserved on the rule for the caller to honour.

## Caveats

- Interning the same payload twice keeps both rule positions — correct for first-match order, slightly more memory than a deduplicated set.
- Keyword rules are substring tests over the host only (that is what Clash means), so a keyword like `example` also matches `example-other.net`.
- The image format is versioned but not yet designed for cross-version compatibility: recompile after upgrading.
- Heap figures in the benchmark include the whole Node process, not just the index.

## Development

```bash
npm install
npm run typecheck     # strict TypeScript, noUncheckedIndexedAccess
npm test              # vitest: unit + differential (cross-checks every generated query)
npm run build         # dist/ with declarations
npm run bench
```

Layout: `src/parser.ts` (rule grammar), `src/domain-trie.ts`, `src/cidr-trie.ts`, `src/aho-corasick.ts`, `src/compiler.ts`, `src/engine.ts`, `src/serialize.ts`, `src/bench/`.

Contributions are welcome; please keep the differential test green — any optimisation that changes answers is a bug, not an optimisation.

## License

MIT