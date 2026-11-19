# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-11-19

### Added

- `MATCH` fallback handling and per-rule diagnostics with source line numbers.
- `DOMAIN-KEYWORD` via Aho-Corasick with failure-link output merging.
- IPv6 support (`IP-CIDR6`) through a 128-bit word trie.
- Binary `.rgp` image: flat layout, checksummed with FNV-1a; corrupt or
  truncated files are rejected on load.
- CLI: `compile`, `match`, `stats`, `bench`.
- Differential test suite: generated rule sets are verified against a linear
  first-match scan, including after an image round-trip.
- Size-sweep benchmark (`npm run bench`) that refuses to report numbers when
  the engine and the reference scan disagree.

### Changed

- `DOMAIN` and `DOMAIN-SUFFIX` now share one reversed-label trie.
- Rule indexes are resolved by minimum source position, which preserves
  first-match-wins semantics instead of "most specific rule wins".

### Known limitations

- `RULE-SET`, `GEOIP`, `IP-ASN`, `SRC-*`, `AND`/`OR`/`NOT` are reported as
  diagnostics rather than compiled.
- The image format is versioned but not backward compatible across versions.

## [0.1.0] - 2026-11-18

- Initial rewrite of the linear matcher into separate indexes (internal).