# Architecture

PostShor is a pipeline: **discover → classify → score → report**. Everything is plain Python with one runtime dependency (`cryptography`, for parsing certificates and keys).

```
                  ┌───────────────────────── engine.scan() ─────────────────────────┐
 path ─► files.walk ─► classify(file) ─┬─► SourceScanner   (pattern rules)          │
                                       ├─► dependencies    (manifests)              ├─► findings ─► filters ─► score.compute ─► reporting/*
                                       └─► certificates    (PEM/DER/PKCS#12/SSH)    │     (baseline, disabled rules,
 --tls host ──────────────────────────────► tls            (live TLS 1.3 probe)     │      test-code cap, min severity)
                  └──────────────────────────────────────────────────────────────────┘
```

## Modules

| Module | Responsibility |
|---|---|
| `models.py` | `Finding`, `Severity`, `Usage`, `Category`, `ScanResult`. A finding's `fingerprint` ignores line numbers so baselines survive edits. |
| `rules/algorithms.py` | The knowledge base: every algorithm, its quantum status, replacement, CycloneDX primitive and OID. `severity_for(algorithm, usage)` implements QRS section 3. Remediation text and per-language hints live here. |
| `rules/data/*.toml` | All built-in pattern rules, as data in the [Rule Format v1](spec/rule-format-v1.md). Each rule has a stable public ID, the file kinds it applies to, a regex, the algorithm, the usage, its own `match`/`no_match` examples, and optionally `unless` (a regex that cancels the match: "this TLS group list has no PQ group") and `refine` (the matched text decides the algorithm). |
| `rules/loader.py`, `rules/rule.py`, `rules/testing.py` | Rule-file parsing and validation (every problem reported at once), the `Rule` type, and the example runner behind `postshor rules test`. |
| `scanners/files.py` | Directory walking, default excludes, file-kind classification, binary detection. |
| `scanners/source.py` | Runs rules over a file, skips comments, honours `postshor:ignore`, deduplicates per line and algorithm, detects embedded PEM private keys. |
| `scanners/certificates.py` | Real parsing of certificates and keys; key size, validity versus NIST dates, CA detection, trust-store collapsing. |
| `scanners/dependencies.py` | Manifest parsers for 10 ecosystems and the known-library table. |
| `scanners/tls.py` | The HelloRetryRequest probe and certificate fetch for live endpoints. |
| `engine.py` | Orchestration, `.postshor.toml`, baselines, the test-code adjustment. |
| `score.py` | QRS v1 formula and grades. |
| `reporting/` | `console`, `json_report`, `sarif`, `cbom` (CycloneDX 1.6), `markdown`, `html_report`, and `plan` (the three migration phases shared by HTML and Markdown). |
| `cli.py` | `scan`, `tls`, `rules`, `baseline`. Exit codes: 0 ok, 1 policy failure (`--fail-on`), 2 error. |

## Design decisions

- **Severity is derived, not hard-coded per rule.** Rules state *what* (algorithm) and *how* (usage); `severity_for` decides. One change to the knowledge base re-rates every rule consistently.
- **Regex over the whole file, not line by line.** Python's regex engine scans each file in one pass in C; line numbers are recovered afterwards with `bisect`, which also lets patterns span lines.
- **Precision over recall for noisy patterns.** Rules match key *creation and use*, not type names or imports, and a generic "elliptic curve" finding is dropped when the same line names ECDSA/ECDH.
- **No network calls during a code scan.** Only `postshor tls` / `--tls` touch the network, and only with a standard handshake.
- **Fixtures are generated, not committed.** Tests create certificates and keys at runtime so the repository never contains private keys.

## Adding a rule

1. Add a `[[rule]]` to the matching file in `rules/data/` with a new, never-reused ID (`LANG-WHAT[-DETAIL]`). The format is specified in [rule-format-v1.md](spec/rule-format-v1.md).
2. Give it `match` examples it must find and `no_match` near-misses it must not (the safe alternative, a look-alike API). Every `refine` entry needs a `match` example that expects its algorithm.
3. `postshor rules test` runs the examples; `python -m pytest` runs them too, plus the rest of the suite.
4. For a rule that changes results on real code, re-run the precision corpus (`docs/precision.md`) and record the effect.

## Known limits and the planned fixes

| Limit | Plan |
|---|---|
| Regex cannot follow data flow (an algorithm chosen from a variable) | Tree-sitter based semantic rules (roadmap v0.4) |
| No binary or container image analysis | OpenSSL/BoringSSL version detection and crypto-constant scanning in images (v0.5) |
