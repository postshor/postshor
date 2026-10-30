# PostShor Rule Format — Specification v1

**Status:** Draft for public comment
**License:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Anyone may implement, adapt and redistribute this specification with attribution.
**Reference implementation:** [PostShor](https://github.com/postshor/postshor) (`src/postshor/rules/loader.py`, `src/postshor/rules/testing.py`; built-in rules in `src/postshor/rules/data/`)

## 1. Purpose

A cryptography-discovery rule says *what text indicates which algorithm, used for what*. Today every scanner keeps that knowledge in its own code, so rules cannot be reviewed, shared or tested independently of the tool.

This format puts detection rules in plain data files. Each rule has:

1. a pattern and the algorithm and usage it detects, using the algorithm vocabulary of the [Quantum Readiness Score](qrs-v1.md), so severity is derived the same way everywhere, and
2. **its own tests**: examples it must find and near-misses it must not. A rule without passing tests is not a valid rule.

All 188+ built-in PostShor rules use this format. Organisations can add rules for in-house libraries the same way.

## 2. File format

A rule file is a [TOML 1.0](https://toml.io/en/v1.0.0) document in UTF-8. TOML was chosen because it needs no third-party parser in Python (3.11+ ships `tomllib`) and because its literal strings (`'''...'''`) hold regular expressions without escaping.

```toml
format = 1

[[rule]]
id = "ACME-LEGACY-SIGNER"
title = "In-house RSA signing helper"
targets = ["python"]
algorithm = "rsa"
usage = "signature"
pattern = '''\bacme_sign_rsa\s*\('''

[rule.tests]
match = ['''sig = acme_sign_rsa(blob)''']
no_match = ['''sig = acme_sign_mldsa(blob)''']
```

Top-level keys:

| Key | Required | Meaning |
|---|---|---|
| `format` | no (default `1`) | Format version. A reader must reject versions it does not know. |
| `rule` | yes | Array of one or more rule tables. |

Any other top-level key is an error.

## 3. Rule fields

| Field | Required | Type | Meaning |
|---|---|---|---|
| `id` | yes | string | Permanent identifier, upper-case words joined by `-` (`^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$`). Unique across all loaded files. Never renamed or reused: IDs appear in SARIF, baselines and suppression lists. |
| `title` | yes | string | Short human-readable description. |
| `targets` | yes | array of strings | File kinds the rule runs on (§4). |
| `algorithm` | yes | string | Algorithm ID the match reports (§5). |
| `usage` | yes | string | One of `key-exchange`, `encryption`, `signature`, `key-generation`, `hash`, `symmetric`, `protocol`, `certificate`, `key-material`, `library`, `unknown`. |
| `pattern` | yes | string | Regular expression (§6) searched in the whole file. |
| `tests` | yes | table | Examples (§8). |
| `confidence` | no | string | `high` (default), `medium` or `low`. `low` lowers the derived severity one level. |
| `severity` | no | string | Fixed severity (`critical`, `high`, `medium`, `low`, `info`) instead of the one derived from algorithm and usage. Use for configuration checks. |
| `flags` | no | array of strings | `ignorecase` is the only flag in v1. |
| `unless` | no | string | Regular expression; when it is found, the match is discarded (§7). Always case-insensitive. |
| `unless_scope` | no | string | `line` (default): test `unless` against the matched line; `match`: against the matched text only. Requires `unless`. |
| `refine` | no | array of tables | Algorithm refinements (§7). |

Unknown fields are errors, so a misspelt `sevrity` cannot be silently ignored.

## 4. Targets

| Target | Files |
|---|---|
| `python`, `javascript`, `jvm`, `go`, `c`, `csharp`, `rust`, `php`, `ruby`, `swift` | Source code (`jvm` covers Java, Kotlin, Scala and Groovy; `javascript` includes TypeScript; `c` includes C++) |
| `config` | Server and application configuration (nginx, Apache, HAProxy, OpenSSL, YAML, JSON, TOML, INI, `.env`, ...), including YAML/JSON infrastructure manifests such as Kubernetes and cert-manager |
| `iac` | Infrastructure-as-code languages (Terraform/HCL, Bicep) |
| `ssh-config` | `sshd_config`, `ssh_config` |
| `any` | Every text file scanned |

Which extensions and file names map to which target is implementation-defined; PostShor's mapping is in `src/postshor/scanners/files.py`.

## 5. Algorithms

`algorithm` and refinement algorithms must be IDs from the QRS algorithm table (`rsa`, `ecdsa`, `ecdh`, `eddsa`, `x25519`, `dh`, `dsa`, `ecc`, `ml-kem`, `ml-dsa`, `slh-dsa`, `hybrid-kem`, `md5`, `sha1`, `des`, `rc4`, ...). `postshor rules --algorithms` prints the full list. The algorithm and usage together determine severity (QRS §4), so a rule never needs to state a severity unless it is a configuration check.

## 6. Regular expressions

Patterns use the Perl-compatible syntax common to Python's `re` module and PCRE: character classes, `\b`, `\s`, `\w`, `\d`, non-capturing groups `(?:...)`, alternation, bounded and lazy quantifiers, and fixed-width look-ahead and look-behind. Patterns are compiled in multi-line mode (`^` and `$` match at line boundaries). Possessive quantifiers, atomic groups, named back-references and inline flags are outside v1; use `flags` instead of `(?i)`. Engines without look-around (RE2, Go `regexp`) cannot run every built-in rule unchanged.

## 7. Matching semantics

For each file whose kind is listed in `targets`:

1. Every match of `pattern` in the file is a candidate at the line where the match starts.
2. If `unless` is set and found in the matched line (`unless_scope = "line"`) or in the matched text (`"match"`), the candidate is discarded. This expresses checks such as "a TLS group list that does not include a post-quantum group".
3. Candidates in comments and documentation are discarded: lines starting with a comment marker, Python triple-quoted strings, C-style `/* */` blocks and trailing `//` or `#` comments.
4. Candidates on lines marked `postshor:ignore` (on the line itself or in a comment on the line above) are suppressed and counted.
5. **Refinement.** The reported algorithm is `algorithm`, unless a `refine` entry applies. Entries are tried in order; the first whose `match` regular expression is found (case-insensitive) in the matched text sets the algorithm:

   ```toml
   [[rule.refine]]
   match = '''ECDSAKey'''
   algorithm = "ecdsa"
   ```

   Refinement lets one rule cover a family (`RSAKey|ECDSAKey|DSSKey`) while reporting the right algorithm, with no special cases in code.
6. Severity is derived from algorithm and usage (QRS), or taken from `severity`; `confidence = "low"` lowers it one level.

Steps 3–4 and the context rules of QRS §5 (test code, hybrid key exchange) are applied by the scanner, not by individual rules.

## 8. Tests

```toml
[rule.tests]
match = [
  '''key = paramiko.RSAKey.generate(2048)''',
  { text = '''key = paramiko.DSSKey.generate(1024)''', algorithm = "dsa" },
]
no_match = ['''key = paramiko.Ed25519Key.from_private_key_file(path)''']
```

- `match` (required, at least one): each example, scanned on its own as a file of the rule's first target, must produce a finding from this rule. An example written as a table with `algorithm` must also report that algorithm, which is how refinements are tested.
- `no_match` (optional, strongly recommended): each example must produce no finding from this rule. Good negatives are near misses: the safe alternative (`ML-KEM` instead of `RSA`), a similar API that is not cryptography, or a configuration that already includes a post-quantum group.

Every built-in rule has at least one example of each kind, and every refinement is exercised by a `match` example. `postshor rules test [FILE ...]` runs the examples; it exits 1 if any fails.

## 9. Validation

A reader must reject a file, reporting every problem rather than only the first, when:

- it is not valid TOML, or declares an unknown `format`;
- a rule lacks a required field, has an unknown field, or a field has the wrong type or an unknown value (target, algorithm, usage, confidence, severity, flag);
- `pattern`, `unless` or a refinement `match` is not a valid regular expression;
- `unless_scope` is set without `unless`;
- an `id` is malformed or already used by a built-in rule, another loaded file or an earlier rule in the same file.

## 10. Using custom rules with PostShor

```bash
postshor rules test acme-rules.toml          # validate and run the examples
postshor scan . --rules acme-rules.toml      # scan with built-in + custom rules
```

or permanently in `.postshor.toml` (paths relative to that file):

```toml
rules = ["security/acme-rules.toml"]
```

Prefix custom IDs with your organisation (`ACME-...`) so they never collide with future built-in rules. Built-in prefixes are reserved: `PY`, `JS`, `JVM`, `GO`, `C`, `CS`, `RS`, `PHP`, `RB`, `SW`, `JWT`, `JOSE`, `PGP`, `HTTPSIG`, `HPKE`, `CFG`, `IAC`, `GEN`.

## 11. Versioning

Adding optional fields, targets, algorithms or flags is a minor change and keeps `format = 1`. Changing the meaning of an existing field or making a field required increments `format`. Built-in rules follow the project's semantic versioning: removing or renaming a rule ID is a breaking change.

## 12. Feedback

Open an issue labelled `spec:rules` in the PostShor repository. Proposed changes are discussed publicly before a version is published.
