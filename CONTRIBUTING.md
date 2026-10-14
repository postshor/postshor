# Contributing to PostShor

Thank you for helping the world get ready for post-quantum cryptography.

## The most valuable contributions

1. **Detection rules** for libraries, languages and configuration formats we do not cover yet, each with a test.
2. **False-positive reports**: a snippet that was flagged but should not have been. Open an issue with the snippet and the rule ID.
3. **Real-world validation**: scan an open-source project you know well and tell us what we missed.
4. **Feedback on the [QRS specification](docs/spec/qrs-v1.md)** (issues labelled `spec:qrs`).

## Development setup

```
git clone https://github.com/postshor/postshor
cd postshor
python -m pip install -e ".[dev]"
ruff check .
python -m pytest -m "not network"
```

Requires Python 3.11+. The [architecture guide](docs/architecture.md) explains how the pieces fit together and how to add a rule.

## Pull requests

- Every rule needs a positive test, and a negative test when the pattern could plausibly over-match.
- Rule IDs are public and permanent. Never rename or reuse one; deprecate instead.
- Cryptographic claims (deadlines, library support, algorithm status) need a source in the PR description.
- Keep runtime dependencies at one (`cryptography`). Supply-chain hygiene matters for a security tool.
- Never commit real keys or certificates. Generate them in tests.

## Releasing (maintainers)

1. Move the "Unreleased" entries in `CHANGELOG.md` under the new version and date.
2. Bump `__version__` in `src/postshor/__init__.py` (the single source of truth) and `version` in `CITATION.cff`.
3. Commit, then tag: `git tag -s vX.Y.Z -m "vX.Y.Z"` and `git push origin vX.Y.Z`.
4. The release workflow builds, publishes to PyPI (trusted publishing) and creates the GitHub release.
5. Move the floating major tag for the GitHub Action: `git tag -f v0 vX.Y.Z && git push -f origin v0`.

## Sign-off

Contributions are accepted under the Apache License 2.0. Please sign off your commits (`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org/).

## Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Report concerns to conduct@postshor.org.
