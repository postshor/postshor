"""Rule Format v1: built-in rule data, the loader's validation, custom rule files and `postshor rules test`."""

import pytest

from postshor import engine
from postshor.cli import main
from postshor.rules import RULES, RuleFormatError, load_rule_files
from postshor.rules.loader import parse_rules
from postshor.rules.testing import check_rule

CUSTOM = """
format = 1

[[rule]]
id = "ACME-LEGACY-SIGNER"
title = "In-house RSA signing helper"
targets = ["python"]
algorithm = "rsa"
usage = "signature"
pattern = '''\\bacme_sign_rsa\\s*\\('''

[rule.tests]
match = ['''sig = acme_sign_rsa(blob)''']
no_match = ['''sig = acme_sign_mldsa(blob)''']
"""


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_builtin_rule_examples(rule):
    assert check_rule(rule) == []


def test_every_builtin_rule_has_positive_and_negative_examples():
    missing = [r.id for r in RULES if not r.match_examples or not r.no_match_examples]
    assert missing == []


def test_every_refinement_is_exercised_by_an_example():
    for rule in RULES:
        tested = {ex.algorithm for ex in rule.match_examples}
        for _, algorithm in rule.refine:
            assert algorithm in tested, f"{rule.id}: no example expects refined algorithm {algorithm!r}"


def test_refinement_mismatch_is_reported():
    rule = parse_rules(CUSTOM.replace("match = ['''sig", "match = [{ text = '''sig", 1)
                       .replace("(blob)''']\nno_match", "(blob)''', algorithm = \"ecdsa\" }]\nno_match", 1), "t")[0]
    assert "expected algorithm 'ecdsa', got 'rsa'" in check_rule(rule)[0]


def test_builtin_rules_load_from_package_data():
    assert len(RULES) >= 188
    assert all(r.origin.startswith("builtin:") for r in RULES)


def _errors(text: str, taken=None) -> str:
    with pytest.raises(RuleFormatError) as exc:
        parse_rules(text, "custom.toml", taken)
    return str(exc.value)


def test_loader_reports_every_problem_at_once():
    bad = (CUSTOM.replace('algorithm = "rsa"', 'algorithm = "rot13"')
                 .replace('usage = "signature"', 'usage = "vibes"')
                 .replace("acme_sign_rsa\\s*\\(", "acme_sign_rsa(")
                 .replace('targets = ["python"]', 'targets = ["cobol"]\nsevrity = "high"'))
    msg = _errors(bad)
    for expected in ("unknown key 'sevrity'",):
        assert expected in msg
    # Unknown keys stop further checks of that rule; fix it and the remaining problems all surface.
    msg = _errors(bad.replace('sevrity = "high"\n', ""))
    for expected in ("unknown algorithm 'rot13'", "unknown usage 'vibes'", "'targets'", "not a valid regular expression"):
        assert expected in msg


@pytest.mark.parametrize("change, expected", [
    (('id = "ACME-LEGACY-SIGNER"', 'id = "acme signer"'), "upper-case"),
    (("format = 1", "format = 2"), "unsupported format"),
    (("[rule.tests]\nmatch = ['''sig = acme_sign_rsa(blob)''']\n", "[rule.tests]\n"), "tests.match"),
    (('usage = "signature"', 'usage = "signature"\nunless_scope = "match"'), "'unless_scope' needs 'unless'"),
    (('usage = "signature"', 'usage = "signature"\nflags = ["dotall"]'), "'flags'"),
])
def test_loader_rejects_invalid_rules(change, expected):
    assert expected in _errors(CUSTOM.replace(*change))


def test_custom_rule_ids_cannot_collide():
    assert "duplicate id" in _errors(CUSTOM.replace("ACME-LEGACY-SIGNER", "PY-RSA-KEYGEN"), {r.id for r in RULES})
    assert "duplicate id" in _errors(CUSTOM + CUSTOM[CUSTOM.index("[[rule]]"):])


def test_custom_rules_from_config_are_scanned(tmp_path):
    (tmp_path / "acme-rules.toml").write_text(CUSTOM, encoding="utf-8")
    (tmp_path / ".postshor.toml").write_text('rules = ["acme-rules.toml"]\n', encoding="utf-8")
    (tmp_path / "app.py").write_text("sig = acme_sign_rsa(blob)\n", encoding="utf-8")
    options, _ = engine.ScanOptions.from_config(tmp_path)
    found = {f.rule_id for f in engine.scan(tmp_path, options).findings}
    assert "ACME-LEGACY-SIGNER" in found
    assert load_rule_files([tmp_path / "acme-rules.toml"], RULES)[0].origin.endswith("acme-rules.toml")


def test_cli_rules_test(tmp_path, capsys):
    good = tmp_path / "good.toml"
    good.write_text(CUSTOM, encoding="utf-8")
    assert main(["rules", "test", str(good)]) == 0
    broken = tmp_path / "broken.toml"
    broken.write_text(CUSTOM.replace("no_match = ['''sig = acme_sign_mldsa", "no_match = ['''sig = acme_sign_rsa"),
                      encoding="utf-8")
    assert main(["rules", "test", str(broken)]) == 1
    assert "should not match" in capsys.readouterr().out
    assert main(["rules", "test"]) == 0


def test_cli_scan_with_custom_rules(tmp_path, capsys):
    rules = tmp_path / "acme.toml"
    rules.write_text(CUSTOM, encoding="utf-8")
    (tmp_path / "app.py").write_text("sig = acme_sign_rsa(blob)\n", encoding="utf-8")
    assert main(["scan", str(tmp_path / "app.py"), "--rules", str(rules), "--fail-on", "high", "-q"]) == 1
    invalid = tmp_path / "invalid.toml"
    invalid.write_text(CUSTOM.replace('usage = "signature"', 'usage = "vibes"'), encoding="utf-8")
    assert main(["scan", str(tmp_path / "app.py"), "--rules", str(invalid)]) == 2
    assert "unknown usage 'vibes'" in capsys.readouterr().err
