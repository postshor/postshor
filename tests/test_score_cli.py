import json

from postshor import score
from postshor.cli import main
from postshor.models import Category, Finding, Location, Severity, Usage


def _f(sev: Severity, i: int = 0) -> Finding:
    return Finding(f"R{i}", "t", sev, Category.SOURCE, "rsa", Usage.UNKNOWN, Location(f"f{i}.py", i), "m", "r")


def test_empty_is_perfect():
    s = score.compute([])
    assert (s.value, s.grade) == (100, "A")


def test_score_is_monotonic():
    values = [score.compute([_f(Severity.HIGH, i) for i in range(n)]).value for n in range(0, 40)]
    assert values == sorted(values, reverse=True)


def test_critical_caps_grade_at_c_and_high_at_b():
    assert score.compute([_f(Severity.CRITICAL)]).grade == "C"
    assert score.compute([_f(Severity.HIGH)]).grade == "B"


def test_duplicate_findings_count_once():
    assert score.compute([_f(Severity.HIGH, 1)] * 10).value == score.compute([_f(Severity.HIGH, 1)]).value


def test_cli_fail_on_and_reports(fixtures, tmp_path, capsys):
    out = tmp_path / "r.json"
    code = main(["scan", str(fixtures / "vulnerable_app"), "-q", "-o", str(out), "--fail-on", "critical"])
    assert code == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["score"]["grade"] == "F"
    assert main(["scan", str(fixtures / "clean_app"), "-q", "--fail-on", "low"]) == 0


def test_cli_baseline_hides_known_findings(fixtures, tmp_path):
    baseline = tmp_path / "baseline.json"
    assert main(["baseline", str(fixtures / "vulnerable_app"), "-o", str(baseline)]) == 0
    assert main(["scan", str(fixtures / "vulnerable_app"), "-q", "--baseline", str(baseline), "--fail-on", "low"]) == 0


def test_config_file(tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (tmp_path / ".postshor.toml").write_text('disable_rules = ["PY-MD5"]\nfail_on = "low"\n')
    assert main(["scan", str(tmp_path), "-q"]) == 0


def test_cli_bad_path_is_error():
    assert main(["scan", "does/not/exist", "-q"]) == 2


def test_rules_command(capsys):
    assert main(["rules"]) == 0
    assert "PY-RSA-KEYGEN" in capsys.readouterr().out
