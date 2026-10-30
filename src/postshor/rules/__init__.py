from postshor.rules.algorithms import ALGORITHMS, explain, remediation, severity_for
from postshor.rules.loader import RuleFormatError, load_builtin_rules, load_rule_files
from postshor.rules.rule import Rule, algorithm_for_match

# Built-in pattern rules, loaded from postshor/rules/data/*.toml (docs/spec/rule-format-v1.md).
RULES: list[Rule] = load_builtin_rules()


def rules_by_id() -> dict[str, Rule]:
    return {r.id: r for r in RULES}


__all__ = ["ALGORITHMS", "RULES", "Rule", "RuleFormatError", "algorithm_for_match", "explain",
           "load_rule_files", "remediation", "rules_by_id", "severity_for"]
