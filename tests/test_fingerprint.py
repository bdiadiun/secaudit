"""Invariant 1: Finding.id is stable under line-number and digit-in-evidence
changes; it changes when rule or file changes.

Interface: secaudit.normalize.fingerprint(source, rule, location, evidence)
-> "fp-<16 hex>". See tests/README.md.
"""
from secaudit.normalize import fingerprint


def test_fingerprint_stable_when_only_line_number_changes():
    fp_a = fingerprint(
        "bandit", "B602", {"file": "app/utils.py", "line": 11},
        "line 11: subprocess.call(cmd, shell=True)",
    )
    fp_b = fingerprint(
        "bandit", "B602", {"file": "app/utils.py", "line": 25},
        "line 25: subprocess.call(cmd, shell=True)",
    )
    assert fp_a == fp_b


def test_fingerprint_stable_when_only_digits_in_evidence_change():
    fp_a = fingerprint(
        "pip-audit", "GHSA-x84v-xcm2-53pg",
        {"ecosystem": "PyPI", "package": "requests", "version": "2.25.0"},
        "affected 2.25.0, fixed in 2.31.0",
    )
    fp_b = fingerprint(
        "pip-audit", "GHSA-x84v-xcm2-53pg",
        {"ecosystem": "PyPI", "package": "requests", "version": "2.31.0"},
        "affected 9.99.1, fixed in 4.02.7",
    )
    assert fp_a == fp_b


def test_fingerprint_changes_when_rule_changes():
    fp_a = fingerprint("bandit", "B602", {"file": "app/utils.py", "line": 11}, "evidence")
    fp_b = fingerprint("bandit", "B603", {"file": "app/utils.py", "line": 11}, "evidence")
    assert fp_a != fp_b


def test_fingerprint_changes_when_file_changes():
    fp_a = fingerprint("bandit", "B602", {"file": "app/utils.py", "line": 11}, "evidence")
    fp_b = fingerprint("bandit", "B602", {"file": "app/other.py", "line": 11}, "evidence")
    assert fp_a != fp_b


def test_fingerprint_url_location_ignores_query_string():
    fp_a = fingerprint(
        "zap", "10038", {"url": "http://127.0.0.1:8000/api/v1/tasks?x=1", "method": "GET"}, None,
    )
    fp_b = fingerprint(
        "zap", "10038", {"url": "http://127.0.0.1:8000/api/v1/tasks?y=2&z=3", "method": "GET"}, None,
    )
    assert fp_a == fp_b


def test_fingerprint_package_location_ignores_version():
    fp_a = fingerprint(
        "osv", "GHSA-8c4r-8v5j-8v5j",
        {"ecosystem": "PyPI", "package": "django", "version": "3.2.0"}, None,
    )
    fp_b = fingerprint(
        "osv", "GHSA-8c4r-8v5j-8v5j",
        {"ecosystem": "PyPI", "package": "django", "version": "3.2.19"}, None,
    )
    assert fp_a == fp_b


def test_fingerprint_two_findings_same_rule_same_file_different_evidence_differ():
    fp_a = fingerprint(
        "gitleaks", "generic-api-key", {"file": "app/config.py", "line": 12},
        "api_key = <REDACTED:29>",
    )
    fp_b = fingerprint(
        "gitleaks", "generic-api-key", {"file": "app/config.py", "line": 40},
        "token = <REDACTED:40>",
    )
    assert fp_a != fp_b


def test_fingerprint_has_fp_prefix_and_16_hex_chars():
    fp = fingerprint("bandit", "B602", {"file": "app/utils.py", "line": 11}, "evidence")
    assert fp.startswith("fp-")
    suffix = fp[len("fp-"):]
    assert len(suffix) == 16
    int(suffix, 16)  # raises ValueError if not hex
