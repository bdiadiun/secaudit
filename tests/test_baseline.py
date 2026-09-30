"""Invariant 7: baseline status (new/known/resolved) computed as specified;
resolved findings are excluded from severity counts but included in
`findings`.

Invariant 8: accepted.yml entry missing a required field -> InvalidAccepted
naming the entry; an expired entry is ignored with a warning; a valid entry
sets status=accepted and is excluded from severity counts.

Interfaces: secaudit.baseline.apply, .load_accepted, .summarize,
secaudit.baseline.InvalidAccepted. See tests/README.md.
"""
from datetime import date, timedelta

import pytest

from secaudit.baseline import InvalidAccepted, apply, load_accepted, summarize
from secaudit.schema import Finding


def _finding(id_, severity="high", status="new"):
    return Finding.model_validate({
        "id": id_,
        "source": "bandit",
        "rule": "B602",
        "severity": severity,
        "confidence": "high",
        "cwe": None,
        "title": "t",
        "location": {"file": "app/utils.py", "line": 1},
        "evidence": None,
        "remediation": None,
        "references": [],
        "status": status,
        "accepted": None,
    })


def test_apply_marks_finding_present_in_both_as_known():
    current = [_finding("fp-aaaaaaaaaaaaaaaa")]
    baseline = [_finding("fp-aaaaaaaaaaaaaaaa")]
    result = apply(current, baseline, [])
    by_id = {f.id: f for f in result}
    assert by_id["fp-aaaaaaaaaaaaaaaa"].status == "known"


def test_apply_marks_finding_only_in_current_as_new():
    current = [_finding("fp-bbbbbbbbbbbbbbbb")]
    result = apply(current, [], [])
    assert result[0].status == "new"


def test_apply_marks_finding_only_in_baseline_as_resolved_and_keeps_it():
    baseline = [_finding("fp-cccccccccccccccc")]
    result = apply([], baseline, [])
    assert len(result) == 1
    assert result[0].status == "resolved"
    assert result[0].id == "fp-cccccccccccccccc"


def test_summarize_excludes_resolved_from_severity_counts():
    findings = [
        _finding("fp-1111111111111111", severity="high", status="new"),
        _finding("fp-2222222222222222", severity="high", status="resolved"),
    ]
    counts = summarize(findings)
    assert counts["high"] == 1
    assert counts["resolved"] == 1


def test_summarize_counts_status_totals():
    findings = [
        _finding("fp-1111111111111111", status="new"),
        _finding("fp-2222222222222222", status="known"),
        _finding("fp-3333333333333333", status="resolved"),
        _finding("fp-4444444444444444", status="accepted"),
    ]
    counts = summarize(findings)
    assert counts["new"] == 1
    assert counts["known"] == 1
    assert counts["resolved"] == 1
    assert counts["accepted"] == 1


def test_load_accepted_missing_reason_raises_naming_entry():
    entries = [{"id": "fp-dddddddddddddddd", "by": "bo", "date": "2024-01-01"}]
    with pytest.raises(InvalidAccepted) as exc_info:
        load_accepted(entries)
    assert "fp-dddddddddddddddd" in str(exc_info.value)


def test_load_accepted_drops_expired_entry_with_warning():
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    entries = [{
        "id": "fp-eeeeeeeeeeeeeeee", "reason": "false positive", "by": "bo",
        "date": "2024-01-01", "expires": yesterday,
    }]
    valid, warnings = load_accepted(entries)
    assert valid == []
    assert len(warnings) == 1
    assert "fp-eeeeeeeeeeeeeeee" in warnings[0]


def test_apply_sets_accepted_status_and_copies_entry():
    current = [_finding("fp-ffffffffffffffff", status="new")]
    accepted, _warnings = load_accepted([{
        "id": "fp-ffffffffffffffff", "reason": "accepted risk", "by": "bo",
        "date": "2024-01-01",
    }])
    result = apply(current, [], accepted)
    finding = result[0]
    assert finding.status == "accepted"
    assert finding.accepted is not None
    assert finding.accepted.reason == "accepted risk"


def test_summarize_excludes_accepted_from_severity_counts():
    current = [_finding("fp-1234567890abcdef", severity="critical", status="new")]
    accepted, _ = load_accepted([{
        "id": "fp-1234567890abcdef", "reason": "r", "by": "bo", "date": "2024-01-01",
    }])
    result = apply(current, [], accepted)
    counts = summarize(result)
    assert counts["critical"] == 0
    assert counts["accepted"] == 1
