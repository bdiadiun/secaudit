"""status = new | known | resolved | accepted, and the accepted.yml loader.

Interfaces fixed by tests/README.md: load_accepted, apply, summarize,
InvalidAccepted.
"""
from __future__ import annotations

from datetime import date

from .schema import Accepted, Finding

_REQUIRED_ACCEPTED_FIELDS = ("id", "reason", "by", "date")


class InvalidAccepted(ValueError):
    """Raised by load_accepted when an accepted.yml entry is missing a
    required field; the message names the entry so the operator can find it.
    """


def load_accepted(raw: list[dict]) -> tuple[list[dict], list[str]]:
    """Validate each entry has id/reason/by/date; drop expired entries with a
    warning instead of raising. Returns (valid_entries, warnings).
    """
    valid: list[dict] = []
    warnings: list[str] = []
    today = date.today()
    for entry in raw:
        missing = [field for field in _REQUIRED_ACCEPTED_FIELDS if not entry.get(field)]
        if missing:
            entry_id = entry.get("id", "<unknown>")
            raise InvalidAccepted(
                f"accepted entry {entry_id!r} is missing required field(s): "
                f"{', '.join(missing)}"
            )
        expires = entry.get("expires")
        if expires:
            expires_date = expires if isinstance(expires, date) else date.fromisoformat(str(expires))
            if expires_date < today:
                warnings.append(
                    f"accepted entry {entry['id']} expired on {expires_date.isoformat()}, ignoring"
                )
                continue
        valid.append(entry)
    return valid, warnings


def apply(
    findings: list[Finding],
    baseline: list[Finding] | None,
    accepted: list[dict] | None,
) -> list[Finding]:
    """Mark new/known by matching `id` against `baseline`, append `resolved`
    findings copied from baseline, then apply already-validated `accepted`
    entries by `id` regardless of new/known.
    """
    baseline = baseline or []
    accepted = accepted or []
    baseline_by_id = {f.id: f for f in baseline}
    current_ids = {f.id for f in findings}

    result: list[Finding] = []
    for finding in findings:
        status = "known" if finding.id in baseline_by_id else "new"
        result.append(finding.model_copy(update={"status": status}))
    for baseline_finding in baseline:
        if baseline_finding.id not in current_ids:
            result.append(baseline_finding.model_copy(update={"status": "resolved"}))

    accepted_by_id = {entry["id"]: entry for entry in accepted}
    final: list[Finding] = []
    for finding in result:
        entry = accepted_by_id.get(finding.id)
        if entry is None:
            final.append(finding)
            continue
        accepted_model = Accepted(
            reason=entry["reason"], by=entry["by"], date=entry["date"],
            expires=entry.get("expires"),
        )
        final.append(finding.model_copy(update={"status": "accepted", "accepted": accepted_model}))
    return final


def summarize(findings: list[Finding]) -> dict:
    """Severity counts include only status in {new, known}; status totals
    count everything.
    """
    counts = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        "new": 0, "known": 0, "resolved": 0, "accepted": 0,
    }
    for finding in findings:
        counts[finding.status] += 1
        if finding.status in ("new", "known"):
            counts[finding.severity] += 1
    return counts
