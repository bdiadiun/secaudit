"""Invariant 11: ratelimit sends at most 30 requests per path and only to
paths matching the auth pattern; a path answering 429 at any point yields no
finding.

Interface: secaudit.collectors.ratelimit.run(ctx) -> raw (sync httpx calls,
paced with time.sleep so tests can neutralize it); parse(raw, ctx) ->
list[Finding]. See tests/README.md.
"""
import json

from secaudit.collectors import ratelimit
from secaudit.collectors.base import Context

from conftest import load_fixture_text

URL = "http://127.0.0.1:8000"


def _ctx():
    return Context(repo=None, url=URL)


def test_path_answering_429_yields_no_finding(httpx_mock, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_args, **_kw: None)
    httpx_mock.add_response(
        url=f"{URL}/openapi.json", json=json.loads(load_fixture_text("openapi.json")),
    )
    for _ in range(6):
        httpx_mock.add_response(url=f"{URL}/api/v1/auth/login", method="POST", status_code=400)
    httpx_mock.add_response(url=f"{URL}/api/v1/auth/login", method="POST", status_code=429)

    raw = ratelimit.run(_ctx())
    findings = ratelimit.parse(raw, _ctx())

    assert findings == []


def test_path_never_answering_429_yields_one_medium_finding(httpx_mock, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_args, **_kw: None)
    httpx_mock.add_response(
        url=f"{URL}/openapi.json", json=json.loads(load_fixture_text("openapi.json")),
    )
    for _ in range(30):
        httpx_mock.add_response(url=f"{URL}/api/v1/auth/login", method="POST", status_code=400)

    raw = ratelimit.run(_ctx())
    findings = ratelimit.parse(raw, _ctx())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source == "ratelimit"
    assert finding.severity == "medium"
    assert finding.location["method"] == "POST"
    assert finding.location["url"].endswith("/api/v1/auth/login")


def test_non_auth_path_is_never_requested(httpx_mock, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_args, **_kw: None)
    httpx_mock.add_response(
        url=f"{URL}/openapi.json", json=json.loads(load_fixture_text("openapi.json")),
    )
    # No mock registered for /api/v1/tasks: if ratelimit touches it, the
    # unmatched request makes httpx_mock fail the test.
    for _ in range(30):
        httpx_mock.add_response(url=f"{URL}/api/v1/auth/login", method="POST", status_code=400)

    raw = ratelimit.run(_ctx())
    ratelimit.parse(raw, _ctx())
