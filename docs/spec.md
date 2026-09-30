# Spec: secaudit 0.1

Canon — `README.md`. Tests live in `tests/`, fixtures in `tests/fixtures/`
(real tool output, trimmed). No collector test invokes a real tool: each
collector is split into `run(repo, url) -> raw` (subprocess, untested) and
`parse(raw, ctx) -> list[Finding]` (tested on fixtures). The CLI is tested
with collectors monkeypatched to return fixtures.

## Schema (`secaudit/schema.py`, pydantic v2)

```jsonc
Report {
  "schema_version": "1.0",
  "target":   { "repo": str, "commit": str|null, "url": str|null },
  "run":      { "started_at": iso, "finished_at": iso,
                "tools": { "<source>": "<version>|null" },
                "skipped": [ { "source": str, "reason": str } ] },
  "findings": [ Finding ],
  "summary":  { "critical": int, "high": int, "medium": int, "low": int, "info": int,
                "new": int, "known": int, "resolved": int, "accepted": int },
  "baseline": { "path": str|null, "commit": str|null }
}

Finding {
  "id": "fp-<16 hex>",                       // fingerprint, stable across runs
  "source": "bandit|semgrep|pip-audit|osv|gitleaks|zap|ratelimit|checklist",
  "rule": str,                               // B602, python.lang..., CVE-..., zap 10038
  "severity": "critical|high|medium|low|info",
  "confidence": "high|medium|low",
  "cwe": str|null,                           // "CWE-78"
  "title": str,
  "location": {                              // exactly one of the three shapes
    "file": str, "line": int|null            // repo-relative, posix
  } | { "url": str, "method": str|null }
    | { "package": str, "version": str, "ecosystem": "PyPI|npm|..." },
  "evidence": str|null,                      // <= 500 chars, secrets REDACTED
  "remediation": str|null,
  "references": [str],
  "status": "new|known|resolved|accepted",
  "accepted": { "reason": str, "by": str, "date": date, "expires": date|null } | null
}
```

`summary.<severity>` counts findings with `status in {new, known}` only.
`resolved` findings carry the last-seen data from the baseline and are in
`findings` so the report can list them; they are never counted in severities.

## Fingerprint

`id = "fp-" + sha256(source | rule | location_key | evidence_norm)[:16]`, where

- `location_key` is `file` (no line — line numbers move), or `method url-path`
  without query, or `ecosystem package` (no version — an upgrade that still
  is vulnerable is the same finding);
- `evidence_norm` is `evidence` with whitespace collapsed and all digits
  replaced by `0`; empty when evidence is null.

Two findings of the same rule in one file with different evidence are two
findings; the same code moved ten lines down is one.

## Severity mapping (`normalize.py`)

| source | raw | severity |
|---|---|---|
| pip-audit, osv | CVSS ≥ 9.0 / ≥ 7.0 / ≥ 4.0 / else / no score | critical / high / medium / low / medium |
| bandit | HIGH / MEDIUM / LOW | high / medium / low; `confidence` from bandit's own field |
| semgrep | ERROR / WARNING / INFO | high / medium / low; `metadata.severity` CRITICAL overrides to critical |
| gitleaks | in working tree / only in history | critical / high |
| zap | riskcode 3 / 2 / 1 / 0 | high / medium / low / info |
| ratelimit | no `429` on an auth endpoint after burst | medium |

`cwe`: bandit `issue_cwe.id`, semgrep `metadata.cwe[0]`, zap `cweid`, else
null. `remediation`: pip-audit/osv — "upgrade to <fix_versions>" when known;
semgrep `metadata.fix` / `fix_regex`; zap `solution`; gitleaks — fixed text
"rotate the secret, then purge it from history".

`evidence` for gitleaks is the match with the secret replaced by
`<REDACTED:len>`; the raw secret never reaches the report or stdout.

## Collectors (`collectors/<source>.py`)

Each exposes `SOURCE: str`, `tool_version() -> str|None`, `run(ctx) -> raw`,
`parse(raw, ctx) -> list[Finding]`. `ctx` carries `repo`, `url`,
`only`/`skip`. Absent binary → `run` raises `ToolMissing`; the CLI records it
in `run.skipped` and continues. Any other exception from `run` → recorded in
`run.skipped` with `reason="error: ..."` and exit code stays as computed from
the findings (a broken collector must not hide the other five).

- **bandit**: `bandit -r <repo> -f json -x <repo>/.venv,<repo>/node_modules`.
  Fixture: `bandit.json`.
- **semgrep**: `semgrep --config auto --json --quiet <repo>`. Fixture:
  `semgrep.json`. `--config auto` needs network; when `SECAUDIT_OFFLINE=1`
  use `p/python p/javascript` … no, offline means `ToolMissing("semgrep
  rules need network")`.
- **pip-audit**: `pip-audit -r <requirements>` when present, else
  `pip-audit --local` inside the repo's `.venv` if it exists, else skipped.
  Output `-f json`. Fixture: `pip_audit.json`.
- **osv**: `osv-scanner --format json -r <repo>`; scans every lockfile it
  finds. Fixture: `osv.json`.
- **gitleaks**: `gitleaks detect -s <repo> -f json -r <tmp>`; a finding whose
  `File` is in the current tree at the same fingerprint is "working tree",
  else "history". Fixture: `gitleaks.json`.
- **zap**: only when `--url`; `docker run --rm --network host
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t <url> -J <out>`; missing
  docker → `ToolMissing`. Fixture: `zap.json`. Location is `{url, method}`.
- **ratelimit**: only when `--url`; discovers `/openapi.json` at the URL,
  picks paths matching `login|token|auth|session|password` with `POST`, sends
  30 requests in 5 s with an invalid body, and reports one finding per path
  that never answered `429`. No openapi → skipped with reason. This is the
  only collector that talks to the target itself; it never sends valid
  credentials and never exceeds 30 requests per path.

## Loopback rule

`--url` host must resolve to a loopback literal: `127.0.0.1`, `::1`,
`localhost`, or any `127.0.0.0/8`. Anything else → exit `2`, message names
the host, nothing runs. There is no flag to override; the test asserts the
CLI has no such option.

## Baseline and accepted (`baseline.py`)

- `baseline.json` is a previous `findings.json`. Match on `id`.
- Present now and in baseline → `known`; only now → `new`; only in baseline →
  `resolved` (copied from baseline with `status=resolved`).
- `accepted.yml`: list of `{id, reason, by, date, expires?}`. Missing any of
  `reason`, `by`, `date` → exit `2` naming the entry. `expires` in the past →
  the entry is ignored and a warning is printed. A matched finding gets
  `status=accepted` and the entry copied into `finding.accepted`, regardless
  of new/known.
- `--fail-on <severity>` (default `high`): exit `1` iff any finding with
  `status in {new, known}` and severity ≥ threshold. `accepted` and
  `resolved` never trip it.

## `report` command

Markdown from `findings.json`: header with target/commit/url/time, summary
table, `Skipped tools` when non-empty, then findings grouped by severity
(desc), within a group `new` before `known`; `accepted` in its own section
with reasons; `resolved` last. Each finding: `id`, `source/rule`, location,
title, evidence (fenced), remediation, references. Deterministic ordering →
byte-identical output for the same input.

## Invariants (test one-to-one)

1. `Finding.id` is stable under line-number change and digit change in
   evidence; changes when `rule` or `file` changes.
2. Severity table above holds for every row; CVSS boundaries inclusive at
   9.0 / 7.0 / 4.0; missing CVSS → medium.
3. gitleaks evidence never contains the raw secret from the fixture.
4. `--url http://example.com` → exit 2, no collector `run` called.
   `--url http://localhost:8000`, `http://127.0.0.1:8000`, `http://[::1]:8000`
   → accepted.
5. Missing tool → `run.skipped` entry, other collectors still run, exit code
   from findings.
6. Collector raising a non-`ToolMissing` exception → skipped with
   `error:` prefix, others still run.
7. Baseline: new/known/resolved computed as specified; resolved excluded from
   severity counts, included in `findings`.
8. `accepted.yml` entry missing `reason` → exit 2; expired entry ignored with
   warning; valid entry → `status=accepted`, not counted in `--fail-on`.
9. `--fail-on` default `high`: one `medium` → exit 0; one `high` → exit 1;
   `--fail-on medium` with one `medium` → exit 1.
10. `report` output is byte-identical across two invocations on the same
    input; groups ordered critical → info; `Skipped tools` section present
    only when `run.skipped` non-empty.
11. `ratelimit` sends at most 30 requests per path and only to paths matching
    the auth pattern; a path answering `429` at any point yields no finding.
12. Every collector's `parse` on its fixture yields ≥ 1 finding with all
    required fields and a location of the shape the table prescribes.
13. `Report` JSON round-trips through `schema.py` without loss;
    `schema_version` is `"1.0"`.

## By hand (after green)

- `secaudit scan --repo <orchestrator> --out /tmp/sa` with real tools
  installed: compare `run.tools` with `--version` of each; open `report.md`.
- With the orchestrator running: add `--url http://127.0.0.1:8000`; confirm
  ZAP baseline finished under 3 min and `ratelimit` touched only auth paths
  (server log).
- Run twice; second run with `--baseline` shows `new=0`.
