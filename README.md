# secaudit

Runs established security scanners against **your own** repository and **your
own** local instance, normalises their output into one findings schema, diffs
against a baseline, and renders a report. It does not write payloads and does
not contain exploits: the collectors wrap tools that already exist (`bandit`,
`semgrep`, `pip-audit`, `osv-scanner`, `gitleaks`, OWASP ZAP baseline) and one
benign probe (does an auth endpoint answer `429` under a short burst).

It knows nothing about any consumer. The orchestrator installs it into the
agent image by tag and runs it from a `security_audit` stage; a human can run
it from a shell the same way.

## Principles

- **Scanners are the deterministic layer; interpretation is someone else's
  job.** `secaudit` emits `findings.json`; an agent or a person adds the
  checklist layer (authz, rate limits, prompt injection) on top.
- **Loopback only.** A `--url` whose host is not `127.0.0.1`, `::1` or
  `localhost` is refused with exit code `2`. There is no override flag.
- **Passive over active.** ZAP runs in baseline mode. Nothing fuzzes, nothing
  brute-forces, nothing writes to the target.
- **Repeat runs show the delta.** Every finding has a stable fingerprint; a
  baseline file turns the second run into "3 new, 1 resolved", not the same
  forty lines again.
- **Accepted risk is a file, not a memory.** `accepted.yml` lists fingerprints
  with a reason, an author and a date; an accepted finding stays in the report
  as `accepted` and never trips the gate.

## Usage

```
secaudit scan --repo . --out .secaudit/
secaudit scan --repo . --url http://127.0.0.1:8000 --out .secaudit/ \
              --baseline .secaudit/baseline.json --accepted .secaudit/accepted.yml \
              --fail-on high
secaudit report .secaudit/findings.json > .secaudit/report.md
secaudit baseline .secaudit/findings.json --out .secaudit/baseline.json
```

Exit codes of `scan`: `0` clean at the `--fail-on` threshold, `1` at least one
`new` or `known` finding at or above it, `2` usage or collector error (missing
tool is a *warning* in `run.skipped`, not an error — see spec).

Missing scanners are skipped and reported, never silently. Install them
separately: `pip install bandit pip-audit semgrep`, `brew install gitleaks
osv-scanner`, ZAP via `docker run ghcr.io/zaproxy/zaproxy:stable
zap-baseline.py`.

## Layout

```
secaudit/
  schema.py        Finding, Report — pydantic v2, the contract with consumers
  normalize.py     tool JSON -> Finding, severity mapping, fingerprint
  baseline.py      status = new | known | resolved | accepted
  collectors/      one module per tool; each returns list[Finding]
  checklist/       generic.md — the layer scanners cannot see
  cli.py           typer: scan, report, baseline
docs/spec.md       invariants the tests are written from
```

## Non-goals

Active scanning, credential testing, fuzzing, anything against a host you do
not own, automatic fixes.
