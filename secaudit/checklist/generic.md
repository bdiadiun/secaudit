# Generic checklist — what scanners cannot see

For the auditor (a person or an agent) after `secaudit scan`. Answer each item
with `pass`, `fail` (→ a `checklist` finding with severity), or `n/a` (with a
reason). Project-specific items live in the target repo at
`docs/security/checklist.md` and are walked after this list.

## Access control

- [ ] Every HTTP route has an authentication dependency, or is explicitly
      listed as public with a reason.
- [ ] Object-level authorisation: a handler that takes an id checks the
      caller may see **that** object, not only that the caller is logged in.
- [ ] Privileged actions (approve, override, delete, admin) check a role, not
      a client-supplied flag.
- [ ] Human gates cannot be passed by a non-human principal.

## Authentication and sessions

- [ ] Auth endpoints (`login`, token, password reset) are rate limited and the
      limit is per identity **and** per IP.
- [ ] Session cookies: `HttpOnly`, `Secure` (outside dev), `SameSite=Lax` or
      stricter; tokens expire; refresh rotates.
- [ ] Password/secret comparison is constant-time; hashes use a slow KDF.

## Input and output

- [ ] User- or agent-produced text rendered in the UI goes through the
      framework's escaping; any `dangerouslySetInnerHTML` / `v-html` /
      `|safe` is justified and sanitised.
- [ ] File paths derived from input are confined to an allowed root
      (`realpath` inside the root, no `..`).
- [ ] Shell commands are argument lists, never interpolated strings.
- [ ] Outbound requests with a user-supplied URL are restricted (allow-list or
      loopback/private-range deny).

## Secrets and configuration

- [ ] No credential in the repo, history, image layers or logs; encryption
      keys come from the environment or a secret store and are not logged.
- [ ] Error responses do not leak stack traces, SQL or file paths.
- [ ] CORS lists origins; no `*` together with credentials.
- [ ] Security headers present: CSP, `X-Content-Type-Options`, `Referrer-Policy`,
      HSTS behind TLS.

## Agents and automation (when the target runs LLM agents)

- [ ] Content from an untrusted repository (README, comments, code) enters the
      agent prompt marked as data, and the prompt says so.
- [ ] The agent's shell policy cannot read secrets, leave its worktree, or
      push to a branch other than its own.
- [ ] Every agent action is attributable (run id, instance, model) in an
      audit trail.
- [ ] Agent output is validated against a schema before it changes state.

## Logging and monitoring

- [ ] Auth failures, gate overrides and privilege changes are logged with the
      principal.
- [ ] Logs are free of tokens, passwords and full request bodies of auth
      endpoints.
