# ORION threat model

What can go wrong with ORION itself, and what is done about it. Written against the code as it is, so every
"mitigation" below points at something that exists and, where possible, at the test that proves it. Weaknesses that
remain are listed as such in section 5.

## 1. What is being protected

| Asset | Why it matters |
|---|---|
| SIEM credentials (Elastic API key, Wazuh user and password) | Whoever holds them can read every log of the organisation |
| The logs ORION pulls (findings, events, context) | Contain hostnames, users, command lines, addresses |
| Analyst decisions and the audit trail | The record of who concluded what; evidence if a decision is questioned |
| Accounts and roles | A stolen admin account manages SIEM connections and users |
| The hunt rules and results | Tampering could hide a real finding or fabricate a false one |

## 2. Actors

- **Analyst (L1, L2, L3)**: legitimate user, trusted for the actions of their role, not trusted with more.
- **Admin**: manages users and SIEM connections.
- **External attacker**: can reach the web interface, may steal a session or phish an analyst.
- **Malicious website**: a page open in an analyst's browser that tries to act as them.
- **Compromised monitored host**: an attacker whose command lines and hostnames end up inside the logs ORION reads, and
  therefore inside the text given to the AI model.
- **The AI provider**: a third party that receives some of the investigation context.

## 3. Trust boundaries

1. Browser <-> ORION API (cookies, JSON).
2. ORION API <-> PostgreSQL (application data, encrypted SIEM configs, audit log).
3. ORION API <-> each SIEM (read-only queries over HTTP or HTTPS).
4. ORION API <-> AI provider (prompts out, JSON proposals back).
5. Exported report and notebook <-> whoever receives the file.

## 4. Threats and controls (STRIDE)

| # | Threat | Control that exists | Evidence | Residual risk |
|---|---|---|---|---|
| S1 | Guessing passwords | bcrypt hashes; login lockout after 5 failures per account (and 20 per address) for 15 minutes; unknown accounts are throttled the same way, so lockout does not reveal which accounts exist | `tests/test_security.py` (LoginThrottle, LoginEndpoint) | Counters are in process memory: a restart clears them, several workers would each keep their own |
| S2 | Stealing the session token with a script | Tokens live in httpOnly cookies, not in storage JavaScript can read | `app/core/security.py` | A browser extension or malware on the analyst's machine is out of reach |
| S3 | A malicious site making the analyst's browser act | SameSite=Strict cookies, plus double-submit CSRF: every state-changing request must repeat the csrf cookie in `X-CSRF-Token`, checked server side | `tests/test_security.py` (CsrfRules, CsrfMiddleware) | Cookies are only marked Secure when `APP_ENV=production`; HTTPS itself must come from a reverse proxy |
| S4 | Using a stolen but expired or forged token | Signed tokens with expiry; the user is reloaded from the database on every request, so a disabled account stops working at once | `app/core/deps.py` | There is no server-side revocation list: a stolen valid token works until it expires, and logout only removes the cookies |
| T1 | Changing records to hide or invent findings | Every state-changing action is audited with user, address and a bounded description; suppressions and decisions are reversible and visible | `tests/test_audit_and_chat.py`, `tests/test_security.py` (AuditCoverage) | The audit table is ordinary rows: a database administrator can edit it. A hash chain would make tampering evident (planned) |
| T2 | Injecting query text through the "Related events" pivots | The analyst picks one of three fixed pivots and a bounded window; the connector builds term filters from the finding's own values, never query strings | `tests/test_context.py` (injection case) | Values still come from logs, which an attacker controls, but they are only ever data |
| T3 | The AI proposing something harmful | The model has no tools. Its reply must be JSON of a fixed shape; each rule must parse, be runnable on a live SIEM and cite real evidence; **nothing runs until an analyst approves it** | `tests/test_investigation.py`, `tests/test_llm.py` | A convincing but wrong proposal can still be approved by a careless analyst |
| R1 | An analyst denying a decision | The audit log records login, hunts, decisions, suppressions, exports, SIEM and user changes with the user id and address; each step of an investigation keeps who approved or rejected it | `tests/test_security.py` (AuditCoverage) | Shared accounts would defeat attribution; the audit log is not tamper-evident (see T1) |
| I1 | Reading another role's data | Role checks on every endpoint; the whole matrix is tested for each role, and a test fails if a new route has no role test | `tests/test_security.py` (RoleMatrix) | Roles are coarse: any analyst can read every finding |
| I2 | SIEM credentials leaking | Stored encrypted (Fernet) and never returned by the API or written to the audit log; reports and notebooks contain none by construction (the notebook reads the analyst's own login from the environment) | `tests/test_export.py`, `tests/test_security.py` | The encryption key sits in `.env` next to the database URL; there is no key rotation tool |
| I3 | Logs reaching the AI provider | A local model can replace the provider with one setting (`LLM_PROVIDER=openai_compatible`) | `tests/test_llm.py` | By default findings (host, process, command line) are sent to Google, and nothing is pseudonymised yet (planned) |
| I4 | Prompt injection through log content | Log-derived text is shortened, flattened to one line, placed inside a fenced "untrusted data" block that attacker text cannot close, and the model is told to treat it as data | `tests/test_investigation.py` (fence test) | A model may still be swayed into a bad proposal; the approval step and validation are the real defence |
| I5 | Errors revealing internals | Most errors return a short message | | Some 500 responses include the exception text (for example the chat routes); should be generic in production |
| D1 | Overloading the SIEMs with heavy queries | Hunts return at most 1000 events per SIEM, pivots also cap their time window, all queries are read-only, and a hunt that fails on a SIEM reports it | `app/services/connectors/*` | A hunt without a time range searches the whole index; no per-user quotas or rate limits on hunts; a wildcard-heavy rule can still be costly |
| D2 | Hanging the server through a slow AI call | The AI call runs in a worker thread, is cut off after 60 seconds, and falls back to rule-based suggestions | `tests/test_llm.py` (PlannerNeverHangs) | Hunts run inside the request: a very long hunt occupies a worker |
| E1 | An analyst acting above their role | `require_role` dependencies; L1 cannot suppress, escalate, conclude or manage anything | `tests/test_security.py` (RoleMatrix, mutation-checked) | L1 may approve and run steps by design: they are read-only queries |
| E2 | A stolen non-admin account reaching SIEM secrets | Admin-only endpoints; the API never returns a connection's config | `tests/test_security.py` | |

## 5. Weaknesses that remain (honest list)

1. **Dependencies are only as clean as the day they were scanned.** The first scan found known vulnerabilities in 20 of
   152 pinned Python packages (126 advisories) and 4 high ones in the frontend. Most belonged to packages the application
   never imports (leftovers of the earlier Kestrel, STIX-Shifter, Azure and AWS plans) and to an unmaintained JWT library.
   They were removed or upgraded (section 6); the scan now reports none. New advisories appear over time, and nothing
   re-runs the scan automatically yet.
2. **SIEM address is admin-supplied and not restricted** (server-side request forgery): an admin account could point a
   connection at an internal address. It is admin-only, but there is no allow-list.
3. **`verify_ssl: false` can be stored** for a connection (used for the lab's self-signed certificate). It must not be
   used outside a lab.
4. **No session revocation, no refresh-token rotation.**
5. **Audit log not tamper-evident.**
6. **No pseudonymisation before the AI provider.**
7. **Development defaults**: CORS allows localhost, cookies are not Secure, and the seed script creates demo accounts.
   None of these may be used in production.
8. **Single process assumptions**: the login throttle keeps its counters in memory.

## 6. Dependency hygiene

- `requirements.in` lists only the packages the code imports; `requirements.txt` is the full resolved set produced
  from it in a clean environment (79 packages, down from 152). Rebuild it the same way, never by hand.
- Scan with `pip-audit -r requirements.txt --no-deps --disable-pip` and `npm audit` in `frontend/`. Result when this
  section was written: no known advisories in either.
- `python-jose` was replaced by `PyJWT` (same calls for what ORION uses): the former is unmaintained and the scan found
  an advisory with no fix published. Token behaviour is tested, including expired, forged, tampered and `none`-algorithm
  tokens (`tests/test_tokens.py`).
- The whole test suite and a smoke test of the running application (login, CSRF, findings, pivots, hunts, AI proposal,
  report and notebook) were run on the upgraded set, against the real database and SIEMs.
- Not done yet: a scheduled scan in CI, and hash-pinned installs.

## 7. Out of scope

Compromise of the host running ORION, of the database server, or of the SIEMs themselves; physical access; denial of
service against the network; the security of the monitored hosts.
