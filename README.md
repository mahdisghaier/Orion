# ORION

**AI-assisted threat hunting across several SIEMs, with the analyst in charge.**

A SIEM only alerts on what a rule describes. Threat hunting looks for what no rule caught, but it needs experts, and every hunt has to be rewritten in each SIEM's query language. ORION lets one analyst write a hunt once, run it on several SIEMs, and get a short, explained list of behaviours. It also says when a SIEM could not have seen the attack at all, so an empty result is never mistaken for a clean one.

Built as a final-year project for the professional master's in information systems security at the Institut Supérieur d'Informatique, Tunisia, 2025-2026.

## What it does

| | |
|---|---|
| **One rule, several SIEMs** | A Sigma rule is compiled to EQL for Elastic and Lucene for Wazuh, then run in parallel, read-only |
| **No silent zeros** | ORION measures which fields each SIEM really fills. A rule that needs a missing field is not run there, and the reason is shown |
| **Triage** | Repeated events are grouped into behaviours, linked across SIEMs and ranked by a score that stores the reason for every point |
| **Controlled AI** | The model proposes rules and investigation steps. Code validates them, and nothing runs until an analyst approves it |
| **Investigations** | Hypothesis, steps, approvals and verdict are recorded, then exported as a PDF report and a Jupyter notebook |
| **Threat intelligence** | A daily check reads CISA KEV, MITRE ATT&CK, abuse.ch and EPSS, hunts recent campaign techniques, and lists what it could not check |
| **Multi-client security** | Roles, client isolation, encrypted SIEM credentials, CSRF protection and an audit log |

## Architecture

```
Monitored host ──> Elastic ─┐
 (Auditbeat)   └─> Wazuh  ──┤ read-only queries
                            ▼
              ORION: FastAPI + PostgreSQL ──> Gemini or a local model
                            ▲
                     Vue interface ── Analyst
```

ORION never copies the logs. It queries the SIEMs on demand and keeps only the matches, the decisions and the audit trail.

**Stack:** Python, FastAPI, SQLAlchemy, PostgreSQL, Vue 3, pySigma, LangGraph, Gemini or any OpenAI-compatible model.

## Measured results

Measured on a lab with one Linux host and real telemetry. The method and the limits are in [docs/evaluation](docs/evaluation).

| Measure | Result |
|---|---|
| Marked attack scenarios found on both SIEMs | 5 of 5 |
| One-second attack instances detected | 120 of 120 |
| Atomic Red Team tests detected, after tuning the rules on those tests | 23 of 28 |
| Raw events grouped into behaviours | 226 to 22 on Elastic, 196 to 23 on Wazuh |
| Rules that fired during two quiet hours | 1 of 20 |
| Three hunts by one analyst, by hand and then with ORION | 33 to 12 minutes, an indication and not a statistic |
| Hidden instructions in log text obeyed by the real model | 0 of 6 |

## Run it

You need Python, Node.js, PostgreSQL and at least one Elastic or Wazuh instance you are allowed to query.

```bash
cp .env.example .env              # then fill in your own values
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
python -m scripts.create_admin
uvicorn app.main:app --port 8000

cd frontend && npm install && npm run dev
```

The interface opens on `http://localhost:5173`. Add a SIEM in **SIEM Connections**, using a read-only account, then refresh its data profile. The scripts used to build the lab are in [scripts/lab](scripts/lab).

Run the tests with `python -m unittest discover tests`.

## Limits

This is a research prototype evaluated on one Linux host, not a production product. Scale has not been tested. The free hosted model should be replaced by a local model or an enterprise contract before any real client data is used.

## Author

**Mahdi Sghaier**
