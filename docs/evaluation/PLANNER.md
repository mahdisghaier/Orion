# ORION planner measurement

Run on 2026-10-19 13:21. Model(s) that answered: gemini-3.6-flash.

## Result

- Hunches answered: 4 of 5
- Proposals made: 10; accepted by validation: 10 (100%)
- Accepted AI rules executed on a live SIEM without error: 10 of 10
- ...and returned at least one event: 9 of 10

## Per hunch

| Hunch | Accepted rules | Accepted pivots | Rejected | Rule runs (events) |
|---|---|---|---|---|
| An attacker left a netcat listener on the workstation to keep access. (AI did not answer) | 0 | 0 | 0 | - |
| Someone is downloading tools onto the workstation with curl or wget. | 1 | 2 | 0 | elastic: 716, wazuh: 316 |
| An attacker is hiding their tracks by clearing the shell history. | 1 | 1 | 0 | elastic: 817, wazuh: 496 |
| A reverse shell was started through bash. | 2 | 1 | 0 | elastic: 6, wazuh: 6, elastic: 0, wazuh: 167 |
| A user is running unusual scripts from the /tmp directory. | 1 | 1 | 0 | elastic: 953, wazuh: 611 |

A returned event does not mean the rule is a good detection: it only means the rule is valid and runs. Whether it is useful needs the ground-truth markers of the main evaluation or an analyst's judgement.

## Limits of this measurement

- Five hunches, one run: a small sample, so the percentages are indicative only.
- Model names such as `gemini-flash-latest` are moving aliases: the same name can mean a different model later, so a re-run may not reproduce these numbers. Pin a dated model name for the final thesis run.
- Rejected proposals here were duplicates of the built-in suggestions; invalid-rule rejections are covered by unit tests only.
- Some free-tier models are limited to a few requests per day, so a hunch can fall through every model in the chain.
