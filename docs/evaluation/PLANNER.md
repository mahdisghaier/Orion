# ORION planner measurement

Run on 2026-10-14 21:40. Model(s) that answered: gemini-flash-latest.

## Result

- Hunches answered: 4 of 5
- Proposals made: 12; accepted by validation: 9 (75%)
- Accepted AI rules executed on a live SIEM without error: 8 of 8
- ...and returned at least one event: 3 of 8

## Per hunch

| Hunch | Accepted rules | Accepted pivots | Rejected | Rule runs (events) |
|---|---|---|---|---|
| An attacker left a netcat listener on the workstation to keep access. | 1 | 2 | 0 | wazuh: 0, elastic: 0 |
| Someone is downloading tools onto the workstation with curl or wget. | 1 | 1 | 1 | wazuh: 0, elastic: 19 |
| An attacker is hiding their tracks by clearing the shell history. | 1 | 1 | 1 | wazuh: 0, elastic: 62 |
| A reverse shell was started through bash. | 1 | 1 | 1 | wazuh: 0, elastic: 5 |
| A user is running unusual scripts from the /tmp directory. (AI did not answer) | 0 | 0 | 0 | - |

## Why proposals were rejected

- duplicate of a step already proposed or taken

A returned event does not mean the rule is a good detection: it only means the rule is valid and runs. Whether it is useful needs the ground-truth markers of the main evaluation or an analyst's judgement.

## Limits of this measurement

- Five hunches, one run: a small sample, so the percentages are indicative only.
- Model names such as `gemini-flash-latest` are moving aliases: the same name can mean a different model later, so a re-run may not reproduce these numbers. Pin a dated model name for the final thesis run.
- Rejected proposals here were duplicates of the built-in suggestions; invalid-rule rejections are covered by unit tests only.
- Some free-tier models are limited to a few requests per day, so a hunch can fall through every model in the chain.
