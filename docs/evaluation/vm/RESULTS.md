# ORION evaluation results

Run on 2026-10-19 00:05 against real telemetry from one Linux host (WSL2). Commit `4b44124`. Each technique was executed as harmless local activity with a unique marker; a detection counts only if the returned event carries that marker. Unrelated matches are reported as noise (the false-positive proxy).

## Sources

- Local Wazuh (wsl-ubuntu) (wazuh): 777 events in the last day
- Elastic (Auditbeat, orion-lab) (elastic): 16,913 events in the last day

## Summary

- **Local Wazuh (wsl-ubuntu)** (wazuh): caught 2/5 long-lived scenarios, median time to appear 134 s; caught 0/120 one-second instances; 0 of 4 returned events were unrelated to the scenarios.
- **Elastic (Auditbeat, orion-lab)** (elastic): caught 5/5 long-lived scenarios, median time to appear 16 s; caught 120/120 one-second instances; 63 of 252 returned events were unrelated to the scenarios.
- Techniques whose long-lived instance was seen by **every** live SIEM: 1 of 5. Where only one SIEM sees an activity, the other's silence is a coverage gap, not a clean result.

## 1. Detection per technique and per SIEM

Cells are `detected / run` with the median time to first appearance. *long* = alive for the whole window, *short* = alive about one second.

| Technique | Variant | wazuh | elastic | Either |
|---|---|---|---|---|
| T1046 Network service discovery: a netcat listener | long | 1/1 (249 s) | 1/1 (16 s) | yes |
| T1046 Network service discovery: a netcat listener | short | 0/30 | 30/30 (16 s) | yes |
| T1059.004 Unix shell command execution | long | 0/1 | 1/1 (16 s) | yes |
| T1059.004 Unix shell command execution | short | 0/30 | 30/30 (16 s) | yes |
| T1105 Ingress tool transfer with curl | long | 0/1 | 1/1 (16 s) | yes |
| T1105 Ingress tool transfer with curl | short | 0/30 | 30/30 (14 s) | yes |
| T1070.003 Clear command history | long | 0/1 | 1/1 (16 s) | yes |
| T1070.003 Clear command history | short | 0/30 | 30/30 (14 s) | yes |
| T1565.001 File modification in a watched folder | file | 1/1 (20 s) | 1/1 (20 s) | yes |

## 2. Noise: what the same rule returns that is NOT the scenario

| Technique | SIEM | Raw events | Unrelated events | Behaviours after grouping | Unrelated behaviours |
|---|---|---|---|---|---|
| T1046 | wazuh | 1 | 0 | 1 | 0 |
| T1046 | elastic | 31 | 0 | 31 | 0 |
| T1059.004 | wazuh | 0 | 0 | 0 | 0 |
| T1059.004 | elastic | 94 | 63 | 91 | 60 |
| T1105 | wazuh | 0 | 0 | 0 | 0 |
| T1105 | elastic | 62 | 0 | 32 | 0 |
| T1070.003 | wazuh | 0 | 0 | 0 | 0 |
| T1070.003 | elastic | 62 | 0 | 62 | 0 |
| T1565.001 | wazuh | 3 | 0 | 3 | 0 |
| T1565.001 | elastic | 3 | 0 | 2 | 0 |

## 3. Does priority scoring put the scenario first?

Precision at k of the list ordered by newest-first versus by ORION's priority score (grouping, correlation and scoring replayed offline on the events above; no analyst labels).

| Technique | Behaviours | True positives | P@1 newest | P@1 priority | P@3 newest | P@3 priority |
|---|---|---|---|---|---|---|
| T1046 | 32 | 32 | 1.0 | 1.0 | 1.0 | 1.0 |
| T1059.004 | 91 | 31 | 0.0 | 0.0 | 0.0 | 0.0 |
| T1105 | 32 | 32 | 1.0 | 1.0 | 1.0 | 1.0 |
| T1070.003 | 62 | 62 | 1.0 | 1.0 | 1.0 | 1.0 |
| T1565.001 | 5 | 5 | 1.0 | 1.0 | 1.0 | 1.0 |

Mean change in P@1 from priority ordering: +0.00; in P@3: +0.00.

## 4. Not measured

- **AI planner quality** (how many proposed rules validate and produce hits): not measured, the model could not answer; see `PLANNER.md`.
- **Analyst time saved** (the 30-90 minute manual-hunt claim): needs a timed study with human analysts; none was run.
- **Effect of analyst feedback over time** (suppression, history in scoring): no labelled analyst decisions exist yet, and the scoring weights have not been calibrated.
- **Windows telemetry, network telemetry, other SIEMs**: the lab has one Linux host, Elastic and Wazuh only.

## 5. Threats to validity

- One host, one run: latencies depend on Metricbeat's 30 s period and Wazuh's 360 s listening-port check.
- The techniques are simulated with harmless commands; real adversary tooling may behave differently.
- The Sigma rules are deliberately broad; a tighter rule would lower noise and could change what is detected.
- Short-lived processes are caught by sampling with a probability of roughly duration / period; with few repeats the catch rate is a rough estimate, not a precise figure.
