# Learning the priority weights

3 labelled runs, 89 behaviours, 44 of them the scenario under test.

Each run is held out in turn; the model is trained on the others. Cells are precision at 1 / precision at 3, averaged over the techniques of the held-out run that contain at least one true positive.

| Held-out run | Techniques | Newest first | Hand-set score | Learned |
|---|---|---|---|---|
| run-090203 | 5 | 0.80 / 0.80 | 0.80 / 0.80 | 0.80 / 0.80 |
| run-091019 | 5 | 0.80 / 0.80 | 0.80 / 0.80 | 1.00 / 0.93 |
| run-091820 | 4 | 0.75 / 0.75 | 0.75 / 0.75 | 0.75 / 0.92 |
| **mean** | | **0.78 / 0.78** | **0.78 / 0.78** | **0.85 / 0.88** |

Learned beat the hand-set score on precision at 1 in 1 of 3 held-out runs (tied in 2).

## Where it matters: by technique

Precision at 1, over all held-out runs. *Share of scenario* is the fraction of the list that is the scenario: a list that is mostly scenario is easy for any ordering, a list dominated by noise is the real test.

| Technique | Share of scenario | Newest first | Hand-set score | Learned |
|---|---|---|---|---|
| T1046 | 100% | 1.00 | 1.00 | 1.00 |
| T1059.004 | 15% | 0.00 | 0.00 | 0.33 |
| T1070.003 | 100% | 1.00 | 1.00 | 1.00 |
| T1105 | 100% | 1.00 | 1.00 | 1.00 |
| T1565.001 | 100% | 1.00 | 1.00 | 1.00 |

## What the model learned (standardised weights, averaged over folds)

| Feature | Weight | Reading |
|---|---|---|
| other SIEMs | +1.34 | pushes a behaviour UP the list |
| tactic severity | +0.63 | pushes a behaviour UP the list |
| log(occurrences) | -0.54 | pushes it DOWN |
| log(span minutes) | -0.42 | pushes it DOWN |
| has process | -0.41 | pushes it DOWN |
| is Wazuh | +0.37 | pushes a behaviour UP the list |
| rule level | +0.35 | pushes a behaviour UP the list |
| derived | +0.05 | pushes a behaviour UP the list |

## How far to trust this

- The labels come from our own scenarios, so what separates them from the noise is partly an artefact of the experiment (scripted commands that run once, versus interactive shells that run all day). A feature such as *fewer occurrences means more suspicious* may be learned for that reason and may not hold in real data.
- Few runs and few true positives: differences of a few hundredths are not meaningful.
- Splitting by run avoids leakage between train and test, but all runs come from one host and one day.
- A real deployment would train on analyst labels (validated findings and false positives), not on synthetic markers.
