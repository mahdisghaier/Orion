"""Can weights learned from labelled runs rank findings better than the hand-set priority score?

    python scripts/eval/learn_priority.py

Input: docs/evaluation/datasets/run-*.json, one file per evaluation run. Each row is one behaviour with numeric
features and a label (1 = the scenario we started, 0 = unrelated activity).

Method: leave-one-run-out. For every run, a logistic regression is trained on the OTHER runs and the held-out run is
ranked three ways: newest first, the current hand-set score, and the learned probability. Splitting by run (not by row)
keeps rows of the same run from leaking into training. Precision at 1 and at 3 is computed per technique and averaged.

Needs at least two runs. Writes docs/evaluation/LEARNING.md. Results are reported as they come, including when the
learned model does not win.
"""
import argparse
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Dict, List

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

OUT_DIR = Path(__file__).resolve().parent.parent.parent / "docs" / "evaluation"
FEATURES = ["log(occurrences)", "log(span minutes)", "other SIEMs", "tactic severity", "rule level", "derived", "has process", "is Wazuh"]


def design(rows: List[dict]) -> np.ndarray:
    return np.array([[math.log1p(r["features"]["occurrences"]), math.log1p(r["features"]["span_minutes"]),
                      r["features"]["other_sources"], r["features"]["tactic_points"] / 25.0,
                      r["features"]["event_level"] / 15.0, r["features"]["derived"], r["features"]["has_process"],
                      r["features"]["is_wazuh"]] for r in rows], dtype=float)


class Logistic:
    """Plain L2-regularised logistic regression with balanced class weights (true positives are rare)."""

    def __init__(self, l2: float = 1.0, iterations: int = 3000, rate: float = 0.1):
        self.l2, self.iterations, self.rate = l2, iterations, rate

    def fit(self, X: np.ndarray, y: np.ndarray) -> "Logistic":
        self.mean, self.std = X.mean(axis=0), X.std(axis=0)
        self.std[self.std == 0] = 1.0
        Z = (X - self.mean) / self.std
        positives = max(int(y.sum()), 1)
        negatives = max(len(y) - positives, 1)
        weights = np.where(y == 1, len(y) / (2 * positives), len(y) / (2 * negatives))
        self.w, self.b = np.zeros(Z.shape[1]), 0.0
        for _ in range(self.iterations):
            p = 1.0 / (1.0 + np.exp(-(Z @ self.w + self.b)))
            error = (p - y) * weights
            self.w -= self.rate * (Z.T @ error / len(y) + self.l2 * self.w / len(y))
            self.b -= self.rate * error.mean()
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        Z = (X - self.mean) / self.std
        return 1.0 / (1.0 + np.exp(-(Z @ self.w + self.b)))


def precision_at(order: List[dict], k: int) -> float:
    top = order[:k]
    return sum(r["label"] for r in top) / len(top)


def load_runs(directory: Path) -> Dict[str, List[dict]]:
    runs = {}
    for path in sorted(directory.glob("run-*.json")):
        runs[path.stem] = json.loads(path.read_text())["rows"]
    return runs


def evaluate(runs: Dict[str, List[dict]], l2: float = 1.0) -> dict:
    folds, weights_seen, by_technique = [], [], {}
    for held in runs:
        train = [r for name, rows in runs.items() if name != held for r in rows]
        y = np.array([r["label"] for r in train])
        if y.sum() == 0 or y.sum() == len(y):
            continue
        model = Logistic(l2).fit(design(train), y)
        weights_seen.append(model.w / 1.0)
        groups: Dict[str, List[dict]] = {}
        for r in runs[held]:
            groups.setdefault(r["technique"], []).append(r)
        scored = {"newest": [], "hand-set score": [], "learned": []}
        for technique, rows in groups.items():
            if len(rows) < 2 or not any(r["label"] for r in rows):
                continue
            learned = model.predict(design(rows))
            for r, p in zip(rows, learned):
                r["_p"] = float(p)
            orders = {
                "newest": sorted(rows, key=lambda r: r["last_ts"], reverse=True),
                "hand-set score": sorted(rows, key=lambda r: (r["score"], r["last_ts"]), reverse=True),
                "learned": sorted(rows, key=lambda r: (r["_p"], r["last_ts"]), reverse=True),
            }
            slot = by_technique.setdefault(technique, {"base_rate": [], "newest": [], "hand-set score": [], "learned": []})
            slot["base_rate"].append(sum(r["label"] for r in rows) / len(rows))
            for name, order in orders.items():
                slot[name].append(precision_at(order, 1))
                scored[name].append((precision_at(order, 1), precision_at(order, 3)))
        if scored["newest"]:
            folds.append({"held_out": held, "groups": len(scored["newest"]),
                          **{name: {"p1": statistics.mean(x[0] for x in vals), "p3": statistics.mean(x[1] for x in vals)}
                             for name, vals in scored.items()}})
    summary = {t: {k: statistics.mean(v) for k, v in slot.items()} for t, slot in by_technique.items()}
    return {"folds": folds, "weights": np.mean(weights_seen, axis=0).tolist() if weights_seen else [], "by_technique": summary}


def render(runs: Dict[str, List[dict]], result: dict) -> str:
    rows = [r for rs in runs.values() for r in rs]
    lines = ["# Learning the priority weights", "",
             f"{len(runs)} labelled runs, {len(rows)} behaviours, {sum(r['label'] for r in rows)} of them the scenario under test.", ""]
    if not result["folds"]:
        return "\n".join(lines + ["Not enough data to evaluate (needs at least two runs that contain both classes).", ""])
    lines += ["Each run is held out in turn; the model is trained on the others. Cells are precision at 1 / precision at 3, "
              "averaged over the techniques of the held-out run that contain at least one true positive.", "",
              "| Held-out run | Techniques | Newest first | Hand-set score | Learned |", "|---|---|---|---|---|"]
    for f in result["folds"]:
        cells = " | ".join(f"{f[n]['p1']:.2f} / {f[n]['p3']:.2f}" for n in ("newest", "hand-set score", "learned"))
        lines.append(f"| {f['held_out']} | {f['groups']} | {cells} |")
    mean = {n: (statistics.mean(f[n]["p1"] for f in result["folds"]), statistics.mean(f[n]["p3"] for f in result["folds"]))
            for n in ("newest", "hand-set score", "learned")}
    lines.append("| **mean** | | " + " | ".join(f"**{mean[n][0]:.2f} / {mean[n][1]:.2f}**" for n in ("newest", "hand-set score", "learned")) + " |")
    wins = sum(1 for f in result["folds"] if f["learned"]["p1"] > f["hand-set score"]["p1"])
    ties = sum(1 for f in result["folds"] if f["learned"]["p1"] == f["hand-set score"]["p1"])
    lines += ["", f"Learned beat the hand-set score on precision at 1 in {wins} of {len(result['folds'])} held-out runs "
                  f"(tied in {ties}).", "", "## Where it matters: by technique", "",
              "Precision at 1, over all held-out runs. *Share of scenario* is the fraction of the list that is the scenario: "
              "a list that is mostly scenario is easy for any ordering, a list dominated by noise is the real test.", "",
              "| Technique | Share of scenario | Newest first | Hand-set score | Learned |", "|---|---|---|---|---|"]
    for t, v in sorted(result["by_technique"].items()):
        lines.append(f"| {t} | {v['base_rate']:.0%} | {v['newest']:.2f} | {v['hand-set score']:.2f} | {v['learned']:.2f} |")
    lines += ["", "## What the model learned (standardised weights, averaged over folds)", "",
              "| Feature | Weight | Reading |", "|---|---|---|"]
    for name, w in sorted(zip(FEATURES, result["weights"]), key=lambda x: -abs(x[1])):
        lines.append(f"| {name} | {w:+.2f} | {'pushes a behaviour UP the list' if w > 0 else 'pushes it DOWN'} |")
    lines += ["", "## How far to trust this", "",
              "- The labels come from our own scenarios, so what separates them from the noise is partly an artefact of the experiment "
              "(scripted commands that run once, versus interactive shells that run all day). A feature such as *fewer occurrences means "
              "more suspicious* may be learned for that reason and may not hold in real data.",
              "- Few runs and few true positives: differences of a few hundredths are not meaningful.",
              "- Splitting by run avoids leakage between train and test, but all runs come from one host and one day.",
              "- A real deployment would train on analyst labels (validated findings and false positives), not on synthetic markers.", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--l2", type=float, default=1.0)
    parser.add_argument("--runs-dir", type=Path, default=OUT_DIR / "datasets")
    args = parser.parse_args()
    runs = load_runs(args.runs_dir)
    if len(runs) < 2:
        raise SystemExit(f"need at least two run-*.json files in {args.runs_dir}, found {len(runs)}")
    text = render(runs, evaluate(runs, args.l2))
    (OUT_DIR / "LEARNING.md").write_text(text)
    print(text)


if __name__ == "__main__":
    main()
