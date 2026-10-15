"""The learning experiment's mechanics (not its result): split by run, honest when there is no signal, handles tiny data.

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest

from scripts.eval.learn_priority import Logistic, evaluate, precision_at, render


def row(technique, label, occurrences, last_ts, score=50, **extra):
    features = {"occurrences": occurrences, "span_minutes": occurrences / 2, "other_sources": 0, "tactic_points": 8,
                "event_level": 0, "derived": 0, "has_process": 1, "is_wazuh": 0}
    features.update(extra)
    return {"technique": technique, "siem": "elastic", "label": label, "score": score, "last_ts": last_ts, "features": features}


def run(seed):
    # scenario rows: few occurrences; noise rows: many. The newest row is always noise, and the hand-set score is flat.
    rows = [row("T1", 1, 2 + seed, 100 + i) for i in range(2)]
    rows += [row("T1", 0, 300 + 10 * i + seed, 200 + i) for i in range(6)]
    return rows


class Mechanics(unittest.TestCase):
    def test_a_separable_signal_is_learned_and_beats_newest_and_flat_scores(self):
        runs = {f"run-{i}": run(i) for i in range(3)}
        result = evaluate(runs)
        self.assertEqual(len(result["folds"]), 3)
        for fold in result["folds"]:
            self.assertEqual(fold["learned"]["p1"], 1.0)
            self.assertEqual(fold["newest"]["p1"], 0.0)
        self.assertLess(result["weights"][0], 0)                      # fewer occurrences means more suspicious here

    def test_no_signal_gives_no_free_lunch(self):
        flat = {f"run-{i}": [row("T1", i % 2, 10, 100 + j, score=50) for j in range(4)] for i in range(3)}
        for name, rows in flat.items():                               # make the labels unrelated to anything numeric
            rows[0]["label"], rows[1]["label"], rows[2]["label"], rows[3]["label"] = 1, 0, 0, 0
        result = evaluate(flat)
        for fold in result["folds"]:
            self.assertLessEqual(fold["learned"]["p1"], 1.0)

    def test_one_run_or_one_class_is_reported_not_crashed_on(self):
        self.assertEqual(evaluate({"run-1": run(1)})["folds"], [])
        only_noise = {f"run-{i}": [row("T1", 0, 5, 1), row("T1", 0, 6, 2)] for i in range(2)}
        self.assertEqual(evaluate(only_noise)["folds"], [])
        self.assertIn("Not enough data", render(only_noise, evaluate(only_noise)))

    def test_precision_at_k(self):
        order = [{"label": 1}, {"label": 0}, {"label": 1}]
        self.assertEqual(precision_at(order, 1), 1.0)
        self.assertAlmostEqual(precision_at(order, 3), 2 / 3)
        self.assertEqual(precision_at(order[:2], 3), 0.5)             # fewer rows than k

    def test_the_model_predicts_probabilities(self):
        import numpy as np
        X = np.array([[0.0], [0.1], [5.0], [5.1]])
        model = Logistic().fit(X, np.array([1, 1, 0, 0]))
        p = model.predict(X)
        self.assertTrue(all(0 <= v <= 1 for v in p))
        self.assertGreater(p[0], p[3])


if __name__ == "__main__":
    unittest.main()
