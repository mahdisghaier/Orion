"""The chat assistant makes a generated rule work before asking the analyst to approve it.

Run:  python -m unittest discover -s tests -t . -v
"""
import unittest

from app.services.agent.rule_repair import compile_error, ensure_valid_rule, library_match, normalise_rule

GOOD = """title: Network scanning tool
id: e4f89d31-8921-4f3b-a178-578491c905b2
status: experimental
date: 2024/05/22
tags:
  - attack.t1046
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith:
      - /nmap
      - /nc
  condition: selection
"""


class Normalise(unittest.TestCase):
    def test_a_date_written_with_slashes_is_fixed(self):
        rule, changes = normalise_rule(GOOD)
        self.assertIn("2024-05-22", rule)
        self.assertTrue(any("date" in c for c in changes))

    def test_an_unreadable_date_is_removed(self):
        rule, changes = normalise_rule(GOOD.replace("2024/05/22", "last tuesday"))
        self.assertNotIn("date:", rule)
        self.assertTrue(changes)

    def test_an_identifier_that_is_not_a_uuid_is_removed(self):
        rule, _ = normalise_rule(GOOD.replace("e4f89d31-8921-4f3b-a178-578491c905b2", "rule-1"))
        self.assertNotIn("rule-1", rule)

    def test_an_unknown_status_becomes_experimental(self):
        rule, _ = normalise_rule(GOOD.replace("experimental", "draft"))
        self.assertIn("status: experimental", rule)

    def test_a_single_selection_gets_its_missing_condition(self):
        rule, changes = normalise_rule(GOOD.replace("  condition: selection\n", ""))
        self.assertIn("condition: selection", rule)
        self.assertTrue(any("condition" in c for c in changes))

    def test_text_that_is_not_a_rule_is_refused(self):
        with self.assertRaises(ValueError):
            normalise_rule("just a sentence about scanning")


class EnsureValid(unittest.TestCase):
    def test_the_rule_of_the_screenshot_now_compiles(self):
        # a date of the form 2024/05/22 stopped every hunt with "Rule date ... is invalid"
        self.assertIsNotNone(compile_error(GOOD))
        rule, notes, from_library = ensure_valid_rule(GOOD, "port scans")
        self.assertIsNone(compile_error(rule))
        self.assertFalse(from_library)
        self.assertTrue(notes)

    def test_the_model_is_asked_to_correct_what_code_cannot(self):
        broken = "title: t\nlogsource:\n  product: linux\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: [/nc\n  condition: selection\n"
        asked = []

        def model(prompt, system):
            asked.append(prompt)
            return "```yaml\n" + GOOD + "\n```"

        rule, notes, from_library = ensure_valid_rule(broken, "port scans", model)
        self.assertEqual(len(asked), 1)
        self.assertIn("Compiler error", asked[0])
        self.assertIsNone(compile_error(rule))

    def test_when_the_model_cannot_help_the_closest_library_rule_is_offered_and_said_so(self):
        rule, notes, from_library = ensure_valid_rule("not yaml at all: [", "someone is scanning the network for open ports")
        self.assertTrue(from_library)
        self.assertIsNone(compile_error(rule))
        self.assertTrue(any("library" in n for n in notes))

    def test_a_model_that_is_down_does_not_stop_the_repair(self):
        def down(prompt, system):
            raise RuntimeError("quota")

        rule, _, _ = ensure_valid_rule(GOOD, "scan", down)
        self.assertIsNone(compile_error(rule))

    def test_a_request_with_no_match_gives_a_clear_error(self):
        with self.assertRaises(ValueError):
            ensure_valid_rule("not yaml at all: [", "zzzz qqqq")


class LibraryMatch(unittest.TestCase):
    def test_the_technique_tag_of_the_broken_rule_picks_the_library_rule(self):
        self.assertEqual(library_match("anything", GOOD)["technique"], "T1046")

    def test_words_of_the_request_pick_a_rule(self):
        self.assertEqual(library_match("hunt for history being cleared")["technique"], "T1070.003")


if __name__ == "__main__":
    unittest.main()
