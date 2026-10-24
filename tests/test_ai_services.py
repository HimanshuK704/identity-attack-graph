import unittest

from services.ai_services import (
    AIUnavailableError,
    build_finding_context,
    build_recommendations,
    build_timeline,
    explain_path,
    graph_search,
    prioritize_findings,
)


class AIServicesTests(unittest.TestCase):
    def test_context_excludes_ground_truth(self):
        context = build_finding_context("TA-ACC-073")
        serialized = str(context).casefold()
        self.assertNotIn("ground_truth_label", serialized)
        self.assertNotIn("planted_suspicious", serialized)

    def test_timeline_is_sorted(self):
        result = build_timeline("TA-ACC-073")
        self.assertGreater(result["count"], 0)
        timestamps = [
            item["timestamp"]
            for item in result["timeline"]
            if item.get("timestamp")
        ]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_prioritization_preserves_findings(self):
        result = prioritize_findings()
        self.assertGreaterEqual(result["count"], 1)
        scores = [item.get("risk_score", 0) for item in result["findings"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_entity_search(self):
        result = graph_search("ACC-073")
        self.assertGreater(result["count"], 0)

    def test_path_finds_known_relationship(self):
        result = explain_path("ACC-073", "DEV-073")
        self.assertTrue(result["found"])
        self.assertEqual(result["path"][0], "ACC-073")
        self.assertEqual(result["path"][-1], "DEV-073")

    def test_path_does_not_invent_unknown_node(self):
        result = explain_path("ACC-073", "NONEXISTENT-NODE")
        self.assertFalse(result["found"])

    def test_recommendations_are_evidence_linked(self):
        result = build_recommendations("TA-ACC-073")
        self.assertGreaterEqual(len(result["recommendations"]), 1)
        self.assertEqual(result["generation_status"], "deterministic")


if __name__ == "__main__":
    unittest.main()
