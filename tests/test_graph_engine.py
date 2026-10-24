
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_dataset import generate
from graph_engine import build_graph, detect_clusters


class GraphEngineTests(unittest.TestCase):

    def setUp(self):
        self.data = generate()

    def test_graph_counts_match_source(self):
        graph = build_graph(self.data)

        self.assertEqual(
            len(graph["nodes"]),
            len(self.data["entities"]),
        )
        self.assertEqual(
            len(graph["edges"]),
            len(self.data["relationships"]),
        )

    def test_detects_suspicious_patterns_without_labels(self):
        # Detection must work without ground-truth labels or scenario IDs.
        for entity in self.data["entities"]:
            entity.pop("ground_truth_label", None)
            entity.pop("scenario_id", None)

        for event in self.data["events"]:
            event.pop("ground_truth_label", None)
            event.pop("scenario_id", None)

        clusters = detect_clusters(self.data)

        self.assertTrue(
            clusters,
            "Expected at least one heuristic cluster.",
        )
        self.assertTrue(
            any(cluster["risk_level"] == "HIGH" for cluster in clusters),
            "Expected at least one high-risk synthetic cluster.",
        )

        for cluster in clusters:
            self.assertEqual(cluster["score_type"], "heuristic")
            self.assertIn("signals", cluster)

    def test_shared_ip_does_not_create_cluster_by_itself(self):
        # ACC-031 through ACC-040 belong to the benign shared-IP scenario.
        benign_shared_ip_accounts = {
            f"ACC-{number:03d}"
            for number in range(31, 41)
        }

        clusters = detect_clusters(self.data)

        for cluster in clusters:
            members = set(cluster["account_ids"])

            self.assertFalse(
                benign_shared_ip_accounts.issubset(members),
                "Benign shared-IP accounts should not form "
                "a high-risk cluster solely due to their shared IP.",
            )

    def test_risk_scores_are_bounded(self):
        for cluster in detect_clusters(self.data):
            self.assertGreaterEqual(cluster["risk_score"], 0)
            self.assertLessEqual(cluster["risk_score"], 100)

    def test_findings_have_explanations(self):
        for cluster in detect_clusters(self.data):
            self.assertTrue(cluster["signals"])

            for signal in cluster["signals"]:
                self.assertIn("code", signal)
                self.assertIn("description", signal)
                self.assertIn("points", signal)


    def test_detects_impersonation_linked_takeover(self):
        from graph_engine import detect_account_takeovers

        findings = detect_account_takeovers(self.data)
        finding = next(
            (item for item in findings if item["cluster_id"] == "TA-ACC-073"),
            None,
        )

        self.assertIsNotNone(finding, "Expected SCN-07 takeover finding.")
        self.assertEqual(finding["risk_score"], 40)
        self.assertEqual(finding["score_type"], "heuristic")

        signal_codes = {signal["code"] for signal in finding["signals"]}
        self.assertIn("UNFAMILIAR_ACCESS_CONTEXT", signal_codes)
        self.assertIn("NEW_BENEFICIARY_AFTER_UNFAMILIAR_ACCESS", signal_codes)

    def test_takeover_finding_has_valid_evidence(self):
        from graph_engine import detect_account_takeovers

        findings = detect_account_takeovers(self.data)
        finding = next(
            item for item in findings if item["cluster_id"] == "TA-ACC-073"
        )

        relationship_evidence = {
            relationship.get("evidence_id")
            for relationship in self.data["relationships"]
        }

        self.assertTrue(finding["evidence_ids"])
        self.assertTrue(
            set(finding["evidence_ids"]).issubset(relationship_evidence),
            "Finding evidence must reference actual relationships.",
        )
        self.assertIn("ACC-073", finding["entity_ids"])
        self.assertIn("BEN-TAKEOVER-01", finding["entity_ids"])

    def test_takeover_detection_does_not_use_ground_truth_labels(self):
        from copy import deepcopy
        from graph_engine import detect_account_takeovers

        original = deepcopy(self.data)
        without_labels = deepcopy(self.data)

        for item in without_labels["entities"] + without_labels["events"]:
            item.pop("ground_truth_label", None)
            item.pop("scenario_id", None)

        self.assertEqual(
            detect_account_takeovers(original),
            detect_account_takeovers(without_labels),
        )

    def test_unfamiliar_access_without_new_beneficiary_transfer_is_not_flagged(self):
        from copy import deepcopy
        from graph_engine import detect_account_takeovers

        data = deepcopy(self.data)

        # Remove the takeover transfers and their SENT_TO edges.
        removed_transaction_ids = {
            relationship["target"]
            for relationship in data["relationships"]
            if relationship.get("type") == "INITIATED_TRANSACTION"
            and relationship.get("source") == "ACC-073"
            and relationship.get("target") in {
                "TXN-0073", "TXN-0074"
            }
        }

        # Derive transaction IDs from the corresponding event targets too,
        # avoiding assumptions about global transaction numbering.
        removed_transaction_ids.update(
            event["target_id"]
            for event in data["events"]
            if event.get("event_type") == "INITIATED_TRANSACTION"
            and event.get("source_id") == "ACC-073"
            and event.get("details", {}).get("amount") in {920.00, 780.00}
        )

        data["relationships"] = [
            relationship for relationship in data["relationships"]
            if not (
                relationship.get("type") == "INITIATED_TRANSACTION"
                and relationship.get("source") == "ACC-073"
                and relationship.get("target") in removed_transaction_ids
            )
            and not (
                relationship.get("type") == "SENT_TO"
                and relationship.get("source") in removed_transaction_ids
            )
        ]

        data["events"] = [
            event for event in data["events"]
            if not (
                event.get("event_type") == "INITIATED_TRANSACTION"
                and event.get("source_id") == "ACC-073"
                and event.get("details", {}).get("amount") in {920.00, 780.00}
            )
        ]

        findings = detect_account_takeovers(data)
        self.assertFalse(
            any(item["cluster_id"] == "TA-ACC-073" for item in findings),
            "Unfamiliar access alone must not trigger a takeover finding.",
        )

    def test_takeover_detector_does_not_flag_benign_shared_ip_by_itself(self):
        from graph_engine import detect_account_takeovers

        findings = detect_account_takeovers(self.data)
        finding_accounts = {
            account_id
            for finding in findings
            for account_id in finding["account_ids"]
        }

        for number in range(31, 41):
            self.assertNotIn(f"ACC-{number:03d}", finding_accounts)


if __name__ == "__main__":
    unittest.main()
