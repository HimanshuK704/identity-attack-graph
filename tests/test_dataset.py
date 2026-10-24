import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from generate_dataset import generate, validate

class DatasetTests(unittest.TestCase):
    def test_minimum_counts_and_integrity(self):
        data=generate(); summary=validate(data)
        self.assertGreaterEqual(summary['entity_count'],100)
        self.assertGreaterEqual(summary['event_count'],300)
        self.assertGreaterEqual(summary['relationship_count'],300)
    def test_deterministic(self):
        self.assertEqual(generate(123)['events'], generate(123)['events'])
    def test_has_benign_suspicious_and_ambiguous(self):
        labels={e['ground_truth_label'] for e in generate()['events']}
        self.assertTrue({'BENIGN','PLANTED_SUSPICIOUS','AMBIGUOUS'} <= labels)

if __name__=='__main__': unittest.main()
