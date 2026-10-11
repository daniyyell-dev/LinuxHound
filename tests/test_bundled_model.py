import copy
import importlib.util
import unittest
from pathlib import Path

from linuxhound.synthetic import before_report


@unittest.skipUnless(importlib.util.find_spec('torch') and importlib.util.find_spec('safetensors'), 'GNN dependencies missing')
class BundledModelTests(unittest.TestCase):
    def test_demo_scores_preserve_evidence(self):
        from linuxhound.checkpoint import load_checkpoint
        from linuxhound.path_gnn import rank_paths
        model = Path(__file__).resolve().parents[1] / 'linuxhound/models/demo-path.safetensors'
        checkpoint = load_checkpoint(model)
        self.assertEqual(checkpoint['metadata']['status'], 'synthetic_demo_only')
        report = before_report()
        original = copy.deepcopy(report)
        ranked = rank_paths(report, checkpoint)
        self.assertEqual(report, original)
        for field in ('analysis', 'nodes', 'edges', 'evidence'):
            self.assertEqual(ranked.get(field), report.get(field))
        self.assertEqual(ranked['gnn']['status'], 'synthetic_demo_only')
        self.assertTrue(ranked['gnn']['paths'])
        self.assertFalse(ranked['gnn']['calibrated'])
        self.assertTrue(all(not p['verified'] for p in ranked['gnn']['paths']))


if __name__ == '__main__':
    unittest.main()
