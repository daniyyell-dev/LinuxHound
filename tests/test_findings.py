import unittest
from linuxhound.synthetic import before_report, incomplete_after_report, with_validation


class FindingsTests(unittest.TestCase):
    def test_findings_reference_real_paths_and_evidence(self):
        report = before_report()
        analysis = report['analysis']
        path_ids = {p['id'] for p in analysis['paths'] + analysis['service_paths']}
        edges = {e['id']: e for e in report['edges']}
        evidence = {e['id'] for e in report['evidence']}
        self.assertTrue(analysis['findings'])
        self.assertFalse(any('dev' == next((p['account'] for p in analysis['paths'] if p['id'] == f.get('path_id')), None) for f in analysis['findings']))
        for finding in analysis['findings']:
            self.assertIn(finding['path_id'], path_ids)
            self.assertTrue(set(finding['edge_ids']) <= edges.keys())
            self.assertTrue(set(finding['evidence_ids']) <= evidence)
            self.assertEqual(finding['status'], 'needs_review')
            self.assertEqual(finding['impact'], 'conditional')
            self.assertNotEqual(finding['classification'], 'verified_vulnerability')
            self.assertTrue(finding['recommendation'])

    def test_service_path_is_a_forward_conditional_chain(self):
        report = before_report()
        edges = {e['id']: e for e in report['edges']}
        path = next(p for p in report['analysis']['paths'] if p['pattern'] == 'writable-root-job' and p['service'] == 'backup.service' and p['account'] == 'backup')
        sequence = [edges[s['edge_id']] for s in path['steps']]
        self.assertEqual([e['type'] for e in sequence], ['CanWrite', 'MayInfluence', 'RunsAs'])
        self.assertTrue(all(a['target'] == b['source'] for a,b in zip(sequence,sequence[1:])))
        self.assertEqual(sequence[1]['classification'], 'conditional')
        self.assertTrue(sequence[1]['prerequisites'])

    def test_external_validation_and_coverage_gaps_are_separate(self):
        report = with_validation(before_report())
        self.assertTrue(any(f['status'] == 'externally_verified' for f in report['analysis']['findings']))
        partial = incomplete_after_report()
        gap = next(f for f in partial['analysis']['findings'] if f['classification'] == 'coverage_gap')
        self.assertEqual(gap['impact'], 'unknown')
        self.assertNotIn('path_id', gap)


if __name__ == '__main__':
    unittest.main()
