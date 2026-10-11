import copy,unittest
from linuxhound.validation import binary_metrics,ranking_metrics
from linuxhound.gnn import _samples
from test_gnn import fixture

class ValidationTests(unittest.TestCase):
    def test_confusion_and_ranking_metrics(self):
        rows=[{'id':'a','label':1,'prediction':1,'score':4},{'id':'b','label':0,'prediction':1,'score':3},{'id':'c','label':1,'prediction':0,'score':2},{'id':'d','label':0,'prediction':0,'score':1}]
        m=binary_metrics(rows);self.assertEqual((m['tp'],m['fp'],m['tn'],m['fn']),(1,1,1,1));self.assertEqual(m['f1'],.5)
        ranking=ranking_metrics(rows,2);self.assertEqual(ranking['precision_at_k'],.5);self.assertAlmostEqual(ranking['average_precision'],(1+2/3)/2)
    def test_empty_and_nonfinite_metrics(self):
        self.assertIsNone(binary_metrics([])['recall']);self.assertIsNone(ranking_metrics([])['average_precision'])
        with self.assertRaises(ValueError):ranking_metrics([{'id':'a','label':1,'score':float('nan')}])
        with self.assertRaises(ValueError):binary_metrics([{'label':True,'prediction':1}])
    def test_shared_kernel_requires_explicit_isolation_protocol(self):
        reports,manifest=fixture()
        for item in manifest['graphs']:item['source_host_id']='shared-kernel';item['source_environment_id']='container-'+item['split'];item['environment_kind']='container'
        with self.assertRaisesRegex(ValueError,'share a source host'):_samples(manifest,reports.__getitem__)
        manifest['evaluation_protocol']='isolated_environment_holdout';self.assertEqual(set(_samples(manifest,reports.__getitem__)),{'train','validation'})
        manifest['graphs'][1]['source_environment_id']=manifest['graphs'][0]['source_environment_id']
        with self.assertRaisesRegex(ValueError,'share a source host'):_samples(manifest,reports.__getitem__)
    def test_isolation_attestation_required(self):
        reports,manifest=fixture();manifest['evaluation_protocol']='isolated_environment_holdout'
        with self.assertRaisesRegex(ValueError,'container identity'):_samples(manifest,reports.__getitem__)
    def test_test_split_never_enters_optimizer(self):
        reports,manifest=fixture();item=copy.deepcopy(manifest['graphs'][0]);item['split']='test';manifest['graphs'].append(item)
        with self.assertRaisesRegex(ValueError,'train or validation'):_samples(manifest,reports.__getitem__)

if __name__=='__main__':unittest.main()
