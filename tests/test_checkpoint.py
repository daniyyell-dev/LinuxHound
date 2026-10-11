import copy, importlib.util,json,tempfile,unittest
from pathlib import Path
from linuxhound.checkpoint import save_checkpoint,load_checkpoint
from test_path_gnn import fixture
from linuxhound.path_gnn import train_paths,rank_paths


@unittest.skipUnless(importlib.util.find_spec('torch') and importlib.util.find_spec('safetensors'),'optional model dependencies missing')
class CheckpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reports,manifest=fixture();cls.model=train_paths(manifest,cls.reports.__getitem__,epochs=2)
    def test_round_trip_identical_predictions_and_checksum(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'model.safetensors';save_checkpoint(p,self.model)
            loaded=load_checkpoint(p)
            self.assertEqual(loaded,self.model)
            self.assertEqual(load_checkpoint(p.with_suffix('.json')),self.model)
            self.assertEqual(rank_paths(self.reports['validation'],loaded),rank_paths(self.reports['validation'],self.model))
            self.assertNotIn('weights',json.loads(p.with_suffix('.json').read_text()))
            self.assertEqual(p.stat().st_mode&0o777,0o600)
    def test_modified_tensor_bytes_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'model.safetensors';save_checkpoint(p,self.model);raw=p.read_bytes();p.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
            with self.assertRaisesRegex(ValueError,'checksum mismatch'):load_checkpoint(p)
    def test_modified_metadata_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'model.safetensors';save_checkpoint(p,self.model);m=p.with_suffix('.json');document=json.loads(m.read_text());document['metadata']['threat_model']='changed';m.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError,'binding mismatch'):load_checkpoint(p)
    def test_path_traversal_and_overwrite_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'model.safetensors';save_checkpoint(p,self.model)
            with self.assertRaisesRegex(ValueError,'overwrite'):save_checkpoint(p,self.model)
            m=p.with_suffix('.json');document=json.loads(m.read_text());document['storage']['weights_file']='../model.safetensors';m.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError,'basename'):load_checkpoint(p)
    def test_invalid_weights_and_schema_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'model.safetensors';model=copy.deepcopy(self.model);model['weights']['head.2.bias'][0]=float('nan')
            with self.assertRaisesRegex(ValueError,'weight shape or value'):save_checkpoint(p,model)
            model=copy.deepcopy(self.model);model['outcomes']=['wrong']
            with self.assertRaisesRegex(ValueError,'schema or vocabulary'):save_checkpoint(p,model)
    def test_legacy_json_remains_supported(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'checkpoint.json';save_checkpoint(p,self.model);self.assertEqual(load_checkpoint(p),self.model)
    def test_original_node_model_round_trip(self):
        from test_gnn import fixture as node_fixture
        from linuxhound.gnn import train,rank
        reports,manifest=node_fixture();model=train(manifest,reports.__getitem__,epochs=2)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'node.safetensors';save_checkpoint(p,model);loaded=load_checkpoint(p)
            self.assertEqual(loaded,model)
            self.assertEqual(rank(reports['validation'],loaded),rank(reports['validation'],model))
