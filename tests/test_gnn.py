import copy
import importlib.util
import unittest
from linuxhound.gnn import features, fingerprint, train, rank, _network


def graph(host, root_uid=0):
    return {'kind': 'linuxhound-report', 'host': {'id': host}, 'collection': {'coverage': {'users': 'complete'}},
        'nodes': [{'id': host+'/a', 'type': 'account', 'name': 'not-a-feature', 'properties': {'uid': 1000, 'secret': 'DO-NOT-EXPORT'}},
                  {'id': host+'/r', 'type': 'account', 'properties': {'uid': root_uid}}],
        'edges': [{'id': host+'/edge', 'source': host+'/a', 'target': host+'/r', 'type': 'SudoAllows'}],
        'evidence': [{'contents': 'DO-NOT-EXPORT'}],
        'analysis': {'paths': [{'id': host+'/path', 'node_ids': [host+'/a', host+'/r'], 'verified': False, 'conclusion': 'conditional_attack_path', 'steps': [{'edge_id': host+'/edge'}]}], 'findings': []}}


def fixture():
    reports={'train': graph('training-host'), 'validation': graph('validation-host', 42)}
    manifest={'reviewer': 'synthetic pipeline test', 'label_policy': 'Toy pipeline labels; not security ground truth', 'graphs': []}
    for split, report in reports.items():
        manifest['graphs'].append({'report': split, 'split': split, 'source_host_id': 'fixture-'+split, 'snapshot_sha256': fingerprint(report),
            'labels': {report['nodes'][0]['id']: 0, report['nodes'][1]['id']: 1}})
    return reports, manifest


class FeatureTests(unittest.TestCase):
    def test_allowlisted_features_and_direction(self):
        data=features(graph('host'))
        self.assertNotIn('DO-NOT-EXPORT', str(data))
        self.assertNotIn('not-a-feature', str(data))
        self.assertEqual(data['edges'][0][:2], [0, 1])
        self.assertEqual(len(data['x'][0]),len(data['feature_names']))

    def test_rich_metadata_and_missing_masks(self):
        from linuxhound.synthetic import before_report
        data=features(before_report());names=data['feature_names']
        self.assertGreater(len(names),100)
        service=next(i for i,n in enumerate(before_report()['nodes']) if n['type']=='service')
        self.assertEqual(data['x'][service][names.index('active_service')],1)
        self.assertEqual(data['x_known'][service][names.index('no_new_privileges')],0,'Missing sandbox values are not known false')
        cap=next(i for i,n in enumerate(before_report()['nodes']) if n['name']=='/opt/lab/helper')
        self.assertEqual(data['x'][cap][names.index('file_cap_setuid')],1)
        status=next(i for i,n in enumerate(before_report()['nodes']) if n['name']=='/usr/local/bin/status')
        self.assertEqual(data['x'][status][names.index('mount_nosuid')],1)
        self.assertEqual(data['x'][status][names.index('mount_noexec')],1)
        edge=next(i for i,e in enumerate(before_report()['edges']) if e.get('properties',{}).get('nopasswd') is True)
        self.assertEqual(data['edge_x'][edge][data['edge_feature_names'].index('sudo_nopasswd')],1)
        self.assertEqual(len(data['edge_x']),len(data['edges']))
        self.assertEqual(len(data['x_known']),len(data['x']))

    def test_container_flags_preserve_unknown_and_false(self):
        report=graph('host');report['nodes'].append({'id':'host/container','type':'container','properties':{'userns_mode':'','security_opt':['no-new-privileges:false'],'cap_drop':['all']}})
        data=features(report);names=data['feature_names']
        self.assertEqual(data['x_known'][-1][names.index('host_user_namespace')],0,'Daemon-default user namespace is unspecified')
        self.assertEqual(data['x'][-1][names.index('no_new_privileges_container')],0)
        self.assertEqual(data['x_known'][-1][names.index('no_new_privileges_container')],1)
        self.assertEqual(data['x'][-1][names.index('cap_drop_all')],1)

    def test_content_and_labels_are_not_feature_inputs(self):
        report=graph('host');a=features(report)
        report['nodes'][0]['properties']['password']='very-secret'
        report['nodes'][0]['properties']['env']={'TOKEN':'very-secret'}
        report['analysis']['findings']=[{'priority':'critical','contents':'very-secret'}]
        report['edges'][0]['verified']=True
        b=features(report)
        self.assertEqual(a['x'],b['x']);self.assertEqual(a['edge_x'],b['edge_x'])
        self.assertNotIn('very-secret',str(b))

    def test_viewer_has_unique_gnn_navigation_and_ids(self):
        from html.parser import HTMLParser
        from linuxhound.html_export import export_html
        from linuxhound.synthetic import before_report
        class IDs(HTMLParser):
            def __init__(self):super().__init__();self.ids=[]
            def handle_starttag(self,tag,attrs):
                self.ids.extend(v for k,v in attrs if k=='id')
        parser=IDs();parser.feed(export_html(before_report()))
        self.assertEqual(len(parser.ids),len(set(parser.ids)))
        self.assertIn('pane-gnn',parser.ids)
        self.assertIn('gnn-export',parser.ids)

    def test_missing_endpoints_fail(self):
        report=graph('host');report['edges'][0]['source']='missing'
        with self.assertRaisesRegex(ValueError,'endpoint'):features(report)

    def test_exact_labels_and_disjoint_hosts_required(self):
        reports, manifest=fixture();manifest['graphs'][0]['snapshot_sha256']='wrong'
        with self.assertRaisesRegex(ValueError,'exact snapshot'):train(manifest,reports.__getitem__,1)
        reports, manifest=fixture();reports['validation']['host']['id']='training-host'
        manifest['graphs'][1]['snapshot_sha256']=fingerprint(reports['validation'])
        with self.assertRaisesRegex(ValueError,'disjoint'):train(manifest,reports.__getitem__,1)

    def test_renamed_host_cannot_reuse_node_identities(self):
        reports, manifest=fixture()
        reports['validation']['nodes'][0]['id']=reports['train']['nodes'][0]['id']
        reports['validation']['edges'][0]['source']=reports['train']['nodes'][0]['id']
        manifest['graphs'][1]['snapshot_sha256']=fingerprint(reports['validation'])
        manifest['graphs'][1]['labels']={n['id']:i for i,n in enumerate(reports['validation']['nodes'])}
        with self.assertRaisesRegex(ValueError,'disjoint'):train(manifest,reports.__getitem__,1)

    def test_source_host_cannot_be_relabelled(self):
        reports, manifest=fixture()
        manifest['graphs'][1]['source_host_id']=manifest['graphs'][0]['source_host_id']
        with self.assertRaisesRegex(ValueError,'share a source host'):
            train(manifest,reports.__getitem__,1)
        reports, manifest=fixture()
        for report in reports.values(): report['host']['hostname']='same-desktop'
        for item in manifest['graphs']: item['snapshot_sha256']=fingerprint(reports[item['report']])
        with self.assertRaisesRegex(ValueError,'share a source host'):
            train(manifest,reports.__getitem__,1)

    def test_source_host_provenance_required(self):
        reports, manifest=fixture(); del manifest['graphs'][0]['source_host_id']
        with self.assertRaisesRegex(ValueError,'source_host_id provenance'):
            train(manifest,reports.__getitem__,1)

    def test_label_provenance_required(self):
        with self.assertRaisesRegex(ValueError,'provenance'):train({},lambda _:None,1)


@unittest.skipUnless(importlib.util.find_spec('torch'), 'optional torch dependency unavailable')
class NeuralTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import torch
        cls.threads=torch.get_num_threads();torch.set_num_threads(1)
        cls.reports, cls.manifest=fixture()
        cls.model=train(cls.manifest,cls.reports.__getitem__,epochs=3)

    @classmethod
    def tearDownClass(cls):
        import torch
        torch.set_num_threads(cls.threads)

    def test_training_and_inference_preserve_evidence(self):
        original=copy.deepcopy(self.reports['train']);result=rank(original,self.model)
        self.assertEqual(original,self.reports['train'])
        self.assertEqual(result['analysis'],original['analysis'])
        self.assertEqual(result['edges'],original['edges'])
        self.assertEqual(result['evidence'],original['evidence'])
        self.assertFalse(result['gnn']['calibrated'])
        self.assertEqual(result['gnn']['paths'][0]['path_id'],original['analysis']['paths'][0]['id'])
        self.assertEqual(result,rank(original,self.model),'Fixed model inference is deterministic')

    def test_schema_and_invalid_weights_rejected(self):
        bad=copy.deepcopy(self.model);bad['feature_names']=[]
        with self.assertRaisesRegex(ValueError,'schema'):rank(self.reports['train'],bad)
        bad=copy.deepcopy(self.model);bad['weights']['output.bias']=[float('nan')]
        with self.assertRaisesRegex(ValueError,'invalid'):rank(self.reports['train'],bad)

    def test_quarantined_model_cannot_rank(self):
        bad=copy.deepcopy(self.model)
        bad['metadata']['evaluation_status']='invalid_same_source_host'
        with self.assertRaisesRegex(ValueError,'quarantined'):rank(self.reports['train'],bad)

    def test_message_passing_affects_output(self):
        import torch
        model=_network();model.load_state_dict({k:torch.tensor(v) for k,v in self.model['weights'].items()})
        data=features(self.reports['train']); disconnected=copy.deepcopy(data);disconnected['edges']=[];disconnected['edge_x']=[];disconnected['edge_x_known']=[]
        self.assertFalse(torch.allclose(model(data),model(disconnected)), 'This is actual learned neighbor message passing, not a static score')
