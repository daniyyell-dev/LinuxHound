import copy, importlib.util, unittest
from linuxhound.path_gnn import path_features,train_paths,rank_paths,OUTCOMES,CHECKS
from linuxhound.gnn import fingerprint
from linuxhound.synthetic import before_report
from test_gnn import graph


def fixture():
    reports={s:graph(s) for s in ('train','validation')}
    for s,r in reports.items():
        r['nodes'].append({'id':s+'/nonroot','type':'account','properties':{'uid':1234}})
        r['edges'].append({'id':s+'/otheredge','source':s+'/a','target':s+'/nonroot','type':'SudoAllows','properties':{'nopasswd':False}})
        r['edges'][0]['properties']={'nopasswd':True}
        r['analysis']['paths'].append({'id':s+'/negative','node_ids':[s+'/a',s+'/nonroot'],'steps':[{'edge_id':s+'/otheredge'}]})
    m={'reviewer':'test oracle','label_policy':'pipeline labels only','threat_model':'compromised account without password','outcomes':list(OUTCOMES),'graphs':[]}
    for s,r in reports.items():
        m['graphs'].append({'split':s,'report':s,'source_host_id':s,'snapshot_sha256':fingerprint(r),'reference_sha256':None,'labels':{s+'/path':3,s+'/negative':0}})
    return reports,m


class PathFeatureTests(unittest.TestCase):
    def test_unrelated_nodes_and_verdicts_do_not_change_path_inputs(self):
        r=graph('test');a=path_features(r)['paths'][0]
        r['analysis']['paths'][0].update(verified=True,conclusion='whatever',summary='SECRET')
        r['analysis']['findings']=[{'severity':'critical'}]
        r['nodes'].append({'id':'unrelated','type':'account','properties':{'uid':50}})
        r['edges'].append({'id':'noise','type':'MemberOf','source':'unrelated','target':'test/r'})
        self.assertEqual(a,path_features(r)['paths'][0]);self.assertNotIn('SECRET',str(a))
    def test_directed_edge_order_is_preserved(self):
        d=path_features(before_report());p=next(p for p in d['paths'] if len(p['edges'])==3)
        self.assertEqual(len(p['edge_x']),3)
        self.assertEqual(p['edges'][0][1],p['edges'][1][0])
    def test_blocked_prospective_routes_exist_without_grants(self):
        r=before_report();original=copy.deepcopy(r);d=path_features(r)
        candidates=[p for p in d['paths'] if p['id'].startswith('candidate:')]
        self.assertTrue(candidates);self.assertEqual(r,original)
        self.assertTrue(any(p['context'][CHECKS.index('file_control')*3+1]==1 for p in candidates))
    def test_missing_edge_fails(self):
        r=graph('test');r['edges']=[]
        with self.assertRaisesRegex(ValueError,'missing edge'):path_features(r)


@unittest.skipUnless(importlib.util.find_spec('torch'),'optional torch missing')
class PathModelTests(unittest.TestCase):
    def test_train_reload_and_evidence_unchanged(self):
        reports,m=fixture();model=train_paths(m,reports.__getitem__,epochs=2);r=reports['validation'];original=copy.deepcopy(r)
        out=rank_paths(r,model);self.assertEqual(r,original);self.assertEqual(out['analysis'],r['analysis'])
        self.assertEqual(len(out['gnn']['paths']),2);self.assertFalse(out['gnn']['calibrated'])
        self.assertTrue(all(p['suggested_effect'] in (OUTCOMES[0],OUTCOMES[3]) for p in out['gnn']['paths']))
        model['weights']['head.2.bias'][0]=float('nan')
        with self.assertRaisesRegex(ValueError,'invalid path model'):rank_paths(r,model)
    def test_no_test_or_same_source_training(self):
        r,m=fixture();m['graphs'][1]['source_host_id']='train'
        with self.assertRaisesRegex(ValueError,'share a source host'):train_paths(m,r.__getitem__,1)
        r,m=fixture();m['graphs'][1]['split']='test'
        with self.assertRaisesRegex(ValueError,'train or validation'):train_paths(m,r.__getitem__,1)
    def test_catalog_must_be_frozen(self):
        r,m=fixture();m['graphs'][0]['reference_sha256']='wrong'
        with self.assertRaisesRegex(ValueError,'frozen reference'):train_paths(m,r.__getitem__,1)
