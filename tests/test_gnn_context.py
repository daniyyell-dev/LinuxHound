import copy,unittest
from linuxhound.gnn import features,FEATURES,EDGE_FEATURES,SCHEMA,rank
from linuxhound.gnn_context import context,NODE_CONTEXT


def fixture():
    nodes=[{'id':'a','type':'account','properties':{'uid':1000,'gids':[1000]}},{'id':'root','type':'account','properties':{'uid':0,'gids':[0]}},{'id':'file','type':'file','properties':{'path':'/lab/job','uid':0,'gid':0,'mode':0o755}},{'id':'job','type':'service','properties':{}}]
    files=[{'path':'/','type':'dir','uid':0,'gid':0,'mode':0o755},{'path':'/lab','type':'dir','uid':0,'gid':0,'mode':0o1777},{'path':'/lab/job','type':'file','uid':0,'gid':0,'mode':0o755,'acl':{'mask':4,'users':{'1000':7},'groups':{}}}]
    return {'host':{'id':'fixture'},'nodes':nodes,'edges':[{'id':'r','source':'job','target':'root','type':'RunsAs'},{'id':'i','source':'file','target':'job','type':'MayInfluence'},{'id':'read','source':'a','target':'file','type':'CanRead'},{'id':'s','source':'a','target':'root','type':'SudoAllows','properties':{'nopasswd':False}}],'observations':{'files':files,'mounts':[{'path':'/','flags':['rw']}]},'analysis':{'paths':[]}}

class ContextTests(unittest.TestCase):
    def test_masked_acl_and_authentication_are_explicit(self):
        r=fixture();d=features(r);f=d['node_ids'].index('file');e=d['edge_ids'].index('read');s=d['edge_ids'].index('s')
        self.assertEqual(d['x'][f][FEATURES.index('acl_mask_restricts_named_write')],1)
        self.assertEqual(d['edge_x'][e][EDGE_FEATURES.index('effective_peer_write')],0)
        self.assertEqual(d['edge_x_known'][e][EDGE_FEATURES.index('effective_peer_write')],1)
        self.assertEqual(d['edge_x'][s][EDGE_FEATURES.index('sudo_password_required')],1)
        self.assertEqual(d['x'][f][FEATURES.index('parent_sticky')],1)
    def test_motifs_depend_on_observed_rights_and_run_as(self):
        r=fixture();a=features(r);i=a['node_ids'].index('a');name=FEATURES.index('observed_write_root_consumer_count');self.assertEqual(a['x'][i][name],0)
        r['edges'].append({'id':'w','source':'a','target':'file','type':'CanWrite'});self.assertGreater(features(r)['x'][i][name],0)
        r['nodes'][1]['properties']['uid']=2000;self.assertEqual(features(r)['x'][i][name],0)
    def test_unrelated_accounts_do_not_change_context(self):
        r=fixture();before=features(r);r['nodes'].append({'id':'other','type':'account','properties':{'uid':4321}});after=features(r)
        for name in NODE_CONTEXT:
            self.assertEqual(before['x'][0][FEATURES.index(name)],after['x'][0][FEATURES.index(name)])
    def test_labels_findings_and_verification_are_excluded(self):
        r=fixture();a=features(r);r['analysis']={'paths':[{'verified':True,'conclusion':'verified_vulnerability','label':1}],'findings':[{'priority':'CRITICAL'}]};r['review_labels']={'a':1};r['edges'][0]['verified']=True;b=features(r)
        self.assertEqual(a['x'],b['x']);self.assertEqual(a['edge_x'],b['edge_x'])
    def test_missing_context_is_not_known_zero(self):
        r=fixture();r['observations']['files']=[];d=features(r);e=d['edge_ids'].index('read')
        self.assertEqual(d['edge_x_known'][e][EDGE_FEATURES.index('effective_peer_write')],0)
        self.assertEqual(d['x_known'][d['node_ids'].index('file')][FEATURES.index('acl_mask_write')],0)
    def test_symlink_mode_is_not_a_target_dac_grant(self):
        r=fixture();r['observations']['files'][-1]['type']='symlink';d=features(r);e=d['edge_ids'].index('read')
        self.assertEqual(d['edge_x_known'][e][EDGE_FEATURES.index('effective_peer_write')],0)

    def test_schema_bump_rejects_old_checkpoint(self):
        self.assertEqual(SCHEMA,'linuxhound-gnn-v3')
        with self.assertRaisesRegex(ValueError,'schema'):rank(fixture(),{'schema':'linuxhound-gnn-v2'})
    def test_blocked_traversal_and_unknown_auth(self):
        r=fixture();r['observations']['files'][1]['mode']=0o700;del r['edges'][-1]['properties']['nopasswd'];d=features(r);e=d['edge_ids'].index('read');s=d['edge_ids'].index('s')
        self.assertEqual(d['edge_x'][e][EDGE_FEATURES.index('ancestor_traversal_denied')],1)
        self.assertEqual(d['edge_x'][s][EDGE_FEATURES.index('sudo_auth_unknown')],1)
        self.assertEqual(d['edge_x_known'][s][EDGE_FEATURES.index('sudo_password_required')],0)

if __name__=='__main__':unittest.main()
