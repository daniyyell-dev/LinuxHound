import copy, unittest
from linuxhound.techniques import normalize_catalog,match
from linuxhound.gnn import fingerprint


def fixture():
    files=[{'path':'/','type':'dir','uid':0,'gid':0,'mode':0o755}, {'path':'/bin','type':'dir','uid':0,'gid':0,'mode':0o755},
        {'path':'/bin/tool','type':'file','uid':0,'gid':0,'mode':0o4755,'capabilities':['cap_setuid']}]
    r={'host':{'id':'test'},'nodes':[{'id':'a','type':'account','properties':{'uid':1000,'gids':[1000]}},{'id':'root','type':'account','properties':{'uid':0,'gids':[0]}},
        {'id':'bin','type':'binary','properties':files[-1]}], 'edges':[{'id':'sudo','type':'SudoAllows','source':'a','target':'root','properties':{'commands':['/bin/tool'],'nopasswd':True,'host_restricted':False}}],
        'observations':{'files':files,'mounts':[{'path':'/','flags':['rw']}]},'analysis':{'paths':[]}}
    api={'executables':{'tool':{'functions':{'shell':[{'code':'DO-NOT-EXPORT','contexts':{'sudo':None,'suid':None,'capabilities':{'list':['CAP_SETUID']}}}]}}}}
    c=normalize_catalog(api,'rawhash','date');return r,c


class TechniquesTests(unittest.TestCase):
    def test_no_payload_or_verdict_mutation(self):
        r,c=fixture();original=copy.deepcopy(r);out=match(r,c)
        self.assertEqual(r,original);self.assertNotIn('DO-NOT-EXPORT',str(c));self.assertEqual(out['analysis'],r['analysis'])
        self.assertEqual(fingerprint(out),fingerprint(r));self.assertEqual(len(out['techniques']['matches']),3)
        self.assertTrue(all(not m['verified'] and m['status']=='conditional' for m in out['techniques']['matches']))
    def test_password_and_restricted_arguments(self):
        r,c=fixture();r['edges'][0]['properties'].update(nopasswd=False,commands=['/bin/tool --fixed'])
        m=next(m for m in match(r,c)['techniques']['matches'] if m['context']=='sudo')
        self.assertEqual(m['status'],'blocked');checks={p['name']:p['state'] for p in m['prerequisites']}
        self.assertEqual(checks['sudo_invocation_arguments'],'unknown')
    def test_missing_mount_and_nosuid(self):
        r,c=fixture();r['observations']['mounts']=[]
        m=next(m for m in match(r,c)['techniques']['matches'] if m['context']=='suid')
        self.assertEqual(next(p['state'] for p in m['prerequisites'] if p['name']=='setuid_mount_policy'),'unknown')
        r['observations']['mounts']=[{'path':'/','flags':['nosuid','noexec']}]
        self.assertTrue(all(m['status']=='blocked' for m in match(r,c)['techniques']['matches']))
    def test_nonroot_owner_and_missing_capability(self):
        r,c=fixture();r['observations']['files'][-1].update(uid=1000,capabilities=['cap_net_bind_service'])
        ms=match(r,c)['techniques']['matches']
        self.assertTrue(all(m['status']=='blocked' for m in ms if m['context']!='sudo'))
    def test_absent_binary_and_denial_are_not_grants(self):
        r,c=fixture();r['edges'][0]['properties']['commands']=['/bin/tool','!/bin/tool --deny']
        m=next(m for m in match(r,c)['techniques']['matches'] if m['context']=='sudo')
        self.assertEqual(next(p['state'] for p in m['prerequisites'] if p['name']=='sudo_invocation_arguments'),'unknown')
        r['observations']['files']=r['observations']['files'][:-1]
        m=match(r,c)['techniques']['matches'][0]
        self.assertEqual(next(p['state'] for p in m['prerequisites'] if p['name']=='privileged_execution'),'unknown')

    def test_reference_write_chain_keeps_hypotheses_separate(self):
        from linuxhound.path_candidates import technique_chains
        r,c=fixture();e=copy.deepcopy(c['entries'][0]);e.update(id='tool/file-write/sudo/0',function='file-write');c['entries'].append(e)
        r['nodes'] += [{'id':'jobfile','type':'file','properties':{'path':'/task.py'}},{'id':'job','type':'service','properties':{'user':'root'}}]
        r['edges'] += [{'id':'influence','source':'jobfile','target':'job','type':'MayInfluence'}, {'id':'runs','source':'job','target':'root','type':'RunsAs'}]
        original=copy.deepcopy(r);out=match(r,c);chains=technique_chains(out)
        self.assertEqual(len(chains),1);self.assertEqual(r,original);self.assertEqual(out['edges'],r['edges'])
        self.assertEqual(chains[0]['checks'][-1]['state'],'unknown')
        self.assertEqual(len(chains[0]['hypothesis_edges']),2);self.assertFalse(chains[0]['verified'])
