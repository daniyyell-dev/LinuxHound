from __future__ import annotations
import copy, hashlib, json, math
from linuxhound.gnn import features, fingerprint, _torch, _samples, NODE_TYPES, RELATIONS

SCHEMA = 'linuxhound-path-gnn-v1'
OUTCOMES = ('blocked_or_no_privileged_effect', 'privileged_read', 'privileged_write', 'limited_root_action', 'root_code_execution')
NODE_FEATURES = NODE_TYPES + ('other_type','root_identity','owner_root','mode_owner_execute','mode_group_execute','mode_other_execute','world_writable','setuid','setgid','sticky','file_cap_setuid','file_cap_sys_admin','file_cap_dac_override','file_cap_dac_read_search','run_as_root','active_service','runtime_observed','no_new_privileges','protect_system','protect_home','privileged_container','readonly_rootfs','container_user_root','host_pid_namespace','host_user_namespace','no_new_privileges_container','docker_socket_bind','host_root_bind','mount_readonly','mount_nosuid','mount_noexec','acl_mask_write','acl_mask_restricts_named_write','parent_sticky')
EDGE_FEATURES = ('sudo_nopasswd','sudo_password_required','sudo_auth_unknown','target_root_identity','source_owns_target','source_in_target_group','bind_writable','effective_peer_read','effective_peer_write','effective_peer_execute','ancestor_traversal_granted','ancestor_traversal_denied','permission_context_conditional')
CHECKS = ('file_control','file_write','file_replace','job_root_identity','job_executes_controlled_code','technique_controls_job_file','root_run_as','authentication_without_credentials','sudo_invocation_arguments','sudo_host_scope','privileged_execution','account_can_execute','setuid_mount_policy','setuid_root_owner','required_capabilities','capability_effective_flags','capability_mount_policy','binary_identity_and_version','technique_behavior')
FUNCTIONS = ('shell','command','file-read','file-write','library-load','privilege-escalation')
CONTEXTS = ('sudo','suid','capabilities')


def path_features(report):
    nodes = {n['id']:n for n in report.get('nodes',[])}
    edges = {e['id']:e for e in report.get('edges',[])}
    if len(nodes)!=len(report.get('nodes',[])) or len(edges)!=len(report.get('edges',[])):
        raise ValueError('duplicate graph identity')
    if any(e['source'] not in nodes or e['target'] not in nodes for e in edges.values()):
        raise ValueError('edge endpoint is missing')
    paths = report.get('analysis',{}).get('paths',[]) + report.get('analysis',{}).get('service_paths',[])
    candidates = {}
    for p in paths:
        ids = [s['edge_id'] for s in p.get('steps',[])]
        if any(i not in edges for i in ids):
            raise ValueError('path references a missing edge')
        if not ids:
            continue
        candidates[p['id']] = {'id':p['id'],'node_ids':p.get('node_ids',[]),'edge_ids':ids,'checks':[], 'function':None,'context':None}
    for t in report.get('techniques',{}).get('matches',[]):
        nids = list(dict.fromkeys(i for i in (t['account_id'],t.get('resource_id')) if i))
        for eid in t.get('edge_ids',[]):
            if eid not in edges:raise ValueError('technique references a missing edge')
            nids.extend([edges[eid]['source'],edges[eid]['target']])
        candidates[t['id']] = {'id':t['id'],'node_ids':list(dict.fromkeys(nids)), 'edge_ids':t.get('edge_ids',[]),
            'checks':t.get('prerequisites',[]),'function':t['function'],'context':t['context']}
    from linuxhound.path_candidates import candidates as prospective, technique_chains
    for p in prospective(report)+technique_chains(report):
        candidates[p['id']]=p
    if len(candidates)>10000:
        raise ValueError('path GNN exceeds 10,000 candidates; nothing was truncated')
    data=[]
    for p in candidates.values():
        nids = list(dict.fromkeys(p['node_ids']))
        for eid in p['edge_ids']:
            nids.extend([edges[eid]['source'],edges[eid]['target']])
        nids=list(dict.fromkeys(nids))
        if any(i not in nodes for i in nids):raise ValueError('candidate references a missing node')
        if len(nids)>128 or len(p['edge_ids'])>256:
            raise ValueError('candidate exceeds 128 nodes / 256 edges; nothing was truncated')
        local={'nodes':[nodes[i] for i in nids], 'edges':p.get('hypothesis_edges',[])+[edges[i] for i in p['edge_ids']],
               'collection':report.get('collection',{}),'observations':report.get('observations',{})}
        f=features(local)
        ni=[f['feature_names'].index(n) for n in NODE_FEATURES]
        ei=[f['edge_feature_names'].index(n) for n in EDGE_FEATURES]
        checks={c['name']:c['state'] for c in p['checks'] if c.get('name') in CHECKS}
        extra=[float(checks.get(c,'unknown')==state) for c in CHECKS for state in ('met','blocked','unknown')]
        extra += [float(p['function']==v) for v in FUNCTIONS] + [float(p['context']==v) for v in CONTEXTS]
        data.append({'id':p['id'], 'node_ids':nids, 'account_id':p.get('account_id'), 'resource_id':p.get('resource_id'), 'consumer_id':p.get('consumer_id'), 'x':[[row[i] for i in ni]+[mask[i] for i in ni] for row,mask in zip(f['x'],f['x_known'])],
            'edges':f['edges'], 'edge_x':[[row[i] for i in ei]+[mask[i] for i in ei] for row,mask in zip(f['edge_x'],f['edge_x_known'])], 'context':extra})
    return {'schema':SCHEMA,'snapshot_sha256':fingerprint(report),'node_ids':list(nodes),'path_ids':[p['id'] for p in data],'paths':data,
        'reference_sha256':report.get('techniques',{}).get('catalog_sha256')}


def _network():
    torch=_torch();hidden=24
    class PathNetwork(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.input=torch.nn.Linear(len(NODE_FEATURES)*2,hidden)
            self.edge_input=torch.nn.Linear(len(EDGE_FEATURES)*2,hidden,bias=False)
            self.relation=torch.nn.Embedding(len(RELATIONS),hidden)
            self.message=torch.nn.Linear(hidden*3,hidden)
            self.update=torch.nn.GRUCell(hidden,hidden)
            self.sequence=torch.nn.GRU(hidden,hidden,batch_first=True)
            self.head=torch.nn.Sequential(torch.nn.Linear(hidden*4+len(CHECKS)*3+len(FUNCTIONS)+len(CONTEXTS),hidden),torch.nn.ReLU(),torch.nn.Linear(hidden,len(OUTCOMES)))
        def forward(self,path):
            h=torch.relu(self.input(torch.tensor(path['x'],dtype=torch.float32)))
            links=torch.tensor(path['edges'],dtype=torch.long).reshape(-1,3)
            ex=torch.tensor(path['edge_x'],dtype=torch.float32).reshape(-1,len(EDGE_FEATURES)*2)
            messages=[]
            for _ in range(3):
                if len(links):
                    source,target,rel=links[:,0],links[:,1],links[:,2]
                    m=torch.relu(self.message(torch.cat([h[source],self.edge_input(ex),self.relation(rel)],dim=1)))
                    aggregate=torch.zeros_like(h);aggregate.index_add_(0,target,m)
                    counts=torch.zeros(len(h));counts.index_add_(0,target,torch.ones(len(target)))
                    h=self.update(aggregate/counts.clamp(min=1).unsqueeze(1),h)
                    messages=m
            if len(links):
                _,sequence=self.sequence(messages.unsqueeze(0));sequence=sequence[0,0]
            else:sequence=torch.zeros(hidden)
            vector=torch.cat([h[0],h[-1],h.mean(0),sequence,torch.tensor(path['context'],dtype=torch.float32)])
            return self.head(vector)
    return PathNetwork()


def train_paths(manifest,load_report,epochs=100,seed=7):
    if not 1<=epochs<=2000:raise ValueError('epochs must be between 1 and 2000')
    if any(not isinstance(manifest.get(k),str) or not manifest[k].strip() for k in ('reviewer','label_policy','threat_model')):
        raise ValueError('reviewer, label_policy and threat_model provenance are required')
    if manifest.get('outcomes') != list(OUTCOMES):raise ValueError('explicit ordered effect-class vocabulary is required')
    samples=_samples(manifest,load_report,path_features,'path_ids',tuple(range(len(OUTCOMES))))
    for item in manifest['graphs']:
        observed=path_features(load_report(item['report']))['reference_sha256']
        if item.get('reference_sha256')!=observed:
            raise ValueError('labels require the exact frozen reference catalog SHA256')
    training_classes=sorted({int(v) for _,labels in samples['train'] for v in labels.values()})
    if 0 not in training_classes:
        raise ValueError('path training requires blocked/no-effect negative examples')
    catalog_hashes={d['reference_sha256'] for split in samples.values() for d,_ in split}
    if len(catalog_hashes)>1:raise ValueError('training references must use the same frozen technique catalog')
    torch=_torch();torch.manual_seed(seed);model=_network();optimizer=torch.optim.Adam(model.parameters(),lr=.003)
    loss_fn=torch.nn.CrossEntropyLoss()
    def loss(split):
        values=[]
        for data,labels in samples[split]:
            chosen=[p for p in data['paths'] if p['id'] in labels]
            logits=torch.stack([model(p) for p in chosen])
            targets=torch.tensor([int(labels[p['id']]) for p in chosen],dtype=torch.long)
            values.append(loss_fn(logits,targets))
        return torch.stack(values).mean()
    best=float('inf');weights=None
    for _ in range(epochs):
        model.train();optimizer.zero_grad();objective=loss('train');objective.backward();optimizer.step();model.eval()
        with torch.no_grad():validation=float(loss('validation'))
        if not math.isfinite(validation):raise ValueError('non-finite validation loss')
        if validation<best:best=validation;weights=copy.deepcopy(model.state_dict())
    return {'schema':SCHEMA,'architecture':'path-local-directed-message-passing-and-ordered-edges',
        'node_features':list(NODE_FEATURES),'edge_features':list(EDGE_FEATURES),'relations':list(RELATIONS),'checks':list(CHECKS),'outcomes':list(OUTCOMES),
        'weights':{k:v.tolist() for k,v in weights.items()},'metadata':{'reviewer':manifest['reviewer'],'label_policy':manifest['label_policy'],'threat_model':manifest['threat_model'],
        'seed':seed,'epochs':epochs,'validation_loss':best,'calibrated':False,'status':'experimental_unvalidated',
        'evaluation_scope':'path-effect validation on disjoint sources; untouched testing still required',
        'reference_sha256':next(iter(catalog_hashes)),
        'training_classes':training_classes,
        'source_hosts':{split:sorted({i['source_host_id'] for i in manifest['graphs'] if i['split']==split}) for split in samples},
        'training_snapshots':[d['snapshot_sha256'] for d,_ in samples['train']], 'validation_snapshots':[d['snapshot_sha256'] for d,_ in samples['validation']]}}


def rank_paths(report,checkpoint):
    if checkpoint.get('schema')!=SCHEMA or checkpoint.get('architecture')!='path-local-directed-message-passing-and-ordered-edges' or any(checkpoint.get(k)!=list(v) for k,v in [('node_features',NODE_FEATURES),('edge_features',EDGE_FEATURES),('relations',RELATIONS),('checks',CHECKS),('outcomes',OUTCOMES)]):
        raise ValueError('path model schema or vocabulary mismatch')
    if checkpoint.get('metadata',{}).get('evaluation_status')=='invalid_same_source_host':raise ValueError('quarantined model')
    data=path_features(report)
    if data['reference_sha256']!=checkpoint.get('metadata',{}).get('reference_sha256'):
        raise ValueError('path model requires the exact frozen technique catalog used for training')
    torch=_torch();model=_network();expected=model.state_dict();weights=checkpoint.get('weights',{})
    if set(weights)!=set(expected):raise ValueError('invalid path model weights')
    def validate(value,shape):
        if shape:
            if not isinstance(value,list) or len(value)!=shape[0]:raise ValueError('invalid path model dimensions')
            for item in value:validate(item,shape[1:])
        elif type(value) not in (int,float) or not math.isfinite(value):raise ValueError('invalid path model values')
    tensors={}
    for k,v in weights.items():
        validate(v,list(expected[k].shape));tensors[k]=torch.tensor(v,dtype=torch.float32)
        if not torch.isfinite(tensors[k]).all():raise ValueError('invalid path model values')
    model.load_state_dict(tensors);model.eval();rows=[]
    existing={p['id'] for p in report.get('analysis',{}).get('paths',[])+report.get('analysis',{}).get('service_paths',[])}
    classes=checkpoint.get('metadata',{}).get('training_classes',[])
    if not isinstance(classes,list) or 0 not in classes or len(classes)<2 or any(type(i) is not int or i not in range(len(OUTCOMES)) for i in classes):
        raise ValueError('invalid supported effect classes')
    with torch.no_grad():
        for path in data['paths']:
            logits=model(path).tolist()
            if any(not math.isfinite(v) for v in logits):raise ValueError('non-finite path scores')
            supported=[i for i in classes if i>0]
            score=max((logits[i] for i in supported),default=logits[0])-logits[0]
            predicted=max(classes,key=lambda i:logits[i])
            rows.append({'path_id':path['id'],'review_score':score,'effect_logits':dict(zip(OUTCOMES,logits)), 'suggested_effect':OUTCOMES[predicted], 'verified':False})
    from linuxhound.path_candidates import candidates,technique_chains
    result=copy.deepcopy(report)
    result['gnn']={'schema':SCHEMA,'snapshot_sha256':data['snapshot_sha256'],'model_sha256':hashlib.sha256(json.dumps(checkpoint,sort_keys=True,allow_nan=False).encode()).hexdigest(),
        'status':'synthetic_demo_only' if checkpoint['metadata'].get('status')=='synthetic_demo_only' else 'experimental_unvalidated','calibrated':False,'evaluation_scope':checkpoint['metadata']['evaluation_scope'], 'label_policy':checkpoint['metadata']['label_policy'],
        'candidate_routes':candidates(report)+technique_chains(report),
        'notice':'Synthetic demo model only. Scores do not establish exploitability or safety.' if checkpoint['metadata'].get('status')=='synthetic_demo_only' else 'Path-local experimental review ordering. Effects are model suggestions, not verified vulnerabilities.',
        'paths':sorted([r for r in rows if r['path_id'] in existing],key=lambda r:(-r['review_score'],r['path_id'])),
        'candidates':sorted([r for r in rows if r['path_id'].startswith(('candidate:','chain:'))] ,key=lambda r:(-r['review_score'],r['path_id'])),
        'techniques':sorted([r for r in rows if r['path_id'].startswith('technique:')],key=lambda r:(-r['review_score'],r['path_id']))}
    return result
