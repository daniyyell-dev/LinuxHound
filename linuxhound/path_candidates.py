import hashlib,json
from linuxhound.access import can_write_content,can_replace


def candidates(report):
    nodes={n['id']:n for n in report.get('nodes',[])}
    files={f['path']:f for f in report.get('observations',{}).get('files',[])}
    mounts=report.get('observations',{}).get('mounts')
    edges=report.get('edges',[])
    runs={e['source']:e for e in edges if e['type']=='RunsAs'}
    actors=[n for n in nodes.values() if n['type']=='account' and n.get('properties',{}).get('uid') not in (None,0)]
    out=[]
    for influence in edges:
        if influence['type'] not in ('MayInfluence','Configures') or influence['target'] not in runs:
            continue
        resource=nodes[influence['source']];path=resource.get('properties',{}).get('path')
        if not path or path not in files or resource['type'] not in ('file','binary'):
            continue
        run=runs[influence['target']];target=nodes[run['target']];uid=target.get('properties',{}).get('uid')
        for actor in actors:
            p=actor['properties'];decisions=[can_write_content(files,mounts,p['uid'],p.get('gids',[]),path),can_replace(files,mounts,p['uid'],p.get('gids',[]),path)]
            states=['met' if d.state=='granted' and not d.assumptions else 'blocked' if d.state=='denied' else 'unknown' for d in decisions]
            control='met' if 'met' in states else 'blocked' if all(s=='blocked' for s in states) else 'unknown'
            key=[actor['id'],resource['id'],influence['id'],run['id']]
            identifier='candidate:'+hashlib.sha256(json.dumps(key).encode()).hexdigest()[:24]
            edge={'id':identifier+'/control','source':actor['id'],'target':resource['id'],'type':'other','classification':'hypothesis','properties':{},'evidence_ids':[]}
            out.append({'id':identifier,'node_ids':[actor['id'],resource['id'],influence['target'],run['target']],
                'edge_ids':[influence['id'],run['id']], 'hypothesis_edges':[edge], 'function':'command','context':None,
                'checks':[{'name':'file_control','state':control},{'name':'file_write','state':states[0]},{'name':'file_replace','state':states[1]},
                          {'name':'job_root_identity','state':'unknown' if uid is None else 'met' if uid==0 else 'blocked'},
                          {'name':'job_executes_controlled_code','state':'unknown'}],
                'account_id':actor['id'],'resource_id':resource['id'],'consumer_id':influence['target'],
                'verified':False,'status':'blocked' if control=='blocked' or uid not in (None,0) else 'conditional'})
            if len(out)>10000:raise ValueError('prospective routes exceed 10,000 candidates; nothing was truncated')
    return out


def technique_chains(report):
    nodes={n['id']:n for n in report.get('nodes',[])}
    edges=report.get('edges',[]);runs={e['source']:e for e in edges if e['type']=='RunsAs'}
    consumers=[e for e in edges if e['type'] in ('MayInfluence','Configures') and e['target'] in runs and nodes[e['source']]['type'] in ('file','binary')]
    out=[]
    for technique in report.get('techniques',{}).get('matches',[]):
        if technique['function']!='file-write' or not technique.get('resource_id'):
            continue
        for influence in consumers:
            run=runs[influence['target']];target=nodes[run['target']];uid=target.get('properties',{}).get('uid')
            if uid!=0:continue
            key=[technique['id'],influence['id'],run['id']]
            identifier='chain:'+hashlib.sha256(json.dumps(key).encode()).hexdigest()[:24]
            checks=technique['prerequisites']+[{'name':'job_root_identity','state':'met'},{'name':'job_executes_controlled_code','state':'unknown'},
                {'name':'technique_controls_job_file','state':'unknown'}]
            hypotheses=[{'id':identifier+'/invoke','source':technique['account_id'],'target':technique['resource_id'],'type':'other','classification':'hypothesis','properties':{}},
                        {'id':identifier+'/write','source':technique['resource_id'],'target':influence['source'],'type':'other','classification':'hypothesis','properties':{}}]
            out.append({'id':identifier,'node_ids':list(dict.fromkeys([technique['account_id'],technique['resource_id'],influence['source'],influence['target'],run['target']])),
                'edge_ids':[influence['id'],run['id']],'hypothesis_edges':hypotheses,'function':'file-write','context':technique['context'],
                'checks':checks,'account_id':technique['account_id'],'resource_id':influence['source'],'consumer_id':influence['target'],
                'technique_id':technique['id'],'verified':False,'status':technique['status']})
            if len(out)>10000:raise ValueError('technique chains exceed 10,000 candidates; nothing was truncated')
    return out
