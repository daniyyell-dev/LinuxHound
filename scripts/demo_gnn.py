from pathlib import Path
import json
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from linuxhound.gnn import fingerprint, train, rank, _torch
from linuxhound.synthetic import before_report, after_report
from linuxhound.html_export import export_html
from linuxhound.cli import _write_text


def main():
    reports, items = {}, []
    for split, report in [('train', before_report()), ('validation', after_report())]:
        report = json.loads(json.dumps(report).replace('lab-01', 'synthetic-gnn-'+split))
        reports[split] = report
        root = next(n for n in report['nodes'] if n['type']=='account' and n['properties'].get('uid')==0)
        host = next(n for n in report['nodes'] if n['type']=='host')
        file = next(n for n in report['nodes'] if n['name']=='/opt/lab/backup.py')
        items.append({'report':split, 'split':split, 'source_host_id':'synthetic-fixture-'+split, 'snapshot_sha256':fingerprint(report),
                      'labels':{root['id']:1, file['id']:1, host['id']:0}})
    manifest = {'reviewer':'Synthetic pipeline fixture',
                'label_policy':'Toy pipeline labels only; not operational security ground truth', 'graphs':items}
    torch = _torch(); previous = torch.get_num_threads(); torch.set_num_threads(1)
    try:
        model = train(manifest, reports.__getitem__, epochs=10)
        ranked = rank(reports['train'], model)
    finally:
        torch.set_num_threads(previous)
    assert ranked['analysis'] == reports['train']['analysis']
    target = Path(__file__).resolve().parents[1] / 'examples/synthetic/gnn-demo.html'
    _write_text(str(target), export_html(ranked))
    print('Synthetic GNN pipeline preview: '+str(target))
    print('Toy training labels demonstrate operation only. No production model written.')


if __name__=='__main__':
    main()
