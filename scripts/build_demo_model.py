import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from linuxhound.checkpoint import save_checkpoint
from linuxhound.gnn import fingerprint, _torch
from linuxhound.path_gnn import OUTCOMES, train_paths


def fixtures():
    reports = {}
    manifest = {
        'reviewer': 'Synthetic fixture specification',
        'label_policy': 'Toy sudo scenarios: fixed root id action=3; password-required or non-root action=0. Not measured host behavior.',
        'threat_model': 'Fictional account without an administrator password; demo only',
        'outcomes': list(OUTCOMES),
        'graphs': [],
    }
    for split in ('train', 'validation'):
        host = 'synthetic-demo-' + split
        report = {'kind': 'linuxhound-report', 'host': {'id': host},
                  'collection': {'coverage': {'users': 'complete', 'sudo': 'complete'}},
                  'nodes': [], 'edges': [], 'analysis': {'paths': [], 'findings': []}}
        labels = {}
        for i, (uid, nopasswd, effect) in enumerate(((0, True, 3), (0, False, 0), (2000, True, 0))):
            prefix = host + '/' + str(i)
            source, target, edge, route = [prefix + '/' + s for s in ('account', 'target', 'edge', 'path')]
            report['nodes'].extend([
                {'id': source, 'type': 'account', 'name': 'demo-user', 'properties': {'uid': 1000}},
                {'id': target, 'type': 'account', 'name': 'demo-target', 'properties': {'uid': uid}},
            ])
            report['edges'].append({'id': edge, 'source': source, 'target': target, 'type': 'SudoAllows',
                                    'properties': {'nopasswd': nopasswd, 'command': '/usr/bin/id'}})
            report['analysis']['paths'].append({'id': route, 'node_ids': [source, target],
                                               'verified': False, 'steps': [{'edge_id': edge}]})
            labels[route] = effect
        reports[split] = report
        manifest['graphs'].append({'report': split, 'split': split, 'source_host_id': host,
                                   'snapshot_sha256': fingerprint(report), 'reference_sha256': None,
                                   'labels': labels})
    return reports, manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    reports, manifest = fixtures()
    torch = _torch()
    torch.set_num_threads(1)
    checkpoint = train_paths(manifest, reports.__getitem__, epochs=30, seed=7)
    checkpoint['metadata'].update(
        status='synthetic_demo_only',
        evaluation_scope='Toy synthetic pipeline fixtures; no independent host evaluation or accuracy claim',
        training_data='Only fixtures defined in scripts/build_demo_model.py',
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    save_checkpoint(output, checkpoint)
    print('Synthetic demonstration model saved:', output)


if __name__ == '__main__':
    main()
