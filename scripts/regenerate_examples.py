from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from linuxhound.cli import _write, _write_text
from linuxhound.compare import compare_reports
from linuxhound.html_export import export_html
from linuxhound.opengraph import export_opengraph
from linuxhound.synthetic import before_report, after_report, incomplete_after_report, snapshot


def main():
    root = Path(__file__).resolve().parents[1] / 'examples' / 'synthetic'
    root.mkdir(parents=True, exist_ok=True)
    before = before_report()
    for name, report in [('before', before), ('after', after_report()), ('after-incomplete', incomplete_after_report())]:
        _write(str(root / (name + '.json')), report)
        comparison = None if name == 'before' else compare_reports(before, report)
        _write_text(str(root / (name + '.html')), export_html(report, comparison))
    _write(str(root / 'before.snapshot.json'), snapshot(False, True, True))
    _write(str(root / 'comparison.json'), compare_reports(before, after_report()))
    exported = export_opengraph(before)
    _write(str(root / 'before.opengraph.json'), exported['payload'])
    notes = {'definition': exported['definition'], 'fidelity': exported['fidelity']}
    _write(str(root / 'before.opengraph.notes.json'), notes)
    _write(str(root / 'before.opengraph.json.notes.json'), notes)
    stress_nodes = [{'id': 'stress-'+str(i), 'name': 'Synthetic '+str(i), 'type': 'file', 'properties': {}} for i in range(350)]
    stress_edges = [{'id': 'edge-'+str(i), 'source': 'stress-'+str(i%349), 'target': 'stress-'+str((i+1)%349),
                     'type': 'CanRead', 'classification': 'observed_permission', 'authority': 'unknown',
                     'evidence_ids': [], 'properties': {}} for i in range(700)]
    stress_report = {'kind': 'linuxhound-report', 'host': {'id': 'stress', 'hostname': 'Synthetic graph completeness test'},
                     'collection': {'collected_at': 'synthetic', 'coverage': {}}, 'nodes': stress_nodes,
                     'edges': stress_edges, 'evidence': [], 'analysis': {'paths': [], 'service_paths': [], 'findings': []}}
    _write_text(str(root / 'graph-completeness.html'), export_html(stress_report))
    print('Regenerated synthetic reports, graph viewers, comparison and OpenGraph export.')


if __name__ == '__main__':
    main()
