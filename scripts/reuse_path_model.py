import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from linuxhound.cli import _write, _write_text, _as_report
from linuxhound.techniques import match
from linuxhound.path_gnn import rank_paths
from linuxhound.checkpoint import load_checkpoint
from linuxhound.html_export import export_html


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('report')
    parser.add_argument('--model', required=True)
    parser.add_argument('--catalog')
    parser.add_argument('--output', required=True)
    parser.add_argument('--html')
    args = parser.parse_args()
    report = _as_report(json.loads(Path(args.report).read_text()))
    if args.catalog:
        report = match(report, json.loads(Path(args.catalog).read_text()))
    ranked = rank_paths(report, load_checkpoint(args.model))
    _write(args.output, ranked)
    if args.html:
        _write_text(args.html, export_html(ranked))
    print('Saved model reused. No training or download performed.')


if __name__ == '__main__':
    main()
