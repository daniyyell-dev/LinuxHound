from __future__ import annotations

import argparse
import json
import os
import sys

from linuxhound.analyze import influencing_root_jobs, paths_from_account, privilege_paths, who_can, list_services, service_paths
from linuxhound.build import build_report
from linuxhound.collector import CollectionError, collect
from linuxhound.compare import compare_reports
from linuxhound.html_export import export_html
from linuxhound.opengraph import export_opengraph


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="linuxhound",
        description="Read-only Linux permissions graph. A clean report does not prove a host is secure.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    collect_parser = sub.add_parser("collect", help="collect a read-only snapshot")
    _collection_options(collect_parser, require_host=True)
    collect_parser.add_argument("--output", required=True)

    scan_parser = sub.add_parser("scan", help="collect, analyze and generate the offline UI in one run")
    _collection_options(scan_parser, require_host=False)
    scan_parser.add_argument("--output-dir", default="linuxhound-results", help="private run directories are created here")
    scan_parser.add_argument("--open", action="store_true", dest="open_browser", help="open the completed local HTML in your browser")
    scan_parser.add_argument("--before", help="compare with an earlier snapshot or report")

    demo_parser = sub.add_parser("demo", help="generate a fictional example and its offline UI")
    demo_parser.add_argument("--output-dir", default="linuxhound-results")
    demo_parser.add_argument("--open", action="store_true", dest="open_browser")
    demo_parser.add_argument("--gnn", action="store_true", help="include bundled synthetic demo-model scores")

    view_parser = sub.add_parser("view", help="generate the offline UI from an existing snapshot or report")
    view_parser.add_argument("report")
    view_parser.add_argument("--output", required=True)
    view_parser.add_argument("--before")
    view_parser.add_argument("--open", action="store_true", dest="open_browser")

    for ui_parser in (scan_parser, demo_parser, view_parser):
        ui_parser.add_argument("--serve", action="store_true", help="serve the completed UI until Ctrl+C")
        _server_options(ui_parser)
    serve_parser = sub.add_parser("serve", help="serve a saved HTML UI, loopback only by default")
    serve_parser.add_argument("html")
    serve_parser.add_argument("--no-open", action="store_false", dest="open_browser", help="do not launch a browser")
    _server_options(serve_parser)

    report_parser = sub.add_parser("report", help="build an evidence graph from a snapshot")
    report_parser.add_argument("snapshot")
    report_parser.add_argument("--output", required=True)

    paths_parser = sub.add_parser("paths", help="explain conditional privilege paths in a report")
    paths_parser.add_argument("report")
    paths_parser.add_argument("--account")
    paths_parser.add_argument("--root-jobs", action="store_true")
    paths_parser.add_argument("--service", help="show conditional influence paths to this service")

    services_parser = sub.add_parser("services", help="list collected service states and run-as identities")
    services_parser.add_argument("report")
    services_parser.add_argument("--running", action="store_true")

    who_parser = sub.add_parser("who", help="list accounts with an observed or conditional right")
    who_parser.add_argument("report")
    who_parser.add_argument("--resource", required=True)
    who_parser.add_argument("--right", required=True, choices=[
        "read", "write", "execute", "replace", "delete", "create", "list", "traverse",
    ])

    compare_parser = sub.add_parser("compare", help="compare two reports")
    compare_parser.add_argument("before")
    compare_parser.add_argument("after")
    compare_parser.add_argument("--output")

    html_parser = sub.add_parser("export-html", help="write a standalone offline viewer")
    html_parser.add_argument("report")
    html_parser.add_argument("--output", required=True)
    html_parser.add_argument("--before", help="embed a coverage-aware comparison with an earlier snapshot")

    graph_parser = sub.add_parser("export-opengraph", help="write a BloodHound OpenGraph payload")
    graph_parser.add_argument("report")
    graph_parser.add_argument("--output", required=True)

    feature_parser = sub.add_parser("gnn-features", help="export allowlisted graph features for optional GNN review")
    feature_parser.add_argument("report")
    feature_parser.add_argument("--output", required=True)
    train_parser = sub.add_parser("gnn-train", help="train experimental review ordering from explicit reviewer labels")
    train_parser.add_argument("manifest")
    train_parser.add_argument("--output", required=True)
    train_parser.add_argument("--epochs", type=int, default=100)
    rank_parser = sub.add_parser("gnn-rank", help="attach experimental review scores without changing evidence")
    rank_parser.add_argument("report")
    rank_parser.add_argument("--model", required=True)
    rank_parser.add_argument("--output", required=True)

    techniques_parser = sub.add_parser("techniques-match", help="match an offline GTFOBins catalog to observed privilege contexts")
    techniques_parser.add_argument("report")
    techniques_parser.add_argument("--catalog", required=True)
    techniques_parser.add_argument("--output", required=True)
    path_features_parser = sub.add_parser("gnn-path-features", help="export path-local features without findings or labels")
    path_features_parser.add_argument("report")
    path_features_parser.add_argument("--output", required=True)
    path_train_parser = sub.add_parser("gnn-path-train", help="train path-effect ordering from independent review labels")
    path_train_parser.add_argument("manifest")
    path_train_parser.add_argument("--output", required=True)
    path_train_parser.add_argument("--epochs", type=int, default=100)

    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            from linuxhound.serve import serve_viewer
            serve_viewer(args.html, args.listen, args.port, args.open_browser)
            return 0
        if args.command == "demo":
            from linuxhound.synthetic import snapshot as demo_snapshot
            snapshot = demo_snapshot(False, True, True)
            _finish_run(args, snapshot)
            return 0
        if args.command in ("collect", "scan"):
            if args.command == "scan" and sys.platform != "linux":
                raise ValueError("Live scan requires Linux. Use 'linuxhound demo --open' here, or 'view' for a Linux report.")
            if args.command == "scan" and not args.host_id:
                import socket
                args.host_id = socket.gethostname()

            snapshot = collect(
                args.roots, args.host_id, args.hostname, args.timeout, args.max_files,
                args.max_depth, args.exclude, args.designated_admin, args.probe_current_user,
                not args.no_runtime_systemd, args.docker, args.max_services, args.max_containers,
            )
            if args.command == "scan":
                _finish_run(args, snapshot)
            else:
                _write(args.output, snapshot)
                print(f"snapshot written: {args.output}")
            print("coverage: " + ", ".join(f"{key}={value}" for key, value in snapshot["coverage"].items()))
            print("No host configuration was changed. Missing coverage is not a clean result.")
            return 0
        if args.command == "report":
            report = build_report(_read(args.snapshot))
            _write(args.output, report)
            print(f"report written: {args.output}")
            print(f"paths: {len(report['analysis']['paths'])}")
            return 0
        if args.command in ("gnn-train", "gnn-path-train"):
            from pathlib import Path
            from linuxhound.gnn import train
            if args.command == "gnn-path-train":
                from linuxhound.path_gnn import train_paths as train
            parent = Path(args.manifest).resolve().parent
            model = train(_read(args.manifest), lambda path: _as_report(_read(str(parent / path))), args.epochs)
            from linuxhound.checkpoint import save_checkpoint
            save_checkpoint(args.output, model)
            print("Experimental GNN model written; validation loss is not proof of security accuracy.")
            return 0
        report = _as_report(_read(args.report)) if args.command != "compare" else None
        if args.command == "techniques-match":
            from linuxhound.techniques import match
            _write(args.output, match(report, _read(args.catalog)))
            print("Conditional technique matches written; no recipes executed or findings verified.")
            return 0
        if args.command == "gnn-path-features":
            from linuxhound.path_gnn import path_features
            _write(args.output, path_features(report))
            print("Path-local directed features written; names and findings are excluded from numeric inputs.")
            return 0
        if args.command == "gnn-features":
            from linuxhound.gnn import features
            _write(args.output, features(report))
            print("Allowlisted graph features written. IDs may contain sensitive host/path metadata.")
            return 0
        if args.command == "gnn-rank":
            from linuxhound.gnn import rank
            from linuxhound.checkpoint import load_checkpoint
            checkpoint = load_checkpoint(args.model)
            if checkpoint.get("schema") == "linuxhound-path-gnn-v1":
                from linuxhound.path_gnn import rank_paths as rank
            _write(args.output, rank(report, checkpoint))
            print("Experimental review scores attached. Evidence, paths and findings unchanged.")
            return 0
        if args.command == "paths":
            if args.service:
                found = service_paths(report, args.service)
                if args.account:
                    found = [path for path in found if path["account"] == args.account]
            elif args.root_jobs:
                found = influencing_root_jobs(report)
            elif args.account:
                found = paths_from_account(report, args.account)
            else:
                found = privilege_paths(report)
            if args.account and args.root_jobs:
                found = [path for path in found if path.get("account") == args.account]
            _print_paths(found)
            return 0
        if args.command == "services":
            for node in list_services(report, args.running):
                props = node["properties"]
                print(f"{node['name']}\t{props.get('active_state', 'unknown')}/{props.get('sub_state', 'unknown')}\tuser={props.get('user', 'unknown')}\tpid={props.get('main_pid') or 'unknown'}")
            return 0
        if args.command == "who":
            for item in who_can(report, args.resource, args.right):
                print(f"{item['account']}\t{item['classification']}\t{item['authority']}\tverified={item['verified']}")
                print(item["explanation"])
            return 0
        if args.command == "compare":
            result = compare_reports(_as_report(_read(args.before)), _as_report(_read(args.after)))
            if args.output:
                _write(args.output, result)
            print(json.dumps(result["summary"], indent=2))
            print(result["statement"])
            for item in result["paths"]["incomplete_not_a_fix"]:
                print("incomplete, not a fix: " + item["summary"])
            for item in result["paths"]["removed_under_complete_coverage"]:
                print("removed under complete coverage: " + item["summary"])
            return 0
        if args.command in ("export-html", "view"):
            comparison = compare_reports(_as_report(_read(args.before)), report) if args.before else None
            _write_text(args.output, export_html(report, comparison=comparison))
            print(f"offline viewer written: {args.output}")
            _display_viewer(args, args.output)
            return 0
        if args.command == "export-opengraph":
            exported = export_opengraph(report)
            _write(args.output, exported["payload"])
            notes = args.output + ".notes.json"
            _write(notes, {"definition": exported["definition"], "fidelity": exported["fidelity"]})
            print(f"OpenGraph payload written: {args.output}")
            print(f"fidelity notes written: {notes}")
            return 0
    except (OSError, ValueError, KeyError, CollectionError, json.JSONDecodeError) as exc:
        print(f"linuxhound: {exc}", file=sys.stderr)
        return 1
    return 2


def _collection_options(parser, require_host):
    parser.add_argument("--root", action="append", required=True, dest="roots", help="directory to inspect; repeat to add scope")
    parser.add_argument("--host-id", required=require_host, help="stable source identity; scan defaults to hostname")
    parser.add_argument("--hostname")
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--max-files", type=int, default=5000)
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--designated-admin", action="append", default=[])
    parser.add_argument("--probe-current-user", action="store_true")
    parser.add_argument("--no-runtime-systemd", action="store_true", help="skip loaded service discovery")
    parser.add_argument("--docker", action="store_true", help="opt in to local Docker socket metadata; never environments")
    parser.add_argument("--max-services", type=int, default=200)
    parser.add_argument("--max-containers", type=int, default=100)


def _finish_run(args, snapshot):
    import tempfile
    from datetime import datetime, timezone
    from pathlib import Path
    report = build_report(snapshot)
    if getattr(args, "gnn", False):
        from pathlib import Path
        from linuxhound.checkpoint import load_checkpoint
        from linuxhound.path_gnn import rank_paths
        report = rank_paths(report, load_checkpoint(Path(__file__).with_name("models") / "demo-path.safetensors"))
        report["gnn"]["status"] = "synthetic_demo_only"
        report["gnn"]["notice"] = "Synthetic demo model only. Scores do not establish exploitability or safety."
    comparison = compare_reports(_as_report(_read(args.before)), report) if getattr(args, "before", None) else None
    html = export_html(report, comparison=comparison)
    parent = Path(args.output_dir)
    if parent.is_symlink():
        raise ValueError("refusing a symlink output directory")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=parent))
    _write(str(run / "snapshot.json"), snapshot)
    _write(str(run / "report.json"), report)
    if comparison is not None:
        _write(str(run / "comparison.json"), comparison)
    _write_text(str(run / "index.html"), html)
    print(f"Results: {run.resolve()}")
    print(f"Offline UI: {(run / 'index.html').resolve()}")
    print(f"Graph: {len(report['nodes'])} nodes, {len(report['edges'])} relationships")
    print("The UI contains this run's results. No server or upload is required.")
    _display_viewer(args, str(run / "index.html"))


def _server_options(parser):
    parser.add_argument("--listen", default="127.0.0.1", help="IPv4 address; default is loopback only")
    parser.add_argument("--port", type=int, default=8765, help="UI port (default 8765; 0 chooses a free port)")


def _display_viewer(args, path):
    if getattr(args, "serve", False):
        from linuxhound.serve import serve_viewer
        serve_viewer(path, args.listen, args.port, args.open_browser)
    elif getattr(args, "open_browser", False):
        _open_viewer(path)


def _open_viewer(path):
    import webbrowser
    from pathlib import Path
    try:
        opened = webbrowser.open(Path(path).resolve().as_uri())
    except (OSError, webbrowser.Error):
        opened = False
    if not opened:
        print("Browser unavailable. Copy index.html to your desktop and open it locally.")


def _as_report(document: dict) -> dict:
    if document.get("kind") == "linuxhound-report":
        return document
    if document.get("kind") == "linuxhound-snapshot":
        return build_report(document)
    raise ValueError("expected a LinuxHound snapshot or report")


def _read(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _write(path: str, document: dict) -> None:
    _write_text(path, json.dumps(document, indent=2) + "\n")


def _write_text(path: str, text: str) -> None:
    import tempfile
    from pathlib import Path
    target = Path(path)
    if target.is_symlink():
        raise ValueError("refusing to overwrite a symlink output")
    descriptor, temporary = tempfile.mkstemp(prefix=".linuxhound-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _print_paths(found: list[dict]) -> None:
    if not found:
        print("No matching path in the collected evidence. This does not prove the host is secure.")
        return
    for path in found:
        print(f"{path['conclusion']}\t{path.get('account')}\t{path['pattern']}\tverified={path['verified']}")
        print(path["summary"])
        for prerequisite in path.get("prerequisites") or []:
            print("prerequisite: " + prerequisite)


if __name__ == "__main__":
    raise SystemExit(main())
