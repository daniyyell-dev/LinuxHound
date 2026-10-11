import copy
import json
import unittest
from unittest.mock import patch

from linuxhound import runtime
from linuxhound.access import can_read
from linuxhound.analyze import list_services, service_paths, attach_analysis
from linuxhound.build import build_report
from linuxhound.compare import compare_reports
from linuxhound.parsers import parse_sudoers, parse_unit
from linuxhound.synthetic import before_report, after_report, with_validation, snapshot


class RuntimeGraphTests(unittest.TestCase):
    def test_loaded_service_state_and_arguments_are_allowlisted(self):
        output = 'Id=demo.service\nLoadState=loaded\nActiveState=active\nSubState=running\nUser=worker\nMainPID=77\nFragmentPath=/etc/systemd/system/demo.service\nExecStart={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /opt/demo.py --token hidden-value ; }\n'
        errors = []
        with patch.object(runtime.shutil, 'which', return_value='/bin/systemctl'), patch.object(runtime, '_run', side_effect=['demo.service loaded active running Demo\n', output]) as run:
            rows, coverage = runtime.services(lambda: 60, lambda *args: errors.append(args))
        self.assertEqual(coverage, 'complete')
        self.assertEqual(rows[0]['active_state'], 'active')
        self.assertEqual(rows[0]['user'], 'worker')
        self.assertNotIn('hidden-value', json.dumps(rows))
        self.assertNotIn('Environment', run.call_args.args[0][-1])

    def test_denied_runtime_is_unknown_not_empty_clean(self):
        errors = []
        with patch.object(runtime.shutil, 'which', return_value='/bin/systemctl'), patch.object(runtime, '_run', side_effect=RuntimeError()):
            rows, coverage = runtime.services(lambda: 60, lambda *args: errors.append(args))
        self.assertEqual((rows, coverage), ([], 'unavailable'))
        self.assertTrue(errors)

    def test_docker_uses_local_socket_and_excludes_environments(self):
        identifier = 'a' * 64
        data = {'id': identifier, 'name': 'demo', 'user': '0', 'running': True, 'status': 'running', 'userns_mode': '', 'mounts': [{'Type': 'bind', 'Source': '/opt/demo', 'Destination': '/app', 'RW': True}]}
        with patch.object(runtime.shutil, 'which', return_value='/bin/docker'), patch.object(runtime, '_run', side_effect=[identifier, json.dumps(data)]) as run:
            rows, coverage = runtime.containers(lambda: 60, lambda *args: None)
        self.assertEqual(coverage, 'complete')
        self.assertEqual(rows[0]['identity_boundary'], 'unknown')
        for call in run.call_args_list:
            self.assertIn('unix:///var/run/docker.sock', call.args[0])
        self.assertNotIn('.Env', runtime.DOCKER_FORMAT)
        self.assertNotIn('.Config.Cmd', runtime.DOCKER_FORMAT)

    def test_sudo_and_unit_do_not_export_arbitrary_credentials(self):
        rules, _ = parse_sudoers('worker ALL=(root) /usr/bin/helper --credential "secret with spaces"', '/etc/sudoers')
        unit, _ = parse_unit('[Service]\nExecStart=/usr/bin/helper opaque-password --token="another secret"', 'demo.service', '/etc/demo.service')
        payload = json.dumps([rules, unit])
        for secret in ('secret with spaces', 'opaque-password', 'another secret'):
            self.assertNotIn(secret, payload)

    def test_service_paths_have_real_edges_and_graph_integrity(self):
        report = before_report()
        self.assertTrue(list_services(report, running_only=True))
        paths = service_paths(report, 'backup.service')
        self.assertTrue(paths)
        self.assertTrue(all(p['conclusion'] == 'conditional_attack_path' for p in paths))
        nodes = {n['id'] for n in report['nodes']}
        evidence = {e['id'] for e in report['evidence']}
        for edge in report['edges']:
            self.assertIn(edge['source'], nodes)
            self.assertIn(edge['target'], nodes)
            self.assertTrue(edge['evidence_ids'])
            self.assertTrue(set(edge['evidence_ids']) <= evidence)
        self.assertTrue(any(e['type'] == 'HasCapability' for e in report['edges']))
        self.assertTrue(any(e['type'] == 'RunsOn' for e in report['edges']))

    def test_stale_validation_cannot_verify_new_snapshot(self):
        report = copy.deepcopy(with_validation(before_report()))
        report['collection']['collected_at'] = '2099-01-01T00:00:00Z'
        report = attach_analysis(report)
        self.assertFalse(any(p['verified'] for p in report['analysis']['paths']))

    def test_excluded_path_is_not_a_fix(self):
        before, after = before_report(), after_report()
        after['collection']['scope']['exclusions'] = ['/opt/lab/*']
        comparison = compare_reports(before, after)
        self.assertTrue(any(p['pattern'] == 'writable-root-job' for p in comparison['paths']['incomplete_not_a_fix']))

    def test_symlink_target_ancestor_is_checked(self):
        def entry(path, kind, mode, **extra):
            return dict(path=path, type=kind, mode=mode, uid=0, gid=0, **extra)
        files = {i['path']: i for i in [entry('/', 'dir', 0o755), entry('/private', 'dir', 0o700), entry('/private/data', 'file', 0o644), entry('/shortcut', 'symlink', 0o777, symlink_target='/private/data')]}
        result = can_read(files, [{'path': '/', 'fstype': 'ext4', 'flags': ['rw']}], 2001, {2001}, '/shortcut')
        self.assertFalse(result.granted)

    def test_unit_configuration_paths_are_compared(self):
        before = snapshot(False, True, True)
        config = '/opt/lab/demo.service'
        before['files'].append(dict(path=config, type='file', mode=0o644, uid=2001, gid=2001))
        before['services'][0]['fragment_path'] = config
        after = copy.deepcopy(before)
        after['files'][-1]['uid'] = 0
        after['files'][-1]['gid'] = 0
        result = compare_reports(build_report(before), build_report(after))
        self.assertTrue(any(p['pattern'] == 'service-influence' for p in result['paths']['removed_under_complete_coverage']))

    def test_privileged_container_path_has_graph_steps(self):
        source = snapshot(False, True, True)
        source['containers'][0]['privileged'] = True
        report = build_report(source)
        path = next(p for p in report['analysis']['paths'] if p['pattern'] == 'docker-boundary')
        self.assertTrue(path['evidence_ids'])
        self.assertTrue(all('edge_id' in step for step in path['steps']))
        self.assertIn('host/lab-01/lab-01', path['node_ids'])
        self.assertFalse(path['verified'])

    def test_partial_groups_make_access_conditional(self):
        source = snapshot(False, True, True)
        source['coverage']['groups'] = 'partial'
        report = build_report(source)
        grant = next(e for e in report['edges'] if e['type'] == 'CanWrite' and e['source'].endswith('/2001') and e['target'].endswith('/backup.py'))
        self.assertEqual(grant['classification'], 'conditional')
        self.assertTrue(any('group' in assumption for assumption in grant['assumptions']))
        difference = compare_reports(before_report(), report)
        self.assertTrue(any(e['changes'].get('classification') for e in difference['edges']['changed']))


if __name__ == '__main__':
    unittest.main()
