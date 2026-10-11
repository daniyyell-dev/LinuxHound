import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from linuxhound.cli import main
from linuxhound.synthetic import snapshot


class QuickstartTests(unittest.TestCase):
    def run_cli(self, args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(args)

    def test_demo_embeds_report_and_creates_private_unique_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            for _ in range(2):
                self.assertEqual(self.run_cli(['demo', '--output-dir', directory]), 0)
            runs = list(Path(directory).iterdir())
            self.assertEqual(len(runs), 2)
            for run in runs:
                report = json.loads((run / 'report.json').read_text())
                self.assertTrue(report['nodes'])
                self.assertIn('backup.service', (run / 'index.html').read_text())
                self.assertEqual(run.stat().st_mode & 0o777, 0o700)
                for file in run.iterdir():
                    self.assertEqual(file.stat().st_mode & 0o777, 0o600)

    def test_scan_pipeline_and_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            before = Path(directory) / 'before.json'
            before.write_text(json.dumps(snapshot(False, True, True)))
            with patch('linuxhound.cli.sys.platform', 'linux'), patch('linuxhound.cli.collect', return_value=snapshot(True, True, True)) as collector:
                result = self.run_cli(['scan', '--root', '/etc', '--root', '/opt', '--output-dir', directory,
                                       '--host-id', 'lab', '--before', str(before), '--docker'])
            self.assertEqual(result, 0)
            self.assertEqual(collector.call_args.args[0], ['/etc', '/opt'])
            self.assertTrue(collector.call_args.args[10])
            run = next(p for p in Path(directory).iterdir() if p.is_dir())
            self.assertTrue((run / 'comparison.json').is_file())
            self.assertIn('comparison', (run / 'index.html').read_text())

    def test_scan_rejects_non_linux_before_collecting(self):
        with patch('linuxhound.cli.sys.platform', 'darwin'), patch('linuxhound.cli.collect') as collector:
            self.assertEqual(self.run_cli(['scan', '--root', '/etc']), 1)
            collector.assert_not_called()

    def test_view_opens_saved_html_only_when_requested(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'snapshot.json'
            source.write_text(json.dumps(snapshot(False, True, True)))
            output = Path(directory) / 'review.html'
            with patch('webbrowser.open', return_value=True) as browser:
                self.assertEqual(self.run_cli(['view', str(source), '--output', str(output)]), 0)
                browser.assert_not_called()
                self.assertEqual(self.run_cli(['view', str(source), '--output', str(output), '--open']), 0)
                browser.assert_called_once_with(output.resolve().as_uri())

    def test_output_directory_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target'
            target.mkdir()
            link = Path(directory) / 'link'
            link.symlink_to(target)
            self.assertEqual(self.run_cli(['demo', '--output-dir', str(link)]), 1)
            self.assertEqual(list(target.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
