"""Public source boundary checks; no real credentials or reports are used."""
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/check_public_release.py'
spec = importlib.util.spec_from_file_location('public_release', SCRIPT)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class PublicReleaseTests(unittest.TestCase):
    def test_reviewed_screenshots_reject_extra_metadata(self):
        root = SCRIPT.parents[1]
        for name in release.IMAGE_FILES:
            raw = (root / name).read_bytes()
            release.validate_image(raw)
            with self.assertRaisesRegex(ValueError, 'metadata'):
                release.validate_image(raw[:2] + b'\xff\xe1\x00\x06Exif' + raw[2:])
            with self.assertRaises(ValueError):
                release.validate_image(raw + b'unexpected trailing data')

    def test_only_readme_and_user_guide_are_public_markdown(self):
        self.assertTrue(release.public_path('README.md'))
        self.assertTrue(release.public_path('GUIDE.md'))
        for name in ('MODEL_CARD.md', 'ARCHITECTURE.md', 'SECURITY.md',
                     'linuxhound/models/MODEL_CARD.md', 'scripts/notes.md',
                     'examples/synthetic/README.md', 'linuxhound/README.MD', 'docs/GUIDE.md', 'linuxhound/GUIDE.md'):
            self.assertFalse(release.public_path(name), name)

    def test_force_added_model_card_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            (root / 'scripts/check_public_release.py').write_bytes(SCRIPT.read_bytes())
            (root / 'linuxhound/models').mkdir(parents=True)
            (root / 'linuxhound/models/MODEL_CARD.md').write_text('Not public.\n')
            (root / 'README.md').write_text('Public usage.\n')
            subprocess.run(['git', 'init', '-q', directory], check=True)
            subprocess.run(['git', '-C', directory, 'add', '.'], check=True)
            result = subprocess.run(['python3', str(root / 'scripts/check_public_release.py')],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('linuxhound/models/MODEL_CARD.md', result.stdout)
            self.assertIn('outside public source allowlist', result.stdout)

    def test_allowed_sources_and_private_paths(self):
        for name in ('linuxhound/collector.py', 'linuxhound/models/demo-path.safetensors',
                     'linuxhound/models/demo-path.json', 'images/screenshots/attack-path.jpg',
                     'images/screenshots/graph-neural-network.jpg'):
            self.assertTrue(release.public_path(name), name)
        for name in ('artifacts/gnn/model.json', 'examples/lab-live/report.json',
                     'scripts/prompt.md', 'linuxhound/credentials.py', '.env',
                     'docs/report.json', 'docs/GNN.md', 'artifacts/README.md', 'validation/results-controlled.json', 'examples/synthetic/before.html', 'linuxhound/models/private.safetensors', 'images/screenshots/host.png'):
            self.assertFalse(release.public_path(name), name)

    def test_secret_indicators(self):
        for value in ('gh' + 'p_' + 'x' * 40, '/' + 'Users/person/reports',
                      '192.' + '168.1.99'):
            self.assertTrue(any(p.search(value) for p in release.SECRET_PATTERNS))

    def test_force_added_private_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            (root / 'scripts/check_public_release.py').write_bytes(SCRIPT.read_bytes())
            (root / '.gitignore').write_text('artifacts/\n')
            (root / 'README.md').write_text('Public source.\n')
            (root / 'artifacts').mkdir()
            (root / 'artifacts/report.json').write_text('{}')
            subprocess.run(['git', 'init', '-q', directory], check=True)
            result = subprocess.run(['python3', str(root / 'scripts/check_public_release.py')],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout)
            subprocess.run(['git', '-C', directory, 'add', '-f', 'artifacts/report.json'], check=True)
            result = subprocess.run(['python3', str(root / 'scripts/check_public_release.py')],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('outside public source allowlist', result.stdout)


if __name__ == '__main__':
    unittest.main()
