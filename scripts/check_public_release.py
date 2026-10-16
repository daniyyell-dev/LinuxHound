import re
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {'.gitignore', 'MANIFEST.in', 'pyproject.toml', 'LICENSE', 'NOTICE',
              'README.md', 'GUIDE.md', 'CONTRIBUTING.md', 'Dockerfile', '.dockerignore'}
SOURCE_DIRS = {'linuxhound', 'tests', 'scripts', 'images'}
PUBLIC_MARKDOWN = {'README.md', 'GUIDE.md', 'CONTRIBUTING.md', '.github/PULL_REQUEST_TEMPLATE.md'}
EXTRA_FILES = {
    '.github/workflows/tests.yml', '.github/workflows/publish.yml',
    '.github/ISSUE_TEMPLATE/config.yml',
    '.github/ISSUE_TEMPLATE/bug.yml',
    '.github/ISSUE_TEMPLATE/feature.yml',
    '.github/PULL_REQUEST_TEMPLATE.md',
}
MODEL_FILES = {'linuxhound/models/demo-path.safetensors', 'linuxhound/models/demo-path.json'}
IMAGE_FILES = {
    'images/screenshots/attack-path.jpg',
    'images/screenshots/graph-neural-network.jpg',
    'images/screenshots/environment-overview.jpg',
    'images/screenshots/root-relationships.jpg',
    'images/screenshots/file-relationships.jpg',
    'images/screenshots/filesystem-relationships.jpg',
}
SECRET_PATTERNS = [
    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}'),
    re.compile(r'AKIA[A-Z0-9]{16}'),
    re.compile(r'/' + r'Users/[^/\s]+/|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+'),
    re.compile('pry' + 'noid', re.I),
]


def public_path(name):
    path = Path(name)
    if path.suffix.lower() == '.md' and name not in PUBLIC_MARKDOWN:
        return False
    if name in ROOT_FILES or name in EXTRA_FILES or name in MODEL_FILES or name in IMAGE_FILES:
        return True
    if path.parts[0] not in SOURCE_DIRS:
        return False
    if any(re.search(r'(?i)prompt|credentials|creds|private', part) for part in path.parts):
        return False
    return path.suffix in {'.py', '.js', '.css', '.html', '.svg'}


def validate_image(raw):
    if not 4 <= len(raw) <= 4 * 1024 * 1024 or raw[:2] != b'\xff\xd8' or raw[-2:] != b'\xff\xd9':
        raise ValueError('invalid screenshot JPEG')
    offset = 2
    frame = False
    while offset + 4 <= len(raw):
        if raw[offset] != 0xff:
            raise ValueError('invalid JPEG marker')
        kind = raw[offset + 1]
        length = struct.unpack('>H', raw[offset + 2:offset + 4])[0]
        end = offset + 2 + length
        if length < 2 or end > len(raw):
            raise ValueError('invalid JPEG segment')
        data = raw[offset + 4:end]
        if kind == 0xfe or 0xe1 <= kind <= 0xef:
            raise ValueError('screenshot contains unexpected metadata')
        if kind == 0xe0 and not data.startswith(b'JFIF\x00'):
            raise ValueError('unexpected JPEG application data')
        if kind in (0xc0, 0xc1, 0xc2):
            if len(data) < 6:
                raise ValueError('invalid JPEG frame')
            height, width = struct.unpack('>HH', data[1:5])
            if not 1 <= width <= 4096 or not 1 <= height <= 4096:
                raise ValueError('invalid screenshot dimensions')
            frame = True
        if kind == 0xda:
            if not frame:
                raise ValueError('missing JPEG frame')
            return
        offset = end
    raise ValueError('incomplete JPEG')


def main():
    result = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                            cwd=ROOT, check=True, stdout=subprocess.PIPE)
    files = sorted(set(result.stdout.decode().split('\0')) - {''})
    errors = []
    for name in files:
        path = ROOT / name
        if not public_path(name):
            errors.append((name, 'outside public source allowlist'))
        if path.is_symlink():
            errors.append((name, 'symlink requires explicit review'))
            continue
        try:
            if name in IMAGE_FILES:
                validate_image(path.read_bytes())
                content = ''
            elif name == 'linuxhound/models/demo-path.safetensors':
                raw = path.read_bytes()
                if not 8 <= len(raw) <= 1024 * 1024:
                    raise ValueError('invalid demo model size')
                header_size = struct.unpack('<Q', raw[:8])[0]
                if not 2 <= header_size <= len(raw) - 8:
                    raise ValueError('invalid tensor header')
                content = raw[8:8 + header_size].decode('utf-8')
                json.loads(content)
                manifest = json.loads(path.with_suffix('.json').read_text())
                if hashlib.sha256(raw).hexdigest() != manifest['storage']['weights_sha256']:
                    raise ValueError('model checksum mismatch')
                if manifest['metadata'].get('status') != 'synthetic_demo_only':
                    raise ValueError('only synthetic demo models may be bundled')
            else:
                content = path.read_text(encoding='utf-8')
        except (UnicodeError, OSError, ValueError, KeyError):
            errors.append((name, 'unreadable or unapproved public model/file'))
            continue
        if any(pattern.search(content) for pattern in SECRET_PATTERNS):
            errors.append((name, 'secret or local identity indicator; inspect privately'))
    for name, reason in errors:
        print('FAIL:', name, '-', reason)
    if not errors:
        print('PASS:', len(files), 'Git-selected public files; no disallowed files or scanned secret indicators.')
    return bool(errors)


if __name__ == '__main__':
    sys.exit(main())
