# Contributing to LinuxHound

Thank you for helping improve LinuxHound. The useful changes are bug fixes,
clearer documentation, tests, and collection or viewer behaviour that stays
within the limits already stated in the [user guide](GUIDE.md).

Contributions are licensed under [Apache-2.0](LICENSE), the same license as
the project. By opening a pull request you agree that your contribution can be
distributed under that license. See [NOTICE](NOTICE) for attribution.

## Ways to help

- Report a defect in collection, analysis, comparison, or the offline viewer.
- Fix documentation in `README.md`, `GUIDE.md`, or this file.
- Add a test that locks in a current behaviour or a bug you are fixing.
- Improve Linux collection, the evidence graph, or the viewer without widening
  what the tool claims to prove.

Live collection is Linux only. A change that collects macOS, BSD, or Windows
permissions is out of scope.

## What not to send

Do not include any of the following in an issue, pull request, or commit:

- A snapshot, report, or HTML viewer from a real host
- Account names, paths, or policies copied from a system you administer, unless
  they are clearly fictional and safe to publish
- Credentials, tokens, private keys, password hashes, or file contents
- Exploit steps, payloads, or GTFOBins recipes
- A claim that a path, score, or catalog match is a verified vulnerability

A missing coverage source is not a clean result. A model score does not prove
that a path is unsafe or safe. Keep that distinction in any text you add.

For a suspected vulnerability in LinuxHound itself, use a
[GitHub security advisory](https://github.com/daniyyell-dev/LinuxHound/security/advisories/new)
rather than a public issue. If private reporting is not available, open an
issue that describes the defect without a live report or a reproduction that
exposes a real host.

## Review what you submit

Read the issue or the pull request before you send it. That includes the
description, the code, and any test or document you changed. Do this when you
wrote the text yourself, and do it when a tool drafted the text or the change
for you.

You are responsible for what the submission says and what the diff does. If you
cannot explain a sentence or a change, revise it or leave it out.

## Issues

Use a GitHub issue template when it fits.

- **Bug.** Say what you ran, the LinuxHound version, and what you expected.
  Prefer a small fictional fixture over output from a real machine.
- **Feature.** Describe the investigation question the change would answer, and
  why the current commands do not answer it.

Questions about how to read a result belong in the user guide first. If the
guide does not answer them, open an issue and name the section you checked.

## Development setup

Python 3.9 or newer is required. The optional neural dependencies are only
needed when you change the graph-model code.

```sh
git clone https://github.com/daniyyell-dev/LinuxHound.git
cd LinuxHound
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[gnn]'
```

Node is required for the viewer checks. You do not need a Linux host to run
the tests or `linuxhound demo`.

## Checks

Run these before you open a pull request:

```sh
python -m unittest discover -s tests -q
node tests/test_viewer_graph.js
python scripts/check_public_release.py
```

The same checks run on every pull request. `check_public_release.py` rejects
files outside the public allowlist, including extra Markdown, real reports,
and screenshots that carry unexpected metadata. Demo screenshots are the only
images that belong in `images/screenshots/`.

If you change `linuxhound/viewer.js`, also run `node --check linuxhound/viewer.js`.

## Pull requests

Keep one pull request to one change. In the description, say what changed and
why a reviewer should accept it.

- Use the demo or a test fixture for evidence. Do not commit a real report.
- Do not add a dependency for a change the Python standard library can do.
  PyTorch, SafeTensors, and NumPy stay optional, under the `gnn` extra.
- Do not present a new score, path, or catalog match as proof of exploitability.
- Update `GUIDE.md` when a command or a stated limit changes.
- New public Markdown, workflow files, and screenshots must be added to the
  allowlist in `scripts/check_public_release.py` and covered by
  `tests/test_public_release.py`.

A reviewer may ask for a smaller change or for a test. That is a normal part
of the review, not a rejection of the idea.
