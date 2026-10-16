<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/daniyyell-dev/LinuxHound/main/images/linuxhound-logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/daniyyell-dev/LinuxHound/main/images/linuxhound-logo.svg">
    <img src="https://raw.githubusercontent.com/daniyyell-dev/LinuxHound/main/images/linuxhound-logo.svg" width="792" alt="LinuxHound logo and red wordmark">
  </picture>
</p>

<p align="center">
  <strong>Evidence-backed Linux permission graphs and attack-path investigation.</strong><br>
  Trace how accounts reach privileged resources, inspect the supporting evidence and compare permission paths before and after hardening changes.
</p>

<p align="center">
  <a href="https://github.com/daniyyell-dev/LinuxHound/releases/latest"><img src="https://img.shields.io/github/v/release/daniyyell-dev/LinuxHound?style=flat&amp;label=release&amp;color=e76f2e" alt="Latest GitHub release"></a>
  <a href="https://github.com/daniyyell-dev/LinuxHound/blob/main/pyproject.toml"><img src="https://img.shields.io/badge/python-3.9%2B-1685bd?style=flat" alt="Python 3.9 or newer"></a>
  <a href="https://github.com/daniyyell-dev/LinuxHound/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-c62138?style=flat" alt="Apache-2.0 license"></a>
  <a href="https://github.com/daniyyell-dev/LinuxHound/actions/workflows/tests.yml"><img src="https://img.shields.io/github/actions/workflow/status/daniyyell-dev/LinuxHound/tests.yml?branch=main&amp;style=flat&amp;label=checks" alt="GitHub source checks"></a>
</p>

<p align="center">
  <a href="https://github.com/daniyyell-dev/LinuxHound/blob/main/GUIDE.md"><strong>Documentation</strong></a> &middot;
  <a href="#quick-start-linux">Quick start</a> &middot;
  <a href="https://github.com/daniyyell-dev/LinuxHound/blob/main/GUIDE.md#docker">Docker</a> &middot;
  <a href="https://github.com/daniyyell-dev/LinuxHound/blob/main/GUIDE.md#graph-neural-network-gnn">GNN</a> &middot;
  <a href="https://github.com/daniyyell-dev/LinuxHound/releases">Releases</a> &middot;
  <a href="https://github.com/daniyyell-dev/LinuxHound/issues">Issues</a>
</p>

**Live collection:** Linux only. macOS, BSD and Windows are not collection
targets. Saved HTML reports open in a modern desktop browser. The demo
can run elsewhere with Python; it does not audit that operating system.

## Features

- Read-only collection of accounts, groups, files, sudo rules, capabilities and services from the directories you choose.
- A standalone HTML graph for Explore, Attack paths, Findings and Targets, with no graph database required.
- Candidate privilege chains that keep unresolved prerequisites on the relationship.
- Evidence for a selected node or edge, including ownership, sudo policy and the identity a service runs as.
- Before-and-after comparison that stays incomplete when the later scan cannot read the same source.
- BloodHound OpenGraph export, plus an SVG export of the graph.
- Optional offline GTFOBins reference matching. A catalog match is context for review, not a verified vulnerability.
- Optional Graph Neural Network scores that order reviews. The bundled model is a synthetic demonstration and does not prove a vulnerability or that a path is safe.

<p align="center">
  <img src="https://raw.githubusercontent.com/daniyyell-dev/LinuxHound/main/images/linuxhound-graph.svg" width="800" alt="LinuxHound demo graph of accounts, services, files and conditional paths">
</p>

The graph above comes from the LinuxHound demo. Red relationships mark modeled
trust boundaries, while dashed relationships retain unresolved prerequisites.
Following a connection helps explain access, but does not establish that an exploit works.

## Quick start: Linux

To begin on a Linux host with Git and Python 3.9 or newer, clone the repository
and enter its directory. Then create a virtual environment, install LinuxHound
and run your first collection:

```sh
git clone https://github.com/daniyyell-dev/LinuxHound.git
cd LinuxHound
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
linuxhound scan --root /etc --root /opt --serve --open
```

When collection finishes, LinuxHound feeds the results directly into the UI.
Each run saves `snapshot.json`,
`report.json` and `index.html` under `linuxhound-results/`. `--serve --open` opens
a localhost viewer. On a headless host, omit those flags and copy the HTML to a
trusted desktop. For installation from the Python Package Index, use
`python -m pip install linuxhound`, or `python -m pip install 'linuxhound[gnn]'`
to include the optional neural dependencies.

If you want to explore the interface first, open the demo without
collecting information from a host:

```sh
linuxhound demo --open
```

Once you are familiar with the graph, you can install the optional
**Graph Neural Network (GNN)** dependencies and explore neural review ordering:

```sh
python -m pip install '.[gnn]'
linuxhound demo --gnn --open
```

The bundled model is an uncalibrated synthetic demonstration. Its scores help
order reviews; they do not prove vulnerabilities or safety. Missing collection
coverage is not a clean result.

## Compare Linux tools

LinuxHound is a better fit when you need to follow permissions across accounts,
inspect a path's evidence in a browser and review what changed after hardening.
The tools below serve different workflows, so the comparison includes strengths
that LinuxHound does not provide.

| Feature | LinuxHound | [LinPEAS](https://github.com/peass-ng/PEASS-ng/tree/622f18f66fdec2b2e3a36d2cb809fb3c961177e1) | [RootHound](https://github.com/Noz2/RootHound/tree/d47f44cfac59b8faea61a689b8e909397087f344) | [privmap](https://pypi.org/project/privmap/2.0.0/) | [Lynis](https://github.com/CISOfy/lynis/tree/9319416fa0726369ab0a48f686155a90363f3f9c) |
| --- | :---: | :---: | :---: | :---: | :---: |
| Native Linux collection | ✅ | ✅ | ✅ | ✅ | ✅ |
| Privilege graph across collected accounts | ✅ | ❌ | ❌ | ✅ | ❌ |
| Interactive, standalone HTML graph | ✅ | ❌ | ✅ | ❌ | ❌ |
| Before/after path comparison that accounts for missing coverage | ✅ | ❌ | ❌ | ❌ | ❌ |
| General hardening and compliance audit | ❌ | ❌ | ❌ | ❌ | ✅ |

## LinuxHound features

<p align="center">
  <img src="https://raw.githubusercontent.com/daniyyell-dev/LinuxHound/main/images/linuxhound-graph_exec.svg" width="520" alt="LinuxHound demo graph of a conditional privilege path">
</p>

What the current release can do:

- ✅ Read-only Linux collection of accounts, groups, files, directories, symlinks, sudo rules, capabilities and services
- ✅ Coverage recorded per source, so an unread policy or directory stays a gap
- ✅ Access control lists when `getfacl` is available
- ✅ Loaded systemd services, with an option to skip that query
- ✅ Optional local Docker metadata, without reading container environments
- ✅ A permission graph across the collected accounts and resources
- ✅ Standalone HTML for Explore, Attack paths, Findings, Targets and GNN
- ✅ Localhost viewer with a private token URL, or a saved HTML file with no server
- ✅ Candidate privilege chains that keep unresolved prerequisites on the path
- ✅ Evidence for a selected account, file, service, relationship or finding
- ✅ Queries for who holds a right, which services are running, and which paths reach a root job
- ✅ Before-and-after comparison that does not count missing coverage as a fix
- ✅ BloodHound OpenGraph export with fidelity notes
- ✅ SVG export of the graph
- ✅ Optional Graph Neural Network review scores that leave the evidence unchanged

## Documentation

Continue with the [user guide](https://github.com/daniyyell-dev/LinuxHound/blob/main/GUIDE.md) for
[investigating results](https://github.com/daniyyell-dev/LinuxHound/blob/main/GUIDE.md#what-the-results-show),
[graph examples](https://github.com/daniyyell-dev/LinuxHound/blob/main/GUIDE.md#graph-examples) and
[model training](https://github.com/daniyyell-dev/LinuxHound/blob/main/GUIDE.md#graph-neural-network-gnn).
It also covers [comparison details](https://github.com/daniyyell-dev/LinuxHound/blob/main/GUIDE.md#tool-comparison),
[collection scope and limitations](https://github.com/daniyyell-dev/LinuxHound/blob/main/GUIDE.md#coverage-privacy-and-limitations),
and [development](https://github.com/daniyyell-dev/LinuxHound/blob/main/GUIDE.md#development-and-license).

## References and acknowledgements

[BloodHound](https://bloodhound.specterops.io/home) inspired the relationship graph
and attack-path investigation approach. LinuxHound also provides an export for
BloodHound's [OpenGraph framework](https://bloodhound.specterops.io/opengraph/overview).

[GTFOBins](https://gtfobins.org/) provides the Unix executable reference used by
LinuxHound's optional technique matching. Catalog matches provide context for
reviewing permissions; they do not establish that a path is exploitable.

LinuxHound is licensed under [Apache-2.0](https://github.com/daniyyell-dev/LinuxHound/blob/main/LICENSE). Attribution information is
available in [NOTICE](https://github.com/daniyyell-dev/LinuxHound/blob/main/NOTICE).
