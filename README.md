<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="images/linuxhound-logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="images/linuxhound-logo.svg">
    <img src="images/linuxhound-logo.svg" width="792" alt="LinuxHound logo and red wordmark">
  </picture>
</p>

# LinuxHound

LinuxHound follows the permissions that connect Linux accounts to files, services
and containers, helping you understand how access can lead to privileged resources.
It collects metadata, builds a directed relationship graph and opens an offline
investigation UI, where you can examine the evidence behind each path and compare
what changes after hardening.

**Live collection:** Linux only. macOS, BSD and Windows are not collection
targets. Saved HTML reports open in a modern desktop browser. The demo
can run elsewhere with Python; it does not audit that operating system.

![LinuxHound environment graph showing demo accounts, services and files](images/screenshots/environment-overview.jpg)

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
trusted desktop. The package is not yet published to PyPI.

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
| Native Linux collection | ✓ | ✓ | ✓ | ✓ | ✓ |
| Privilege graph across collected accounts | ✓ | ✗ | ✗ | ✓ | ✗ |
| Interactive, standalone HTML graph | ✓ | ✗ | ✓ | ✗ | ✗ |
| Before/after path comparison that accounts for missing coverage | ✓ | ✗ | ✗ | ✗ | ✗ |
| General hardening and compliance audit | ✗ | ✗ | ✗ | ✗ | ✓ |

✓ means the feature is provided; ✗ means no matching built-in feature was found
in the reviewed documentation and interface. This compares open-source editions,
not detection accuracy. See the [comparison notes](GUIDE.md#tool-comparison)
for sources, scope and experimental features.

## User guide

- [Tool comparison and feature notes](GUIDE.md#tool-comparison)
- [Docker installation and running LinuxHound](GUIDE.md#docker)
- [Investigating paths and comparing snapshots](GUIDE.md#what-the-results-show)
- [Graph examples](GUIDE.md#graph-examples)
- [Graph Neural Network (GNN) models and training](GUIDE.md#graph-neural-network-gnn)
- [Collection scope, privacy and limitations](GUIDE.md#coverage-privacy-and-limitations)
- [Development](GUIDE.md#development-and-license)

## References and acknowledgements

[BloodHound](https://bloodhound.specterops.io/home) inspired the relationship graph
and attack-path investigation approach. LinuxHound also provides an export for
BloodHound's [OpenGraph framework](https://bloodhound.specterops.io/opengraph/overview).

[GTFOBins](https://gtfobins.org/) provides the Unix executable reference used by
LinuxHound's optional technique matching. Catalog matches provide context for
reviewing permissions; they do not establish that a path is exploitable.

LinuxHound is licensed under [Apache-2.0](LICENSE). Attribution information is
available in [NOTICE](NOTICE).
