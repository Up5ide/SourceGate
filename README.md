# SourceGate

SourceGate is a security-first Go CLI that sits in front of package managers and inspects package information before installation.

The long-term goal is to become a local, policy-driven enforcement layer for software supply-chain risk. SourceGate should help developers and CI systems identify risky packages, explain the reasons clearly, and eventually allow, warn, or block installation based on deterministic policy.

## Version 0.5 Scope

Version 0.5 is intentionally small.

SourceGate does not install packages, download package archives, or invoke the real package manager. It accepts familiar install-shaped commands and fetches public registry metadata for the requested package.

Supported command shape:

```bash
sourcegate npm install <package>
sourcegate pip install <package>
```

Expected behavior:

1. Parse the ecosystem, package-manager command, and package name.
2. Query the relevant public registry.
3. Display available package metadata and tiered policy findings.
4. Exit without installing the package.

## Mission

Modern software depends on public package registries. Package managers generally assume trust by default: they resolve, download, install, and often execute install-time hooks.

SourceGate exists to add an explicit inspection step before that trust is granted.

The project aims to:

- Inspect dependency risk before installation.
- Support multiple package ecosystems through adapters.
- Make risk findings explainable.
- Prefer deterministic rules over opaque scoring.
- Provide local-first behavior with no cloud dependency required.
- Support policy enforcement in later versions.

## Current Support

SourceGate currently targets metadata inspection for npm and PyPI packages.

Supported ecosystems:

- JavaScript / TypeScript through `npm` and the npm registry.
- Python through `pip` and PyPI.

Supported behavior:

- Parse install-shaped commands.
- Identify the target ecosystem.
- Extract the requested package name.
- Query the relevant public registry.
- Read local policy from `sourcegate.config.json`.
- Emit tiered policy findings for release timing, package history, package names, npm lifecycle metadata, and PyPI artifact/provenance metadata.
- Exit without installing the package.
- Avoid invoking `npm`, `pip`, or any package lifecycle hooks.

The current version does not download archives, analyze package contents, or invoke package-manager install behavior.

## Documentation

- [Configuration](docs/configuration.md)
- [Design](docs/design.md)
- [Attack Vectors](docs/attack-vectors.md)

## Planned Next

Near-term work:

- Normalize npm and PyPI metadata into a shared package report format.
- Add structured JSON output for automation and CI.
- Support version-specific package requests such as `lodash@4.17.21` and `requests==2.31.0`.
- Add registry error handling for missing packages, private packages, rate limits, and network failures.
- Add more metadata findings, such as unusual release timing and missing project information.

Later work:

- Download and inspect package archives without installing them.
- Detect Python build-time execution surfaces such as `setup.py` and build backends.
- Add typosquatting and dependency confusion checks.
- Add upstream repository commit-time analysis where package metadata exposes a source repository.
- Detect suspicious file paths, embedded binaries, obfuscated code, credential access, environment variable access, network indicators, and remote payload download behavior.
- Add local policy configuration for allow, warn, and block decisions.
- Add CI-compatible exit codes.

## Non-Goals

SourceGate is not intended to replace vulnerability scanners, antivirus tools, or full runtime malware analysis.

It is a supply-chain risk gate. The goal is to inspect, explain, and eventually enforce decisions before package installation.

## Development

SourceGate is written in Go.

```bash
go build ./cmd/sourcegate
```

## License

See [LICENSE](LICENSE).
