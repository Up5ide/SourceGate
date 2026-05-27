# SourceGate

SourceGate is a security-first Go CLI that sits in front of package managers and inspects package information before installation.

The long-term goal is to become a local, policy-driven enforcement layer for software supply-chain risk. SourceGate should help developers and CI systems identify risky packages, explain the reasons clearly, and eventually allow, warn, or block installation based on deterministic policy.

## Version 0.1 Scope

Version 0.1 is intentionally small.

The first milestone does not install packages, download package archives, or invoke the real package manager. Instead, it accepts familiar install-shaped commands and fetches public registry metadata for the requested package.

Supported command shape:

```bash
sourcegate npm install <package>
sourcegate pip install <package>
```

Expected behavior:

1. Parse the ecosystem, package-manager command, and package name.
2. Query the relevant public registry.
3. Display available package metadata.
4. Exit without installing the package.

This establishes the CLI shape and ecosystem adapter boundary before deeper archive analysis, scoring, and policy enforcement are added.

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

Supported command shapes:

```bash
sourcegate npm install <package>
sourcegate pip install <package>
```

Supported behavior:

- Parse install-shaped commands.
- Identify the target ecosystem.
- Extract the requested package name.
- Query the relevant public registry.
- Display package metadata available from the registry.
- Read local policy from `sourcegate.config.json`.
- Block packages whose latest registry release is newer than the configured minimum age.
- Exit without installing the package.
- Avoid invoking `npm`, `pip`, or any package lifecycle hooks.

The current version does not download archives, analyze package contents, or invoke package-manager install behavior.

## Configuration

SourceGate reads configuration from `sourcegate.config.json` in the current working directory.

Current configuration:

```json
{
  "policy": {
    "minimum_days_since_latest_release": 3
  }
}
```

`minimum_days_since_latest_release` blocks packages when the latest registry release is newer than the configured number of days.

This is intended to reduce exposure to fast-moving compromise windows where an attacker gains publish access, releases malicious code, and users update before the incident is detected and remediated.

In version 0.1 this check uses registry publish time, not upstream Git commit time. Repository commit analysis is planned for a later version.

## Planned Next

Near-term work:

- Normalize npm and PyPI metadata into a shared package report format.
- Add structured JSON output for automation and CI.
- Support version-specific package requests such as `lodash@4.17.21` and `requests==2.31.0`.
- Add registry error handling for missing packages, private packages, rate limits, and network failures.
- Add more metadata findings, such as new packages, unusual release timing, and missing project information.

Later work:

- Download and inspect package archives without installing them.
- Detect npm lifecycle scripts such as `preinstall`, `postinstall`, and `prepare`.
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
