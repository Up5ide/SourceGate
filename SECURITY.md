# Security Policy

SourceGate is a pre-1.0 security tool. This policy describes how to report vulnerabilities in SourceGate itself, not suspicious third-party npm or PyPI packages found by SourceGate.

## Supported Versions

SourceGate has not reached a stable 1.0 release yet.

| Version | Supported |
| --- | --- |
| `main` branch | Best effort |
| Tagged pre-1.0 releases | Best effort |
| Older commits or forks | Not supported |

Security fixes are handled on a best-effort basis until the project has a stable release and a clearer maintenance policy.

## Reporting A Vulnerability

Please do not report sensitive vulnerabilities through public GitHub issues, pull requests, discussions, or social media.

Use GitHub private vulnerability reporting from the repository Security tab when it is available. If private vulnerability reporting is not available, open a public issue that asks for a private reporting contact without including technical details, exploit steps, crash inputs, secrets, or proof-of-concept code.

Useful reports include:

- The affected SourceGate version, commit, or branch.
- The operating system and Go version used, if relevant.
- The exact command, mode, config, and package spec involved.
- A minimal reproduction case when it is safe to share privately.
- The expected impact, such as policy bypass, unsafe artifact handling, command execution, sensitive data exposure, or denial of service.

## Response Expectations

Maintainers will triage reports as capacity allows. Because SourceGate is currently pre-1.0, this project does not promise a fixed response or disclosure timeline.

When a report is accepted, the expected process is:

1. Confirm the affected behavior and severity.
2. Prepare a fix or mitigation.
3. Credit the reporter if requested and appropriate.
4. Publish release notes or advisory information when the issue affects users.

## Scope

In scope:

- Vulnerabilities in SourceGate CLI parsing, config handling, registry metadata handling, artifact download or verification, archive inspection, policy evaluation, output rendering, or install-mode invocation.
- Bugs that allow a package to bypass a configured `BLOCK` policy.
- Unsafe handling of untrusted package metadata or archive contents.

Out of scope:

- Vulnerabilities in third-party packages inspected by SourceGate.
- Reports that rely on unsupported package-manager workflows.
- General malware reports for npm or PyPI packages without a SourceGate bug.
- Dependency vulnerabilities that are already reported by standard dependency scanners and do not create a SourceGate-specific exposure.

