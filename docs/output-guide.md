# How To Read SourceGate Output

SourceGate output is designed to answer three questions:

- What package and version did SourceGate inspect?
- Which configured policy checks produced findings?
- Did any finding block the requested install?

## Human Output

Human output is the default:

```bash
sourcegate --preset balanced npm install lodash
```

The exact findings depend on the active config and registry state, but the main sections are stable.

`Mode` shows which evaluation path ran:

- `metadata`: registry metadata only; no artifact download and no install.
- `artifact`: metadata checks plus one verified root-artifact inspection; no install.
- `install`: metadata and root-artifact checks, followed by the real package-manager install only when policy does not block.

`Package` and `Selected Version` identify the selected registry package and release. An unversioned request inspects the registry latest release. An exact request such as `lodash@4.17.21` or `requests==2.32.5` inspects only that version.

`Decision` is the final policy decision:

- `ALLOW`: no configured block-level policy finding matched.
- `BLOCK`: at least one configured block-level finding matched.

`ALLOW` can still appear with `INFORM` or `ALERT` findings. That means SourceGate found something worth reporting, but the active policy did not classify it as install-blocking.

## Finding Severities

SourceGate policy has three finding severities:

| Severity | Meaning | Exit code |
| --- | --- | --- |
| `INFORM` | Low-noise visibility. Review when useful. | `10` |
| `ALERT` | Attention recommended. The install is not blocked unless this same condition is configured at the `block` tier. | `20` |
| `BLOCK` | Hard stop. In install mode, SourceGate skips the package-manager install. | `30` |

SourceGate evaluates stronger tiers first. If the same check matches in `block`, `alert`, and `inform`, only the strongest matching result is reported.

## Warnings

Warnings are not policy findings. They explain evaluation limits or environmental uncertainty.

Common examples:

- Artifact policy is configured, but the command ran in default metadata mode, so artifact checks did not run.
- PyPI compatibility-tag discovery failed, so install-target provenance for compatible wheels is indeterminate.

Use warnings to decide whether to rerun with a different mode or environment.

## Artifact Sections

Artifact sections appear in `--mode artifact` and `--mode install` when metadata policy does not block before download.

Artifact download information describes whether SourceGate selected, downloaded, size-checked, and digest-verified one install-target artifact. Temporary file paths and artifact URLs are not included in public output.

Artifact inspection information summarizes archive metadata without extracting or executing package contents. It can include inventory counts, unsafe path findings, install/build execution surfaces, suspicious native or executable file types, general risk signals, behavior indicators, and previous-artifact deltas when those checks are enabled.

If metadata policy already produced `BLOCK`, artifact download and inspection are skipped.

## Install Summary

Install summaries appear only in `--mode install`.

If policy blocks, `Install executed` is `no` and SourceGate does not invoke `npm` or `pip`.

If policy allows, SourceGate invokes the package manager without a shell:

```bash
npm install <name>@<selected-version>
pip install <name>==<selected-version>
```

Successful installs preserve SourceGate policy exit codes: `0`, `10`, or `20`. Package-manager failure or timeout is an operational error and exits `2`.

Install mode gates only the requested root package. Transitive dependencies are still resolved and installed by the package manager.

## JSON Formats

Use full JSON when you want the complete structured report:

```bash
sourcegate --preset balanced --format json npm install lodash
```

Use compact report JSON for automation, CI, IDEs, and AI agents:

```bash
sourcegate --preset balanced --format report npm install lodash
sourcegate --preset balanced --format report -v npm install lodash
```

`--format report` includes command arguments, package identity, triggered findings, optional install summary, and final decision. `-v` adds config status and effective normalized policy. `--debug --format report` is rejected because debug traces belong in full JSON output.

## Exit Codes

| Exit code | Meaning |
| --- | --- |
| `0` | No policy findings. |
| `10` | Highest finding severity is `INFORM`. |
| `20` | Highest finding severity is `ALERT`. |
| `30` | Highest finding severity is `BLOCK`. |
| `2` | Usage, config, registry, network, parse, install failure, timeout, or other operational error. |

For CI patterns, see [CI Usage](ci-usage.md).
