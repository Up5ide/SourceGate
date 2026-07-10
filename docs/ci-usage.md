# CI Usage

SourceGate can produce deterministic exit codes and compact JSON for CI. The examples here use advisory CI by default: `INFORM` and `ALERT` are reported, while only `BLOCK` and operational errors fail the job.

## Recommended Mode

Use `--mode artifact` in CI when you want deeper inspection without installing a package:

```bash
sourcegate --preset strict --mode artifact --format report npm install lodash
sourcegate --preset strict --mode artifact --format report pip install requests
```

Use a checked-in `sourcegate.config.json` instead of `--preset strict` when your project has a tuned policy. Without a config file or preset, relaxed SourceGate builds allow missing default config and evaluate with disabled policy.

Use `--mode install` only when the CI job is intentionally testing the real install path. Install mode gates only the requested root package; transitive dependencies are still resolved and installed by the package manager.

## GitHub Actions Example

This example installs SourceGate with Go, runs one npm package check, captures the SourceGate exit code, uploads the compact report as an artifact, and fails only on `BLOCK` or operational error.

The action versions are shown as readable tags for clarity. Pin third-party actions to full commit SHAs in security-sensitive production workflows.

```yaml
name: SourceGate

on:
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  sourcegate:
    runs-on: ubuntu-latest
    steps:
      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.25.12"

      - name: Install SourceGate
        run: |
          go install github.com/sourcegate/sourcegate/cmd/sourcegate@v1.0.0
          echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"

      - name: Run SourceGate
        id: sourcegate
        shell: bash
        run: |
          set +e
          sourcegate --preset strict --mode artifact --format report npm install lodash > sourcegate-report.json
          code=$?
          set -e

          echo "exit_code=$code" >> "$GITHUB_OUTPUT"

          case "$code" in
            0)
              echo "SourceGate completed with no policy findings."
              ;;
            10)
              echo "SourceGate reported informational findings."
              ;;
            20)
              echo "SourceGate reported alert findings. Review sourcegate-report.json."
              ;;
            30)
              echo "SourceGate blocked the package."
              exit 1
              ;;
            2)
              echo "SourceGate failed with an operational error."
              exit 1
              ;;
            *)
              echo "SourceGate returned unexpected exit code $code."
              exit 1
              ;;
          esac

      - name: Upload SourceGate report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sourcegate-report
          path: sourcegate-report.json
```

For a PyPI package, change the command:

```bash
sourcegate --preset strict --mode artifact --format report pip install requests
```

For an exact version, use the supported package spec shape:

```bash
sourcegate --preset strict --mode artifact --format report npm install lodash@4.17.21
sourcegate --preset strict --mode artifact --format report pip install requests==2.32.5
```

## Exit-Code Policy

SourceGate exit codes are:

| Exit code | CI recommendation |
| --- | --- |
| `0` | Pass. No policy findings. |
| `10` | Pass by default. Informational findings are visible in the report. |
| `20` | Pass by default. Alert findings need review but are not a hard stop in advisory CI. |
| `30` | Fail. A configured block-level policy matched. |
| `2` | Fail. The result is incomplete because of a usage, config, registry, network, parse, install, timeout, or other operational error. |

Teams that want stricter CI can change the `20` case to `exit 1`. That is a policy choice, not a SourceGate requirement.

## Report Output

`--format report` emits compact deterministic JSON for tools. It includes the command arguments, package identity, triggered findings, optional install summary, and final decision.

Use verbose report output when the CI job should also record the effective config:

```bash
sourcegate --preset strict --format report -v npm install lodash
```

Do not combine `--debug` with `--format report`; debug trace data belongs in full JSON output.

## Boundaries

The CI examples intentionally use one root package per command. SourceGate 1.0 does not support lockfile-only installs, requirements files, package-manager flags after `npm` or `pip`, private registry authentication, or recursive transitive dependency gating.
