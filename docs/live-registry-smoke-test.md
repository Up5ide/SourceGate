# Live Registry Smoke Test

This report records a SourceGate `0.5.1` live-registry validation run performed on
`2026-05-31T23:26:25+03:00`.

The run used normal npm and PyPI packages. SourceGate queried registry metadata
with `--debug`; it did not install packages, download archives, or execute
lifecycle scripts.

## Preflight

The preflight completed successfully:

```powershell
go test ./...
go build -o .\sourcegate.exe .\cmd\sourcegate
```

All live commands exited with status `0`. No network retry was required.

## Baseline Matrix

The baseline used the checked-in `sourcegate.config.json` without modification.
Each hypothesis was written before the registry request.

| Ecosystem | Package | Version | Pre-run hypothesis | Observed result | Classification |
| --- | --- | --- | --- | --- | --- |
| npm | `react` | `19.2.6` | Clean baseline unless a recent release causes release-age drift. | No findings. | PASS |
| npm | `sharp` | `0.34.5` | Lifecycle-script alert, suspicious-command block, and lifecycle-history alert. | All three expected findings matched. | PASS |
| npm | `aws-sdk` | `2.1693.0` | Dormant-release alert, protected `aws` token alert, and lifecycle-script alert. | All three expected alerts matched. | PASS |
| npm | `@aws-sdk/client-s3` | `3.1057.0` | Protected `aws` token alert; release-age alert is time-sensitive. | Token and release-age alerts matched. | PASS, time-sensitive |
| npm | `core-js` | `3.49.0` | `postinstall` lifecycle-script alert. | Expected lifecycle-script alert matched. | PASS |
| PyPI | `requests` | `2.34.2` | Clean baseline unless registry metadata changed. | No findings. | PASS |
| PyPI | `django-filter` | `25.2` | Dormant-release, protected `django` token, dependency-addition, and missing-provenance alerts. | All expected alerts matched. | PASS |
| PyPI | `pytest-cov` | `7.1.0` | Dormant-release, protected `pytest` token, and missing-provenance alerts. | All expected alerts matched. | PASS |
| PyPI | `sqlalchemy` | `2.0.50` | Artifact-shape, dependency-change, missing-provenance, and release-file-count alerts. | All expected alert families matched. | PASS |
| PyPI | `cryptography` | `48.0.0` | Artifact-shape alert from new wheel platform tags; exact tags may drift. | Expected artifact-shape alert matched. | PASS |

No baseline hypothesis changed because of registry drift during this snapshot.

## Baseline Trace Excerpts

`sharp` exercised the npm lifecycle checks:

```text
[npm_lifecycle_scripts] MATCH severity=ALERT
  lifecycle script install: node install/check.js || npm run build
[npm_suspicious_install_commands] MATCH severity=BLOCK
  lifecycle script install suspicious patterns: package-manager invocation
[npm_lifecycle_history] MATCH severity=ALERT
  lifecycle script install absent from 5 compared version(s)
```

`django-filter` exercised PyPI dependency and provenance checks:

```text
[pypi_dependency_change] MATCH severity=ALERT
  compared against version: 25.1
  added dependencies: djangorestframework
  removed dependencies: none
[pypi_provenance] MATCH severity=ALERT
  release files: 2
  provenance checked: 2
  provenance available: 0
```

`sqlalchemy` exercised several PyPI artifact checks:

```text
[pypi_artifact_shape] MATCH severity=ALERT
[pypi_dependency_change] MATCH severity=ALERT
  compared against version: 2.1.0b2
  added dependencies: importlib-metadata, psycopg2
  removed dependencies: cymysql, mssql-python, sqlalchemy, types-greenlet
[pypi_provenance] MATCH severity=ALERT
  release files: 58
  provenance checked: 58
  provenance available: 0
[pypi_release_file_count] MATCH severity=ALERT
  latest release file count: 58
  historical median file count: 63
```

`cryptography` showed a provenance-positive comparison:

```text
[pypi_artifact_shape] MATCH severity=ALERT
[pypi_dependency_change] NO MATCH
  compared against version: 47.0.0
  added dependencies: none
  removed dependencies: none
[pypi_provenance] NO MATCH
  release files: 49
  provenance checked: 49
  provenance available: 49
```

## Temporary Policy Experiments

Each policy experiment ran from a temporary workspace-local directory containing
a full copy of `sourcegate.config.json`. Every policy key remained present in
the `inform`, `alert`, and `block` tiers. The checked-in config was not changed.

| Experiment | Package | Temporary config delta | Expected trace | Observed trace | Result |
| --- | --- | --- | --- | --- | --- |
| Release age | `react` | Set alert-tier `minimum_days_since_latest_release` to `10000`. | `[release_age] MATCH severity=ALERT` | `[release_age] MATCH severity=ALERT` | PASS |
| Protected package | `core-js` | Replace alert-tier npm `protected_packages` with `["corejs"]`. | `[protected_package] MATCH severity=ALERT` | `[protected_package] MATCH severity=ALERT` | PASS |
| Protected token | `core-js` | Replace alert-tier npm `protected_tokens` with `["core"]`. | `[protected_token] MATCH severity=ALERT` | `[protected_token] MATCH severity=ALERT` | PASS |
| npm lifecycle | `sharp` | Keep alert-tier `install_lifecycle_scripts` enabled and disable block-tier `suspicious_install_script_commands` to isolate the lifecycle alert. | `[npm_lifecycle_scripts] MATCH severity=ALERT` | `[npm_lifecycle_scripts] MATCH severity=ALERT` | PASS |
| PyPI size jump | `django-filter` | Keep five history versions and set alert-tier `pypi_file_size_jump_percent` to `1`. | `[pypi_file_size_jump] MATCH severity=ALERT` | `[pypi_file_size_jump] MATCH severity=ALERT` | PASS |

Representative policy-experiment evidence:

```text
[release_age] MATCH severity=ALERT
  thresholds (day(s)): block=disabled, alert=10000, inform=1
  finding: latest release was published 25 day(s) ago, below configured minimum of 10000 day(s)

[protected_package] MATCH severity=ALERT
  normalized package name: core-js
  finding: package name may be typosquatting protected package corejs

[protected_token] MATCH severity=ALERT
  normalized package name: core-js
  finding: package name uses protected token core

[pypi_file_size_jump] MATCH severity=ALERT
  latest total file size: 237963 bytes
  historical median total file size: 237135 bytes
  thresholds (percent): block=disabled, alert=1, inform=disabled
```

## Follow-up Observations

The validation exposed history-selection behavior that should be reviewed
separately:

- npm packages can report `Previous Published` later than the `latest` dist-tag
  timestamp. This occurred for `react`, `sharp`, and `core-js`. The debug trace
  renders the resulting negative inactivity gap as `0 hour(s)`. The adapter
  likely includes prerelease versions when selecting the previous timestamp.
- The PyPI dependency comparison for stable `sqlalchemy 2.0.50` selected
  prerelease `2.1.0b2` as the prior release. Decide whether prereleases should
  participate in historical policy comparisons.
- Packages with many PyPI artifacts, such as `sqlalchemy`, produce many
  provenance findings in the normal report. The debug trace correctly
  summarizes the successful request count, but the normal findings remain
  verbose.

These observations did not prevent the smoke-test matrix or policy experiments
from completing successfully.

## SourceGate 0.5.2 Follow-up

This follow-up records a SourceGate `0.5.2` live-registry validation run
performed on `2026-06-01T01:21:49+03:00`.

Preflight passed:

```powershell
go test ./...
go build -o .\sourcegate-live.exe .\cmd\sourcegate
```

All live commands exited with status `0`. No package was installed.

| Ecosystem | Package | Version | Observed result | Classification |
| --- | --- | --- | --- | --- |
| npm | `react` | `19.2.6` | No findings. Later and prerelease npm versions were skipped for stable history. | PASS |
| npm | `sharp` | `0.34.5` | Lifecycle-script alert, suspicious-command block, and lifecycle-history alert. | PASS |
| npm | `aws-sdk` | `2.1693.0` | Dormant-release and lifecycle-script alerts. Protected-token default is now disabled. | PASS, expected default change |
| npm | `@aws-sdk/client-s3` | `3.1057.0` | Release-age alert only. Protected-token default is now disabled. | PASS, expected default change |
| npm | `core-js` | `3.49.0` | `postinstall` lifecycle-script alert. | PASS |
| PyPI | `requests` | `2.34.2` | No findings. Old releases with missing upload timestamps remained visible in debug but did not poison the filled recent comparison window. | PASS |
| PyPI | `django-filter` | `25.2` | Dormant-release alert and two missing install-target provenance files. Optional dependency changes are ignored by default. | PASS, expected default change |
| PyPI | `pytest-cov` | `7.1.0` | Dormant-release alert and two missing install-target provenance files. Protected-token default is now disabled. | PASS, expected default change |
| PyPI | `sqlalchemy` | `2.0.50` | Artifact-shape, install-target provenance, and release-file-count alerts. Dependency comparison used stable `2.0.49`, not prerelease `2.1.0b2`. | PASS |
| PyPI | `cryptography` | `48.0.0` | Artifact-shape alert. Install-target provenance checked 3 relevant files and all had provenance. | PASS |

Representative `0.5.2` trace excerpts:

```text
[dormant_release] NO MATCH
  selected comparison versions: 2.34.1, 2.34.0, 2.33.1, 2.33.0, 2.32.5, and 153 more
  skipped prerelease versions: 1
  skipped malformed publish times: 0.0.1, 0.12.01, 2.15.0

[pypi_dependency_change] NO MATCH
  compared against version: 2.0.49
  added dependencies: none
  removed dependencies: none

[pypi_provenance] MATCH severity=ALERT
  checked compatible files: 3
  skipped non-target files: 55
  scope install-target missing provenance files: sqlalchemy-2.0.50-cp313-cp313-win_amd64.whl; sqlalchemy-2.0.50-py3-none-any.whl; sqlalchemy-2.0.50.tar.gz
```

The forced fallback smoke test also passed:

```powershell
.\sourcegate-live.exe --debug --python definitely-missing-python pip install cryptography
```

It printed a non-policy warning, fell back to `win_amd64`, checked five
fallback-relevant files, and left the decision as `ALLOW`.
