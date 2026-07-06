# SourceGate Configuration Questionnaire

Use these questions before generating or changing a SourceGate config for a user. The goal is to produce an explicit config file, not hidden preset inheritance.

## Required Questions

1. Where will SourceGate run?
   - Local development only.
   - CI only.
   - Both local development and CI.

2. Which ecosystems should be covered?
   - npm only.
   - PyPI only.
   - Both npm and PyPI.

3. Which baseline should the config start from?
   - `minimal`: low-noise local visibility.
   - `balanced`: recommended default.
   - `strict`: CI-oriented, more block-level policy.

4. What should block immediately?
   - Only high-confidence install-script and archive-safety issues.
   - Also block suspicious artifact behavior.
   - Alert only; do not block yet.

5. Are there important public packages to protect from lookalikes?
   - npm examples: `react`, `lodash`, `@tanstack/react-query`.
   - PyPI examples: `requests`, `django`.

6. Are there private or internal package names that must never resolve from public registries?
   - Ask for exact npm package names and scopes.
   - Ask for exact PyPI distribution names.

7. Should artifact inspection be part of normal use?
   - No, metadata mode is enough.
   - Yes, users will run `--mode artifact`.
   - Yes, CI or install mode should use artifact inspection.

8. How strict should PyPI provenance be?
   - Disabled for now.
   - Alert when install-target provenance is missing.
   - Block when install-target provenance is missing.

## Optional Tuning Questions

1. How much release-age noise is acceptable?
   - Minimal: inform only.
   - Balanced: alert on very recent releases.
   - Strict: block very new releases in CI.

2. Should dependency metadata changes alert?
   - npm dependency name changes.
   - direct npm dependency lifecycle metadata.
   - PyPI dependency changes.

3. Should npm source metadata changes alert?
   - missing repository or `gitHead`.
   - repository, publisher, or `gitHead` changes.
   - release bursts.

4. Should artifact deltas alert?
   - new files.
   - new execution surfaces.
   - new native or executable file types.
   - size and file-count deltas.

## Output Rules For AI Agents

- Generate explicit JSON that only contains the selected groups and checks.
- Do not rely on a preset at runtime unless the user asks to run with `--preset`.
- Prefer `groups` for normal users and `checks` for specific tuning.
- Use `sourcegate config test` after writing a config.
- Use `sourcegate config explain` to summarize the final behavior for the user.
