# SourceGate AI Rules

- At the start of a new chat or materially new task, read `contex.md` first to understand the project structure, safety boundaries, and conventions. Treat it as orientation only; still inspect the relevant source files before making changes.

- SourceGate policy input is grouped and override-only. Omitted policy, tiers, groups, group keys, and checks are disabled. Group defaults set tier values only when a group is explicitly `true`; detailed settings belong under optional `checks` overrides, and explicit check overrides always win, including `false`. Keep `sourcegate.config.json`, the embedded config fixture, README examples, config structs, validation, registry definitions, and tests aligned with this rule.

- After code changes, search for Markdown files. If the change affects user-facing behavior, CLI usage, configuration, versioning, architecture, tests, safety boundaries, or AI-assistant project context, update the relevant Markdown files in the same task without asking first. Always consider `README.md` for GitHub/user-facing behavior, `contex.md` for AI-assistant orientation, and `docs/*.md` for design, configuration, attack-vector, and smoke-test behavior. Ask before editing Markdown only when the documentation change is subjective, unusually large, or not clearly implied by the code change.
