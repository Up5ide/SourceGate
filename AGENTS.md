# SourceGate AI Rules

- At the start of a new chat or materially new task, read `contex.md` first to understand the project structure, safety boundaries, and conventions. Treat it as orientation only; still inspect the relevant source files before making changes.

- SourceGate policy input is grouped and override-only. Omitted policy, tiers, groups, group keys, and checks are disabled. Group defaults set tier values only when a group is explicitly `true`; detailed settings belong under optional `checks` overrides, and explicit check overrides always win, including `false`. Keep `sourcegate.config.json`, the embedded config fixture, README examples, config structs, validation, registry definitions, and tests aligned with this rule.
