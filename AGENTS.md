# SourceGate AI Rules

- At the start of a new chat or materially new task, read `contex.md` first to understand the project structure, safety boundaries, and conventions. Treat it as orientation only; still inspect the relevant source files before making changes.

- SourceGate policy input is grouped. Each policy tier must include every supported group under `groups`; detailed settings belong under optional `checks` overrides. Group defaults set tier values, and explicit check overrides always win, including `false`. Keep `sourcegate.config.json`, the embedded config fixture, README examples, config structs, validation, registry definitions, and tests aligned with this rule.
