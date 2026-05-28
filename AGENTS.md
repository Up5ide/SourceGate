# SourceGate AI Rules

- When adding any new SourceGate config option under `policy`, always add that option to all three policy tiers: `inform`, `alert`, and `block`. A tier may disable the option with an appropriate neutral value such as `false`, `0`, `{}`, or `[]`, but the key must still be present in every tier. Keep `sourcegate.config.json`, README examples, config structs, validation, and tests aligned with this rule.
