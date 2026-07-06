# SourceGate Companion Rules

These optional rule files help AI coding agents use SourceGate instead of calling `npm install` or `pip install` directly.

Copy the file for your coding tool into the target project. These files do not install SourceGate by themselves; they only instruct the AI assistant to route package installs through SourceGate when the `sourcegate` command is available.

## Available Rule Packs

| Tool | Copy from | Copy to |
| --- | --- | --- |
| Codex | `docs/companion-rules/codex/AGENTS.md` | `AGENTS.md` or merge into an existing `AGENTS.md` |
| Claude Code | `docs/companion-rules/claude/CLAUDE.md` | `CLAUDE.md` or `.claude/CLAUDE.md` |
| Claude Code path rule | `docs/companion-rules/claude/.claude/rules/sourcegate-package-installs.md` | `.claude/rules/sourcegate-package-installs.md` |
| Cursor | `docs/companion-rules/cursor/.cursor/rules/sourcegate-package-installs.mdc` | `.cursor/rules/sourcegate-package-installs.mdc` |
| Antigravity | `docs/companion-rules/antigravity/AGENTS.md` | Use as workspace agent instructions, or as `AGENTS.md` if supported by the workspace |

## What The Rules Require

- Use `sourcegate --mode install npm install <package>` instead of `npm install <package>`.
- Use `sourcegate --mode install pip install <package>` instead of `pip install <package>`.
- Do not silently fall back to direct `npm` or `pip` if SourceGate is unavailable or rejects the command.
- Treat `BLOCK` as a hard stop.
- Treat `ALERT` and `INFORM` as install-completed-with-findings states that must be reported to the user.

## Notes

SourceGate currently supports one package spec per install command. If a user asks for unsupported package-manager options, lockfile installs, requirements files, workspaces, global installs, editable installs, or multiple packages in one command, the agent should ask before using direct package-manager commands.
