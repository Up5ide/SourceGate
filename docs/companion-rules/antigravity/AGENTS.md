# SourceGate Install Rules For Antigravity

Use these instructions as workspace agent guidance in Antigravity, or place them in `AGENTS.md` if the workspace is configured to read agent instruction files.

## Package Installs

- Use `sourcegate --mode install npm install <package>` instead of `npm install <package>`.
- Use `sourcegate --mode install npm install <package>@<version>` instead of `npm install <package>@<version>`.
- Use `sourcegate --mode install pip install <package>` instead of `pip install <package>`.
- Use `sourcegate --mode install pip install <package>==<version>` instead of `pip install <package>==<version>`.
- Prefer exact versions when the requested version is known.

## Policy Results

- `BLOCK` or exit code `30`: stop. Do not install the package another way.
- `ALERT` or exit code `20`: report the alert findings; the install may have completed.
- `INFORM` or exit code `10`: report the informational findings; the install may have completed.
- Operational error or exit code `2`: report the failure and ask before using direct `npm` or `pip`.

## Bypass Rules

Do not bypass SourceGate with direct package-manager commands, alternate registries, direct artifact URLs, or package-manager flags unless the user explicitly approves that action.

If SourceGate is unavailable on `PATH` or does not support the requested install shape, ask the user how to proceed.
