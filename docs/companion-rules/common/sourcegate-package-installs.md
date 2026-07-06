# SourceGate Package Install Rule

When adding or installing npm or PyPI packages, route the install through SourceGate instead of calling the package manager directly.

## Required Behavior

- Use `sourcegate --mode install npm install <package>` instead of `npm install <package>`.
- Use `sourcegate --mode install npm install <package>@<version>` instead of `npm install <package>@<version>`.
- Use `sourcegate --mode install pip install <package>` instead of `pip install <package>`.
- Use `sourcegate --mode install pip install <package>==<version>` instead of `pip install <package>==<version>`.
- Prefer exact versions when the requested version is known.
- If SourceGate returns `BLOCK` or exit code `30`, stop and do not install the package another way.
- If SourceGate returns `ALERT` or exit code `20`, the install may have completed, but report the alert findings to the user.
- If SourceGate returns `INFORM` or exit code `10`, the install may have completed, but report the informational findings to the user.
- If SourceGate is not installed, unavailable on `PATH`, or rejects the command shape, ask the user before falling back to direct `npm` or `pip`.

## Do Not Bypass

Do not run direct `npm install` or `pip install` to work around SourceGate policy findings.

Do not automatically retry a blocked install with package-manager flags, alternate package names, alternate registries, or direct artifact URLs unless the user explicitly approves that different action.

## Unsupported Command Shapes

SourceGate currently supports one package spec per command. Ask the user before using direct package-manager commands for:

- multiple packages in one install command
- `npm install` with no package argument
- `pip install -r requirements.txt`
- lockfile-only installs
- global installs
- editable installs
- local path, Git URL, tarball, or wheel installs
- package-manager options not accepted by SourceGate
