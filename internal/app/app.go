package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sourcegate/sourcegate/internal/archiveinspect"
	"github.com/sourcegate/sourcegate/internal/artifact"
	"github.com/sourcegate/sourcegate/internal/checks"
	"github.com/sourcegate/sourcegate/internal/cli"
	"github.com/sourcegate/sourcegate/internal/config"
	"github.com/sourcegate/sourcegate/internal/configsource"
	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/ecosystem/npm"
	"github.com/sourcegate/sourcegate/internal/ecosystem/pypi"
	"github.com/sourcegate/sourcegate/internal/output"
	"github.com/sourcegate/sourcegate/internal/report"
	"github.com/sourcegate/sourcegate/internal/version"
)

const (
	ExitClean            = 0
	ExitInformFinding    = 10
	ExitAlertFinding     = 20
	ExitBlockFinding     = 30
	ExitOperationalError = 2
)

type App struct {
	client                *http.Client
	out                   io.Writer
	errOut                io.Writer
	loadConfig            func(string) (config.Config, error)
	configStatus          func(string) configsource.Status
	configMode            func() string
	acceptsExternalConfig func() bool
	acceptedConfigInputs  func() string
}

type RunResult struct {
	Report   report.PackageReport
	ExitCode int
}

func New(client *http.Client, out, errOut io.Writer) *App {
	return &App{
		client:                client,
		out:                   out,
		errOut:                errOut,
		loadConfig:            configsource.Load,
		configStatus:          configsource.PrintStatus,
		configMode:            configsource.Mode,
		acceptsExternalConfig: configsource.AcceptsExternalConfig,
		acceptedConfigInputs:  configsource.AcceptedInputs,
	}
}

func (a *App) Run(ctx context.Context, args []string) (RunResult, error) {
	req, err := cli.ParseInstallCommand(args)
	if err != nil {
		printUsage(a.errOut)
		return RunResult{ExitCode: ExitOperationalError}, err
	}

	if req.ConfigPath != "" && !a.acceptsExternalConfig() {
		printUsage(a.errOut)
		return RunResult{ExitCode: ExitOperationalError}, fmt.Errorf("embedded config build does not accept --config")
	}

	switch req.Action {
	case cli.ActionHelp:
		printHelp(a.out, a.configMode(), a.acceptedConfigInputs())
		return RunResult{ExitCode: ExitClean}, nil
	case cli.ActionVersion:
		printVersion(a.out, a.configMode(), a.acceptedConfigInputs())
		return RunResult{ExitCode: ExitClean}, nil
	case cli.ActionPrintConfig:
		if err := renderConfigStatus(a.out, a.configStatus(req.ConfigPath)); err != nil {
			return RunResult{ExitCode: ExitOperationalError}, err
		}
		return RunResult{ExitCode: ExitClean}, nil
	}

	if req.Mode == cli.ModeInstall {
		return RunResult{ExitCode: ExitOperationalError}, fmt.Errorf("install mode is reserved for SourceGate 1.0 and is not implemented yet")
	}

	cfg, err := a.loadConfig(req.ConfigPath)
	if err != nil {
		return RunResult{ExitCode: ExitOperationalError}, err
	}

	adapter, err := a.adapterFor(req, cfg)
	if err != nil {
		return RunResult{ExitCode: ExitOperationalError}, err
	}

	pkg, err := adapter.FetchMetadata(ctx, req.Package)
	if err != nil {
		return RunResult{ExitCode: ExitOperationalError}, err
	}

	checks.EvaluateWithOptions(&pkg, cfg, time.Now(), checks.EvaluationOptions{
		Debug: req.Debug,
	})
	exitCode := ExitCodeForReport(pkg)
	if req.Mode == cli.ModeArtifact {
		if pkg.Decision == report.DecisionBlock {
			pkg.ArtifactDownload = &report.ArtifactDownloadSummary{Status: report.ArtifactDownloadStatusSkippedBlocked}
		} else {
			var inspection report.ArtifactInspectionSummary
			summary, err := artifact.DownloadAndVerify(ctx, a.client, pkg.ArtifactCandidate, func(path string) error {
				var inspectErr error
				inspection, inspectErr = archiveinspect.Inspect(path, pkg.ArtifactCandidate.Filename)
				return inspectErr
			})
			if err != nil {
				return RunResult{Report: pkg, ExitCode: ExitOperationalError}, err
			}
			pkg.ArtifactDownload = &summary
			pkg.ArtifactInspection = &inspection
			checks.EvaluateArtifactInspection(&pkg, cfg, checks.EvaluationOptions{
				Debug: req.Debug,
			})
			exitCode = ExitCodeForReport(pkg)
		}
	}
	switch req.OutputFormat {
	case cli.OutputFormatJSON:
		if err := output.RenderJSON(a.out, pkg); err != nil {
			return RunResult{Report: pkg, ExitCode: ExitOperationalError}, err
		}
	default:
		output.RenderHuman(a.out, pkg)
	}
	return RunResult{Report: pkg, ExitCode: exitCode}, nil
}

func ExitCodeForReport(pkg report.PackageReport) int {
	exitCode := ExitClean
	for _, finding := range pkg.Findings {
		switch finding.Severity {
		case "BLOCK":
			return ExitBlockFinding
		case "ALERT":
			if exitCode < ExitAlertFinding {
				exitCode = ExitAlertFinding
			}
		case "INFORM":
			if exitCode < ExitInformFinding {
				exitCode = ExitInformFinding
			}
		}
	}
	return exitCode
}

func (a *App) adapterFor(req cli.InstallRequest, cfg config.Config) (ecosystem.Adapter, error) {
	switch req.Ecosystem {
	case ecosystem.NPM:
		return npm.NewWithOptions(a.client, npm.Options{
			HistoryVersions: maxNPMHistoryVersions(cfg.Policy),
			SelectArtifact:  req.Mode == cli.ModeArtifact,
		}), nil
	case ecosystem.PyPI:
		return pypi.NewWithOptions(a.client, pypi.Options{
			HistoryVersions:   maxPyPIArtifactHistoryVersions(cfg.Policy),
			FetchDependencies: pypiDependencyHistoryEnabled(cfg.Policy),
			SelectArtifact:    req.Mode == cli.ModeArtifact,
			ProvenanceScopes:  pypiProvenanceScopes(cfg.Policy),
			Target:            effectivePyPITarget(cfg.PyPIRuntime, req.PyPIRuntime),
		}), nil
	default:
		return nil, fmt.Errorf("unsupported ecosystem: %s", req.Ecosystem)
	}
}

func pypiDependencyHistoryEnabled(policy config.PolicyConfig) bool {
	for _, tier := range []config.PolicyTierConfig{policy.Inform, policy.Alert, policy.Block} {
		if tier.PyPIDependencyChange {
			return true
		}
	}
	return false
}

func maxNPMHistoryVersions(policy config.PolicyConfig) int {
	max := 0
	for _, tier := range []config.PolicyTierConfig{policy.Inform, policy.Alert, policy.Block} {
		if tier.InstallLifecycleHistoryVersions > max {
			max = tier.InstallLifecycleHistoryVersions
		}
	}
	return max
}

func maxPyPIArtifactHistoryVersions(policy config.PolicyConfig) int {
	max := 0
	for _, tier := range []config.PolicyTierConfig{policy.Inform, policy.Alert, policy.Block} {
		if tier.PyPIArtifactHistoryVersions > max {
			max = tier.PyPIArtifactHistoryVersions
		}
	}
	return max
}

func pypiProvenanceScopes(policy config.PolicyConfig) []string {
	seen := make(map[string]struct{})
	for _, tier := range []config.PolicyTierConfig{policy.Inform, policy.Alert, policy.Block} {
		if tier.PyPIProvenanceRequired {
			seen[tier.PyPIProvenanceScope] = struct{}{}
		}
	}
	scopes := make([]string, 0, len(seen))
	for scope := range seen {
		scopes = append(scopes, scope)
	}
	return scopes
}

func effectivePyPITarget(runtime config.PyPIRuntimeConfig, overrides cli.PyPIRuntimeOptions) pypi.TargetOptions {
	target := pypi.TargetOptions{
		TargetPlatform: runtime.TargetPlatform,
		PythonVersion:  runtime.PythonVersion,
		Implementation: runtime.Implementation,
		ABIs:           append([]string(nil), runtime.ABIs...),
	}
	if overrides.PythonExecutable != "" {
		target.PythonExecutable = overrides.PythonExecutable
	}
	if overrides.TargetPlatform != "" {
		target.TargetPlatform = overrides.TargetPlatform
	}
	if overrides.PythonVersion != "" {
		target.PythonVersion = overrides.PythonVersion
	}
	if overrides.Implementation != "" {
		target.Implementation = overrides.Implementation
	}
	if len(overrides.ABIs) > 0 {
		target.ABIs = append([]string(nil), overrides.ABIs...)
	}
	return target
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  sourcegate --help")
	fmt.Fprintln(w, "  sourcegate --version")
	fmt.Fprintln(w, "  sourcegate [--config <path>] --print-config")
	fmt.Fprintln(w, "  sourcegate [--config <path>] [--mode metadata|artifact|install] [--debug] [--format human|json] npm install <package>[@<version>]")
	fmt.Fprintln(w, "  sourcegate [--config <path>] [--mode metadata|artifact|install] [--debug] [--format human|json] pip install <package>[==<version>]")
	fmt.Fprintln(w, "  sourcegate [--config <path>] [--mode metadata|artifact|install] [--debug] [--format human|json] [--python <executable>] [--target-platform <platform>] [--python-version <version>] [--implementation <name>] [--abi <abi>] pip install <package>[==<version>]")
	fmt.Fprintln(w, "  sourcegate --inspect ...  (deprecated alias for --mode artifact)")
}

func printHelp(w io.Writer, configMode, acceptedConfigInputs string) {
	printUsage(w)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  --help                         Show this help text.")
	fmt.Fprintln(w, "  --version                      Show version, config mode, and build metadata when available.")
	fmt.Fprintln(w, "  --config <path>                Use a custom config file in relaxed file-config builds.")
	fmt.Fprintln(w, "  --print-config                 Print JSON config status and the effective config when valid.")
	fmt.Fprintln(w, "  --mode metadata                Inspect registry metadata only. This is the current default.")
	fmt.Fprintln(w, "  --mode artifact                Inspect metadata, then download and inspect one verified install-target artifact if metadata policy does not block.")
	fmt.Fprintln(w, "  --mode install                 Reserved for SourceGate 1.0; accepted but not implemented yet.")
	fmt.Fprintln(w, "  --inspect                      Deprecated alias for --mode artifact.")
	fmt.Fprintln(w, "  --debug                        Include a bounded policy evaluation trace.")
	fmt.Fprintln(w, "  --format human|json            Select report output format for package inspection.")
	fmt.Fprintln(w, "  --python <executable>          Python executable used only for PyPI compatibility-tag inspection.")
	fmt.Fprintln(w, "  --target-platform <platform>   PyPI target platform override.")
	fmt.Fprintln(w, "  --python-version <version>     PyPI target Python version override.")
	fmt.Fprintln(w, "  --implementation <name>        PyPI target implementation override.")
	fmt.Fprintln(w, "  --abi <abi>                    PyPI target ABI override. May be repeated.")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Config mode: %s\n", configMode)
	fmt.Fprintf(w, "Config inputs: %s\n", acceptedConfigInputs)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Exit codes: 0 clean, 10 inform, 20 alert, 30 block, 2 usage/config/registry/network/operational error.")
}

func printVersion(w io.Writer, configMode, acceptedConfigInputs string) {
	fmt.Fprintf(w, "SourceGate version: %s\n", version.Current)
	fmt.Fprintf(w, "Config mode: %s\n", configMode)
	fmt.Fprintf(w, "Config inputs: %s\n", acceptedConfigInputs)
	build := version.Build()
	if build.Commit != "" {
		fmt.Fprintf(w, "Commit: %s\n", build.Commit)
	}
	if build.CommitDate != "" {
		fmt.Fprintf(w, "Commit date: %s\n", build.CommitDate)
	}
	if build.Modified != "" {
		fmt.Fprintf(w, "Modified: %s\n", build.Modified)
	}
}

func renderConfigStatus(w io.Writer, status configsource.Status) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(status)
}
