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
	"github.com/sourcegate/sourcegate/internal/artifactdelta"
	"github.com/sourcegate/sourcegate/internal/checks"
	"github.com/sourcegate/sourcegate/internal/cli"
	"github.com/sourcegate/sourcegate/internal/config"
	"github.com/sourcegate/sourcegate/internal/configsource"
	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/ecosystem/npm"
	"github.com/sourcegate/sourcegate/internal/ecosystem/pypi"
	pkginstaller "github.com/sourcegate/sourcegate/internal/installer"
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
	installer             packageInstaller
	loadConfig            func(string) (config.Config, error)
	configStatus          func(string) configsource.Status
	configMode            func() string
	acceptsExternalConfig func() bool
	acceptedConfigInputs  func() string
}

type packageInstaller interface {
	Install(context.Context, pkginstaller.Request) report.InstallSummary
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
		installer:             pkginstaller.New(),
		loadConfig:            configsource.Load,
		configStatus:          configsource.PrintStatus,
		configMode:            configsource.Mode,
		acceptsExternalConfig: configsource.AcceptsExternalConfig,
		acceptedConfigInputs:  configsource.AcceptedInputs,
	}
}

func (a *App) Run(ctx context.Context, args []string) (RunResult, error) {
	rawArgs := append([]string(nil), args...)
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
		if err := renderConfigStatus(a.out, a.configStatusForRequest(req)); err != nil {
			return RunResult{ExitCode: ExitOperationalError}, err
		}
		return RunResult{ExitCode: ExitClean}, nil
	case cli.ActionConfigTest:
		cfg, err := a.loadConfigForRequest(req)
		if err != nil {
			fmt.Fprintf(a.errOut, "Config invalid: %v\n", err)
			return RunResult{ExitCode: ExitOperationalError}, err
		}
		fmt.Fprintln(a.out, "Config valid.")
		for _, diagnostic := range config.Diagnostics(cfg) {
			fmt.Fprintf(a.out, "Note: %s\n", diagnostic)
		}
		return RunResult{ExitCode: ExitClean}, nil
	case cli.ActionConfigExplain:
		cfg, err := a.loadConfigForRequest(req)
		if err != nil {
			fmt.Fprintf(a.errOut, "Config invalid: %v\n", err)
			return RunResult{ExitCode: ExitOperationalError}, err
		}
		renderConfigExplanation(a.out, cfg)
		return RunResult{ExitCode: ExitClean}, nil
	case cli.ActionConfigPreset:
		data, err := config.PresetJSON(req.ConfigPreset, req.PresetFormat)
		if err != nil {
			return RunResult{ExitCode: ExitOperationalError}, err
		}
		if _, err := a.out.Write(data); err != nil {
			return RunResult{ExitCode: ExitOperationalError}, err
		}
		return RunResult{ExitCode: ExitClean}, nil
	}

	cfg, err := a.loadConfigForRequest(req)
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
	pkg.EvaluationMode = req.Mode
	if req.Mode == cli.ModeInstall {
		pkg.Warnings = append(pkg.Warnings, "install mode gates only the requested root package; transitive dependencies are resolved by the package manager and are not fully gated yet.")
	}

	checks.EvaluateWithOptions(&pkg, cfg, time.Now(), checks.EvaluationOptions{
		Debug: req.Debug,
	})
	exitCode := ExitCodeForReport(pkg)
	if req.Mode == cli.ModeMetadata && checks.ArtifactPolicyEnabled(cfg.Policy) {
		pkg.Warnings = append(pkg.Warnings, "artifact checks are enabled by policy but did not run because the command used metadata mode.")
	}
	if req.Mode == cli.ModeArtifact || req.Mode == cli.ModeInstall {
		var inspectErr error
		exitCode, inspectErr = a.inspectArtifact(ctx, &pkg, cfg, req.Debug)
		if inspectErr != nil {
			return RunResult{Report: pkg, ExitCode: ExitOperationalError}, inspectErr
		}
	}
	if req.Mode == cli.ModeInstall {
		exitCode = a.installIfAllowed(ctx, &pkg, req, exitCode)
	}
	switch req.OutputFormat {
	case cli.OutputFormatJSON:
		if err := output.RenderJSON(a.out, pkg); err != nil {
			return RunResult{Report: pkg, ExitCode: ExitOperationalError}, err
		}
	case cli.OutputFormatReport:
		var configStatus *configsource.Status
		if req.ReportVerbose {
			status := a.configStatusForRequest(req)
			configStatus = &status
		}
		if err := output.RenderReport(a.out, pkg, output.ReportOptions{
			Argv:         append([]string{"sourcegate"}, rawArgs...),
			Manager:      req.Manager,
			Command:      req.Command,
			ExitCode:     exitCode,
			ConfigStatus: configStatus,
		}); err != nil {
			return RunResult{Report: pkg, ExitCode: ExitOperationalError}, err
		}
	default:
		output.RenderHuman(a.out, pkg)
	}
	return RunResult{Report: pkg, ExitCode: exitCode}, nil
}

func (a *App) loadConfigForRequest(req cli.InstallRequest) (config.Config, error) {
	if req.Preset != "" {
		return config.LoadPreset(req.Preset)
	}
	return a.loadConfig(req.ConfigPath)
}

func (a *App) configStatusForRequest(req cli.InstallRequest) configsource.Status {
	if req.Preset == "" {
		return a.configStatus(req.ConfigPath)
	}
	cfg, err := config.LoadPreset(req.Preset)
	status := configsource.Status{
		ConfigMode:            a.configMode(),
		AcceptsExternalConfig: a.acceptsExternalConfig(),
		Preset:                req.Preset,
		Exists:                true,
	}
	if err != nil {
		status.Valid = false
		status.Error = err.Error()
		return status
	}
	status.Valid = true
	status.Config = &cfg
	return status
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

func (a *App) inspectArtifact(ctx context.Context, pkg *report.PackageReport, cfg config.Config, debug bool) (int, error) {
	if pkg.Decision == report.DecisionBlock {
		pkg.ArtifactDownload = &report.ArtifactDownloadSummary{Status: report.ArtifactDownloadStatusSkippedBlocked}
		return ExitCodeForReport(*pkg), nil
	}

	var inspection report.ArtifactInspectionSummary
	summary, err := artifact.DownloadAndVerify(ctx, a.client, pkg.ArtifactCandidate, func(path string) error {
		var inspectErr error
		inspection, inspectErr = archiveinspect.Inspect(path, pkg.ArtifactCandidate.Filename)
		return inspectErr
	})
	if err != nil {
		return ExitOperationalError, err
	}
	pkg.ArtifactDownload = &summary
	pkg.ArtifactInspection = &inspection
	if checks.RequiresArtifactDelta(cfg.Policy) {
		delta := a.downloadPreviousArtifactDelta(ctx, *pkg)
		pkg.ArtifactDelta = &delta
	}
	checks.EvaluateArtifactInspection(pkg, cfg, checks.EvaluationOptions{
		Debug: debug,
	})
	return ExitCodeForReport(*pkg), nil
}

func (a *App) installIfAllowed(ctx context.Context, pkg *report.PackageReport, req cli.InstallRequest, exitCode int) int {
	installReq := installRequest(req, *pkg)
	if pkg.Decision == report.DecisionBlock {
		summary := report.InstallSummary{
			Status:   report.InstallStatusSkippedBlocked,
			Executed: false,
			Manager:  req.Manager,
			Message:  "policy decision BLOCK skipped package-manager install",
		}
		if exactSpec, err := pkginstaller.ExactPackageSpec(installReq); err == nil {
			summary.PackageSpec = exactSpec
		}
		pkg.Install = &summary
		return exitCode
	}

	runner := a.installer
	if runner == nil {
		defaultRunner := pkginstaller.New()
		runner = defaultRunner
	}
	summary := runner.Install(ctx, installReq)
	pkg.Install = &summary
	if summary.Status != report.InstallStatusExecutedSuccess {
		return ExitOperationalError
	}
	return exitCode
}

func installRequest(req cli.InstallRequest, pkg report.PackageReport) pkginstaller.Request {
	return pkginstaller.Request{
		Ecosystem:       req.Ecosystem,
		Manager:         req.Manager,
		PackageName:     pkg.Name,
		SelectedVersion: pkg.SelectedVersion,
	}
}

func (a *App) downloadPreviousArtifactDelta(ctx context.Context, pkg report.PackageReport) report.ArtifactDeltaSummary {
	if pkg.ArtifactInspection == nil {
		return artifactdelta.Unavailable(pkg.PreviousArtifactCandidate, "selected artifact inspection is unavailable")
	}
	candidate := pkg.PreviousArtifactCandidate
	if candidate.SelectionError != "" {
		return artifactdelta.Unavailable(candidate, "previous comparable artifact selection failed: "+candidate.SelectionError)
	}
	if candidate.URL == "" && candidate.Filename == "" {
		return artifactdelta.Unavailable(candidate, "immediate previous comparable artifact is unavailable")
	}

	var previousInspection report.ArtifactInspectionSummary
	download, err := artifact.DownloadAndVerify(ctx, a.client, candidate, func(path string) error {
		var inspectErr error
		previousInspection, inspectErr = archiveinspect.Inspect(path, candidate.Filename)
		return inspectErr
	})
	if err != nil {
		delta := artifactdelta.Unavailable(candidate, "previous comparable artifact download or inspection failed: "+err.Error())
		delta.PreviousArtifactDownloadStatus = download.Status
		delta.PreviousArtifactDigestVerified = download.DigestVerified
		delta.PreviousArtifactDownloadedSize = download.DownloadedSize
		delta.PreviousArtifactDigestAlgorithm = download.DigestAlgorithm
		delta.PreviousArtifactInspectionError = err.Error()
		return delta
	}
	return artifactdelta.Compare(*pkg.ArtifactInspection, previousInspection, candidate, download)
}

func (a *App) adapterFor(req cli.InstallRequest, cfg config.Config) (ecosystem.Adapter, error) {
	switch req.Ecosystem {
	case ecosystem.NPM:
		needsArtifact := req.Mode == cli.ModeArtifact || req.Mode == cli.ModeInstall
		return npm.NewWithOptions(a.client, npm.Options{
			HistoryVersions:           checks.RequiredNPMHistoryVersions(cfg.Policy),
			SelectArtifact:            needsArtifact,
			SelectPreviousArtifact:    needsArtifact && checks.RequiresArtifactDelta(cfg.Policy),
			InspectDirectDependencies: checks.RequiresNPMDirectDependencyInspection(cfg.Policy),
			MaxDirectDependencies:     checks.MaxNPMDirectDependencies(cfg.Policy),
		}), nil
	case ecosystem.PyPI:
		needsArtifact := req.Mode == cli.ModeArtifact || req.Mode == cli.ModeInstall
		return pypi.NewWithOptions(a.client, pypi.Options{
			HistoryVersions:        checks.RequiredPyPIArtifactHistoryVersions(cfg.Policy),
			FetchDependencies:      checks.RequiresPyPIDependencyHistory(cfg.Policy),
			SelectArtifact:         needsArtifact,
			SelectPreviousArtifact: needsArtifact && checks.RequiresArtifactDelta(cfg.Policy),
			ProvenanceScopes:       checks.RequiredPyPIProvenanceScopes(cfg.Policy),
			Target:                 effectivePyPITarget(cfg.PyPIRuntime, req.PyPIRuntime),
		}), nil
	default:
		return nil, fmt.Errorf("unsupported ecosystem: %s", req.Ecosystem)
	}
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
	fmt.Fprintln(w, "  sourcegate config test [--config <path>]")
	fmt.Fprintln(w, "  sourcegate config explain [--config <path>]")
	fmt.Fprintln(w, "  sourcegate config preset <minimal|balanced|strict> [--format compact|full]")
	fmt.Fprintln(w, "  sourcegate [--config <path>|--preset <name>] [--mode metadata|artifact|install] [--debug] [--format human|json|report] [-v] npm install <package>[@<version>]")
	fmt.Fprintln(w, "  sourcegate [--config <path>|--preset <name>] [--mode metadata|artifact|install] [--debug] [--format human|json|report] [-v] pip install <package>[==<version>]")
	fmt.Fprintln(w, "  sourcegate [--config <path>|--preset <name>] [--mode metadata|artifact|install] [--debug] [--format human|json|report] [-v] [--python <executable>] [--target-platform <platform>] [--python-version <version>] [--implementation <name>] [--abi <abi>] pip install <package>[==<version>]")
	fmt.Fprintln(w, "  sourcegate --inspect ...  (deprecated alias for --mode artifact)")
}

func printHelp(w io.Writer, configMode, acceptedConfigInputs string) {
	printUsage(w)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  --help                         Show this help text.")
	fmt.Fprintln(w, "  --version                      Show version, config mode, and build metadata when available.")
	fmt.Fprintln(w, "  --config <path>                Use a custom config file in relaxed file-config builds.")
	fmt.Fprintln(w, "  --preset <name>                Use a hard-coded config preset for this run.")
	fmt.Fprintln(w, "  --print-config                 Print JSON config status and the effective config when valid.")
	fmt.Fprintln(w, "  config test                    Validate configuration without registry access.")
	fmt.Fprintln(w, "  config explain                 Summarize effective configuration without registry access.")
	fmt.Fprintln(w, "  config preset                  Print a hard-coded preset config.")
	fmt.Fprintln(w, "  --mode metadata                Inspect registry metadata only. This is the current default.")
	fmt.Fprintln(w, "  --mode artifact                Inspect metadata, then download and inspect one verified install-target artifact if metadata policy does not block.")
	fmt.Fprintln(w, "  --mode install                 Inspect metadata and one verified root artifact, then run the real package-manager install unless policy blocks.")
	fmt.Fprintln(w, "  --inspect                      Deprecated alias for --mode artifact.")
	fmt.Fprintln(w, "  --debug                        Include a bounded policy evaluation trace.")
	fmt.Fprintln(w, "  --format human|json|report     Select output format for package inspection.")
	fmt.Fprintln(w, "  -v                             Include effective configuration with --format report.")
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

func renderConfigExplanation(w io.Writer, cfg config.Config) {
	fmt.Fprintln(w, "SourceGate configuration")
	renderTierExplanation(w, "inform", cfg.Policy.Inform)
	renderTierExplanation(w, "alert", cfg.Policy.Alert)
	renderTierExplanation(w, "block", cfg.Policy.Block)
	diagnostics := config.Diagnostics(cfg)
	if len(diagnostics) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Notes:")
		for _, diagnostic := range diagnostics {
			fmt.Fprintf(w, "- %s\n", diagnostic)
		}
	}
}

func renderTierExplanation(w io.Writer, name string, tier config.PolicyTierConfig) {
	fmt.Fprintf(w, "\n%s tier:\n", name)
	lines := tierExplanationLines(tier)
	if len(lines) == 0 {
		fmt.Fprintln(w, "- disabled")
		return
	}
	for _, line := range lines {
		fmt.Fprintf(w, "- %s\n", line)
	}
}

func tierExplanationLines(tier config.PolicyTierConfig) []string {
	var lines []string
	if tier.MinimumDaysSinceLatestRelease > 0 {
		lines = append(lines, fmt.Sprintf("release age must be at least %d day(s)", tier.MinimumDaysSinceLatestRelease))
	}
	if tier.DormantReleaseThresholdDays > 0 {
		lines = append(lines, fmt.Sprintf("dormant release threshold is %d day(s)", tier.DormantReleaseThresholdDays))
	}
	if tier.AlertOnFirstRelease {
		lines = append(lines, "first-release packages are checked")
	}
	if tier.InstallLifecycleScripts {
		lines = append(lines, "npm install lifecycle scripts are checked")
	}
	if tier.SuspiciousInstallScriptCommands {
		lines = append(lines, "suspicious npm install script commands are checked")
	}
	if tier.InstallLifecycleHistoryVersions > 0 {
		lines = append(lines, fmt.Sprintf("npm lifecycle history compares %d previous version(s)", tier.InstallLifecycleHistoryVersions))
	}
	if tier.NPMDependencyChange || tier.NPMDirectDependencyLifecycleScripts || tier.NPMDirectDependencySuspiciousInstallCommands {
		lines = append(lines, "npm dependency metadata is checked")
	}
	if tier.PyPIArtifactShapeChange || tier.PyPIFileSizeJumpPercent > 0 || tier.PyPIDependencyChange || tier.PyPIProvenanceRequired || tier.PyPIReleaseFileCountChange {
		lines = append(lines, "PyPI artifact metadata is checked")
	}
	if tier.NPMGitHeadMissing || tier.NPMRepositoryMissing || tier.NPMGitHeadChangedAfterDormancy || tier.NPMRepositoryChanged || tier.NPMPublisherChanged || tier.NPMReleaseBurstCount > 0 {
		lines = append(lines, "npm source and publisher metadata is checked")
	}
	if tier.ArtifactUnsafePaths || tier.ArtifactMaxFileCount > 0 || tier.ArtifactMaxUncompressedSizeMB > 0 || tier.ArtifactMaxExpansionRatio > 0 {
		lines = append(lines, "artifact safety checks are enabled")
	}
	if tier.ArtifactExecutionSurfaces || tier.ArtifactSuspiciousFileTypes || tier.ArtifactBehaviorIndicators || tier.ArtifactGeneralRiskSignals || tier.ArtifactFileListChange || tier.ArtifactNewExecutionSurfaces || tier.ArtifactNewSuspiciousFileTypes || tier.ArtifactSizeDelta {
		lines = append(lines, "artifact behavior and delta checks are enabled")
	}
	if len(tier.ProtectedPackages) > 0 {
		lines = append(lines, "protected package name checks are configured")
	}
	if len(tier.ProtectedTokens) > 0 {
		lines = append(lines, "protected token checks are configured")
	}
	if len(tier.PrivatePackages) > 0 {
		lines = append(lines, "private package public-registry checks are configured")
	}
	return lines
}
