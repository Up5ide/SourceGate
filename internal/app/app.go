package app

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sourcegate/sourcegate/internal/checks"
	"github.com/sourcegate/sourcegate/internal/cli"
	"github.com/sourcegate/sourcegate/internal/config"
	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/ecosystem/npm"
	"github.com/sourcegate/sourcegate/internal/ecosystem/pypi"
	"github.com/sourcegate/sourcegate/internal/output"
)

type App struct {
	client *http.Client
	out    io.Writer
	errOut io.Writer
}

func New(client *http.Client, out, errOut io.Writer) *App {
	return &App{
		client: client,
		out:    out,
		errOut: errOut,
	}
}

func (a *App) Run(ctx context.Context, args []string) error {
	req, err := cli.ParseInstallCommand(args)
	if err != nil {
		printUsage(a.errOut)
		return err
	}

	cfg, err := config.Load(config.DefaultPath)
	if err != nil {
		return err
	}

	adapter, err := a.adapterFor(req, cfg)
	if err != nil {
		return err
	}

	pkg, err := adapter.FetchMetadata(ctx, req.Package)
	if err != nil {
		return err
	}

	checks.EvaluateWithOptions(&pkg, cfg, time.Now(), checks.EvaluationOptions{
		Debug: req.Debug,
	})
	output.RenderHuman(a.out, pkg)
	return nil
}

func (a *App) adapterFor(req cli.InstallRequest, cfg config.Config) (ecosystem.Adapter, error) {
	switch req.Ecosystem {
	case ecosystem.NPM:
		return npm.NewWithOptions(a.client, npm.Options{
			HistoryVersions: maxNPMHistoryVersions(cfg.Policy),
		}), nil
	case ecosystem.PyPI:
		return pypi.NewWithOptions(a.client, pypi.Options{
			HistoryVersions:  maxPyPIArtifactHistoryVersions(cfg.Policy),
			ProvenanceScopes: pypiProvenanceScopes(cfg.Policy),
			Target:           effectivePyPITarget(cfg.PyPIRuntime, req.PyPIRuntime),
		}), nil
	default:
		return nil, fmt.Errorf("unsupported ecosystem: %s", req.Ecosystem)
	}
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
	fmt.Fprintln(w, "  sourcegate --debug npm install <package>[@<version>]")
	fmt.Fprintln(w, "  sourcegate --debug pip install <package>[==<version>]")
	fmt.Fprintln(w, "  sourcegate [--debug] [--python <executable>] [--target-platform <platform>] [--python-version <version>] [--implementation <name>] [--abi <abi>] pip install <package>[==<version>]")
	fmt.Fprintln(w, "  sourcegate npm install <package>[@<version>]")
	fmt.Fprintln(w, "  sourcegate pip install <package>[==<version>]")
}
