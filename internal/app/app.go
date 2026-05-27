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

	adapter, err := a.adapterFor(req.Ecosystem)
	if err != nil {
		return err
	}

	pkg, err := adapter.FetchMetadata(ctx, req.Package)
	if err != nil {
		return err
	}

	checks.Evaluate(&pkg, cfg, time.Now())
	output.RenderHuman(a.out, pkg)
	return nil
}

func (a *App) adapterFor(ecosystemKey ecosystem.Ecosystem) (ecosystem.Adapter, error) {
	switch ecosystemKey {
	case ecosystem.NPM:
		return npm.New(a.client), nil
	case ecosystem.PyPI:
		return pypi.New(a.client), nil
	default:
		return nil, fmt.Errorf("unsupported ecosystem: %s", ecosystemKey)
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  sourcegate npm install <package>")
	fmt.Fprintln(w, "  sourcegate pip install <package>")
}
