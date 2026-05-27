package sourcegate

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

type App struct {
	client *http.Client
	out    io.Writer
	errOut io.Writer
}

func NewApp(client *http.Client, out, errOut io.Writer) *App {
	return &App{
		client: client,
		out:    out,
		errOut: errOut,
	}
}

func (a *App) Run(ctx context.Context, args []string) error {
	req, err := ParseInstallCommand(args)
	if err != nil {
		printUsage(a.errOut)
		return err
	}

	var report PackageReport
	switch req.Ecosystem {
	case EcosystemNPM:
		report, err = FetchNPMMetadata(ctx, a.client, req.Package)
	case EcosystemPyPI:
		report, err = FetchPyPIMetadata(ctx, a.client, req.Package)
	default:
		err = fmt.Errorf("unsupported ecosystem: %s", req.Ecosystem)
	}
	if err != nil {
		return err
	}

	RenderHuman(a.out, report)
	return nil
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  sourcegate npm install <package>")
	fmt.Fprintln(w, "  sourcegate pip install <package>")
}
