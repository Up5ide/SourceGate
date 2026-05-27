package ecosystem

import (
	"context"

	"github.com/sourcegate/sourcegate/internal/report"
)

type Ecosystem string

const (
	NPM  Ecosystem = "npm"
	PyPI Ecosystem = "pypi"
)

type Adapter interface {
	FetchMetadata(ctx context.Context, packageName string) (report.PackageReport, error)
}
