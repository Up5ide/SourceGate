package artifactexecution

import (
	"strings"
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestCheckExecutionSurfaces(t *testing.T) {
	empty := report.PackageReport{ArtifactInspection: &report.ArtifactInspectionSummary{}}
	if findings := CheckExecutionSurfaces(empty); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}

	pkg := report.PackageReport{
		ArtifactInspection: &report.ArtifactInspectionSummary{
			ExecutionSurfaceCount: 2,
			ExecutionSurfaceExamples: []report.ArtifactExecutionSurface{
				{Type: "npm_lifecycle_script", Path: "package/package.json", Name: "postinstall", Detail: "node setup.js"},
				{Type: "pypi_build_file", Path: "pkg/setup.py", Name: "setup.py"},
			},
		},
	}
	findings := CheckExecutionSurfaces(pkg)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one", findings)
	}
	for _, want := range []string{"2 install/build execution surface", "postinstall", "setup.py"} {
		if !strings.Contains(findings[0].Message, want) {
			t.Fatalf("message = %q, want %q", findings[0].Message, want)
		}
	}
}
