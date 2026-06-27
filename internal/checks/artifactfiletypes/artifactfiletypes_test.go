package artifactfiletypes

import (
	"strings"
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestCheckSuspiciousFileTypes(t *testing.T) {
	empty := report.PackageReport{ArtifactInspection: &report.ArtifactInspectionSummary{}}
	if findings := CheckSuspiciousFileTypes(empty); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}

	pkg := report.PackageReport{
		ArtifactInspection: &report.ArtifactInspectionSummary{
			SuspiciousFileTypeCount: 2,
			SuspiciousFileTypeExamples: []report.ArtifactSuspiciousFileType{
				{Type: "elf_binary", Path: "pkg/bin/tool", Reason: "magic", Detail: "ELF executable or shared object"},
				{Type: "node_native_extension", Path: "package/build/addon.node", Reason: "extension", Detail: ".node"},
			},
		},
	}
	findings := CheckSuspiciousFileTypes(pkg)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one", findings)
	}
	for _, want := range []string{"2 suspicious native/executable file type", "elf_binary", "addon.node"} {
		if !strings.Contains(findings[0].Message, want) {
			t.Fatalf("message = %q, want %q", findings[0].Message, want)
		}
	}
}
