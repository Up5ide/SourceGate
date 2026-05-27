package sourcegate

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderHumanStatesInspectOnly(t *testing.T) {
	var buf bytes.Buffer
	RenderHuman(&buf, PackageReport{
		Ecosystem:     "npm",
		Registry:      "npm registry",
		Name:          "lodash",
		LatestVersion: "4.17.21",
		Decision:      DecisionAllow,
		Findings: []Finding{
			{Severity: "INFO", Message: "latest release age satisfies configured minimum of 3 day(s)"},
		},
		VersionCount: 2,
	})

	output := buf.String()
	for _, want := range []string{
		"Ecosystem: npm",
		"Package: lodash",
		"Previous Published: unknown",
		"Decision: ALLOW",
		"[INFO] latest release age satisfies configured minimum of 3 day(s)",
		"Install executed: no",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
