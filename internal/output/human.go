package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/sourcegate/sourcegate/internal/report"
)

func RenderHuman(w io.Writer, pkg report.PackageReport) {
	fmt.Fprintf(w, "Ecosystem: %s\n", pkg.Ecosystem)
	fmt.Fprintf(w, "Registry: %s\n", pkg.Registry)
	fmt.Fprintf(w, "Package: %s\n", valueOrUnknown(pkg.Name))
	fmt.Fprintf(w, "Latest Version: %s\n", valueOrUnknown(pkg.LatestVersion))
	fmt.Fprintf(w, "Latest Published: %s\n", valueOrUnknown(pkg.LatestPublishedAt))
	fmt.Fprintf(w, "Previous Published: %s\n", valueOrUnknown(pkg.PreviousPublishedAt))
	fmt.Fprintf(w, "Description: %s\n", valueOrUnknown(pkg.Description))
	fmt.Fprintf(w, "License: %s\n", valueOrUnknown(pkg.License))
	fmt.Fprintf(w, "Author: %s\n", valueOrUnknown(pkg.Author))
	fmt.Fprintf(w, "Versions: %d\n", pkg.VersionCount)
	fmt.Fprintf(w, "Created: %s\n", valueOrUnknown(pkg.CreatedAt))
	fmt.Fprintf(w, "Modified: %s\n", valueOrUnknown(pkg.ModifiedAt))

	if len(pkg.Maintainers) > 0 {
		fmt.Fprintf(w, "Maintainers: %s\n", strings.Join(pkg.Maintainers, ", "))
	}
	if len(pkg.ProjectURLs) > 0 {
		fmt.Fprintln(w, "Project URLs:")
		for _, url := range pkg.ProjectURLs {
			fmt.Fprintf(w, "  - %s\n", url)
		}
	}
	if pkg.PolicySummary != "" {
		fmt.Fprintf(w, "Policy: %s\n", pkg.PolicySummary)
	}
	if len(pkg.Warnings) > 0 {
		fmt.Fprintln(w, "Warnings:")
		for _, warning := range pkg.Warnings {
			fmt.Fprintf(w, "  - %s\n", warning)
		}
	}
	if len(pkg.Findings) > 0 {
		fmt.Fprintln(w, "Findings:")
		for _, finding := range pkg.Findings {
			fmt.Fprintf(w, "  - [%s] %s\n", finding.Severity, finding.Message)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Decision: %s\n", decisionOrInspectOnly(pkg.Decision))
	fmt.Fprintln(w, "Install executed: no")

	if len(pkg.DebugTrace) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Debug Evaluation Trace:")
		for _, entry := range pkg.DebugTrace {
			if entry.Severity == "" {
				fmt.Fprintf(w, "  [%s] %s\n", entry.CheckID, entry.Status)
			} else {
				fmt.Fprintf(w, "  [%s] %s severity=%s\n", entry.CheckID, entry.Status, entry.Severity)
			}
			for _, evidence := range entry.Evidence {
				fmt.Fprintf(w, "    %s\n", evidence)
			}
			fmt.Fprintln(w)
		}
	}
}

func valueOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func decisionOrInspectOnly(decision report.Decision) report.Decision {
	if decision == "" {
		return report.DecisionInspectOnly
	}
	return decision
}
