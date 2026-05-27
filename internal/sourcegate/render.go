package sourcegate

import (
	"fmt"
	"io"
	"strings"
)

func RenderHuman(w io.Writer, report PackageReport) {
	fmt.Fprintf(w, "Ecosystem: %s\n", report.Ecosystem)
	fmt.Fprintf(w, "Registry: %s\n", report.Registry)
	fmt.Fprintf(w, "Package: %s\n", valueOrUnknown(report.Name))
	fmt.Fprintf(w, "Latest Version: %s\n", valueOrUnknown(report.LatestVersion))
	fmt.Fprintf(w, "Latest Published: %s\n", valueOrUnknown(report.LatestPublishedAt))
	fmt.Fprintf(w, "Previous Published: %s\n", valueOrUnknown(report.PreviousPublishedAt))
	fmt.Fprintf(w, "Description: %s\n", valueOrUnknown(report.Description))
	fmt.Fprintf(w, "License: %s\n", valueOrUnknown(report.License))
	fmt.Fprintf(w, "Author: %s\n", valueOrUnknown(report.Author))
	fmt.Fprintf(w, "Versions: %d\n", report.VersionCount)
	fmt.Fprintf(w, "Created: %s\n", valueOrUnknown(report.CreatedAt))
	fmt.Fprintf(w, "Modified: %s\n", valueOrUnknown(report.ModifiedAt))

	if len(report.Maintainers) > 0 {
		fmt.Fprintf(w, "Maintainers: %s\n", strings.Join(report.Maintainers, ", "))
	}
	if len(report.ProjectURLs) > 0 {
		fmt.Fprintln(w, "Project URLs:")
		for _, url := range report.ProjectURLs {
			fmt.Fprintf(w, "  - %s\n", url)
		}
	}
	if report.PolicySummary != "" {
		fmt.Fprintf(w, "Policy: %s\n", report.PolicySummary)
	}
	if len(report.Findings) > 0 {
		fmt.Fprintln(w, "Findings:")
		for _, finding := range report.Findings {
			fmt.Fprintf(w, "  - [%s] %s\n", finding.Severity, finding.Message)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Decision: %s\n", decisionOrInspectOnly(report.Decision))
	fmt.Fprintln(w, "Install executed: no")
}

func valueOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func decisionOrInspectOnly(decision Decision) Decision {
	if decision == "" {
		return DecisionInspectOnly
	}
	return decision
}
