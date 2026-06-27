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
	fmt.Fprintf(w, "Selected Version: %s\n", valueOrUnknown(pkg.SelectedVersion))
	fmt.Fprintf(w, "Selected Published: %s\n", valueOrUnknown(pkg.SelectedPublishedAt))
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
	if pkg.ArtifactDownload != nil {
		fmt.Fprintln(w, "Artifact Download:")
		fmt.Fprintf(w, "  Status: %s\n", pkg.ArtifactDownload.Status)
		if pkg.ArtifactDownload.Filename != "" {
			fmt.Fprintf(w, "  Filename: %s\n", pkg.ArtifactDownload.Filename)
			fmt.Fprintf(w, "  Package Type: %s\n", valueOrUnknown(pkg.ArtifactDownload.PackageType))
			fmt.Fprintf(w, "  Downloaded Size: %d bytes\n", pkg.ArtifactDownload.DownloadedSize)
			fmt.Fprintf(w, "  Digest: %s verified=%t\n", valueOrUnknown(pkg.ArtifactDownload.DigestAlgorithm), pkg.ArtifactDownload.DigestVerified)
		}
	}
	if pkg.ArtifactInspection != nil {
		fmt.Fprintln(w, "Artifact Inspection:")
		fmt.Fprintf(w, "  Status: %s\n", pkg.ArtifactInspection.Status)
		fmt.Fprintf(w, "  Archive Format: %s\n", valueOrUnknown(pkg.ArtifactInspection.ArchiveFormat))
		fmt.Fprintf(w, "  Files: %d\n", pkg.ArtifactInspection.FileCount)
		fmt.Fprintf(w, "  Directories: %d\n", pkg.ArtifactInspection.DirectoryCount)
		fmt.Fprintf(w, "  Symlinks: %d\n", pkg.ArtifactInspection.SymlinkCount)
		fmt.Fprintf(w, "  Hardlinks: %d\n", pkg.ArtifactInspection.HardlinkCount)
		fmt.Fprintf(w, "  Total Uncompressed Size: %d bytes\n", pkg.ArtifactInspection.TotalUncompressedBytes)
		fmt.Fprintf(w, "  Compressed Size: %d bytes\n", pkg.ArtifactInspection.CompressedBytes)
		if pkg.ArtifactInspection.ExpansionRatioApplicable {
			fmt.Fprintf(w, "  Expansion Ratio: %.2f\n", pkg.ArtifactInspection.ExpansionRatio)
		} else {
			fmt.Fprintln(w, "  Expansion Ratio: not evaluated")
		}
		fmt.Fprintf(w, "  Max Path Depth: %d\n", pkg.ArtifactInspection.MaxPathDepth)
		fmt.Fprintf(w, "  Duplicate Paths: %d\n", pkg.ArtifactInspection.DuplicatePathCount)
		fmt.Fprintf(w, "  Nested Archives: %d\n", pkg.ArtifactInspection.NestedArchiveCount)
		fmt.Fprintf(w, "  Unsafe Paths: %d\n", pkg.ArtifactInspection.UnsafePathCount)
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
