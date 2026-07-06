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
	fmt.Fprintf(w, "Mode: %s\n", valueOrUnknown(pkg.EvaluationMode))
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
	if hasNPMSourceMetadata(pkg.NPMSource) {
		fmt.Fprintln(w, "NPM Source Metadata:")
		fmt.Fprintf(w, "  Repository URL: %s\n", valueOrUnknown(pkg.NPMSource.RepositoryURL))
		fmt.Fprintf(w, "  Selected gitHead: %s\n", valueOrUnknown(pkg.NPMSource.SelectedGitHead))
		fmt.Fprintf(w, "  Previous gitHead: %s\n", valueOrUnknown(pkg.NPMSource.PreviousGitHead))
		fmt.Fprintf(w, "  Selected Publisher: %s\n", valueOrUnknown(pkg.NPMSource.SelectedPublisher))
		fmt.Fprintf(w, "  Previous Publisher: %s\n", valueOrUnknown(pkg.NPMSource.PreviousPublisher))
	}
	if len(pkg.NPMDirectDependencies) > 0 || pkg.NPMDirectDependencyOverflow > 0 {
		fmt.Fprintf(w, "NPM Direct Dependencies Inspected: %d", len(pkg.NPMDirectDependencies))
		if pkg.NPMDirectDependencyOverflow > 0 {
			fmt.Fprintf(w, " (%d skipped by limit)", pkg.NPMDirectDependencyOverflow)
		}
		fmt.Fprintln(w)
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
		fmt.Fprintf(w, "  Execution Surfaces: %d\n", pkg.ArtifactInspection.ExecutionSurfaceCount)
		for _, surface := range pkg.ArtifactInspection.ExecutionSurfaceExamples {
			fmt.Fprintf(w, "    - %s\n", executionSurfaceDisplay(surface))
		}
		fmt.Fprintf(w, "  Suspicious File Types: %d\n", pkg.ArtifactInspection.SuspiciousFileTypeCount)
		for _, fileType := range pkg.ArtifactInspection.SuspiciousFileTypeExamples {
			fmt.Fprintf(w, "    - %s\n", suspiciousFileTypeDisplay(fileType))
		}
		fmt.Fprintf(w, "  Behavior Indicators: %d\n", pkg.ArtifactInspection.BehaviorIndicatorCount)
		for _, indicator := range pkg.ArtifactInspection.BehaviorIndicatorExamples {
			fmt.Fprintf(w, "    - %s\n", behaviorIndicatorDisplay(indicator))
		}
		fmt.Fprintf(w, "  General Risk Signals: %d\n", pkg.ArtifactInspection.GeneralRiskSignalCount)
		for _, signal := range pkg.ArtifactInspection.GeneralRiskSignalExamples {
			fmt.Fprintf(w, "    - %s\n", generalRiskSignalDisplay(signal))
		}
	}
	if pkg.ArtifactDelta != nil {
		fmt.Fprintln(w, "Artifact Delta:")
		fmt.Fprintf(w, "  Status: %s\n", valueOrUnknown(pkg.ArtifactDelta.Status))
		fmt.Fprintf(w, "  Previous Artifact: %s\n", valueOrUnknown(pkg.ArtifactDelta.PreviousFilename))
		if pkg.ArtifactDelta.PreviousArtifactUnavailableMessage != "" {
			fmt.Fprintf(w, "  Previous Artifact Unavailable: %s\n", pkg.ArtifactDelta.PreviousArtifactUnavailableMessage)
		}
		fmt.Fprintf(w, "  Added Paths: %d\n", pkg.ArtifactDelta.AddedPathCount)
		for _, path := range pkg.ArtifactDelta.AddedPathExamples {
			fmt.Fprintf(w, "    + %s\n", path)
		}
		fmt.Fprintf(w, "  Removed Paths: %d\n", pkg.ArtifactDelta.RemovedPathCount)
		for _, path := range pkg.ArtifactDelta.RemovedPathExamples {
			fmt.Fprintf(w, "    - %s\n", path)
		}
		fmt.Fprintf(w, "  New Execution Surfaces: %d\n", pkg.ArtifactDelta.NewExecutionSurfaceCount)
		fmt.Fprintf(w, "  New Suspicious File Types: %d\n", pkg.ArtifactDelta.NewSuspiciousFileTypeCount)
		fmt.Fprintf(w, "  File Count Delta: %+d\n", pkg.ArtifactDelta.FileCountDelta)
		fmt.Fprintf(w, "  Uncompressed Size Delta: %+d bytes\n", pkg.ArtifactDelta.UncompressedSizeDeltaBytes)
	}
	if pkg.Install != nil {
		fmt.Fprintln(w, "Install Summary:")
		fmt.Fprintf(w, "  Status: %s\n", valueOrUnknown(pkg.Install.Status))
		fmt.Fprintf(w, "  Executed: %s\n", yesNo(pkg.Install.Executed))
		if pkg.Install.Manager != "" {
			fmt.Fprintf(w, "  Manager: %s\n", pkg.Install.Manager)
		}
		if pkg.Install.PackageSpec != "" {
			fmt.Fprintf(w, "  Package: %s\n", pkg.Install.PackageSpec)
		}
		if pkg.Install.PackageManagerExitCode != nil {
			fmt.Fprintf(w, "  Package Manager Exit Code: %d\n", *pkg.Install.PackageManagerExitCode)
		}
		if pkg.Install.DurationMilliseconds > 0 {
			fmt.Fprintf(w, "  Duration: %d ms\n", pkg.Install.DurationMilliseconds)
		}
		if pkg.Install.Message != "" {
			fmt.Fprintf(w, "  Message: %s\n", pkg.Install.Message)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Decision: %s\n", decisionOrInspectOnly(pkg.Decision))
	fmt.Fprintf(w, "Install executed: %s\n", yesNo(installExecuted(pkg)))

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

func hasNPMSourceMetadata(source report.NPMSourceMetadata) bool {
	return source.RepositoryURL != "" ||
		source.PreviousRepositoryURL != "" ||
		source.SelectedGitHead != "" ||
		source.PreviousGitHead != "" ||
		source.SelectedPublisher != "" ||
		source.PreviousPublisher != ""
}

func decisionOrInspectOnly(decision report.Decision) report.Decision {
	if decision == "" {
		return report.DecisionInspectOnly
	}
	return decision
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func executionSurfaceDisplay(surface report.ArtifactExecutionSurface) string {
	parts := []string{surface.Type, surface.Path}
	if strings.TrimSpace(surface.Name) != "" {
		parts = append(parts, surface.Name)
	}
	if strings.TrimSpace(surface.Detail) != "" {
		parts = append(parts, surface.Detail)
	}
	return strings.Join(parts, " ")
}

func suspiciousFileTypeDisplay(fileType report.ArtifactSuspiciousFileType) string {
	parts := []string{fileType.Type, fileType.Path, fileType.Reason}
	if strings.TrimSpace(fileType.Detail) != "" {
		parts = append(parts, fileType.Detail)
	}
	return strings.Join(parts, " ")
}

func behaviorIndicatorDisplay(indicator report.ArtifactBehaviorIndicator) string {
	parts := []string{indicator.Type, indicator.Path, indicator.Reason}
	if strings.TrimSpace(indicator.Detail) != "" {
		parts = append(parts, indicator.Detail)
	}
	return strings.Join(parts, " ")
}

func generalRiskSignalDisplay(signal report.ArtifactGeneralRiskSignal) string {
	parts := []string{signal.Type}
	if strings.TrimSpace(signal.Path) != "" {
		parts = append(parts, signal.Path)
	}
	parts = append(parts, signal.Reason)
	if strings.TrimSpace(signal.Detail) != "" {
		parts = append(parts, signal.Detail)
	}
	return strings.Join(parts, " ")
}
