package npmdependencies

import (
	"fmt"
	"strings"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/report"
)

func CheckDependencyChange(pkg report.PackageReport, historyVersions int) []report.Finding {
	if !isNPM(pkg) || historyVersions <= 0 || len(pkg.NPMDependencyHistory) == 0 {
		return nil
	}
	previous := pkg.NPMDependencyHistory[0]
	if !previous.DependenciesKnown {
		return nil
	}
	changes := dependencyChanges(pkg.NPMDependencies, previous.Dependencies)
	if len(changes) == 0 {
		return nil
	}
	return []report.Finding{{
		Message: fmt.Sprintf("selected npm version changes direct dependency names compared with previous version %s: %s", previous.Version, strings.Join(changes, "; ")),
	}}
}

func CheckDirectDependencyLifecycleScripts(pkg report.PackageReport) []report.Finding {
	if !isNPM(pkg) {
		return nil
	}
	var findings []report.Finding
	for _, dependency := range pkg.NPMDirectDependencies {
		if len(dependency.LifecycleFindings) == 0 {
			continue
		}
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf(
				"direct npm dependency %s%s declares install-relevant lifecycle script(s): %s",
				dependency.Name,
				selectedVersionSuffix(dependency.SelectedVersion),
				strings.Join(dependency.LifecycleFindings, "; "),
			),
		})
	}
	return findings
}

func CheckDirectDependencySuspiciousInstallCommands(pkg report.PackageReport) []report.Finding {
	if !isNPM(pkg) {
		return nil
	}
	var findings []report.Finding
	for _, dependency := range pkg.NPMDirectDependencies {
		if len(dependency.SuspiciousCommandFindings) == 0 {
			continue
		}
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf(
				"direct npm dependency %s%s has suspicious install command metadata: %s",
				dependency.Name,
				selectedVersionSuffix(dependency.SelectedVersion),
				strings.Join(dependency.SuspiciousCommandFindings, "; "),
			),
		})
	}
	return findings
}

func DependencyEvidence(pkg report.PackageReport, historyVersions int) []string {
	evidence := []string{
		fmt.Sprintf("selected dependency names: dependencies=%d optional=%d peer=%d dev=%d",
			len(pkg.NPMDependencies.Dependencies),
			len(pkg.NPMDependencies.OptionalDependencies),
			len(pkg.NPMDependencies.PeerDependencies),
			len(pkg.NPMDependencies.DevDependencies),
		),
		fmt.Sprintf("history limit: %d", historyVersions),
	}
	if len(pkg.NPMDependencyHistory) == 0 {
		return append(evidence, "immediate previous dependency metadata: unavailable")
	}
	previous := pkg.NPMDependencyHistory[0]
	evidence = append(evidence, fmt.Sprintf("immediate previous version: %s known=%t", previous.Version, previous.DependenciesKnown))
	if previous.DependenciesKnown {
		evidence = append(evidence, fmt.Sprintf("previous dependency names: dependencies=%d optional=%d peer=%d dev=%d",
			len(previous.Dependencies.Dependencies),
			len(previous.Dependencies.OptionalDependencies),
			len(previous.Dependencies.PeerDependencies),
			len(previous.Dependencies.DevDependencies),
		))
	}
	return evidence
}

func DirectDependencyEvidence(pkg report.PackageReport) []string {
	evidence := []string{
		fmt.Sprintf("direct dependency inspection limit: %d", pkg.NPMDirectDependencyLimit),
		fmt.Sprintf("direct dependency overflow: %d", pkg.NPMDirectDependencyOverflow),
		fmt.Sprintf("direct dependency inspections: %d", len(pkg.NPMDirectDependencies)),
	}
	const maxEvidence = 12
	for i, dependency := range pkg.NPMDirectDependencies {
		if i >= maxEvidence {
			evidence = append(evidence, fmt.Sprintf("direct dependency evidence truncated: %d more", len(pkg.NPMDirectDependencies)-i))
			break
		}
		evidence = append(evidence, fmt.Sprintf(
			"direct dependency: %s kind=%s range=%s selection=%s selected=%s status=%s lifecycle_findings=%d suspicious_findings=%d",
			dependency.Name,
			dependency.DependencyKind,
			valueOrUnavailable(dependency.RequestedRange),
			dependency.Selection,
			valueOrUnavailable(dependency.SelectedVersion),
			dependency.FetchStatus,
			len(dependency.LifecycleFindings),
			len(dependency.SuspiciousCommandFindings),
		))
		if dependency.FetchError != "" {
			evidence = append(evidence, "direct dependency fetch error: "+dependency.Name+": "+dependency.FetchError)
		}
	}
	return evidence
}

func DependencyIndeterminateReason(pkg report.PackageReport, historyVersions int) string {
	if !isNPM(pkg) || historyVersions <= 0 {
		return ""
	}
	if len(pkg.NPMDependencyHistory) == 0 {
		return "immediate previous npm release metadata is unavailable for dependency comparison"
	}
	if !pkg.NPMDependencyHistory[0].DependenciesKnown {
		return "immediate previous npm release dependency metadata is unavailable"
	}
	return ""
}

func DirectDependencyIndeterminateReason(pkg report.PackageReport) string {
	if !isNPM(pkg) || pkg.NPMDirectDependencyOverflow <= 0 {
		return ""
	}
	return fmt.Sprintf("direct npm dependency inspection skipped %d dependency(ies) beyond configured limit %d", pkg.NPMDirectDependencyOverflow, pkg.NPMDirectDependencyLimit)
}

func dependencyChanges(selected, previous report.NPMDependencySet) []string {
	var changes []string
	for _, group := range []struct {
		label    string
		selected []string
		previous []string
	}{
		{label: "dependencies", selected: selected.Dependencies, previous: previous.Dependencies},
		{label: "optionalDependencies", selected: selected.OptionalDependencies, previous: previous.OptionalDependencies},
		{label: "peerDependencies", selected: selected.PeerDependencies, previous: previous.PeerDependencies},
		{label: "devDependencies", selected: selected.DevDependencies, previous: previous.DevDependencies},
	} {
		added, removed := diffStrings(group.selected, group.previous)
		if len(added) > 0 {
			changes = append(changes, fmt.Sprintf("%s added %s", group.label, strings.Join(added, ", ")))
		}
		if len(removed) > 0 {
			changes = append(changes, fmt.Sprintf("%s removed %s", group.label, strings.Join(removed, ", ")))
		}
	}
	return changes
}

func diffStrings(selected, previous []string) ([]string, []string) {
	selectedSet := stringSet(selected)
	previousSet := stringSet(previous)
	var added []string
	for _, value := range selected {
		if _, ok := previousSet[value]; !ok {
			added = append(added, value)
		}
	}
	var removed []string
	for _, value := range previous {
		if _, ok := selectedSet[value]; !ok {
			removed = append(removed, value)
		}
	}
	return added, removed
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func selectedVersionSuffix(version string) string {
	if strings.TrimSpace(version) == "" {
		return ""
	}
	return "@" + version
}

func valueOrUnavailable(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unavailable"
	}
	return value
}

func isNPM(pkg report.PackageReport) bool {
	return strings.EqualFold(strings.TrimSpace(pkg.Ecosystem), string(ecosystem.NPM))
}
