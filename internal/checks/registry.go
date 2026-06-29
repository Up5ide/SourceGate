package checks

import (
	"fmt"
	"time"

	"github.com/sourcegate/sourcegate/internal/checks/artifactbehavior"
	"github.com/sourcegate/sourcegate/internal/checks/artifactexecution"
	"github.com/sourcegate/sourcegate/internal/checks/artifactfiletypes"
	"github.com/sourcegate/sourcegate/internal/checks/artifactsafety"
	"github.com/sourcegate/sourcegate/internal/checks/dormant"
	"github.com/sourcegate/sourcegate/internal/checks/firstrelease"
	"github.com/sourcegate/sourcegate/internal/checks/installlifecycle"
	"github.com/sourcegate/sourcegate/internal/checks/namesquat"
	"github.com/sourcegate/sourcegate/internal/checks/pypiartifacts"
	"github.com/sourcegate/sourcegate/internal/checks/releaseage"
	"github.com/sourcegate/sourcegate/internal/config"
	"github.com/sourcegate/sourcegate/internal/report"
)

type policyPhase string

const (
	phaseMetadata policyPhase = "metadata"
	phaseArtifact policyPhase = "artifact"
)

type policyCheckDefinition struct {
	id                   string
	group                string
	phase                policyPhase
	applicable           func(report.PackageReport) bool
	enabled              func([]policyTier) bool
	evidence             func(report.PackageReport, []policyTier, time.Time) []string
	checkOnIndeterminate bool
	indeterminate        func(report.PackageReport, config.PolicyTierConfig) string
	check                func(report.PackageReport, config.PolicyTierConfig, time.Time) []report.Finding
	summary              func(config.PolicyTierConfig) string
}

func (definition policyCheckDefinition) debugCheck(pkg *report.PackageReport, tiers []policyTier, now time.Time) debugPolicyCheck {
	return debugPolicyCheck{
		id:                   definition.id,
		applicable:           definition.applicable(*pkg),
		enabled:              definition.enabled(tiers),
		checkOnIndeterminate: definition.checkOnIndeterminate,
		indeterminate: func(policy config.PolicyTierConfig) string {
			if definition.indeterminate == nil {
				return ""
			}
			return definition.indeterminate(*pkg, policy)
		},
		evidence: func() []string {
			return definition.evidence(*pkg, tiers, now)
		},
		check: func(policy config.PolicyTierConfig) []report.Finding {
			return definition.check(*pkg, policy, now)
		},
	}
}

func policyDefinitionsForPhase(phase policyPhase) []policyCheckDefinition {
	var definitions []policyCheckDefinition
	for _, definition := range policyDefinitions {
		if definition.phase == phase {
			definitions = append(definitions, definition)
		}
	}
	return definitions
}

var policyDefinitions = []policyCheckDefinition{
	{
		id:         "release_age",
		group:      config.GroupReleaseMetadata,
		phase:      phaseMetadata,
		applicable: alwaysApplicable,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.MinimumDaysSinceLatestRelease > 0 })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			return append(releaseAgeEvidence(pkg, now), integerThresholdEvidence("thresholds (day(s))", tiers, func(policy config.PolicyTierConfig) int {
				return policy.MinimumDaysSinceLatestRelease
			}))
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if policy.MinimumDaysSinceLatestRelease <= 0 {
				return nil
			}
			return releaseage.Check(pkg, policy.MinimumDaysSinceLatestRelease, now)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if policy.MinimumDaysSinceLatestRelease <= 0 {
				return ""
			}
			return fmt.Sprintf("latest release must be at least %d day(s) old", policy.MinimumDaysSinceLatestRelease)
		},
	},
	{
		id:         "dormant_release",
		group:      config.GroupReleaseMetadata,
		phase:      phaseMetadata,
		applicable: alwaysApplicable,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.DormantReleaseThresholdDays > 0 })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			return append(dormantReleaseEvidence(pkg), integerThresholdEvidence("thresholds (day(s))", tiers, func(policy config.PolicyTierConfig) int {
				return policy.DormantReleaseThresholdDays
			}))
		},
		indeterminate: func(pkg report.PackageReport, policy config.PolicyTierConfig) string {
			if policy.DormantReleaseThresholdDays <= 0 {
				return ""
			}
			return packageHistoryIndeterminateReason(pkg)
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if policy.DormantReleaseThresholdDays <= 0 {
				return nil
			}
			return dormant.Check(pkg, policy.DormantReleaseThresholdDays)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if policy.DormantReleaseThresholdDays <= 0 {
				return ""
			}
			return fmt.Sprintf("release inactivity gap must be below %d day(s)", policy.DormantReleaseThresholdDays)
		},
	},
	{
		id:         "protected_package",
		group:      config.GroupNameProtection,
		phase:      phaseMetadata,
		applicable: alwaysApplicable,
		enabled:    func(tiers []policyTier) bool { return anyTier(tiers, hasProtectedPackagePolicy) },
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			return protectedNameEvidence(pkg, "configured protected packages", tiers, func(policy config.PolicyTierConfig) map[string][]string {
				return policy.ProtectedPackages
			})
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if !hasProtectedPackagePolicy(policy) {
				return nil
			}
			return namesquat.CheckProtectedPackages(pkg, policy)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if !hasProtectedPackagePolicy(policy) {
				return ""
			}
			return "protected package checks enabled"
		},
	},
	{
		id:         "protected_token",
		group:      config.GroupNameProtection,
		phase:      phaseMetadata,
		applicable: alwaysApplicable,
		enabled:    func(tiers []policyTier) bool { return anyTier(tiers, hasProtectedTokenPolicy) },
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			return protectedNameEvidence(pkg, "configured protected tokens", tiers, func(policy config.PolicyTierConfig) map[string][]string {
				return policy.ProtectedTokens
			})
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if !hasProtectedTokenPolicy(policy) {
				return nil
			}
			return namesquat.CheckProtectedTokens(pkg, policy)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if !hasProtectedTokenPolicy(policy) {
				return ""
			}
			return "protected token checks enabled"
		},
	},
	{
		id:         "first_release",
		group:      config.GroupReleaseMetadata,
		phase:      phaseMetadata,
		applicable: alwaysApplicable,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.AlertOnFirstRelease })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			return append(firstReleaseEvidence(pkg), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.AlertOnFirstRelease
			}))
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if !policy.AlertOnFirstRelease {
				return nil
			}
			return firstrelease.Check(pkg)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if !policy.AlertOnFirstRelease {
				return ""
			}
			return "first-release package checks enabled"
		},
	},
	{
		id:         "npm_lifecycle_scripts",
		group:      config.GroupNPMLifecycle,
		phase:      phaseMetadata,
		applicable: isNPM,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.InstallLifecycleScripts })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			return append(installlifecycle.DeclaredScriptsEvidence(pkg), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.InstallLifecycleScripts
			}))
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if !policy.InstallLifecycleScripts {
				return nil
			}
			return installlifecycle.CheckDeclaredScripts(pkg)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if !policy.InstallLifecycleScripts {
				return ""
			}
			return "npm install lifecycle script checks enabled"
		},
	},
	{
		id:         "npm_suspicious_install_commands",
		group:      config.GroupNPMLifecycle,
		phase:      phaseMetadata,
		applicable: isNPM,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.SuspiciousInstallScriptCommands })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			return append(installlifecycle.SuspiciousCommandsEvidence(pkg), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.SuspiciousInstallScriptCommands
			}))
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if !policy.SuspiciousInstallScriptCommands {
				return nil
			}
			return installlifecycle.CheckSuspiciousCommands(pkg)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if !policy.SuspiciousInstallScriptCommands {
				return ""
			}
			return "suspicious npm install script command checks enabled"
		},
	},
	{
		id:         "npm_lifecycle_history",
		group:      config.GroupNPMLifecycle,
		phase:      phaseMetadata,
		applicable: isNPM,
		enabled: func(tiers []policyTier) bool {
			return maxTierInteger(tiers, func(policy config.PolicyTierConfig) int { return policy.InstallLifecycleHistoryVersions }) > 0
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			historyVersions := maxTierInteger(tiers, func(policy config.PolicyTierConfig) int { return policy.InstallLifecycleHistoryVersions })
			return append(installlifecycle.HistoryEvidence(pkg, historyVersions), integerThresholdEvidence("history limits", tiers, func(policy config.PolicyTierConfig) int {
				return policy.InstallLifecycleHistoryVersions
			}))
		},
		indeterminate: func(pkg report.PackageReport, policy config.PolicyTierConfig) string {
			if policy.InstallLifecycleHistoryVersions <= 0 {
				return ""
			}
			if pkg.NPMHistory.IndeterminateReason != "" {
				return pkg.NPMHistory.IndeterminateReason
			}
			return installlifecycle.HistoryIndeterminateReason(pkg, policy.InstallLifecycleHistoryVersions)
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if policy.InstallLifecycleHistoryVersions <= 0 {
				return nil
			}
			return installlifecycle.CheckHistoryChanges(pkg, policy.InstallLifecycleHistoryVersions)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if policy.InstallLifecycleHistoryVersions <= 0 {
				return ""
			}
			return fmt.Sprintf("npm install lifecycle history checks compare previous %d version(s)", policy.InstallLifecycleHistoryVersions)
		},
	},
	{
		id:         "npm_lifecycle_added_after_dormancy",
		group:      config.GroupNPMLifecycle,
		phase:      phaseMetadata,
		applicable: isNPM,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.InstallScriptAddedAfterDormancy })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			historyVersions := maxTierInteger(tiers, func(policy config.PolicyTierConfig) int { return policy.InstallLifecycleHistoryVersions })
			dormancyThreshold := maxTierInteger(tiers, func(policy config.PolicyTierConfig) int { return policy.DormantReleaseThresholdDays })
			return append(installlifecycle.DormantAddedEvidence(pkg, historyVersions, dormancyThreshold), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.InstallScriptAddedAfterDormancy
			}))
		},
		indeterminate: func(pkg report.PackageReport, policy config.PolicyTierConfig) string {
			if !policy.InstallScriptAddedAfterDormancy {
				return ""
			}
			if pkg.NPMHistory.IndeterminateReason != "" {
				return pkg.NPMHistory.IndeterminateReason
			}
			return installlifecycle.DormantAddedIndeterminateReason(pkg, policy.InstallLifecycleHistoryVersions, policy.DormantReleaseThresholdDays)
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if !policy.InstallScriptAddedAfterDormancy {
				return nil
			}
			return installlifecycle.CheckDormantAdded(pkg, policy.InstallLifecycleHistoryVersions, policy.DormantReleaseThresholdDays)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if !policy.InstallScriptAddedAfterDormancy {
				return ""
			}
			return "dormant npm install script addition checks enabled"
		},
	},
	{
		id:         "pypi_artifact_history",
		group:      config.GroupPyPIArtifacts,
		phase:      phaseMetadata,
		applicable: isPyPI,
		enabled: func(tiers []policyTier) bool {
			return maxTierInteger(tiers, func(policy config.PolicyTierConfig) int { return policy.PyPIArtifactHistoryVersions }) > 0
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			historyVersions := maxTierInteger(tiers, func(policy config.PolicyTierConfig) int { return policy.PyPIArtifactHistoryVersions })
			return pypiartifacts.ArtifactHistoryEvidence(pkg, historyVersions)
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			return nil
		},
		summary: func(policy config.PolicyTierConfig) string {
			if policy.PyPIArtifactHistoryVersions <= 0 {
				return ""
			}
			return fmt.Sprintf("PyPI artifact history checks compare previous %d version(s)", policy.PyPIArtifactHistoryVersions)
		},
	},
	{
		id:         "pypi_artifact_shape",
		group:      config.GroupPyPIArtifacts,
		phase:      phaseMetadata,
		applicable: isPyPI,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.PyPIArtifactShapeChange })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			historyVersions := maxTierInteger(tiers, func(policy config.PolicyTierConfig) int { return policy.PyPIArtifactHistoryVersions })
			return append(pypiartifacts.ArtifactShapeEvidence(pkg, historyVersions), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.PyPIArtifactShapeChange
			}))
		},
		indeterminate: func(pkg report.PackageReport, policy config.PolicyTierConfig) string {
			if reason := pypiHistoryIndeterminateReason(pkg, policy.PyPIArtifactShapeChange); reason != "" {
				return reason
			}
			if !policy.PyPIArtifactShapeChange {
				return ""
			}
			return pypiartifacts.ArtifactShapeIndeterminateReason(pkg, policy.PyPIArtifactHistoryVersions)
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if !policy.PyPIArtifactShapeChange {
				return nil
			}
			return pypiartifacts.CheckArtifactShapeChange(pkg, policy.PyPIArtifactHistoryVersions)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if !policy.PyPIArtifactShapeChange {
				return ""
			}
			return "PyPI artifact shape change checks enabled"
		},
	},
	{
		id:         "pypi_file_size_jump",
		group:      config.GroupPyPIArtifacts,
		phase:      phaseMetadata,
		applicable: isPyPI,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.PyPIFileSizeJumpPercent > 0 })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			historyVersions := maxTierInteger(tiers, func(policy config.PolicyTierConfig) int { return policy.PyPIArtifactHistoryVersions })
			return append(pypiartifacts.FileSizeEvidence(pkg, historyVersions), integerThresholdEvidence("thresholds (percent)", tiers, func(policy config.PolicyTierConfig) int {
				return policy.PyPIFileSizeJumpPercent
			}))
		},
		indeterminate: func(pkg report.PackageReport, policy config.PolicyTierConfig) string {
			if reason := pypiHistoryIndeterminateReason(pkg, policy.PyPIFileSizeJumpPercent > 0); reason != "" {
				return reason
			}
			if policy.PyPIFileSizeJumpPercent <= 0 {
				return ""
			}
			return pypiartifacts.FileSizeIndeterminateReason(pkg, policy.PyPIArtifactHistoryVersions)
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if policy.PyPIFileSizeJumpPercent <= 0 {
				return nil
			}
			return pypiartifacts.CheckFileSizeJump(pkg, policy.PyPIArtifactHistoryVersions, policy.PyPIFileSizeJumpPercent)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if policy.PyPIFileSizeJumpPercent <= 0 {
				return ""
			}
			return fmt.Sprintf("PyPI file size jump threshold is a %d%% increase over historical median", policy.PyPIFileSizeJumpPercent)
		},
	},
	{
		id:         "pypi_dependency_change",
		group:      config.GroupPyPIArtifacts,
		phase:      phaseMetadata,
		applicable: isPyPI,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.PyPIDependencyChange })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			historyVersions := maxTierInteger(tiers, func(policy config.PolicyTierConfig) int { return policy.PyPIArtifactHistoryVersions })
			includeOptional := anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.PyPIIncludeOptionalDependencies })
			evidence := append(pypiartifacts.DependencyEvidence(pkg, historyVersions, includeOptional), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.PyPIDependencyChange
			}))
			return append(evidence, booleanThresholdEvidence("optional dependency comparison tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.PyPIIncludeOptionalDependencies
			}))
		},
		indeterminate: func(pkg report.PackageReport, policy config.PolicyTierConfig) string {
			if reason := pypiHistoryIndeterminateReason(pkg, policy.PyPIDependencyChange); reason != "" {
				return reason
			}
			if !policy.PyPIDependencyChange {
				return ""
			}
			return pypiartifacts.DependencyIndeterminateReason(pkg, policy.PyPIArtifactHistoryVersions)
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if !policy.PyPIDependencyChange {
				return nil
			}
			return pypiartifacts.CheckDependencyChange(pkg, policy.PyPIArtifactHistoryVersions, policy.PyPIIncludeOptionalDependencies)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if !policy.PyPIDependencyChange {
				return ""
			}
			if policy.PyPIIncludeOptionalDependencies {
				return "PyPI required and optional dependency change checks enabled"
			}
			return "PyPI required dependency change checks enabled"
		},
	},
	{
		id:         "pypi_provenance",
		group:      config.GroupPyPIArtifacts,
		phase:      phaseMetadata,
		applicable: isPyPI,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.PyPIProvenanceRequired })
		},
		checkOnIndeterminate: true,
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			return append(pypiartifacts.ProvenanceEvidence(pkg), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.PyPIProvenanceRequired
			}))
		},
		indeterminate: func(pkg report.PackageReport, policy config.PolicyTierConfig) string {
			if !policy.PyPIProvenanceRequired {
				return ""
			}
			return pypiartifacts.ProvenanceIndeterminateReason(pkg, policy.PyPIProvenanceScope)
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if !policy.PyPIProvenanceRequired {
				return nil
			}
			return pypiartifacts.CheckProvenanceRequired(pkg, policy.PyPIProvenanceScope)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if !policy.PyPIProvenanceRequired {
				return ""
			}
			return fmt.Sprintf("PyPI provenance availability checks enabled for %s", policy.PyPIProvenanceScope)
		},
	},
	{
		id:         "pypi_release_file_count",
		group:      config.GroupPyPIArtifacts,
		phase:      phaseMetadata,
		applicable: isPyPI,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.PyPIReleaseFileCountChange })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			historyVersions := maxTierInteger(tiers, func(policy config.PolicyTierConfig) int { return policy.PyPIArtifactHistoryVersions })
			return append(pypiartifacts.ReleaseFileCountEvidence(pkg, historyVersions), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.PyPIReleaseFileCountChange
			}))
		},
		indeterminate: func(pkg report.PackageReport, policy config.PolicyTierConfig) string {
			if reason := pypiHistoryIndeterminateReason(pkg, policy.PyPIReleaseFileCountChange); reason != "" {
				return reason
			}
			if !policy.PyPIReleaseFileCountChange {
				return ""
			}
			return pypiartifacts.ReleaseFileCountIndeterminateReason(pkg, policy.PyPIArtifactHistoryVersions)
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if !policy.PyPIReleaseFileCountChange {
				return nil
			}
			return pypiartifacts.CheckReleaseFileCountChange(pkg, policy.PyPIArtifactHistoryVersions)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if !policy.PyPIReleaseFileCountChange {
				return ""
			}
			return "PyPI release file count change checks enabled"
		},
	},
	{
		id:         "artifact_unsafe_paths",
		group:      config.GroupArtifactSafety,
		phase:      phaseArtifact,
		applicable: artifactInspectionAvailable,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.ArtifactUnsafePaths })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			return append(artifactsafety.Evidence(pkg), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.ArtifactUnsafePaths
			}))
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if !policy.ArtifactUnsafePaths {
				return nil
			}
			return artifactsafety.CheckUnsafePaths(pkg)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if !policy.ArtifactUnsafePaths {
				return ""
			}
			return "artifact unsafe path checks enabled"
		},
	},
	{
		id:         "artifact_file_count",
		group:      config.GroupArtifactSafety,
		phase:      phaseArtifact,
		applicable: artifactInspectionAvailable,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.ArtifactMaxFileCount > 0 })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			return append(artifactsafety.Evidence(pkg), integerThresholdEvidence("thresholds (files)", tiers, func(policy config.PolicyTierConfig) int {
				return policy.ArtifactMaxFileCount
			}))
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if policy.ArtifactMaxFileCount <= 0 {
				return nil
			}
			return artifactsafety.CheckFileCount(pkg, policy.ArtifactMaxFileCount)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if policy.ArtifactMaxFileCount <= 0 {
				return ""
			}
			return fmt.Sprintf("artifact file count limit is %d", policy.ArtifactMaxFileCount)
		},
	},
	{
		id:         "artifact_uncompressed_size",
		group:      config.GroupArtifactSafety,
		phase:      phaseArtifact,
		applicable: artifactInspectionAvailable,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.ArtifactMaxUncompressedSizeMB > 0 })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			return append(artifactsafety.Evidence(pkg), integerThresholdEvidence("thresholds (MiB)", tiers, func(policy config.PolicyTierConfig) int {
				return policy.ArtifactMaxUncompressedSizeMB
			}))
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if policy.ArtifactMaxUncompressedSizeMB <= 0 {
				return nil
			}
			return artifactsafety.CheckUncompressedSize(pkg, policy.ArtifactMaxUncompressedSizeMB)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if policy.ArtifactMaxUncompressedSizeMB <= 0 {
				return ""
			}
			return fmt.Sprintf("artifact uncompressed size limit is %d MiB", policy.ArtifactMaxUncompressedSizeMB)
		},
	},
	{
		id:         "artifact_expansion_ratio",
		group:      config.GroupArtifactSafety,
		phase:      phaseArtifact,
		applicable: artifactInspectionAvailable,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.ArtifactMaxExpansionRatio > 0 })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			return append(artifactsafety.Evidence(pkg), integerThresholdEvidence("thresholds (ratio)", tiers, func(policy config.PolicyTierConfig) int {
				return policy.ArtifactMaxExpansionRatio
			}))
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if policy.ArtifactMaxExpansionRatio <= 0 {
				return nil
			}
			return artifactsafety.CheckExpansionRatio(pkg, policy.ArtifactMaxExpansionRatio)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if policy.ArtifactMaxExpansionRatio <= 0 {
				return ""
			}
			return fmt.Sprintf("artifact expansion ratio limit is %d", policy.ArtifactMaxExpansionRatio)
		},
	},
	{
		id:         "artifact_execution_surfaces",
		group:      config.GroupArtifactBehavior,
		phase:      phaseArtifact,
		applicable: artifactInspectionAvailable,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.ArtifactExecutionSurfaces })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			return append(artifactexecution.Evidence(pkg), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.ArtifactExecutionSurfaces
			}))
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if !policy.ArtifactExecutionSurfaces {
				return nil
			}
			return artifactexecution.CheckExecutionSurfaces(pkg)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if !policy.ArtifactExecutionSurfaces {
				return ""
			}
			return "artifact install/build execution surface checks enabled"
		},
	},
	{
		id:         "artifact_suspicious_file_types",
		group:      config.GroupArtifactBehavior,
		phase:      phaseArtifact,
		applicable: artifactInspectionAvailable,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.ArtifactSuspiciousFileTypes })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			return append(artifactfiletypes.Evidence(pkg), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.ArtifactSuspiciousFileTypes
			}))
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if !policy.ArtifactSuspiciousFileTypes {
				return nil
			}
			return artifactfiletypes.CheckSuspiciousFileTypes(pkg)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if !policy.ArtifactSuspiciousFileTypes {
				return ""
			}
			return "artifact suspicious file type checks enabled"
		},
	},
	{
		id:         "artifact_behavior_indicators",
		group:      config.GroupArtifactBehavior,
		phase:      phaseArtifact,
		applicable: artifactInspectionAvailable,
		enabled: func(tiers []policyTier) bool {
			return anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.ArtifactBehaviorIndicators })
		},
		evidence: func(pkg report.PackageReport, tiers []policyTier, now time.Time) []string {
			return append(artifactbehavior.Evidence(pkg), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.ArtifactBehaviorIndicators
			}))
		},
		check: func(pkg report.PackageReport, policy config.PolicyTierConfig, now time.Time) []report.Finding {
			if !policy.ArtifactBehaviorIndicators {
				return nil
			}
			return artifactbehavior.CheckBehaviorIndicators(pkg)
		},
		summary: func(policy config.PolicyTierConfig) string {
			if !policy.ArtifactBehaviorIndicators {
				return ""
			}
			return "artifact behavior indicator checks enabled"
		},
	},
}

func alwaysApplicable(report.PackageReport) bool {
	return true
}

func artifactInspectionAvailable(pkg report.PackageReport) bool {
	return pkg.ArtifactInspection != nil
}
