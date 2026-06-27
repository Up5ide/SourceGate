package checks

import (
	"fmt"
	"time"

	"github.com/sourcegate/sourcegate/internal/checks/dormant"
	"github.com/sourcegate/sourcegate/internal/checks/firstrelease"
	"github.com/sourcegate/sourcegate/internal/checks/installlifecycle"
	"github.com/sourcegate/sourcegate/internal/checks/namesquat"
	"github.com/sourcegate/sourcegate/internal/checks/pypiartifacts"
	"github.com/sourcegate/sourcegate/internal/checks/releaseage"
	"github.com/sourcegate/sourcegate/internal/config"
	"github.com/sourcegate/sourcegate/internal/report"
)

const (
	levelInform = "INFORM"
	levelAlert  = "ALERT"
	levelBlock  = "BLOCK"
)

type policyTier struct {
	level  string
	policy config.PolicyTierConfig
}

type EvaluationOptions struct {
	Debug bool
}

func Evaluate(pkg *report.PackageReport, cfg config.Config, now time.Time) {
	EvaluateWithOptions(pkg, cfg, now, EvaluationOptions{})
}

func EvaluateWithOptions(pkg *report.PackageReport, cfg config.Config, now time.Time, options EvaluationOptions) {
	pkg.Decision = report.DecisionInspectOnly
	pkg.DebugTrace = nil

	tiers := strongestFirstPolicyTiers(cfg.Policy)
	enabledPolicy := policyEnabled(tiers)
	if !enabledPolicy && !options.Debug {
		return
	}

	if enabledPolicy {
		pkg.PolicySummary = policySummary(cfg.Policy)
	}

	evaluate := func(check debugPolicyCheck) {
		findings, trace := evaluatePolicyCheck(tiers, options.Debug, check)
		pkg.Findings = append(pkg.Findings, findings...)
		if options.Debug {
			pkg.DebugTrace = append(pkg.DebugTrace, trace)
		}
	}

	evaluate(debugPolicyCheck{
		id:         "release_age",
		applicable: true,
		enabled:    anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.MinimumDaysSinceLatestRelease > 0 }),
		evidence: func() []string {
			return append(releaseAgeEvidence(*pkg, now), integerThresholdEvidence("thresholds (day(s))", tiers, func(policy config.PolicyTierConfig) int {
				return policy.MinimumDaysSinceLatestRelease
			}))
		},
		check: func(policy config.PolicyTierConfig) []report.Finding {
			if policy.MinimumDaysSinceLatestRelease <= 0 {
				return nil
			}
			return releaseage.Check(*pkg, policy.MinimumDaysSinceLatestRelease, now)
		},
	})
	evaluate(debugPolicyCheck{
		id:         "dormant_release",
		applicable: true,
		enabled:    anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.DormantReleaseThresholdDays > 0 }),
		indeterminate: func(policy config.PolicyTierConfig) string {
			if policy.DormantReleaseThresholdDays <= 0 {
				return ""
			}
			return packageHistoryIndeterminateReason(*pkg)
		},
		evidence: func() []string {
			return append(dormantReleaseEvidence(*pkg), integerThresholdEvidence("thresholds (day(s))", tiers, func(policy config.PolicyTierConfig) int {
				return policy.DormantReleaseThresholdDays
			}))
		},
		check: func(policy config.PolicyTierConfig) []report.Finding {
			if policy.DormantReleaseThresholdDays <= 0 {
				return nil
			}
			return dormant.Check(*pkg, policy.DormantReleaseThresholdDays)
		},
	})
	evaluate(debugPolicyCheck{
		id:         "protected_package",
		applicable: true,
		enabled:    anyTier(tiers, hasProtectedPackagePolicy),
		evidence: func() []string {
			return protectedNameEvidence(*pkg, "configured protected packages", tiers, func(policy config.PolicyTierConfig) map[string][]string {
				return policy.ProtectedPackages
			})
		},
		check: func(policy config.PolicyTierConfig) []report.Finding {
			if !hasProtectedPackagePolicy(policy) {
				return nil
			}
			return namesquat.CheckProtectedPackages(*pkg, policy)
		},
	})
	evaluate(debugPolicyCheck{
		id:         "protected_token",
		applicable: true,
		enabled:    anyTier(tiers, hasProtectedTokenPolicy),
		evidence: func() []string {
			return protectedNameEvidence(*pkg, "configured protected tokens", tiers, func(policy config.PolicyTierConfig) map[string][]string {
				return policy.ProtectedTokens
			})
		},
		check: func(policy config.PolicyTierConfig) []report.Finding {
			if !hasProtectedTokenPolicy(policy) {
				return nil
			}
			return namesquat.CheckProtectedTokens(*pkg, policy)
		},
	})
	evaluate(debugPolicyCheck{
		id:         "first_release",
		applicable: true,
		enabled:    anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.AlertOnFirstRelease }),
		evidence: func() []string {
			return append(firstReleaseEvidence(*pkg), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.AlertOnFirstRelease
			}))
		},
		check: func(policy config.PolicyTierConfig) []report.Finding {
			if !policy.AlertOnFirstRelease {
				return nil
			}
			return firstrelease.Check(*pkg)
		},
	})

	npmApplicable := isNPM(*pkg)
	npmHistoryVersions := maxTierInteger(tiers, func(policy config.PolicyTierConfig) int { return policy.InstallLifecycleHistoryVersions })
	evaluate(debugPolicyCheck{
		id:         "npm_lifecycle_scripts",
		applicable: npmApplicable,
		enabled:    anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.InstallLifecycleScripts }),
		evidence: func() []string {
			return append(installlifecycle.DeclaredScriptsEvidence(*pkg), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.InstallLifecycleScripts
			}))
		},
		check: func(policy config.PolicyTierConfig) []report.Finding {
			if !policy.InstallLifecycleScripts {
				return nil
			}
			return installlifecycle.CheckDeclaredScripts(*pkg)
		},
	})
	evaluate(debugPolicyCheck{
		id:         "npm_suspicious_install_commands",
		applicable: npmApplicable,
		enabled:    anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.SuspiciousInstallScriptCommands }),
		evidence: func() []string {
			return append(installlifecycle.SuspiciousCommandsEvidence(*pkg), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.SuspiciousInstallScriptCommands
			}))
		},
		check: func(policy config.PolicyTierConfig) []report.Finding {
			if !policy.SuspiciousInstallScriptCommands {
				return nil
			}
			return installlifecycle.CheckSuspiciousCommands(*pkg)
		},
	})
	evaluate(debugPolicyCheck{
		id:         "npm_lifecycle_history",
		applicable: npmApplicable,
		enabled:    npmHistoryVersions > 0,
		indeterminate: func(policy config.PolicyTierConfig) string {
			if policy.InstallLifecycleHistoryVersions <= 0 {
				return ""
			}
			if pkg.NPMHistory.IndeterminateReason != "" {
				return pkg.NPMHistory.IndeterminateReason
			}
			return installlifecycle.HistoryIndeterminateReason(*pkg, policy.InstallLifecycleHistoryVersions)
		},
		evidence: func() []string {
			return append(installlifecycle.HistoryEvidence(*pkg, npmHistoryVersions), integerThresholdEvidence("history limits", tiers, func(policy config.PolicyTierConfig) int {
				return policy.InstallLifecycleHistoryVersions
			}))
		},
		check: func(policy config.PolicyTierConfig) []report.Finding {
			if policy.InstallLifecycleHistoryVersions <= 0 {
				return nil
			}
			return installlifecycle.CheckHistoryChanges(*pkg, policy.InstallLifecycleHistoryVersions)
		},
	})
	evaluate(debugPolicyCheck{
		id:         "npm_lifecycle_added_after_dormancy",
		applicable: npmApplicable,
		enabled:    anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.InstallScriptAddedAfterDormancy }),
		indeterminate: func(policy config.PolicyTierConfig) string {
			if !policy.InstallScriptAddedAfterDormancy {
				return ""
			}
			if pkg.NPMHistory.IndeterminateReason != "" {
				return pkg.NPMHistory.IndeterminateReason
			}
			return installlifecycle.DormantAddedIndeterminateReason(*pkg, policy.InstallLifecycleHistoryVersions, policy.DormantReleaseThresholdDays)
		},
		evidence: func() []string {
			return append(installlifecycle.DormantAddedEvidence(*pkg, npmHistoryVersions, maxTierInteger(tiers, func(policy config.PolicyTierConfig) int {
				return policy.DormantReleaseThresholdDays
			})), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.InstallScriptAddedAfterDormancy
			}))
		},
		check: func(policy config.PolicyTierConfig) []report.Finding {
			if !policy.InstallScriptAddedAfterDormancy {
				return nil
			}
			return installlifecycle.CheckDormantAdded(*pkg, policy.InstallLifecycleHistoryVersions, policy.DormantReleaseThresholdDays)
		},
	})

	pypiApplicable := isPyPI(*pkg)
	pypiHistoryVersions := maxTierInteger(tiers, func(policy config.PolicyTierConfig) int { return policy.PyPIArtifactHistoryVersions })
	appendInformationalTrace(pkg, options.Debug, "pypi_artifact_history", pypiApplicable, pypiHistoryVersions > 0, func() []string {
		return pypiartifacts.ArtifactHistoryEvidence(*pkg, pypiHistoryVersions)
	})
	evaluate(debugPolicyCheck{
		id:         "pypi_artifact_shape",
		applicable: pypiApplicable,
		enabled:    anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.PyPIArtifactShapeChange }),
		indeterminate: func(policy config.PolicyTierConfig) string {
			if reason := pypiHistoryIndeterminateReason(*pkg, policy.PyPIArtifactShapeChange); reason != "" {
				return reason
			}
			if !policy.PyPIArtifactShapeChange {
				return ""
			}
			return pypiartifacts.ArtifactShapeIndeterminateReason(*pkg, policy.PyPIArtifactHistoryVersions)
		},
		evidence: func() []string {
			return append(pypiartifacts.ArtifactShapeEvidence(*pkg, pypiHistoryVersions), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.PyPIArtifactShapeChange
			}))
		},
		check: func(policy config.PolicyTierConfig) []report.Finding {
			if !policy.PyPIArtifactShapeChange {
				return nil
			}
			return pypiartifacts.CheckArtifactShapeChange(*pkg, policy.PyPIArtifactHistoryVersions)
		},
	})
	evaluate(debugPolicyCheck{
		id:         "pypi_file_size_jump",
		applicable: pypiApplicable,
		enabled:    anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.PyPIFileSizeJumpPercent > 0 }),
		indeterminate: func(policy config.PolicyTierConfig) string {
			if reason := pypiHistoryIndeterminateReason(*pkg, policy.PyPIFileSizeJumpPercent > 0); reason != "" {
				return reason
			}
			if policy.PyPIFileSizeJumpPercent <= 0 {
				return ""
			}
			return pypiartifacts.FileSizeIndeterminateReason(*pkg, policy.PyPIArtifactHistoryVersions)
		},
		evidence: func() []string {
			return append(pypiartifacts.FileSizeEvidence(*pkg, pypiHistoryVersions), integerThresholdEvidence("thresholds (percent)", tiers, func(policy config.PolicyTierConfig) int {
				return policy.PyPIFileSizeJumpPercent
			}))
		},
		check: func(policy config.PolicyTierConfig) []report.Finding {
			if policy.PyPIFileSizeJumpPercent <= 0 {
				return nil
			}
			return pypiartifacts.CheckFileSizeJump(*pkg, policy.PyPIArtifactHistoryVersions, policy.PyPIFileSizeJumpPercent)
		},
	})
	evaluate(debugPolicyCheck{
		id:         "pypi_dependency_change",
		applicable: pypiApplicable,
		enabled:    anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.PyPIDependencyChange }),
		indeterminate: func(policy config.PolicyTierConfig) string {
			if reason := pypiHistoryIndeterminateReason(*pkg, policy.PyPIDependencyChange); reason != "" {
				return reason
			}
			if !policy.PyPIDependencyChange {
				return ""
			}
			return pypiartifacts.DependencyIndeterminateReason(*pkg, policy.PyPIArtifactHistoryVersions)
		},
		evidence: func() []string {
			evidence := append(pypiartifacts.DependencyEvidence(*pkg, pypiHistoryVersions, anyTier(tiers, func(policy config.PolicyTierConfig) bool {
				return policy.PyPIIncludeOptionalDependencies
			})), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.PyPIDependencyChange
			}))
			return append(evidence, booleanThresholdEvidence("optional dependency comparison tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.PyPIIncludeOptionalDependencies
			}))
		},
		check: func(policy config.PolicyTierConfig) []report.Finding {
			if !policy.PyPIDependencyChange {
				return nil
			}
			return pypiartifacts.CheckDependencyChange(*pkg, policy.PyPIArtifactHistoryVersions, policy.PyPIIncludeOptionalDependencies)
		},
	})
	evaluate(debugPolicyCheck{
		id:                   "pypi_provenance",
		applicable:           pypiApplicable,
		enabled:              anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.PyPIProvenanceRequired }),
		checkOnIndeterminate: true,
		indeterminate: func(policy config.PolicyTierConfig) string {
			if !policy.PyPIProvenanceRequired {
				return ""
			}
			return pypiartifacts.ProvenanceIndeterminateReason(*pkg, policy.PyPIProvenanceScope)
		},
		evidence: func() []string {
			return append(pypiartifacts.ProvenanceEvidence(*pkg), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.PyPIProvenanceRequired
			}))
		},
		check: func(policy config.PolicyTierConfig) []report.Finding {
			if !policy.PyPIProvenanceRequired {
				return nil
			}
			return pypiartifacts.CheckProvenanceRequired(*pkg, policy.PyPIProvenanceScope)
		},
	})
	evaluate(debugPolicyCheck{
		id:         "pypi_release_file_count",
		applicable: pypiApplicable,
		enabled:    anyTier(tiers, func(policy config.PolicyTierConfig) bool { return policy.PyPIReleaseFileCountChange }),
		indeterminate: func(policy config.PolicyTierConfig) string {
			if reason := pypiHistoryIndeterminateReason(*pkg, policy.PyPIReleaseFileCountChange); reason != "" {
				return reason
			}
			if !policy.PyPIReleaseFileCountChange {
				return ""
			}
			return pypiartifacts.ReleaseFileCountIndeterminateReason(*pkg, policy.PyPIArtifactHistoryVersions)
		},
		evidence: func() []string {
			return append(pypiartifacts.ReleaseFileCountEvidence(*pkg, pypiHistoryVersions), booleanThresholdEvidence("tiers", tiers, func(policy config.PolicyTierConfig) bool {
				return policy.PyPIReleaseFileCountChange
			}))
		},
		check: func(policy config.PolicyTierConfig) []report.Finding {
			if !policy.PyPIReleaseFileCountChange {
				return nil
			}
			return pypiartifacts.CheckReleaseFileCountChange(*pkg, policy.PyPIArtifactHistoryVersions)
		},
	})

	if enabledPolicy {
		if hasBlockFinding(pkg.Findings) {
			pkg.Decision = report.DecisionBlock
		} else {
			pkg.Decision = report.DecisionAllow
		}
	}
}

func hasBlockFinding(findings []report.Finding) bool {
	for _, finding := range findings {
		if finding.Severity == levelBlock {
			return true
		}
	}
	return false
}

type debugPolicyCheck struct {
	id                   string
	applicable           bool
	enabled              bool
	checkOnIndeterminate bool
	indeterminate        func(config.PolicyTierConfig) string
	evidence             func() []string
	check                func(config.PolicyTierConfig) []report.Finding
}

func evaluatePolicyCheck(tiers []policyTier, debug bool, check debugPolicyCheck) ([]report.Finding, report.DebugTraceEntry) {
	trace := report.DebugTraceEntry{CheckID: check.id}
	if !check.applicable {
		trace.Status = report.DebugTraceNotApplicable
		return nil, trace
	}
	if !check.enabled {
		trace.Status = report.DebugTraceDisabled
		if debug {
			trace.Evidence = check.evidence()
		}
		return nil, trace
	}

	findings, severity, indeterminate := firstMatchingTierCheckResult(tiers, check)
	if !debug {
		return findings, trace
	}
	trace.Evidence = check.evidence()
	if indeterminate {
		trace.Status = report.DebugTraceIndeterminate
		trace.Severity = severity
		for _, finding := range findings {
			trace.Evidence = append(trace.Evidence, "finding: "+finding.Message)
		}
		return findings, trace
	}
	if len(findings) == 0 {
		trace.Status = report.DebugTraceNoMatch
		return findings, trace
	}
	trace.Status = report.DebugTraceMatch
	trace.Severity = severity
	for _, finding := range findings {
		trace.Evidence = append(trace.Evidence, "finding: "+finding.Message)
	}
	return findings, trace
}

func firstMatchingTierCheckResult(tiers []policyTier, check debugPolicyCheck) ([]report.Finding, string, bool) {
	for _, tier := range tiers {
		if check.indeterminate != nil {
			if reason := check.indeterminate(tier.policy); reason != "" {
				findings := []report.Finding{{Message: "policy evaluation is indeterminate: " + reason}}
				if check.checkOnIndeterminate {
					findings = append(check.check(tier.policy), findings...)
				}
				return withSeverity(findings, tier.level), tier.level, true
			}
		}
		findings := check.check(tier.policy)
		if len(findings) > 0 {
			return withSeverity(findings, tier.level), tier.level, false
		}
	}
	return nil, "", false
}

func appendInformationalTrace(pkg *report.PackageReport, debug bool, id string, applicable bool, enabled bool, evidence func() []string) {
	if !debug {
		return
	}
	trace := report.DebugTraceEntry{CheckID: id}
	switch {
	case !applicable:
		trace.Status = report.DebugTraceNotApplicable
	case !enabled:
		trace.Status = report.DebugTraceDisabled
		trace.Evidence = evidence()
	default:
		trace.Status = report.DebugTraceNoMatch
		trace.Evidence = evidence()
	}
	pkg.DebugTrace = append(pkg.DebugTrace, trace)
}

func strongestFirstPolicyTiers(policy config.PolicyConfig) []policyTier {
	return []policyTier{
		{level: levelBlock, policy: policy.Block},
		{level: levelAlert, policy: policy.Alert},
		{level: levelInform, policy: policy.Inform},
	}
}

func displayOrderPolicyTiers(policy config.PolicyConfig) []policyTier {
	return []policyTier{
		{level: "inform", policy: policy.Inform},
		{level: "alert", policy: policy.Alert},
		{level: "block", policy: policy.Block},
	}
}

func policyEnabled(tiers []policyTier) bool {
	for _, tier := range tiers {
		if policyTierEnabled(tier.policy) {
			return true
		}
	}
	return false
}

func policyTierEnabled(policy config.PolicyTierConfig) bool {
	return policy.MinimumDaysSinceLatestRelease > 0 ||
		policy.DormantReleaseThresholdDays > 0 ||
		policy.AlertOnFirstRelease ||
		policy.InstallLifecycleScripts ||
		policy.InstallLifecycleHistoryVersions > 0 ||
		policy.SuspiciousInstallScriptCommands ||
		policy.InstallScriptAddedAfterDormancy ||
		policy.PyPIArtifactHistoryVersions > 0 ||
		policy.PyPIArtifactShapeChange ||
		policy.PyPIFileSizeJumpPercent > 0 ||
		policy.PyPIDependencyChange ||
		policy.PyPIProvenanceRequired ||
		policy.PyPIReleaseFileCountChange ||
		hasProtectedNamePolicy(policy)
}

func hasProtectedNamePolicy(policy config.PolicyTierConfig) bool {
	return len(policy.ProtectedPackages) > 0 || len(policy.ProtectedTokens) > 0
}

func hasProtectedPackagePolicy(policy config.PolicyTierConfig) bool {
	return len(policy.ProtectedPackages) > 0
}

func hasProtectedTokenPolicy(policy config.PolicyTierConfig) bool {
	return len(policy.ProtectedTokens) > 0
}

func firstMatchingTierFinding(tiers []policyTier, check func(config.PolicyTierConfig) []report.Finding) []report.Finding {
	findings, _ := firstMatchingTierResult(tiers, check)
	return findings
}

func firstMatchingTierResult(tiers []policyTier, check func(config.PolicyTierConfig) []report.Finding) ([]report.Finding, string) {
	for _, tier := range tiers {
		findings := check(tier.policy)
		if len(findings) > 0 {
			return withSeverity(findings, tier.level), tier.level
		}
	}
	return nil, ""
}

func withSeverity(findings []report.Finding, severity string) []report.Finding {
	result := make([]report.Finding, 0, len(findings))
	for _, finding := range findings {
		finding.Severity = severity
		result = append(result, finding)
	}
	return result
}

func policySummary(policy config.PolicyConfig) string {
	var summaries []string
	for _, tier := range displayOrderPolicyTiers(policy) {
		if summary := policyTierSummary(tier.policy); summary != "" {
			summaries = append(summaries, tier.level+": "+summary)
		}
	}
	return joinPolicySummaries(summaries)
}

func policyTierSummary(policy config.PolicyTierConfig) string {
	var summaries []string
	if policy.MinimumDaysSinceLatestRelease > 0 {
		summaries = append(
			summaries,
			fmt.Sprintf("latest release must be at least %d day(s) old", policy.MinimumDaysSinceLatestRelease),
		)
	}
	if policy.DormantReleaseThresholdDays > 0 {
		summaries = append(
			summaries,
			fmt.Sprintf("release inactivity gap must be below %d day(s)", policy.DormantReleaseThresholdDays),
		)
	}
	if hasProtectedNamePolicy(policy) {
		summaries = append(summaries, "protected package or token checks enabled")
	}
	if policy.AlertOnFirstRelease {
		summaries = append(summaries, "first-release package checks enabled")
	}
	if policy.InstallLifecycleScripts {
		summaries = append(summaries, "npm install lifecycle script checks enabled")
	}
	if policy.InstallLifecycleHistoryVersions > 0 {
		summaries = append(
			summaries,
			fmt.Sprintf("npm install lifecycle history checks compare previous %d version(s)", policy.InstallLifecycleHistoryVersions),
		)
	}
	if policy.SuspiciousInstallScriptCommands {
		summaries = append(summaries, "suspicious npm install script command checks enabled")
	}
	if policy.InstallScriptAddedAfterDormancy {
		summaries = append(summaries, "dormant npm install script addition checks enabled")
	}
	if policy.PyPIArtifactHistoryVersions > 0 {
		summaries = append(
			summaries,
			fmt.Sprintf("PyPI artifact history checks compare previous %d version(s)", policy.PyPIArtifactHistoryVersions),
		)
	}
	if policy.PyPIArtifactShapeChange {
		summaries = append(summaries, "PyPI artifact shape change checks enabled")
	}
	if policy.PyPIFileSizeJumpPercent > 0 {
		summaries = append(
			summaries,
			fmt.Sprintf("PyPI file size jump threshold is a %d%% increase over historical median", policy.PyPIFileSizeJumpPercent),
		)
	}
	if policy.PyPIDependencyChange {
		if policy.PyPIIncludeOptionalDependencies {
			summaries = append(summaries, "PyPI required and optional dependency change checks enabled")
		} else {
			summaries = append(summaries, "PyPI required dependency change checks enabled")
		}
	}
	if policy.PyPIProvenanceRequired {
		summaries = append(summaries, fmt.Sprintf("PyPI provenance availability checks enabled for %s", policy.PyPIProvenanceScope))
	}
	if policy.PyPIReleaseFileCountChange {
		summaries = append(summaries, "PyPI release file count change checks enabled")
	}
	return joinPolicySummaries(summaries)
}

func packageHistoryIndeterminateReason(pkg report.PackageReport) string {
	if isNPM(pkg) {
		return pkg.NPMHistory.IndeterminateReason
	}
	if isPyPI(pkg) {
		return pkg.PyPIHistory.IndeterminateReason
	}
	return ""
}

func pypiHistoryIndeterminateReason(pkg report.PackageReport, enabled bool) string {
	if !enabled {
		return ""
	}
	return pkg.PyPIHistory.IndeterminateReason
}

func joinPolicySummaries(values []string) string {
	if len(values) == 0 {
		return ""
	}
	result := values[0]
	for _, value := range values[1:] {
		result += "; " + value
	}
	return result
}
