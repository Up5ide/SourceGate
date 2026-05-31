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

func Evaluate(pkg *report.PackageReport, cfg config.Config, now time.Time) {
	pkg.Decision = report.DecisionInspectOnly

	tiers := strongestFirstPolicyTiers(cfg.Policy)
	if !policyEnabled(tiers) {
		return
	}

	pkg.PolicySummary = policySummary(cfg.Policy)
	pkg.Findings = append(pkg.Findings, firstMatchingTierFinding(tiers, func(policy config.PolicyTierConfig) []report.Finding {
		if policy.MinimumDaysSinceLatestRelease <= 0 {
			return nil
		}
		return releaseage.Check(*pkg, policy.MinimumDaysSinceLatestRelease, now)
	})...)
	pkg.Findings = append(pkg.Findings, firstMatchingTierFinding(tiers, func(policy config.PolicyTierConfig) []report.Finding {
		if policy.DormantReleaseThresholdDays <= 0 {
			return nil
		}
		return dormant.Check(*pkg, policy.DormantReleaseThresholdDays)
	})...)
	pkg.Findings = append(pkg.Findings, firstMatchingTierFinding(tiers, func(policy config.PolicyTierConfig) []report.Finding {
		if !hasProtectedNamePolicy(policy) {
			return nil
		}
		return namesquat.Check(*pkg, policy)
	})...)
	pkg.Findings = append(pkg.Findings, firstMatchingTierFinding(tiers, func(policy config.PolicyTierConfig) []report.Finding {
		if !policy.AlertOnFirstRelease {
			return nil
		}
		return firstrelease.Check(*pkg)
	})...)
	pkg.Findings = append(pkg.Findings, firstMatchingTierFinding(tiers, func(policy config.PolicyTierConfig) []report.Finding {
		if !policy.InstallLifecycleScripts {
			return nil
		}
		return installlifecycle.CheckDeclaredScripts(*pkg)
	})...)
	pkg.Findings = append(pkg.Findings, firstMatchingTierFinding(tiers, func(policy config.PolicyTierConfig) []report.Finding {
		if !policy.SuspiciousInstallScriptCommands {
			return nil
		}
		return installlifecycle.CheckSuspiciousCommands(*pkg)
	})...)
	pkg.Findings = append(pkg.Findings, firstMatchingTierFinding(tiers, func(policy config.PolicyTierConfig) []report.Finding {
		if policy.InstallLifecycleHistoryVersions <= 0 {
			return nil
		}
		return installlifecycle.CheckHistoryChanges(*pkg, policy.InstallLifecycleHistoryVersions)
	})...)
	pkg.Findings = append(pkg.Findings, firstMatchingTierFinding(tiers, func(policy config.PolicyTierConfig) []report.Finding {
		if !policy.InstallScriptAddedAfterDormancy {
			return nil
		}
		return installlifecycle.CheckDormantAdded(*pkg, policy.InstallLifecycleHistoryVersions, policy.DormantReleaseThresholdDays)
	})...)
	pkg.Findings = append(pkg.Findings, firstMatchingTierFinding(tiers, func(policy config.PolicyTierConfig) []report.Finding {
		if !policy.PyPIArtifactShapeChange {
			return nil
		}
		return pypiartifacts.CheckArtifactShapeChange(*pkg, policy.PyPIArtifactHistoryVersions)
	})...)
	pkg.Findings = append(pkg.Findings, firstMatchingTierFinding(tiers, func(policy config.PolicyTierConfig) []report.Finding {
		if policy.PyPIFileSizeJumpPercent <= 0 {
			return nil
		}
		return pypiartifacts.CheckFileSizeJump(*pkg, policy.PyPIArtifactHistoryVersions, policy.PyPIFileSizeJumpPercent)
	})...)
	pkg.Findings = append(pkg.Findings, firstMatchingTierFinding(tiers, func(policy config.PolicyTierConfig) []report.Finding {
		if !policy.PyPIDependencyChange {
			return nil
		}
		return pypiartifacts.CheckDependencyChange(*pkg, policy.PyPIArtifactHistoryVersions)
	})...)
	pkg.Findings = append(pkg.Findings, firstMatchingTierFinding(tiers, func(policy config.PolicyTierConfig) []report.Finding {
		if !policy.PyPIProvenanceRequired {
			return nil
		}
		return pypiartifacts.CheckProvenanceRequired(*pkg)
	})...)
	pkg.Findings = append(pkg.Findings, firstMatchingTierFinding(tiers, func(policy config.PolicyTierConfig) []report.Finding {
		if !policy.PyPIReleaseFileCountChange {
			return nil
		}
		return pypiartifacts.CheckReleaseFileCountChange(*pkg, policy.PyPIArtifactHistoryVersions)
	})...)

	pkg.Decision = report.DecisionAllow
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

func firstMatchingTierFinding(tiers []policyTier, check func(config.PolicyTierConfig) []report.Finding) []report.Finding {
	for _, tier := range tiers {
		findings := check(tier.policy)
		if len(findings) > 0 {
			return withSeverity(findings, tier.level)
		}
	}
	return nil
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
		summaries = append(summaries, "protected package and token checks enabled")
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
			fmt.Sprintf("PyPI file size jump threshold is %d%% of historical median", policy.PyPIFileSizeJumpPercent),
		)
	}
	if policy.PyPIDependencyChange {
		summaries = append(summaries, "PyPI dependency change checks enabled")
	}
	if policy.PyPIProvenanceRequired {
		summaries = append(summaries, "PyPI provenance availability checks enabled")
	}
	if policy.PyPIReleaseFileCountChange {
		summaries = append(summaries, "PyPI release file count change checks enabled")
	}
	return joinPolicySummaries(summaries)
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
