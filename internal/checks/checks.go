package checks

import (
	"sort"
	"time"

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
	definitions := policyDefinitionsForPhase(phaseMetadata)
	enabledPolicy := phasePolicyEnabled(tiers, definitions)
	if !enabledPolicy && !options.Debug {
		return
	}

	if enabledPolicy {
		pkg.PolicySummary = policySummary(cfg.Policy, phaseMetadata)
	}

	for _, definition := range definitions {
		findings, trace := evaluatePolicyCheck(tiers, options.Debug, definition.debugCheck(pkg, tiers, now))
		pkg.Findings = append(pkg.Findings, findings...)
		if options.Debug {
			pkg.DebugTrace = append(pkg.DebugTrace, trace)
		}
	}

	if enabledPolicy {
		if hasBlockFinding(pkg.Findings) {
			pkg.Decision = report.DecisionBlock
		} else {
			pkg.Decision = report.DecisionAllow
		}
	}
}

func EvaluateArtifactInspection(pkg *report.PackageReport, cfg config.Config, options EvaluationOptions) {
	tiers := strongestFirstPolicyTiers(cfg.Policy)
	definitions := policyDefinitionsForPhase(phaseArtifact)
	enabledPolicy := phasePolicyEnabled(tiers, definitions)
	if !enabledPolicy && !options.Debug {
		return
	}

	if enabledPolicy {
		pkg.PolicySummary = appendPolicySummary(pkg.PolicySummary, policySummary(cfg.Policy, phaseArtifact))
	}

	for _, definition := range definitions {
		findings, trace := evaluatePolicyCheck(tiers, options.Debug, definition.debugCheck(pkg, tiers, time.Time{}))
		pkg.Findings = append(pkg.Findings, findings...)
		if options.Debug {
			pkg.DebugTrace = append(pkg.DebugTrace, trace)
		}
	}

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

func RequiredNPMHistoryVersions(policy config.PolicyConfig) int {
	tiers := strongestFirstPolicyTiers(policy)
	required := maxTierInteger(tiers, func(tier config.PolicyTierConfig) int {
		return tier.InstallLifecycleHistoryVersions
	})
	if dependencyHistory := maxTierInteger(tiers, func(tier config.PolicyTierConfig) int {
		return tier.NPMDependencyHistoryVersions
	}); dependencyHistory > required {
		required = dependencyHistory
	}
	if sourceHistory := maxTierInteger(tiers, func(tier config.PolicyTierConfig) int {
		if tier.NPMGitHeadChangedAfterDormancy || tier.NPMRepositoryChanged || tier.NPMPublisherChanged {
			return 1
		}
		return 0
	}); sourceHistory > required {
		required = sourceHistory
	}
	if releaseBurstHistory := maxTierInteger(tiers, func(tier config.PolicyTierConfig) int {
		return tier.NPMReleaseBurstCount
	}); releaseBurstHistory > required {
		required = releaseBurstHistory
	}
	return required
}

func RequiredPyPIArtifactHistoryVersions(policy config.PolicyConfig) int {
	return maxTierInteger(strongestFirstPolicyTiers(policy), func(tier config.PolicyTierConfig) int {
		return tier.PyPIArtifactHistoryVersions
	})
}

func RequiresPyPIDependencyHistory(policy config.PolicyConfig) bool {
	return anyTier(strongestFirstPolicyTiers(policy), func(tier config.PolicyTierConfig) bool {
		return tier.PyPIDependencyChange
	})
}

func RequiresNPMDirectDependencyInspection(policy config.PolicyConfig) bool {
	return anyTier(strongestFirstPolicyTiers(policy), func(tier config.PolicyTierConfig) bool {
		return tier.NPMDirectDependencyLifecycleScripts || tier.NPMDirectDependencySuspiciousInstallCommands
	})
}

func MaxNPMDirectDependencies(policy config.PolicyConfig) int {
	maximum := maxTierInteger(strongestFirstPolicyTiers(policy), func(tier config.PolicyTierConfig) int {
		return tier.NPMMaxDirectDependencies
	})
	if maximum <= 0 {
		return 25
	}
	return maximum
}

func RequiresArtifactDelta(policy config.PolicyConfig) bool {
	return anyTier(strongestFirstPolicyTiers(policy), func(tier config.PolicyTierConfig) bool {
		return tier.ArtifactFileListChange ||
			tier.ArtifactNewExecutionSurfaces ||
			tier.ArtifactNewSuspiciousFileTypes ||
			tier.ArtifactSizeDelta
	})
}

func ArtifactPolicyEnabled(policy config.PolicyConfig) bool {
	return phasePolicyEnabled(strongestFirstPolicyTiers(policy), policyDefinitionsForPhase(phaseArtifact))
}

func RequiredPyPIProvenanceScopes(policy config.PolicyConfig) []string {
	seen := make(map[string]struct{})
	for _, tier := range strongestFirstPolicyTiers(policy) {
		if tier.policy.PyPIProvenanceRequired {
			seen[tier.policy.PyPIProvenanceScope] = struct{}{}
		}
	}
	scopes := make([]string, 0, len(seen))
	for scope := range seen {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	return scopes
}

func phasePolicyEnabled(tiers []policyTier, definitions []policyCheckDefinition) bool {
	for _, tier := range tiers {
		if phaseTierEnabled(tier.policy, definitions) {
			return true
		}
	}
	return false
}

func phaseTierEnabled(policy config.PolicyTierConfig, definitions []policyCheckDefinition) bool {
	tier := []policyTier{{policy: policy}}
	for _, definition := range definitions {
		if definition.enabled(tier) {
			return true
		}
	}
	return false
}

func hasProtectedPackagePolicy(policy config.PolicyTierConfig) bool {
	return len(policy.ProtectedPackages) > 0
}

func hasProtectedTokenPolicy(policy config.PolicyTierConfig) bool {
	return len(policy.ProtectedTokens) > 0
}

func hasPrivatePackagePolicy(policy config.PolicyTierConfig) bool {
	return len(policy.PrivatePackages) > 0
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

func policySummary(policy config.PolicyConfig, phase policyPhase) string {
	definitions := policyDefinitionsForPhase(phase)
	var summaries []string
	for _, tier := range displayOrderPolicyTiers(policy) {
		if summary := policyTierSummary(tier.policy, definitions); summary != "" {
			summaries = append(summaries, tier.level+": "+summary)
		}
	}
	return joinPolicySummaries(summaries)
}

func policyTierSummary(policy config.PolicyTierConfig, definitions []policyCheckDefinition) string {
	var summaries []string
	for _, definition := range definitions {
		if summary := definition.summary(policy); summary != "" {
			summaries = append(summaries, summary)
		}
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

func appendPolicySummary(existing, addition string) string {
	if addition == "" {
		return existing
	}
	if existing == "" {
		return addition
	}
	return existing + "; " + addition
}
