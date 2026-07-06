package config

func Diagnostics(cfg Config) []string {
	var diagnostics []string
	if artifactPolicyEnabled(cfg.Policy) {
		diagnostics = append(diagnostics, "artifact policy is enabled; artifact checks run only with --mode artifact or --mode install.")
	}
	diagnostics = append(diagnostics, thresholdDiagnostics("minimum_days_since_latest_release", cfg.Policy.Alert.MinimumDaysSinceLatestRelease, cfg.Policy.Block.MinimumDaysSinceLatestRelease)...)
	diagnostics = append(diagnostics, thresholdDiagnostics("dormant_release_threshold_days", cfg.Policy.Alert.DormantReleaseThresholdDays, cfg.Policy.Block.DormantReleaseThresholdDays)...)
	diagnostics = append(diagnostics, thresholdDiagnostics("pypi_file_size_jump_percent", cfg.Policy.Alert.PyPIFileSizeJumpPercent, cfg.Policy.Block.PyPIFileSizeJumpPercent)...)
	diagnostics = append(diagnostics, thresholdDiagnostics("artifact_max_file_count", cfg.Policy.Alert.ArtifactMaxFileCount, cfg.Policy.Block.ArtifactMaxFileCount)...)
	diagnostics = append(diagnostics, thresholdDiagnostics("artifact_max_uncompressed_size_mb", cfg.Policy.Alert.ArtifactMaxUncompressedSizeMB, cfg.Policy.Block.ArtifactMaxUncompressedSizeMB)...)
	diagnostics = append(diagnostics, thresholdDiagnostics("artifact_max_expansion_ratio", cfg.Policy.Alert.ArtifactMaxExpansionRatio, cfg.Policy.Block.ArtifactMaxExpansionRatio)...)
	return diagnostics
}

func artifactPolicyEnabled(policy PolicyConfig) bool {
	return tierArtifactPolicyEnabled(policy.Inform) ||
		tierArtifactPolicyEnabled(policy.Alert) ||
		tierArtifactPolicyEnabled(policy.Block)
}

func tierArtifactPolicyEnabled(policy PolicyTierConfig) bool {
	return policy.ArtifactUnsafePaths ||
		policy.ArtifactMaxFileCount > 0 ||
		policy.ArtifactMaxUncompressedSizeMB > 0 ||
		policy.ArtifactMaxExpansionRatio > 0 ||
		policy.ArtifactExecutionSurfaces ||
		policy.ArtifactSuspiciousFileTypes ||
		policy.ArtifactBehaviorIndicators ||
		policy.ArtifactGeneralRiskSignals ||
		policy.ArtifactFileListChange ||
		policy.ArtifactNewExecutionSurfaces ||
		policy.ArtifactNewSuspiciousFileTypes ||
		policy.ArtifactSizeDelta
}

func thresholdDiagnostics(name string, alert, block int) []string {
	if alert > 0 && block > 0 && block <= alert {
		return []string{name + " has a block threshold less than or equal to alert; block thresholds are usually stricter when they are higher."}
	}
	return nil
}
