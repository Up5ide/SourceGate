package namesquat

import (
	"strings"
	"unicode"

	"github.com/sourcegate/sourcegate/internal/config"
	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/report"
)

func Check(pkg report.PackageReport, policy config.PolicyTierConfig) []report.Finding {
	var findings []report.Finding
	findings = append(findings, CheckProtectedPackages(pkg, policy)...)
	findings = append(findings, CheckProtectedTokens(pkg, policy)...)
	return findings
}

func CheckProtectedPackages(pkg report.PackageReport, policy config.PolicyTierConfig) []report.Finding {
	ecosystemKey := reportEcosystemKey(pkg)
	if ecosystemKey == "" {
		return nil
	}

	packageName := NormalizePackageName(ecosystemKey, pkg.Name)
	protectedPackages := normalizedSet(ecosystemKey, policy.ProtectedPackages[ecosystemKey])
	return protectedPackageTypos(packageName, protectedPackages)
}

func CheckProtectedTokens(pkg report.PackageReport, policy config.PolicyTierConfig) []report.Finding {
	ecosystemKey := reportEcosystemKey(pkg)
	if ecosystemKey == "" {
		return nil
	}

	packageName := NormalizePackageName(ecosystemKey, pkg.Name)
	protectedPackages := normalizedSet(ecosystemKey, policy.ProtectedPackages[ecosystemKey])
	return protectedTokenUse(packageName, protectedPackages, policy.ProtectedTokens[ecosystemKey])
}

func protectedPackageTypos(packageName string, protectedPackages map[string]struct{}) []report.Finding {
	if packageName == "" {
		return nil
	}
	if _, ok := protectedPackages[packageName]; ok {
		return nil
	}

	for protectedPackage := range protectedPackages {
		if IsOneEditPackageName(packageName, protectedPackage) {
			return []report.Finding{{
				Message: "package name may be typosquatting protected package " + protectedPackage,
			}}
		}
	}
	return nil
}

func protectedTokenUse(packageName string, protectedPackages map[string]struct{}, protectedTokens []string) []report.Finding {
	if packageName == "" {
		return nil
	}
	if _, ok := protectedPackages[packageName]; ok {
		return nil
	}

	packageTokens := SplitPackageTokens(packageName)
	if len(packageTokens) == 0 {
		return nil
	}

	for _, protectedToken := range protectedTokens {
		protectedToken = normalizeToken(protectedToken)
		if protectedToken == "" {
			continue
		}
		for _, packageToken := range packageTokens {
			if packageToken == protectedToken {
				return []report.Finding{{
					Message: "package name uses protected token " + protectedToken,
				}}
			}
		}
	}
	return nil
}

func reportEcosystemKey(pkg report.PackageReport) string {
	switch strings.ToLower(strings.TrimSpace(pkg.Ecosystem)) {
	case string(ecosystem.NPM):
		return string(ecosystem.NPM)
	case string(ecosystem.PyPI):
		return string(ecosystem.PyPI)
	default:
		return ""
	}
}

func normalizedSet(ecosystemKey string, values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := NormalizePackageName(ecosystemKey, value)
		if normalized != "" {
			result[normalized] = struct{}{}
		}
	}
	return result
}

func NormalizePackageName(ecosystemKey, value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch ecosystemKey {
	case string(ecosystem.PyPI):
		return normalizePyPIName(value)
	default:
		return value
	}
}

func normalizePyPIName(value string) string {
	var builder strings.Builder
	lastWasSeparator := false
	for _, r := range value {
		if r == '-' || r == '_' || r == '.' {
			if !lastWasSeparator {
				builder.WriteRune('-')
				lastWasSeparator = true
			}
			continue
		}
		builder.WriteRune(r)
		lastWasSeparator = false
	}
	return strings.Trim(builder.String(), "-")
}

func normalizeToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	tokens := SplitPackageTokens(value)
	if len(tokens) == 1 {
		return tokens[0]
	}
	return value
}

func SplitPackageTokens(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

func IsOneEditPackageName(candidate, protected string) bool {
	if candidate == protected || candidate == "" || protected == "" {
		return false
	}

	candidateRunes := []rune(candidate)
	protectedRunes := []rune(protected)
	lengthDiff := len(candidateRunes) - len(protectedRunes)
	if lengthDiff < -1 || lengthDiff > 1 {
		return false
	}

	if len(candidateRunes) == len(protectedRunes) {
		return oneSubstitutionOrTransposition(candidateRunes, protectedRunes)
	}
	return oneInsertionOrDeletion(candidateRunes, protectedRunes)
}

func oneSubstitutionOrTransposition(candidate, protected []rune) bool {
	var diffs []int
	for i := range candidate {
		if candidate[i] != protected[i] {
			diffs = append(diffs, i)
			if len(diffs) > 2 {
				return false
			}
		}
	}
	if len(diffs) == 1 {
		return true
	}
	if len(diffs) != 2 || diffs[1] != diffs[0]+1 {
		return false
	}
	return candidate[diffs[0]] == protected[diffs[1]] &&
		candidate[diffs[1]] == protected[diffs[0]]
}

func oneInsertionOrDeletion(candidate, protected []rune) bool {
	shorter := candidate
	longer := protected
	if len(candidate) > len(protected) {
		shorter = protected
		longer = candidate
	}

	i, j := 0, 0
	edits := 0
	for i < len(shorter) && j < len(longer) {
		if shorter[i] == longer[j] {
			i++
			j++
			continue
		}
		edits++
		if edits > 1 {
			return false
		}
		j++
	}
	return true
}
