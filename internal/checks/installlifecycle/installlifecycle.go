package installlifecycle

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/report"
)

var installLifecycleScripts = map[string]struct{}{
	"preinstall":  {},
	"install":     {},
	"postinstall": {},
	"prepublish":  {},
	"prepare":     {},
	"preprepare":  {},
	"postprepare": {},
}

var highSignalInstallScripts = map[string]struct{}{
	"preinstall":  {},
	"install":     {},
	"postinstall": {},
}

func CheckDeclaredScripts(pkg report.PackageReport) []report.Finding {
	if !isNPM(pkg) {
		return nil
	}

	names := installScriptNames(pkg.LifecycleScripts)
	findings := make([]report.Finding, 0, len(names))
	for _, name := range names {
		message := fmt.Sprintf("package declares npm install-relevant lifecycle script %q: %s", name, pkg.LifecycleScripts[name])
		if _, ok := highSignalInstallScripts[name]; ok {
			message = fmt.Sprintf("package declares high-signal npm install lifecycle script %q: %s", name, pkg.LifecycleScripts[name])
		}
		findings = append(findings, report.Finding{Message: message})
	}
	return findings
}

func CheckSuspiciousCommands(pkg report.PackageReport) []report.Finding {
	if !isNPM(pkg) {
		return nil
	}

	var findings []report.Finding
	for _, name := range installScriptNames(pkg.LifecycleScripts) {
		reasons := suspiciousCommandReasons(pkg.LifecycleScripts[name])
		if len(reasons) == 0 {
			continue
		}
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf(
				"npm lifecycle script %q has suspicious command pattern(s): %s: %s",
				name,
				strings.Join(reasons, ", "),
				pkg.LifecycleScripts[name],
			),
		})
	}
	return findings
}

func CheckHistoryChanges(pkg report.PackageReport, historyVersions int) []report.Finding {
	if !isNPM(pkg) || historyVersions <= 0 {
		return nil
	}

	var findings []report.Finding
	for _, name := range installScriptNames(pkg.LifecycleScripts) {
		result := scriptHistory(pkg, name, historyVersions)
		switch {
		case result.found && normalizeCommand(result.previousCommand) != normalizeCommand(pkg.LifecycleScripts[name]):
			findings = append(findings, report.Finding{
				Message: fmt.Sprintf("latest npm version changes lifecycle script %q from version %s", name, result.previousVersion),
			})
		case !result.found && result.compared > 0 && !result.unknown:
			findings = append(findings, report.Finding{
				Message: fmt.Sprintf("latest npm version adds lifecycle script %q not present in previous %d version(s)", name, result.compared),
			})
		case !result.found && result.unknown:
			findings = append(findings, report.Finding{
				Message: fmt.Sprintf("npm lifecycle script history for %q is incomplete because prior version metadata is missing scripts", name),
			})
		}
	}
	return findings
}

func CheckDormantAdded(pkg report.PackageReport, historyVersions int, thresholdDays int) []report.Finding {
	if !isNPM(pkg) || historyVersions <= 0 || thresholdDays <= 0 {
		return nil
	}

	inactivityDays, dormant := dormantReleaseGap(pkg, thresholdDays)
	if !dormant {
		return nil
	}

	var findings []report.Finding
	for _, name := range installScriptNames(pkg.LifecycleScripts) {
		result := scriptHistory(pkg, name, historyVersions)
		if result.found || result.compared == 0 || result.unknown {
			continue
		}
		findings = append(findings, report.Finding{
			Message: fmt.Sprintf(
				"latest npm version adds lifecycle script %q after %d day(s) of package inactivity",
				name,
				inactivityDays,
			),
		})
	}
	return findings
}

type historyResult struct {
	found           bool
	unknown         bool
	compared        int
	previousVersion string
	previousCommand string
}

func scriptHistory(pkg report.PackageReport, scriptName string, historyVersions int) historyResult {
	result := historyResult{}
	for _, version := range pkg.LifecycleHistory {
		if result.compared >= historyVersions {
			break
		}
		result.compared++
		if !version.ScriptsKnown {
			result.unknown = true
			continue
		}
		command, ok := version.Scripts[scriptName]
		if !ok {
			continue
		}
		result.found = true
		result.previousVersion = version.Version
		result.previousCommand = command
		return result
	}
	return result
}

func installScriptNames(scripts map[string]string) []string {
	names := make([]string, 0, len(scripts))
	for name, command := range scripts {
		name = strings.ToLower(strings.TrimSpace(name))
		if _, ok := installLifecycleScripts[name]; ok && strings.TrimSpace(command) != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func suspiciousCommandReasons(command string) []string {
	lower := strings.ToLower(command)
	var reasons []string

	networkCommand := hasCommandToken(lower, "curl") ||
		hasCommandToken(lower, "wget") ||
		hasCommandToken(lower, "iwr") ||
		hasCommandToken(lower, "invoke-webrequest")
	shellCommand := hasCommandToken(lower, "sh") ||
		hasCommandToken(lower, "bash") ||
		hasCommandToken(lower, "zsh") ||
		hasCommandToken(lower, "dash") ||
		hasCommandToken(lower, "cmd") ||
		hasCommandToken(lower, "powershell") ||
		hasCommandToken(lower, "pwsh")

	if networkCommand && strings.Contains(lower, "|") && shellCommand {
		reasons = append(reasons, "download-and-execute")
	}
	if networkCommand {
		reasons = append(reasons, "network download command")
	}
	if strings.Contains(lower, "http://") || strings.Contains(lower, "https://") {
		reasons = append(reasons, "direct URL")
	}
	if shellCommand {
		reasons = append(reasons, "shell or command interpreter")
	}
	if hasCommandToken(lower, "iex") || hasCommandToken(lower, "invoke-expression") {
		reasons = append(reasons, "PowerShell expression execution")
	}
	if hasCommandToken(lower, "node-gyp") ||
		hasCommandToken(lower, "prebuild-install") ||
		hasCommandToken(lower, "cmake-js") ||
		hasCommandToken(lower, "make") {
		reasons = append(reasons, "native build tooling")
	}
	if hasCommandToken(lower, "npm") ||
		hasCommandToken(lower, "pnpm") ||
		hasCommandToken(lower, "yarn") ||
		hasCommandToken(lower, "npx") {
		reasons = append(reasons, "package-manager invocation")
	}
	if hasCommandToken(lower, "chmod") ||
		hasCommandToken(lower, "icacls") ||
		hasCommandToken(lower, "cacls") ||
		hasCommandToken(lower, "takeown") {
		reasons = append(reasons, "permission-changing command")
	}

	return compactReasons(reasons)
}

func compactReasons(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func hasCommandToken(command string, token string) bool {
	for _, value := range commandTokens(command) {
		if value == token {
			return true
		}
	}
	return false
}

func commandTokens(command string) []string {
	return strings.FieldsFunc(command, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_'
	})
}

func dormantReleaseGap(pkg report.PackageReport, thresholdDays int) (int, bool) {
	selectedPublishedAt, err := parseRegistryTime(pkg.SelectedPublishedAt)
	if err != nil {
		return 0, false
	}
	previousPublishedAt, err := parseRegistryTime(pkg.PreviousPublishedAt)
	if err != nil {
		return 0, false
	}

	inactivity := selectedPublishedAt.UTC().Sub(previousPublishedAt.UTC())
	threshold := time.Duration(thresholdDays) * 24 * time.Hour
	if inactivity < threshold {
		return 0, false
	}
	return int(inactivity.Hours() / 24), true
}

func parseRegistryTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, nil
	}
	return time.Parse(time.RFC3339, value)
}

func normalizeCommand(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func isNPM(pkg report.PackageReport) bool {
	return strings.EqualFold(strings.TrimSpace(pkg.Ecosystem), string(ecosystem.NPM))
}
