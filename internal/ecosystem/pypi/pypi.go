package pypi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/report"
	"github.com/sourcegate/sourcegate/internal/text"
	sourcegateversion "github.com/sourcegate/sourcegate/internal/version"
	"github.com/sourcegate/sourcegate/internal/versioning"
)

var BaseURL = "https://pypi.org/pypi"
var IntegrityBaseURL = "https://pypi.org/integrity"

type Options struct {
	HistoryVersions   int
	FetchDependencies bool
	SelectArtifact    bool
	ProvenanceScopes  []string
	Target            TargetOptions
	RunCommand        CommandRunner
}

type TargetOptions struct {
	PythonExecutable string
	TargetPlatform   string
	PythonVersion    string
	Implementation   string
	ABIs             []string
}

type CommandRunner func(ctx context.Context, executable string, args ...string) ([]byte, error)

const (
	ProvenanceScopeInstallTarget = "install-target"
	ProvenanceScopeAllArtifacts  = "all-artifacts"
	ProvenanceScopeSdistOnly     = "sdist-only"
)

type Adapter struct {
	client  *http.Client
	options Options
}

func New(client *http.Client) *Adapter {
	return &Adapter{client: client}
}

func NewWithOptions(client *http.Client, options Options) *Adapter {
	if options.HistoryVersions < 0 {
		options.HistoryVersions = 0
	}
	options.ProvenanceScopes = compactSortedStrings(options.ProvenanceScopes)
	return &Adapter{client: client, options: options}
}

type registryResponse struct {
	Info     info                 `json:"info"`
	Releases map[string][]release `json:"releases"`
	URLs     []release            `json:"urls"`
}

type info struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Summary      string            `json:"summary"`
	License      string            `json:"license"`
	Author       string            `json:"author"`
	AuthorEmail  string            `json:"author_email"`
	ProjectURLs  map[string]string `json:"project_urls"`
	HomePage     string            `json:"home_page"`
	RequiresDist []string          `json:"requires_dist"`
	Dynamic      []string          `json:"dynamic"`
}

type release struct {
	Digests        map[string]string `json:"digests"`
	Filename       string            `json:"filename"`
	PackageType    string            `json:"packagetype"`
	PythonVersion  string            `json:"python_version"`
	RequiresPython string            `json:"requires_python"`
	Size           int64             `json:"size"`
	UploadTimeISO  string            `json:"upload_time_iso_8601"`
	Yanked         bool              `json:"yanked"`
	YankedReason   string            `json:"yanked_reason"`
	URL            string            `json:"url"`
}

func (a *Adapter) FetchMetadata(ctx context.Context, spec ecosystem.PackageSpec) (report.PackageReport, error) {
	client := a.client
	if client == nil {
		client = http.DefaultClient
	}

	packageName := spec.Name
	endpoint := BaseURL + "/" + url.PathEscape(packageName) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return report.PackageReport{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", sourcegateversion.UserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return report.PackageReport{}, fmt.Errorf("fetch PyPI metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return report.PackageReport{}, fmt.Errorf("PyPI package not found: %s", packageName)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return report.PackageReport{}, fmt.Errorf("PyPI returned status %d for %s", resp.StatusCode, packageName)
	}

	var data registryResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return report.PackageReport{}, fmt.Errorf("decode PyPI metadata: %w", err)
	}

	created, modified := releaseBounds(data.Releases)
	name := text.FirstNonEmpty(data.Info.Name, packageName)
	selectedVersion := spec.Version
	if selectedVersion == "" {
		selectedVersion = data.Info.Version
	}
	selectedFiles, ok := data.Releases[selectedVersion]
	if selectedVersion == "" || !ok {
		if spec.Version != "" {
			return report.PackageReport{}, fmt.Errorf("PyPI package version not found: %s==%s", packageName, spec.Version)
		}
		return report.PackageReport{}, fmt.Errorf("PyPI latest version is unavailable for %s", packageName)
	}

	selectedInfo := data.Info
	selectedURLs := data.URLs
	if spec.Version != "" && spec.Version != data.Info.Version {
		versionData, err := fetchVersionMetadata(ctx, client, packageName, spec.Version)
		if err != nil {
			return report.PackageReport{}, err
		}
		selectedInfo = versionData.Info
		selectedURLs = versionData.URLs
	}
	if len(selectedURLs) > 0 {
		selectedFiles = selectedURLs
	}

	historyEntries, historyDiagnostics := selectHistory(data.Releases, selectedVersion, max(1, a.options.HistoryVersions))
	dependencies, optionalDependencies := normalizeRequirements(selectedInfo.RequiresDist)
	selectedRelease := report.PyPIReleaseInfo{
		Version:              selectedVersion,
		PublishedAt:          latestReleaseTime(selectedFiles),
		Files:                releaseFiles(selectedFiles),
		Dependencies:         dependencies,
		OptionalDependencies: optionalDependencies,
		DependenciesKnown:    dependenciesKnown(selectedInfo),
	}
	provenance, warning := prepareProvenance(ctx, client, name, selectedVersion, selectedRelease.Files, a.options)
	var warnings []string
	if warning != "" {
		warnings = append(warnings, warning)
	}

	pkg := report.PackageReport{
		Ecosystem:           "PyPI",
		Registry:            "PyPI",
		Name:                name,
		SelectedVersion:     selectedVersion,
		SelectedPublishedAt: selectedRelease.PublishedAt,
		PreviousPublishedAt: previousPublishedAt(historyEntries),
		Description:         text.FirstNonEmpty(selectedInfo.Summary, data.Info.Summary),
		License:             text.FirstNonEmpty(selectedInfo.License, data.Info.License),
		Author:              text.FirstNonEmpty(formatAuthor(selectedInfo.Author, selectedInfo.AuthorEmail), formatAuthor(data.Info.Author, data.Info.AuthorEmail)),
		PyPISelectedRelease: selectedRelease,
		PyPIReleaseHistory:  releaseHistory(ctx, client, name, data.Releases, historyEntries, a.options.HistoryVersions, a.options.FetchDependencies),
		ProjectURLs:         projectURLs(selectedInfo, data.Info),
		CreatedAt:           created,
		ModifiedAt:          modified,
		VersionCount:        len(data.Releases),
		Warnings:            warnings,
		PyPIHistory:         historyDiagnostics,
		PyPIProvenance:      provenance,
	}
	if a.options.SelectArtifact {
		candidate, err := selectPreferredArtifact(ctx, selectedRelease.Files, a.options)
		if err != nil {
			candidate.SelectionError = err.Error()
		}
		pkg.ArtifactCandidate = candidate
	}
	return pkg, nil
}

type releaseHistoryEntry struct {
	version     string
	publishedAt string
}

func releaseHistory(ctx context.Context, client *http.Client, packageName string, releases map[string][]release, entries []releaseHistoryEntry, historyVersions int, fetchDependencies bool) []report.PyPIReleaseInfo {
	if historyVersions <= 0 {
		return nil
	}
	if len(entries) > historyVersions {
		entries = entries[:historyVersions]
	}

	history := make([]report.PyPIReleaseInfo, 0, len(entries))
	for index, entry := range entries {
		var deps, optionalDeps []string
		depsKnown := false
		if fetchDependencies && index == 0 {
			deps, optionalDeps, depsKnown = fetchReleaseDependencies(ctx, client, packageName, entry.version)
		}
		history = append(history, report.PyPIReleaseInfo{
			Version:              entry.version,
			PublishedAt:          entry.publishedAt,
			Files:                releaseFiles(releases[entry.version]),
			Dependencies:         deps,
			OptionalDependencies: optionalDeps,
			DependenciesKnown:    depsKnown,
		})
	}
	return history
}

func fetchVersionMetadata(ctx context.Context, client *http.Client, packageName string, version string) (registryResponse, error) {
	endpoint := BaseURL + "/" + url.PathEscape(packageName) + "/" + url.PathEscape(version) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return registryResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", sourcegateversion.UserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return registryResponse{}, fmt.Errorf("fetch PyPI version metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return registryResponse{}, fmt.Errorf("PyPI package version not found: %s==%s", packageName, version)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return registryResponse{}, fmt.Errorf("PyPI returned status %d for %s==%s", resp.StatusCode, packageName, version)
	}

	var data registryResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return registryResponse{}, fmt.Errorf("decode PyPI version metadata: %w", err)
	}
	return data, nil
}

func fetchReleaseDependencies(ctx context.Context, client *http.Client, packageName string, version string) ([]string, []string, bool) {
	endpoint := BaseURL + "/" + url.PathEscape(packageName) + "/" + url.PathEscape(version) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", sourcegateversion.UserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, nil, false
	}

	var data registryResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, nil, false
	}
	if !dependenciesKnown(data.Info) {
		return nil, nil, false
	}
	required, optional := normalizeRequirements(data.Info.RequiresDist)
	return required, optional, true
}

func annotateProvenance(ctx context.Context, client *http.Client, packageName string, version string, files []report.PyPIReleaseFile, selected []int) {
	if len(selected) == 0 {
		return
	}
	jobs := make(chan int)
	var workers sync.WaitGroup
	workerCount := 4
	if len(selected) < workerCount {
		workerCount = len(selected)
	}
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range jobs {
				annotateFileProvenance(ctx, client, packageName, version, &files[i])
			}
		}()
	}
	for _, i := range selected {
		jobs <- i
	}
	close(jobs)
	workers.Wait()
}

func annotateFileProvenance(ctx context.Context, client *http.Client, packageName string, version string, file *report.PyPIReleaseFile) {
	file.ProvenanceChecked = true
	endpoint := IntegrityBaseURL + "/" + url.PathEscape(packageName) + "/" + url.PathEscape(version) + "/" + url.PathEscape(file.Filename) + "/provenance"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		file.ProvenanceError = err.Error()
		return
	}
	req.Header.Set("Accept", "application/vnd.pypi.integrity.v1+json")
	req.Header.Set("User-Agent", sourcegateversion.UserAgent())

	resp, err := client.Do(req)
	if err != nil {
		file.ProvenanceError = err.Error()
		return
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		file.ProvenanceAvailable = true
	case http.StatusNotFound:
		file.ProvenanceAvailable = false
	default:
		file.ProvenanceError = fmt.Sprintf("PyPI Integrity API returned status %d", resp.StatusCode)
	}
}

func prepareProvenance(ctx context.Context, client *http.Client, packageName string, version string, files []report.PyPIReleaseFile, options Options) (report.PyPIProvenanceSummary, string) {
	summary := report.PyPIProvenanceSummary{
		RequestedScopes:  append([]string(nil), options.ProvenanceScopes...),
		PythonExecutable: text.FirstNonEmpty(options.Target.PythonExecutable, "python"),
		TargetPlatform:   options.Target.TargetPlatform,
		PythonVersion:    options.Target.PythonVersion,
		Implementation:   options.Target.Implementation,
		ABIs:             append([]string(nil), options.Target.ABIs...),
	}
	if len(options.ProvenanceScopes) == 0 {
		return summary, ""
	}

	var compatibleTags map[string]struct{}
	if containsString(options.ProvenanceScopes, ProvenanceScopeInstallTarget) && releaseHasWheel(files) {
		var err error
		compatibleTags, err = resolveCompatibleTags(ctx, options)
		if err != nil {
			summary.CompatibilityError = err.Error()
		} else {
			summary.CompatibleTagCount = len(compatibleTags)
		}
	}

	var selected []int
	for i := range files {
		for _, scope := range options.ProvenanceScopes {
			if fileMatchesScope(files[i], scope, compatibleTags) {
				files[i].ProvenanceScopes = append(files[i].ProvenanceScopes, scope)
			}
		}
		if len(files[i].ProvenanceScopes) > 0 {
			selected = append(selected, i)
		}
		if containsString(files[i].ProvenanceScopes, ProvenanceScopeInstallTarget) {
			summary.CheckedCompatibleFiles++
		} else if containsString(options.ProvenanceScopes, ProvenanceScopeInstallTarget) {
			summary.SkippedNonTargetFiles++
		}
	}
	annotateProvenance(ctx, client, packageName, version, files, selected)
	if summary.CompatibilityError == "" {
		return summary, ""
	}
	return summary, fmt.Sprintf("PyPI install-target compatibility inspection failed; compatible wheel provenance cannot be confirmed: %s", summary.CompatibilityError)
}

func releaseHasWheel(files []report.PyPIReleaseFile) bool {
	for _, file := range files {
		if file.PackageType == "bdist_wheel" {
			return true
		}
	}
	return false
}

func resolveCompatibleTags(ctx context.Context, options Options) (map[string]struct{}, error) {
	ordered, err := resolveCompatibleTagList(ctx, options)
	if err != nil {
		return nil, err
	}
	tags := make(map[string]struct{}, len(ordered))
	for _, tag := range ordered {
		tags[tag] = struct{}{}
	}
	return tags, nil
}

func resolveCompatibleTagList(ctx context.Context, options Options) ([]string, error) {
	runner := options.RunCommand
	if runner == nil {
		runner = runCommand
	}
	executable := text.FirstNonEmpty(options.Target.PythonExecutable, "python")
	args := []string{"-m", "pip", "debug", "--verbose"}
	if options.Target.TargetPlatform != "" {
		args = append(args, "--platform", options.Target.TargetPlatform)
	}
	if options.Target.PythonVersion != "" {
		args = append(args, "--python-version", options.Target.PythonVersion)
	}
	if options.Target.Implementation != "" {
		args = append(args, "--implementation", options.Target.Implementation)
	}
	for _, abi := range options.Target.ABIs {
		args = append(args, "--abi", abi)
	}
	output, err := runner(ctx, executable, args...)
	if err != nil {
		return nil, fmt.Errorf("%s -m pip debug --verbose failed: %w", executable, err)
	}
	tags := parseCompatibleTagList(string(output))
	if len(tags) == 0 {
		return nil, fmt.Errorf("%s -m pip debug --verbose returned no compatible tags", executable)
	}
	return tags, nil
}

func runCommand(ctx context.Context, executable string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, executable, args...).CombinedOutput()
}

func selectHistory(releases map[string][]release, selectedVersion string, reliabilityLimit int) ([]releaseHistoryEntry, report.HistoryDiagnostics) {
	diagnostics := report.HistoryDiagnostics{}
	selectedPublishedAt, err := parseRegistryTime(latestReleaseTime(releases[selectedVersion]))
	if err != nil {
		diagnostics.IndeterminateReason = "selected PyPI release publish time is unavailable or invalid"
		return nil, diagnostics
	}
	selectedPrerelease, err := versioning.PyPIPreRelease(selectedVersion)
	if err != nil {
		diagnostics.IndeterminateReason = err.Error()
		return nil, diagnostics
	}

	var entries []releaseHistoryEntry
	var malformedVersions []releaseHistoryEntry
	for version, files := range releases {
		if version == selectedVersion {
			continue
		}
		publishedAt := latestReleaseTime(files)
		published, err := parseRegistryTime(publishedAt)
		if err != nil {
			diagnostics.SkippedMalformedTimes = append(diagnostics.SkippedMalformedTimes, version)
			continue
		}
		if !published.Before(selectedPublishedAt) {
			diagnostics.SkippedLaterVersions++
			continue
		}
		prerelease, err := versioning.PyPIPreRelease(version)
		if err != nil {
			diagnostics.SkippedMalformedVersions = append(diagnostics.SkippedMalformedVersions, version)
			malformedVersions = append(malformedVersions, releaseHistoryEntry{version: version, publishedAt: publishedAt})
			continue
		}
		if !selectedPrerelease && prerelease {
			diagnostics.SkippedPrereleaseVersions++
			continue
		}
		entries = append(entries, releaseHistoryEntry{version: version, publishedAt: publishedAt})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].publishedAt == entries[j].publishedAt {
			return entries[i].version > entries[j].version
		}
		return entries[i].publishedAt > entries[j].publishedAt
	})
	for _, entry := range entries {
		diagnostics.SelectedVersions = append(diagnostics.SelectedVersions, entry.version)
	}
	sort.Strings(diagnostics.SkippedMalformedTimes)
	sort.Strings(diagnostics.SkippedMalformedVersions)
	if (len(entries) < reliabilityLimit && len(diagnostics.SkippedMalformedTimes) > 0) || malformedPyPIEntryCanAffectWindow(malformedVersions, entries, reliabilityLimit) {
		diagnostics.IndeterminateReason = "PyPI release history contains malformed version or publish-time metadata"
	}
	return entries, diagnostics
}

func malformedPyPIEntryCanAffectWindow(malformed []releaseHistoryEntry, valid []releaseHistoryEntry, reliabilityLimit int) bool {
	if len(malformed) == 0 {
		return false
	}
	if len(valid) < reliabilityLimit {
		return true
	}
	cutoff := valid[reliabilityLimit-1].publishedAt
	for _, entry := range malformed {
		if entry.publishedAt >= cutoff {
			return true
		}
	}
	return false
}

func fileMatchesScope(file report.PyPIReleaseFile, scope string, compatibleTags map[string]struct{}) bool {
	switch scope {
	case ProvenanceScopeAllArtifacts:
		return true
	case ProvenanceScopeSdistOnly:
		return file.PackageType == "sdist"
	case ProvenanceScopeInstallTarget:
		if file.PackageType == "sdist" {
			return true
		}
		if file.PackageType != "bdist_wheel" {
			return false
		}
		for _, tag := range wheelTags(file.Filename) {
			if _, ok := compatibleTags[tag]; ok {
				return true
			}
		}
	}
	return false
}

func parseCompatibleTags(output string) map[string]struct{} {
	ordered := parseCompatibleTagList(output)
	tags := make(map[string]struct{}, len(ordered))
	for _, tag := range ordered {
		tags[tag] = struct{}{}
	}
	return tags
}

func parseCompatibleTagList(output string) []string {
	var tags []string
	seen := make(map[string]struct{})
	inTags := false
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Compatible tags:") {
			inTags = true
			continue
		}
		if !inTags {
			continue
		}
		if trimmed == "" {
			continue
		}
		if strings.Count(trimmed, "-") < 2 {
			break
		}
		if _, ok := seen[trimmed]; !ok {
			seen[trimmed] = struct{}{}
			tags = append(tags, trimmed)
		}
	}
	return tags
}

func wheelTags(filename string) []string {
	if !strings.HasSuffix(filename, ".whl") {
		return nil
	}
	parts := strings.Split(strings.TrimSuffix(filename, ".whl"), "-")
	if len(parts) < 5 {
		return nil
	}
	pythonTags := strings.Split(parts[len(parts)-3], ".")
	abiTags := strings.Split(parts[len(parts)-2], ".")
	platformTags := strings.Split(parts[len(parts)-1], ".")
	var tags []string
	for _, pythonTag := range pythonTags {
		for _, abiTag := range abiTags {
			for _, platformTag := range platformTags {
				tags = append(tags, pythonTag+"-"+abiTag+"-"+platformTag)
			}
		}
	}
	return tags
}

func compactSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func releaseFiles(files []release) []report.PyPIReleaseFile {
	result := make([]report.PyPIReleaseFile, 0, len(files))
	for _, file := range files {
		result = append(result, report.PyPIReleaseFile{
			Filename:       file.Filename,
			PackageType:    file.PackageType,
			PythonVersion:  file.PythonVersion,
			Size:           file.Size,
			UploadedAt:     file.UploadTimeISO,
			RequiresPython: file.RequiresPython,
			Digests:        compactDigests(file.Digests),
			Yanked:         file.Yanked,
			YankedReason:   file.YankedReason,
			URL:            file.URL,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Filename < result[j].Filename
	})
	return result
}

func selectPreferredArtifact(ctx context.Context, files []report.PyPIReleaseFile, options Options) (report.ArtifactCandidate, error) {
	if releaseHasWheel(files) {
		tags, err := resolveCompatibleTagList(ctx, options)
		if err == nil {
			for _, tag := range tags {
				for _, file := range files {
					if file.PackageType == "bdist_wheel" && !file.Yanked && containsString(wheelTags(file.Filename), tag) {
						return pypiArtifactCandidate(file), nil
					}
				}
			}
		}
	}
	for _, file := range files {
		if file.PackageType == "sdist" && !file.Yanked {
			return pypiArtifactCandidate(file), nil
		}
	}
	return report.ArtifactCandidate{}, fmt.Errorf("no downloadable non-yanked install-target artifact is available")
}

func pypiArtifactCandidate(file report.PyPIReleaseFile) report.ArtifactCandidate {
	return report.ArtifactCandidate{
		URL:             file.URL,
		Filename:        file.Filename,
		PackageType:     file.PackageType,
		ExpectedSize:    file.Size,
		DigestAlgorithm: "sha256",
		DigestValue:     file.Digests["sha256"],
	}
}

func compactDigests(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			result[key] = value
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func dependenciesKnown(info info) bool {
	for _, value := range info.Dynamic {
		value = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_")
		if value == "requires_dist" {
			return false
		}
	}
	return true
}

func normalizeRequirements(values []string) ([]string, []string) {
	required := make(map[string]struct{}, len(values))
	optional := make(map[string]struct{}, len(values))
	for _, value := range values {
		name := normalizeRequirementName(value)
		if name == "" {
			continue
		}
		if requirementIsOptional(value) {
			optional[name] = struct{}{}
			continue
		}
		required[name] = struct{}{}
	}
	return sortedStringSet(required), sortedStringSet(optional)
}

func requirementIsOptional(value string) bool {
	parts := strings.SplitN(value, ";", 2)
	if len(parts) != 2 {
		return false
	}
	marker := strings.ToLower(parts[1])
	return strings.Contains(marker, "extra ==") ||
		strings.Contains(marker, "extra==") ||
		strings.Contains(marker, "extra ===") ||
		strings.Contains(marker, "extra===")
}

func sortedStringSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func normalizeRequirementName(value string) string {
	value = strings.TrimSpace(strings.Split(value, ";")[0])
	var builder strings.Builder
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-' {
			builder.WriteRune(unicode.ToLower(r))
			continue
		}
		break
	}
	name := strings.Trim(builder.String(), ".-_")
	if name == "" {
		return ""
	}
	return normalizePyPIName(name)
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

func previousPublishedAt(entries []releaseHistoryEntry) string {
	if len(entries) == 0 {
		return ""
	}
	return entries[0].publishedAt
}

func releaseBounds(releases map[string][]release) (string, string) {
	var uploads []string
	for _, files := range releases {
		for _, file := range files {
			if file.UploadTimeISO != "" {
				uploads = append(uploads, file.UploadTimeISO)
			}
		}
	}
	if len(uploads) == 0 {
		return "", ""
	}
	sort.Strings(uploads)
	return uploads[0], uploads[len(uploads)-1]
}

func latestReleaseTime(files []release) string {
	var uploads []string
	for _, file := range files {
		if file.UploadTimeISO != "" {
			uploads = append(uploads, file.UploadTimeISO)
		}
	}
	if len(uploads) == 0 {
		return ""
	}
	sort.Strings(uploads)
	return uploads[len(uploads)-1]
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

func formatAuthor(name, email string) string {
	switch {
	case name != "" && email != "":
		return fmt.Sprintf("%s <%s>", name, email)
	case name != "":
		return name
	case email != "":
		return email
	default:
		return ""
	}
}

func projectURLs(primary info, fallback info) []string {
	if primary.HomePage == "" && len(primary.ProjectURLs) == 0 {
		primary = fallback
	}
	values := make([]string, 0, len(primary.ProjectURLs)+1)
	values = append(values, primary.HomePage)
	for _, value := range primary.ProjectURLs {
		values = append(values, value)
	}
	sort.Strings(values)
	return text.CompactUnique(values)
}
