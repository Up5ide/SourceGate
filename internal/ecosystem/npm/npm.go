package npm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sourcegate/sourcegate/internal/checks/installlifecycle"
	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/report"
	"github.com/sourcegate/sourcegate/internal/text"
	"github.com/sourcegate/sourcegate/internal/version"
	"github.com/sourcegate/sourcegate/internal/versioning"
)

var RegistryBaseURL = "https://registry.npmjs.org"

type Adapter struct {
	client  *http.Client
	options Options
}

type Options struct {
	HistoryVersions           int
	SelectArtifact            bool
	SelectPreviousArtifact    bool
	InspectDirectDependencies bool
	MaxDirectDependencies     int
}

func New(client *http.Client) *Adapter {
	return &Adapter{client: client}
}

func NewWithOptions(client *http.Client, options Options) *Adapter {
	if options.HistoryVersions < 0 {
		options.HistoryVersions = 0
	}
	return &Adapter{client: client, options: options}
}

type registryResponse struct {
	Name        string                `json:"name"`
	Description string                `json:"description"`
	DistTags    map[string]string     `json:"dist-tags"`
	License     string                `json:"license"`
	Author      person                `json:"author"`
	Maintainers []person              `json:"maintainers"`
	Time        map[string]string     `json:"time"`
	Versions    map[string]versionDoc `json:"versions"`
	Homepage    string                `json:"homepage"`
	Repository  repository            `json:"repository"`
	Bugs        bugs                  `json:"bugs"`
}

type versionDoc struct {
	License              string            `json:"license"`
	Scripts              map[string]string `json:"scripts"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	Dist                 distribution      `json:"dist"`
	GitHead              string            `json:"gitHead"`
	NPMUser              person            `json:"_npmUser"`
	Repository           repository        `json:"repository"`
}

type distribution struct {
	Tarball   string `json:"tarball"`
	Integrity string `json:"integrity"`
}

type person struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	URL   string `json:"url"`
}

type repository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type bugs struct {
	URL string `json:"url"`
}

func (a *Adapter) FetchMetadata(ctx context.Context, spec ecosystem.PackageSpec) (report.PackageReport, error) {
	client := a.client
	if client == nil {
		client = http.DefaultClient
	}

	packageName := spec.Name
	endpoint := RegistryBaseURL + "/" + url.PathEscape(packageName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return report.PackageReport{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return report.PackageReport{}, fmt.Errorf("fetch npm metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return report.PackageReport{}, fmt.Errorf("npm package not found: %s", packageName)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return report.PackageReport{}, fmt.Errorf("npm registry returned status %d for %s", resp.StatusCode, packageName)
	}

	var data registryResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return report.PackageReport{}, fmt.Errorf("decode npm metadata: %w", err)
	}

	selectedVersion := spec.Version
	if selectedVersion == "" {
		selectedVersion = data.DistTags["latest"]
	}
	selectedDoc, ok := data.Versions[selectedVersion]
	if selectedVersion == "" || !ok {
		if spec.Version != "" {
			return report.PackageReport{}, fmt.Errorf("npm package version not found: %s@%s", packageName, spec.Version)
		}
		return report.PackageReport{}, fmt.Errorf("npm latest version is unavailable for %s", packageName)
	}
	license := data.License
	if license == "" {
		license = selectedDoc.License
	}
	historyEntries, historyDiagnostics := selectHistory(data.Time, selectedVersion, max(1, a.options.HistoryVersions))

	dependencyHistory := npmDependencyHistory(historyEntries, data.Versions)
	sourceMetadata := npmSourceMetadata(data, selectedDoc, historyEntries, data.Versions)
	pkg := report.PackageReport{
		Ecosystem:            "npm",
		Registry:             "npm registry",
		Name:                 text.FirstNonEmpty(data.Name, packageName),
		SelectedVersion:      selectedVersion,
		SelectedPublishedAt:  data.Time[selectedVersion],
		PreviousPublishedAt:  previousPublishedAt(historyEntries),
		Description:          data.Description,
		License:              license,
		Author:               formatPerson(data.Author),
		Maintainers:          formatPeople(data.Maintainers),
		LifecycleScripts:     compactStringMap(selectedDoc.Scripts),
		LifecycleHistory:     lifecycleHistory(historyEntries, data.Versions),
		NPMDependencies:      npmDependencySet(selectedDoc),
		NPMDependencyHistory: dependencyHistory,
		NPMSource:            sourceMetadata,
		ProjectURLs:          projectURLs(data),
		CreatedAt:            data.Time["created"],
		ModifiedAt:           data.Time["modified"],
		VersionCount:         len(data.Versions),
		NPMHistory:           historyDiagnostics,
	}
	if a.options.SelectArtifact {
		pkg.ArtifactCandidate = npmArtifactCandidate(packageName, selectedVersion, selectedDoc.Dist)
		if a.options.SelectPreviousArtifact && len(historyEntries) > 0 {
			if previousDoc, ok := data.Versions[historyEntries[0].version]; ok {
				pkg.PreviousArtifactCandidate = npmArtifactCandidate(packageName, historyEntries[0].version, previousDoc.Dist)
			}
		}
	}
	if a.options.InspectDirectDependencies {
		pkg.NPMDirectDependencyLimit = a.options.MaxDirectDependencies
		if pkg.NPMDirectDependencyLimit <= 0 {
			pkg.NPMDirectDependencyLimit = 25
		}
		pkg.NPMDirectDependencies, pkg.NPMDirectDependencyOverflow = a.inspectDirectDependencies(ctx, client, selectedDoc)
	}
	return pkg, nil
}

func (a *Adapter) inspectDirectDependencies(ctx context.Context, client *http.Client, selectedDoc versionDoc) ([]report.NPMDirectDependencyInspection, int) {
	entries := directDependencyEntries(selectedDoc)
	limit := a.options.MaxDirectDependencies
	if limit <= 0 {
		limit = 25
	}
	overflow := 0
	if len(entries) > limit {
		overflow = len(entries) - limit
		entries = entries[:limit]
	}
	inspections := make([]report.NPMDirectDependencyInspection, 0, len(entries))
	for _, entry := range entries {
		inspection := report.NPMDirectDependencyInspection{
			Name:           entry.name,
			DependencyKind: entry.kind,
			RequestedRange: entry.versionRange,
			Selection:      "latest",
			FetchStatus:    "ERROR",
		}
		selectedVersion := ""
		if versioning.ValidNPMVersion(entry.versionRange) {
			selectedVersion = entry.versionRange
			inspection.Selection = "exact"
			inspection.ExactVersionRangeSupported = true
		}
		dependencyData, err := fetchRegistryPackage(ctx, client, entry.name)
		if err != nil {
			inspection.FetchError = err.Error()
			inspections = append(inspections, inspection)
			continue
		}
		if selectedVersion == "" {
			selectedVersion = dependencyData.DistTags["latest"]
		}
		dependencyDoc, ok := dependencyData.Versions[selectedVersion]
		if selectedVersion == "" || !ok {
			inspection.FetchError = "selected dependency version metadata is unavailable"
			inspections = append(inspections, inspection)
			continue
		}
		inspection.SelectedVersion = selectedVersion
		inspection.FetchStatus = "FETCHED"
		inspection.LifecycleScripts = compactStringMap(dependencyDoc.Scripts)
		inspection.LifecycleFindings = findingMessages(installlifecycle.CheckDeclaredScripts(report.PackageReport{
			Ecosystem:        "npm",
			LifecycleScripts: inspection.LifecycleScripts,
		}))
		inspection.SuspiciousCommandFindings = findingMessages(installlifecycle.CheckSuspiciousCommands(report.PackageReport{
			Ecosystem:        "npm",
			LifecycleScripts: inspection.LifecycleScripts,
		}))
		inspections = append(inspections, inspection)
	}
	return inspections, overflow
}

type directDependencyEntry struct {
	name         string
	kind         string
	versionRange string
}

func directDependencyEntries(doc versionDoc) []directDependencyEntry {
	var entries []directDependencyEntry
	for _, source := range []struct {
		kind   string
		values map[string]string
	}{
		{kind: "dependencies", values: doc.Dependencies},
		{kind: "optionalDependencies", values: doc.OptionalDependencies},
	} {
		for _, name := range sortedMapKeys(source.values) {
			entries = append(entries, directDependencyEntry{
				name:         name,
				kind:         source.kind,
				versionRange: strings.TrimSpace(source.values[name]),
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].kind == entries[j].kind {
			return entries[i].name < entries[j].name
		}
		return entries[i].kind < entries[j].kind
	})
	return entries
}

func findingMessages(findings []report.Finding) []string {
	messages := make([]string, 0, len(findings))
	for _, finding := range findings {
		messages = append(messages, finding.Message)
	}
	return messages
}

func fetchRegistryPackage(ctx context.Context, client *http.Client, packageName string) (registryResponse, error) {
	endpoint := RegistryBaseURL + "/" + url.PathEscape(packageName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return registryResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return registryResponse{}, fmt.Errorf("fetch npm metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return registryResponse{}, fmt.Errorf("npm package not found: %s", packageName)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return registryResponse{}, fmt.Errorf("npm registry returned status %d for %s", resp.StatusCode, packageName)
	}
	var data registryResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return registryResponse{}, fmt.Errorf("decode npm metadata: %w", err)
	}
	return data, nil
}

func npmArtifactCandidate(packageName, selectedVersion string, dist distribution) report.ArtifactCandidate {
	algorithm, digest := strongestSRI(dist.Integrity)
	return report.ArtifactCandidate{
		URL:             strings.TrimSpace(dist.Tarball),
		Filename:        npmTarballFilename(packageName, selectedVersion),
		PackageType:     "npm-tarball",
		DigestAlgorithm: algorithm,
		DigestValue:     digest,
	}
}

func strongestSRI(integrity string) (string, string) {
	values := strings.Fields(integrity)
	for _, algorithm := range []string{"sha512", "sha256"} {
		prefix := algorithm + "-"
		for _, value := range values {
			if !strings.HasPrefix(value, prefix) {
				continue
			}
			digest := strings.TrimPrefix(value, prefix)
			if _, err := base64.StdEncoding.DecodeString(digest); err == nil {
				return algorithm, digest
			}
		}
	}
	return "", ""
}

func npmTarballFilename(packageName, selectedVersion string) string {
	name := packageName
	if index := strings.LastIndex(name, "/"); index >= 0 {
		name = name[index+1:]
	}
	return name + "-" + selectedVersion + ".tgz"
}

type lifecycleHistoryEntry struct {
	version     string
	publishedAt string
}

func lifecycleHistory(entries []lifecycleHistoryEntry, versions map[string]versionDoc) []report.VersionLifecycleScripts {
	history := make([]report.VersionLifecycleScripts, 0, len(entries))
	for _, entry := range entries {
		version, ok := versions[entry.version]
		history = append(history, report.VersionLifecycleScripts{
			Version:      entry.version,
			PublishedAt:  entry.publishedAt,
			Scripts:      compactStringMap(version.Scripts),
			ScriptsKnown: ok,
		})
	}
	return history
}

func npmDependencyHistory(entries []lifecycleHistoryEntry, versions map[string]versionDoc) []report.VersionNPMDependencies {
	history := make([]report.VersionNPMDependencies, 0, len(entries))
	for _, entry := range entries {
		version, ok := versions[entry.version]
		history = append(history, report.VersionNPMDependencies{
			Version:           entry.version,
			PublishedAt:       entry.publishedAt,
			Dependencies:      npmDependencySet(version),
			DependenciesKnown: ok,
		})
	}
	return history
}

func npmDependencySet(doc versionDoc) report.NPMDependencySet {
	return report.NPMDependencySet{
		Dependencies:         sortedMapKeys(compactStringMap(doc.Dependencies)),
		OptionalDependencies: sortedMapKeys(compactStringMap(doc.OptionalDependencies)),
		PeerDependencies:     sortedMapKeys(compactStringMap(doc.PeerDependencies)),
		DevDependencies:      sortedMapKeys(compactStringMap(doc.DevDependencies)),
	}
}

func npmSourceMetadata(data registryResponse, selectedDoc versionDoc, entries []lifecycleHistoryEntry, versions map[string]versionDoc) report.NPMSourceMetadata {
	source := report.NPMSourceMetadata{
		RepositoryURL:     selectedRepositoryURL(data, selectedDoc),
		SelectedGitHead:   strings.TrimSpace(selectedDoc.GitHead),
		SelectedPublisher: formatPerson(selectedDoc.NPMUser),
	}
	if len(entries) == 0 {
		return source
	}
	previous, ok := versions[entries[0].version]
	if !ok {
		return source
	}
	source.PreviousRepositoryURL = selectedRepositoryURL(data, previous)
	source.PreviousGitHead = strings.TrimSpace(previous.GitHead)
	source.PreviousPublisher = formatPerson(previous.NPMUser)
	return source
}

func selectedRepositoryURL(data registryResponse, doc versionDoc) string {
	if value := normalizeRepositoryURL(doc.Repository.URL); value != "" {
		return value
	}
	return normalizeRepositoryURL(data.Repository.URL)
}

func selectHistory(times map[string]string, selectedVersion string, reliabilityLimit int) ([]lifecycleHistoryEntry, report.HistoryDiagnostics) {
	diagnostics := report.HistoryDiagnostics{}
	selectedPublishedAt, err := parseRegistryTime(times[selectedVersion])
	if err != nil {
		diagnostics.IndeterminateReason = "selected npm release publish time is unavailable or invalid"
		return nil, diagnostics
	}
	selectedPrerelease, err := versioning.NPMPrerelease(selectedVersion)
	if err != nil {
		diagnostics.IndeterminateReason = err.Error()
		return nil, diagnostics
	}

	var entries []lifecycleHistoryEntry
	var malformedVersions []lifecycleHistoryEntry
	for version, publishedAt := range times {
		if version == "created" || version == "modified" || version == selectedVersion {
			continue
		}
		published, err := parseRegistryTime(publishedAt)
		if err != nil {
			diagnostics.SkippedMalformedTimes = append(diagnostics.SkippedMalformedTimes, version)
			continue
		}
		if !published.Before(selectedPublishedAt) {
			diagnostics.SkippedLaterVersions++
			continue
		}
		prerelease, err := versioning.NPMPrerelease(version)
		if err != nil {
			diagnostics.SkippedMalformedVersions = append(diagnostics.SkippedMalformedVersions, version)
			malformedVersions = append(malformedVersions, lifecycleHistoryEntry{version: version, publishedAt: publishedAt})
			continue
		}
		if !selectedPrerelease && prerelease {
			diagnostics.SkippedPrereleaseVersions++
			continue
		}
		entries = append(entries, lifecycleHistoryEntry{version: version, publishedAt: publishedAt})
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
	if (len(entries) < reliabilityLimit && len(diagnostics.SkippedMalformedTimes) > 0) || malformedEntryCanAffectWindow(malformedVersions, entries, reliabilityLimit) {
		diagnostics.IndeterminateReason = "npm release history contains malformed version or publish-time metadata"
	}
	return entries, diagnostics
}

func malformedEntryCanAffectWindow(malformed []lifecycleHistoryEntry, valid []lifecycleHistoryEntry, reliabilityLimit int) bool {
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

func compactStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	compacted := make(map[string]string)
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			compacted[key] = value
		}
	}
	if len(compacted) == 0 {
		return nil
	}
	return compacted
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func previousPublishedAt(entries []lifecycleHistoryEntry) string {
	if len(entries) == 0 {
		return ""
	}
	return entries[0].publishedAt
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

func formatPeople(people []person) []string {
	formatted := make([]string, 0, len(people))
	for _, person := range people {
		value := formatPerson(person)
		if value != "" {
			formatted = append(formatted, value)
		}
	}
	sort.Strings(formatted)
	return formatted
}

func formatPerson(person person) string {
	switch {
	case person.Name != "" && person.Email != "":
		return fmt.Sprintf("%s <%s>", person.Name, person.Email)
	case person.Name != "":
		return person.Name
	case person.Email != "":
		return person.Email
	case person.URL != "":
		return person.URL
	default:
		return ""
	}
}

func projectURLs(data registryResponse) []string {
	values := []string{data.Homepage, normalizeRepositoryURL(data.Repository.URL), data.Bugs.URL}
	return text.CompactUnique(values)
}

func normalizeRepositoryURL(value string) string {
	if strings.HasPrefix(value, "git+") {
		return strings.TrimPrefix(value, "git+")
	}
	return value
}
