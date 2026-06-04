package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

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
	HistoryVersions int
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
	License string            `json:"license"`
	Scripts map[string]string `json:"scripts"`
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

func (a *Adapter) FetchMetadata(ctx context.Context, packageName string) (report.PackageReport, error) {
	client := a.client
	if client == nil {
		client = http.DefaultClient
	}

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

	latest := data.DistTags["latest"]
	latestVersion := data.Versions[latest]
	license := data.License
	if license == "" && latest != "" {
		license = latestVersion.License
	}
	historyEntries, historyDiagnostics := selectHistory(data.Time, latest, max(1, a.options.HistoryVersions))

	return report.PackageReport{
		Ecosystem:           "npm",
		Registry:            "npm registry",
		Name:                text.FirstNonEmpty(data.Name, packageName),
		LatestVersion:       latest,
		LatestPublishedAt:   data.Time[latest],
		PreviousPublishedAt: previousPublishedAt(historyEntries),
		Description:         data.Description,
		License:             license,
		Author:              formatPerson(data.Author),
		Maintainers:         formatPeople(data.Maintainers),
		LifecycleScripts:    compactStringMap(latestVersion.Scripts),
		LifecycleHistory:    lifecycleHistory(historyEntries, data.Versions),
		ProjectURLs:         projectURLs(data),
		CreatedAt:           data.Time["created"],
		ModifiedAt:          data.Time["modified"],
		VersionCount:        len(data.Versions),
		NPMHistory:          historyDiagnostics,
	}, nil
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

func selectHistory(times map[string]string, latestVersion string, reliabilityLimit int) ([]lifecycleHistoryEntry, report.HistoryDiagnostics) {
	diagnostics := report.HistoryDiagnostics{}
	latestPublishedAt, err := parseRegistryTime(times[latestVersion])
	if err != nil {
		diagnostics.IndeterminateReason = "selected npm release publish time is unavailable or invalid"
		return nil, diagnostics
	}
	latestPrerelease, err := versioning.NPMPrerelease(latestVersion)
	if err != nil {
		diagnostics.IndeterminateReason = err.Error()
		return nil, diagnostics
	}

	var entries []lifecycleHistoryEntry
	var malformedVersions []lifecycleHistoryEntry
	for version, publishedAt := range times {
		if version == "created" || version == "modified" || version == latestVersion {
			continue
		}
		published, err := parseRegistryTime(publishedAt)
		if err != nil {
			diagnostics.SkippedMalformedTimes = append(diagnostics.SkippedMalformedTimes, version)
			continue
		}
		if !published.Before(latestPublishedAt) {
			diagnostics.SkippedLaterVersions++
			continue
		}
		prerelease, err := versioning.NPMPrerelease(version)
		if err != nil {
			diagnostics.SkippedMalformedVersions = append(diagnostics.SkippedMalformedVersions, version)
			malformedVersions = append(malformedVersions, lifecycleHistoryEntry{version: version, publishedAt: publishedAt})
			continue
		}
		if !latestPrerelease && prerelease {
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
