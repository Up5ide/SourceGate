package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/sourcegate/sourcegate/internal/report"
	"github.com/sourcegate/sourcegate/internal/text"
)

var RegistryBaseURL = "https://registry.npmjs.org"

type Adapter struct {
	client *http.Client
}

func New(client *http.Client) *Adapter {
	return &Adapter{client: client}
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
	req.Header.Set("User-Agent", "sourcegate/0.5")

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

	return report.PackageReport{
		Ecosystem:           "npm",
		Registry:            "npm registry",
		Name:                text.FirstNonEmpty(data.Name, packageName),
		LatestVersion:       latest,
		LatestPublishedAt:   data.Time[latest],
		PreviousPublishedAt: previousPublishedAt(data.Time, latest),
		Description:         data.Description,
		License:             license,
		Author:              formatPerson(data.Author),
		Maintainers:         formatPeople(data.Maintainers),
		LifecycleScripts:    compactStringMap(latestVersion.Scripts),
		LifecycleHistory:    lifecycleHistory(data.Time, data.Versions, latest),
		ProjectURLs:         projectURLs(data),
		CreatedAt:           data.Time["created"],
		ModifiedAt:          data.Time["modified"],
		VersionCount:        len(data.Versions),
	}, nil
}

type lifecycleHistoryEntry struct {
	version     string
	publishedAt string
}

func lifecycleHistory(times map[string]string, versions map[string]versionDoc, latestVersion string) []report.VersionLifecycleScripts {
	var entries []lifecycleHistoryEntry
	for version, publishedAt := range times {
		if version == "created" || version == "modified" || version == latestVersion || publishedAt == "" {
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

func previousPublishedAt(times map[string]string, latestVersion string) string {
	var releases []string
	for version, publishedAt := range times {
		if version == "created" || version == "modified" || version == latestVersion || publishedAt == "" {
			continue
		}
		releases = append(releases, publishedAt)
	}
	if len(releases) == 0 {
		return ""
	}
	sort.Strings(releases)
	return releases[len(releases)-1]
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
