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
	License string `json:"license"`
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
	req.Header.Set("User-Agent", "sourcegate/0.1")

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
	license := data.License
	if license == "" && latest != "" {
		license = data.Versions[latest].License
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
		ProjectURLs:         projectURLs(data),
		CreatedAt:           data.Time["created"],
		ModifiedAt:          data.Time["modified"],
		VersionCount:        len(data.Versions),
	}, nil
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
