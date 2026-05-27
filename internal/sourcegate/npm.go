package sourcegate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

var npmRegistryBaseURL = "https://registry.npmjs.org"

type npmRegistryResponse struct {
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	DistTags    map[string]string        `json:"dist-tags"`
	License     string                   `json:"license"`
	Author      npmPerson                `json:"author"`
	Maintainers []npmPerson              `json:"maintainers"`
	Time        map[string]string        `json:"time"`
	Versions    map[string]npmVersionDoc `json:"versions"`
	Homepage    string                   `json:"homepage"`
	Repository  npmRepository            `json:"repository"`
	Bugs        npmBugs                  `json:"bugs"`
}

type npmVersionDoc struct {
	License string `json:"license"`
}

type npmPerson struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	URL   string `json:"url"`
}

type npmRepository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type npmBugs struct {
	URL string `json:"url"`
}

func FetchNPMMetadata(ctx context.Context, client *http.Client, packageName string) (PackageReport, error) {
	endpoint := npmRegistryBaseURL + "/" + url.PathEscape(packageName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return PackageReport{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sourcegate/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return PackageReport{}, fmt.Errorf("fetch npm metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return PackageReport{}, fmt.Errorf("npm package not found: %s", packageName)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return PackageReport{}, fmt.Errorf("npm registry returned status %d for %s", resp.StatusCode, packageName)
	}

	var data npmRegistryResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return PackageReport{}, fmt.Errorf("decode npm metadata: %w", err)
	}

	latest := data.DistTags["latest"]
	license := data.License
	if license == "" && latest != "" {
		license = data.Versions[latest].License
	}

	return PackageReport{
		Ecosystem:     "npm",
		Registry:      "npm registry",
		Name:          firstNonEmpty(data.Name, packageName),
		LatestVersion: latest,
		Description:   data.Description,
		License:       license,
		Author:        formatNPMPerson(data.Author),
		Maintainers:   formatNPMPeople(data.Maintainers),
		ProjectURLs:   npmProjectURLs(data),
		CreatedAt:     data.Time["created"],
		ModifiedAt:    data.Time["modified"],
		VersionCount:  len(data.Versions),
	}, nil
}

func formatNPMPeople(people []npmPerson) []string {
	formatted := make([]string, 0, len(people))
	for _, person := range people {
		value := formatNPMPerson(person)
		if value != "" {
			formatted = append(formatted, value)
		}
	}
	sort.Strings(formatted)
	return formatted
}

func formatNPMPerson(person npmPerson) string {
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

func npmProjectURLs(data npmRegistryResponse) []string {
	values := []string{data.Homepage, normalizeNPMRepositoryURL(data.Repository.URL), data.Bugs.URL}
	return compactUnique(values)
}

func normalizeNPMRepositoryURL(value string) string {
	if strings.HasPrefix(value, "git+") {
		return strings.TrimPrefix(value, "git+")
	}
	return value
}
