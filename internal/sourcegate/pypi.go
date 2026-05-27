package sourcegate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
)

var pypiBaseURL = "https://pypi.org/pypi"

type pypiResponse struct {
	Info     pypiInfo                 `json:"info"`
	Releases map[string][]pypiRelease `json:"releases"`
	URLs     []pypiRelease            `json:"urls"`
}

type pypiInfo struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Summary     string            `json:"summary"`
	License     string            `json:"license"`
	Author      string            `json:"author"`
	AuthorEmail string            `json:"author_email"`
	ProjectURLs map[string]string `json:"project_urls"`
	HomePage    string            `json:"home_page"`
}

type pypiRelease struct {
	UploadTimeISO string `json:"upload_time_iso_8601"`
}

func FetchPyPIMetadata(ctx context.Context, client *http.Client, packageName string) (PackageReport, error) {
	endpoint := pypiBaseURL + "/" + url.PathEscape(packageName) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return PackageReport{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sourcegate/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return PackageReport{}, fmt.Errorf("fetch PyPI metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return PackageReport{}, fmt.Errorf("PyPI package not found: %s", packageName)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return PackageReport{}, fmt.Errorf("PyPI returned status %d for %s", resp.StatusCode, packageName)
	}

	var data pypiResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return PackageReport{}, fmt.Errorf("decode PyPI metadata: %w", err)
	}

	created, modified := pypiReleaseBounds(data.Releases)
	latestPublishedAt := pypiLatestReleaseTime(data.Releases[data.Info.Version])
	previousPublishedAt := previousPyPIPublishedAt(data.Releases, data.Info.Version)

	return PackageReport{
		Ecosystem:           "PyPI",
		Registry:            "PyPI",
		Name:                firstNonEmpty(data.Info.Name, packageName),
		LatestVersion:       data.Info.Version,
		LatestPublishedAt:   latestPublishedAt,
		PreviousPublishedAt: previousPublishedAt,
		Description:         data.Info.Summary,
		License:             data.Info.License,
		Author:              formatPyPIAuthor(data.Info.Author, data.Info.AuthorEmail),
		ProjectURLs:         pypiProjectURLs(data.Info),
		CreatedAt:           created,
		ModifiedAt:          modified,
		VersionCount:        len(data.Releases),
	}, nil
}

func previousPyPIPublishedAt(releases map[string][]pypiRelease, latestVersion string) string {
	var uploads []string
	for version, files := range releases {
		if version == latestVersion {
			continue
		}
		for _, file := range files {
			if file.UploadTimeISO != "" {
				uploads = append(uploads, file.UploadTimeISO)
			}
		}
	}
	if len(uploads) == 0 {
		return ""
	}
	sort.Strings(uploads)
	return uploads[len(uploads)-1]
}

func pypiReleaseBounds(releases map[string][]pypiRelease) (string, string) {
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

func pypiLatestReleaseTime(files []pypiRelease) string {
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

func formatPyPIAuthor(name, email string) string {
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

func pypiProjectURLs(info pypiInfo) []string {
	values := make([]string, 0, len(info.ProjectURLs)+1)
	values = append(values, info.HomePage)
	for _, value := range info.ProjectURLs {
		values = append(values, value)
	}
	sort.Strings(values)
	return compactUnique(values)
}
