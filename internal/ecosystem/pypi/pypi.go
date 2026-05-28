package pypi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"

	"github.com/sourcegate/sourcegate/internal/report"
	"github.com/sourcegate/sourcegate/internal/text"
)

var BaseURL = "https://pypi.org/pypi"

type Adapter struct {
	client *http.Client
}

func New(client *http.Client) *Adapter {
	return &Adapter{client: client}
}

type registryResponse struct {
	Info     info                 `json:"info"`
	Releases map[string][]release `json:"releases"`
	URLs     []release            `json:"urls"`
}

type info struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Summary     string            `json:"summary"`
	License     string            `json:"license"`
	Author      string            `json:"author"`
	AuthorEmail string            `json:"author_email"`
	ProjectURLs map[string]string `json:"project_urls"`
	HomePage    string            `json:"home_page"`
}

type release struct {
	UploadTimeISO string `json:"upload_time_iso_8601"`
}

func (a *Adapter) FetchMetadata(ctx context.Context, packageName string) (report.PackageReport, error) {
	client := a.client
	if client == nil {
		client = http.DefaultClient
	}

	endpoint := BaseURL + "/" + url.PathEscape(packageName) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return report.PackageReport{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sourcegate/0.4")

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

	return report.PackageReport{
		Ecosystem:           "PyPI",
		Registry:            "PyPI",
		Name:                text.FirstNonEmpty(data.Info.Name, packageName),
		LatestVersion:       data.Info.Version,
		LatestPublishedAt:   latestReleaseTime(data.Releases[data.Info.Version]),
		PreviousPublishedAt: previousPublishedAt(data.Releases, data.Info.Version),
		Description:         data.Info.Summary,
		License:             data.Info.License,
		Author:              formatAuthor(data.Info.Author, data.Info.AuthorEmail),
		ProjectURLs:         projectURLs(data.Info),
		CreatedAt:           created,
		ModifiedAt:          modified,
		VersionCount:        len(data.Releases),
	}, nil
}

func previousPublishedAt(releases map[string][]release, latestVersion string) string {
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

func projectURLs(info info) []string {
	values := make([]string, 0, len(info.ProjectURLs)+1)
	values = append(values, info.HomePage)
	for _, value := range info.ProjectURLs {
		values = append(values, value)
	}
	sort.Strings(values)
	return text.CompactUnique(values)
}
