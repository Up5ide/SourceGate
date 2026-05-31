package pypi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/sourcegate/sourcegate/internal/report"
	"github.com/sourcegate/sourcegate/internal/text"
)

var BaseURL = "https://pypi.org/pypi"
var IntegrityBaseURL = "https://pypi.org/integrity"

type Options struct {
	HistoryVersions int
	CheckProvenance bool
}

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
	req.Header.Set("User-Agent", "sourcegate/0.5")

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
	latestVersion := data.Info.Version
	latestRelease := report.PyPIReleaseInfo{
		Version:           latestVersion,
		PublishedAt:       latestReleaseTime(data.Releases[latestVersion]),
		Files:             releaseFiles(data.Releases[latestVersion]),
		Dependencies:      normalizeRequirements(data.Info.RequiresDist),
		DependenciesKnown: dependenciesKnown(data.Info),
	}
	if a.options.CheckProvenance {
		annotateProvenance(ctx, client, name, latestVersion, latestRelease.Files)
	}

	return report.PackageReport{
		Ecosystem:           "PyPI",
		Registry:            "PyPI",
		Name:                name,
		LatestVersion:       latestVersion,
		LatestPublishedAt:   latestRelease.PublishedAt,
		PreviousPublishedAt: previousPublishedAt(data.Releases, latestVersion),
		Description:         data.Info.Summary,
		License:             data.Info.License,
		Author:              formatAuthor(data.Info.Author, data.Info.AuthorEmail),
		PyPILatestRelease:   latestRelease,
		PyPIReleaseHistory:  releaseHistory(ctx, client, name, data.Releases, latestVersion, a.options.HistoryVersions),
		ProjectURLs:         projectURLs(data.Info),
		CreatedAt:           created,
		ModifiedAt:          modified,
		VersionCount:        len(data.Releases),
	}, nil
}

type releaseHistoryEntry struct {
	version     string
	publishedAt string
}

func releaseHistory(ctx context.Context, client *http.Client, packageName string, releases map[string][]release, latestVersion string, historyVersions int) []report.PyPIReleaseInfo {
	if historyVersions <= 0 {
		return nil
	}

	entries := make([]releaseHistoryEntry, 0, len(releases))
	for version, files := range releases {
		if version == latestVersion {
			continue
		}
		publishedAt := latestReleaseTime(files)
		if publishedAt == "" {
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
	if len(entries) > historyVersions {
		entries = entries[:historyVersions]
	}

	history := make([]report.PyPIReleaseInfo, 0, len(entries))
	for _, entry := range entries {
		deps, depsKnown := fetchReleaseDependencies(ctx, client, packageName, entry.version)
		history = append(history, report.PyPIReleaseInfo{
			Version:           entry.version,
			PublishedAt:       entry.publishedAt,
			Files:             releaseFiles(releases[entry.version]),
			Dependencies:      deps,
			DependenciesKnown: depsKnown,
		})
	}
	return history
}

func fetchReleaseDependencies(ctx context.Context, client *http.Client, packageName string, version string) ([]string, bool) {
	endpoint := BaseURL + "/" + url.PathEscape(packageName) + "/" + url.PathEscape(version) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sourcegate/0.5")

	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, false
	}

	var data registryResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, false
	}
	if !dependenciesKnown(data.Info) {
		return nil, false
	}
	return normalizeRequirements(data.Info.RequiresDist), true
}

func annotateProvenance(ctx context.Context, client *http.Client, packageName string, version string, files []report.PyPIReleaseFile) {
	for i := range files {
		files[i].ProvenanceChecked = true
		endpoint := IntegrityBaseURL + "/" + url.PathEscape(packageName) + "/" + url.PathEscape(version) + "/" + url.PathEscape(files[i].Filename) + "/provenance"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			files[i].ProvenanceError = err.Error()
			continue
		}
		req.Header.Set("Accept", "application/vnd.pypi.integrity.v1+json")
		req.Header.Set("User-Agent", "sourcegate/0.5")

		resp, err := client.Do(req)
		if err != nil {
			files[i].ProvenanceError = err.Error()
			continue
		}
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			files[i].ProvenanceAvailable = true
		case http.StatusNotFound:
			files[i].ProvenanceAvailable = false
		default:
			files[i].ProvenanceError = fmt.Sprintf("PyPI Integrity API returned status %d", resp.StatusCode)
		}
	}
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
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Filename < result[j].Filename
	})
	return result
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
	if info.RequiresDist == nil {
		return false
	}
	for _, value := range info.Dynamic {
		if strings.EqualFold(strings.TrimSpace(value), "requires_dist") {
			return false
		}
	}
	return true
}

func normalizeRequirements(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		name := normalizeRequirementName(value)
		if name != "" {
			seen[name] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
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
