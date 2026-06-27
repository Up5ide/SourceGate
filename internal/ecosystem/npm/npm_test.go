package npm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
)

func TestFetchMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lodash" {
			t.Fatalf("path = %q, want /lodash", r.URL.Path)
		}
		if got := r.Header.Get("User-Agent"); got != "sourcegate/0.6.5" {
			t.Fatalf("user agent = %q, want sourcegate/0.6.5", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"name": "lodash",
			"description": "Lodash utilities",
			"dist-tags": {"latest": "4.17.21"},
			"license": "MIT",
			"author": {"name": "John Doe", "email": "john@example.com"},
			"maintainers": [{"name": "Jane Doe"}],
			"time": {
				"created": "2012-04-23T16:37:43.123Z",
				"modified": "2021-02-20T15:42:16.891Z",
				"4.17.19": "2019-02-20T15:42:16.891Z",
				"4.17.20": "2020-02-20T15:42:16.891Z",
				"4.17.21": "2021-02-20T15:42:16.891Z"
			},
			"versions": {
				"4.17.19": {},
				"4.17.20": {"scripts": {"test": "go test ./..."}},
				"4.17.21": {"scripts": {"postinstall": "node setup.js"}}
			},
			"homepage": "https://lodash.com/",
			"repository": {"url": "git+https://github.com/lodash/lodash.git"},
			"bugs": {"url": "https://github.com/lodash/lodash/issues"}
		}`))
	}))
	defer server.Close()

	oldBase := RegistryBaseURL
	RegistryBaseURL = server.URL
	defer func() { RegistryBaseURL = oldBase }()

	report, err := New(server.Client()).FetchMetadata(context.Background(), ecosystem.PackageSpec{Name: "lodash"})
	if err != nil {
		t.Fatalf("FetchMetadata returned error: %v", err)
	}

	if report.Name != "lodash" || report.SelectedVersion != "4.17.21" || report.VersionCount != 3 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.SelectedPublishedAt != "2021-02-20T15:42:16.891Z" {
		t.Fatalf("latest published = %q", report.SelectedPublishedAt)
	}
	if report.PreviousPublishedAt != "2020-02-20T15:42:16.891Z" {
		t.Fatalf("previous published = %q", report.PreviousPublishedAt)
	}
	if len(report.ProjectURLs) != 3 {
		t.Fatalf("project urls = %v, want 3 urls", report.ProjectURLs)
	}
	if strings.HasPrefix(report.ProjectURLs[1], "git+") {
		t.Fatalf("repository url was not normalized: %s", report.ProjectURLs[1])
	}
	if report.LifecycleScripts["postinstall"] != "node setup.js" {
		t.Fatalf("latest lifecycle scripts = %+v, want postinstall script", report.LifecycleScripts)
	}
	if len(report.LifecycleHistory) != 2 {
		t.Fatalf("lifecycle history = %+v, want 2 entries", report.LifecycleHistory)
	}
	if report.LifecycleHistory[0].Version != "4.17.20" || report.LifecycleHistory[0].Scripts["test"] != "go test ./..." {
		t.Fatalf("first lifecycle history entry = %+v, want 4.17.20 with test script", report.LifecycleHistory[0])
	}
	if report.LifecycleHistory[1].Version != "4.17.19" || !report.LifecycleHistory[1].ScriptsKnown || len(report.LifecycleHistory[1].Scripts) != 0 {
		t.Fatalf("second lifecycle history entry = %+v, want 4.17.19 with known empty scripts", report.LifecycleHistory[1])
	}
}

func TestFetchMetadataSelectsExactVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"name": "lodash",
			"dist-tags": {"latest": "4.17.21"},
			"time": {
				"created": "2019-01-01T00:00:00Z",
				"modified": "2021-01-01T00:00:00Z",
				"4.17.19": "2019-01-01T00:00:00Z",
				"4.17.20": "2020-01-01T00:00:00Z",
				"4.17.21": "2021-01-01T00:00:00Z"
			},
			"versions": {
				"4.17.19": {"license": "MIT-OLD", "scripts": {"postinstall": "node old.js"}},
				"4.17.20": {"license": "MIT-MID"},
				"4.17.21": {"license": "MIT-NEW", "scripts": {"postinstall": "node new.js"}}
			}
		}`))
	}))
	defer server.Close()

	oldBase := RegistryBaseURL
	RegistryBaseURL = server.URL
	defer func() { RegistryBaseURL = oldBase }()

	report, err := NewWithOptions(server.Client(), Options{HistoryVersions: 2}).FetchMetadata(context.Background(), ecosystem.PackageSpec{Name: "lodash", Version: "4.17.20"})
	if err != nil {
		t.Fatalf("FetchMetadata returned error: %v", err)
	}

	if report.SelectedVersion != "4.17.20" || report.SelectedPublishedAt != "2020-01-01T00:00:00Z" {
		t.Fatalf("selected release = %s %s, want 4.17.20 publish time", report.SelectedVersion, report.SelectedPublishedAt)
	}
	if report.License != "MIT-MID" {
		t.Fatalf("license = %q, want selected version license", report.License)
	}
	if len(report.LifecycleScripts) != 0 {
		t.Fatalf("lifecycle scripts = %+v, want selected version scripts only", report.LifecycleScripts)
	}
	if report.PreviousPublishedAt != "2019-01-01T00:00:00Z" {
		t.Fatalf("previous published = %q, want release before selected version", report.PreviousPublishedAt)
	}
	if len(report.LifecycleHistory) != 1 || report.LifecycleHistory[0].Version != "4.17.19" {
		t.Fatalf("history = %+v, want only versions before selected release", report.LifecycleHistory)
	}
}

func TestFetchMetadataSelectsVerifiedArtifactCandidate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"name": "@scope/pkg",
			"dist-tags": {"latest": "1.2.3"},
			"time": {"1.2.3": "2026-01-01T00:00:00Z"},
			"versions": {"1.2.3": {"dist": {
				"tarball": "https://registry.example/pkg.tgz",
				"integrity": "sha256-YWJj sha512-ZGVm"
			}}}
		}`))
	}))
	defer server.Close()

	oldBase := RegistryBaseURL
	RegistryBaseURL = server.URL
	defer func() { RegistryBaseURL = oldBase }()

	pkg, err := NewWithOptions(server.Client(), Options{SelectArtifact: true}).FetchMetadata(context.Background(), ecosystem.PackageSpec{Name: "@scope/pkg"})
	if err != nil {
		t.Fatalf("FetchMetadata returned error: %v", err)
	}
	candidate := pkg.ArtifactCandidate
	if candidate.URL != "https://registry.example/pkg.tgz" || candidate.Filename != "pkg-1.2.3.tgz" || candidate.DigestAlgorithm != "sha512" || candidate.DigestValue != "ZGVm" {
		t.Fatalf("candidate = %+v, want selected npm tarball with strongest digest", candidate)
	}
}

func TestFetchMetadataRejectsMissingExactVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"name": "lodash",
			"dist-tags": {"latest": "4.17.21"},
			"time": {"4.17.21": "2021-01-01T00:00:00Z"},
			"versions": {"4.17.21": {}}
		}`))
	}))
	defer server.Close()

	oldBase := RegistryBaseURL
	RegistryBaseURL = server.URL
	defer func() { RegistryBaseURL = oldBase }()

	_, err := New(server.Client()).FetchMetadata(context.Background(), ecosystem.PackageSpec{Name: "lodash", Version: "4.17.20"})
	if err == nil || !strings.Contains(err.Error(), "npm package version not found") {
		t.Fatalf("error = %v, want missing version error", err)
	}
}

func TestSelectHistoryExcludesLaterAndPrereleaseVersionsForStableLatest(t *testing.T) {
	entries, diagnostics := selectHistory(map[string]string{
		"1.0.0":      "2026-01-01T00:00:00Z",
		"1.1.0-beta": "2026-02-01T00:00:00Z",
		"1.1.0":      "2026-03-01T00:00:00Z",
		"1.2.0-beta": "2026-04-01T00:00:00Z",
	}, "1.1.0", 1)

	if len(entries) != 1 || entries[0].version != "1.0.0" {
		t.Fatalf("entries = %+v, want earlier stable release only", entries)
	}
	if diagnostics.SkippedLaterVersions != 1 || diagnostics.SkippedPrereleaseVersions != 1 {
		t.Fatalf("diagnostics = %+v, want one later and one prerelease skip", diagnostics)
	}
}

func TestSelectHistoryAllowsEarlierPrereleaseForPrereleaseLatest(t *testing.T) {
	entries, diagnostics := selectHistory(map[string]string{
		"1.0.0":      "2026-01-01T00:00:00Z",
		"1.1.0-beta": "2026-02-01T00:00:00Z",
		"1.1.0-rc.1": "2026-03-01T00:00:00Z",
	}, "1.1.0-rc.1", 1)

	if len(entries) != 2 || entries[0].version != "1.1.0-beta" {
		t.Fatalf("entries = %+v, want earlier stable and prerelease versions", entries)
	}
	if diagnostics.IndeterminateReason != "" {
		t.Fatalf("diagnostics = %+v, want reliable history", diagnostics)
	}
}

func TestSelectHistoryMarksMalformedMetadataIndeterminate(t *testing.T) {
	_, diagnostics := selectHistory(map[string]string{
		"1.0.0": "not-a-time",
		"2.0.0": "2026-03-01T00:00:00Z",
	}, "2.0.0", 2)

	if diagnostics.IndeterminateReason == "" {
		t.Fatalf("diagnostics = %+v, want indeterminate history", diagnostics)
	}
}
