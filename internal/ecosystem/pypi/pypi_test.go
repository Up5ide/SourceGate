package pypi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/report"
)

func TestFetchMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/requests/json" {
			t.Fatalf("path = %q, want /requests/json", r.URL.Path)
		}
		if got := r.Header.Get("User-Agent"); got != "sourcegate/0.6.5" {
			t.Fatalf("user agent = %q, want sourcegate/0.6.5", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"info": {
				"name": "requests",
				"version": "2.32.3",
				"summary": "Python HTTP for Humans.",
				"license": "Apache-2.0",
				"author": "Kenneth Reitz",
				"author_email": "me@example.com",
				"home_page": "https://requests.readthedocs.io",
				"project_urls": {
					"Source": "https://github.com/psf/requests",
					"Tracker": "https://github.com/psf/requests/issues"
				}
			},
			"releases": {
				"2.32.2": [{"upload_time_iso_8601": "2024-05-21T00:00:00.000000Z"}],
				"2.32.3": [{"upload_time_iso_8601": "2024-05-29T00:00:00.000000Z"}]
			}
		}`))
	}))
	defer server.Close()

	oldBase := BaseURL
	BaseURL = server.URL
	defer func() { BaseURL = oldBase }()

	report, err := New(server.Client()).FetchMetadata(context.Background(), ecosystem.PackageSpec{Name: "requests"})
	if err != nil {
		t.Fatalf("FetchMetadata returned error: %v", err)
	}

	if report.Name != "requests" || report.SelectedVersion != "2.32.3" || report.VersionCount != 2 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.SelectedPublishedAt != "2024-05-29T00:00:00.000000Z" {
		t.Fatalf("latest published = %q", report.SelectedPublishedAt)
	}
	if report.PreviousPublishedAt != "2024-05-21T00:00:00.000000Z" {
		t.Fatalf("previous published = %q", report.PreviousPublishedAt)
	}
	if report.CreatedAt != "2024-05-21T00:00:00.000000Z" {
		t.Fatalf("created = %q", report.CreatedAt)
	}
	if report.ModifiedAt != "2024-05-29T00:00:00.000000Z" {
		t.Fatalf("modified = %q", report.ModifiedAt)
	}
}

func TestSelectHistoryExcludesLaterAndPrereleaseVersionsForStableLatest(t *testing.T) {
	entries, diagnostics := selectHistory(map[string][]release{
		"1.0.0":   {{UploadTimeISO: "2026-01-01T00:00:00Z"}},
		"1.1.0b1": {{UploadTimeISO: "2026-02-01T00:00:00Z"}},
		"1.1.0":   {{UploadTimeISO: "2026-03-01T00:00:00Z"}},
		"1.2.0b1": {{UploadTimeISO: "2026-04-01T00:00:00Z"}},
	}, "1.1.0", 1)

	if len(entries) != 1 || entries[0].version != "1.0.0" {
		t.Fatalf("entries = %+v, want earlier stable release only", entries)
	}
	if diagnostics.SkippedLaterVersions != 1 || diagnostics.SkippedPrereleaseVersions != 1 {
		t.Fatalf("diagnostics = %+v, want one later and one prerelease skip", diagnostics)
	}
}

func TestSelectHistoryDoesNotPoisonFilledRecentWindowWithOldMissingTimestamp(t *testing.T) {
	entries, diagnostics := selectHistory(map[string][]release{
		"1.0.0": {},
		"2.0.0": {{UploadTimeISO: "2026-01-01T00:00:00Z"}},
		"2.1.0": {{UploadTimeISO: "2026-02-01T00:00:00Z"}},
		"2.2.0": {{UploadTimeISO: "2026-03-01T00:00:00Z"}},
	}, "2.2.0", 2)

	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want filled recent window", entries)
	}
	if diagnostics.IndeterminateReason != "" {
		t.Fatalf("diagnostics = %+v, want old missing timestamp reported but not indeterminate", diagnostics)
	}
	if len(diagnostics.SkippedMalformedTimes) != 1 || diagnostics.SkippedMalformedTimes[0] != "1.0.0" {
		t.Fatalf("diagnostics = %+v, want skipped old timestamp evidence", diagnostics)
	}
}

func TestNormalizeRequirementsSeparatesOptionalExtras(t *testing.T) {
	required, optional := normalizeRequirements([]string{
		"urllib3>=1.0",
		"charset-normalizer ; python_version >= '3'",
		"socks ; extra == 'socks'",
	})

	if strings.Join(required, ",") != "charset-normalizer,urllib3" {
		t.Fatalf("required = %v, want normalized required names", required)
	}
	if strings.Join(optional, ",") != "socks" {
		t.Fatalf("optional = %v, want optional extra name", optional)
	}
}

func TestDependenciesKnownTreatsNullAsKnownEmptyUnlessDynamic(t *testing.T) {
	if !dependenciesKnown(info{RequiresDist: nil}) {
		t.Fatalf("null requires_dist without dynamic marker should be known empty")
	}
	if dependenciesKnown(info{RequiresDist: nil, Dynamic: []string{"Requires-Dist"}}) {
		t.Fatalf("dynamic requires_dist should be unknown")
	}
}

func TestReleaseHistorySkipsDependencyRequestsWhenDisabled(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		t.Fatalf("unexpected dependency metadata request: %s", r.URL.Path)
	}))
	defer server.Close()

	history := releaseHistory(context.Background(), server.Client(), "pkg", map[string][]release{
		"1.0.0": {{Filename: "pkg-1.0.0.tar.gz", PackageType: "sdist"}},
	}, []releaseHistoryEntry{{version: "1.0.0", publishedAt: "2026-01-01T00:00:00Z"}}, 1, false)

	if requests.Load() != 0 || len(history) != 1 || history[0].DependenciesKnown {
		t.Fatalf("requests = %d history = %+v, want artifact history without dependency fetch", requests.Load(), history)
	}
}

func TestReleaseHistoryFetchesOnlyImmediatePreviousDependencies(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/pkg/2.0.0/json" {
			t.Fatalf("unexpected dependency metadata request: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"info":{"requires_dist":[]}}`))
	}))
	defer server.Close()

	oldBase := BaseURL
	BaseURL = server.URL
	defer func() { BaseURL = oldBase }()

	history := releaseHistory(context.Background(), server.Client(), "pkg", map[string][]release{
		"2.0.0": {{Filename: "pkg-2.0.0.tar.gz", PackageType: "sdist"}},
		"1.0.0": {{Filename: "pkg-1.0.0.tar.gz", PackageType: "sdist"}},
	}, []releaseHistoryEntry{
		{version: "2.0.0", publishedAt: "2026-02-01T00:00:00Z"},
		{version: "1.0.0", publishedAt: "2026-01-01T00:00:00Z"},
	}, 2, true)

	if requests.Load() != 1 || len(history) != 2 || !history[0].DependenciesKnown || history[1].DependenciesKnown {
		t.Fatalf("requests = %d history = %+v, want only immediate previous dependencies fetched", requests.Load(), history)
	}
}

func TestPrepareProvenanceFiltersInstallTargetFiles(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()

	oldIntegrityBase := IntegrityBaseURL
	IntegrityBaseURL = server.URL
	defer func() { IntegrityBaseURL = oldIntegrityBase }()

	files := provenanceFixtureFiles()
	summary, warning := prepareProvenance(context.Background(), server.Client(), "pkg", "1.0.0", files, Options{
		ProvenanceScopes: []string{ProvenanceScopeInstallTarget},
		Target:           TargetOptions{PythonExecutable: "py", TargetPlatform: "win_amd64"},
		RunCommand: func(ctx context.Context, executable string, args ...string) ([]byte, error) {
			if executable != "py" || !strings.Contains(strings.Join(args, " "), "--platform win_amd64") {
				t.Fatalf("command = %s %v, want configured Python and platform", executable, args)
			}
			return []byte("Compatible tags: 2\n  cp311-cp311-win_amd64\n  py3-none-any\n"), nil
		},
	})

	if warning != "" || summary.CheckedCompatibleFiles != 3 || summary.SkippedNonTargetFiles != 1 {
		t.Fatalf("summary = %+v warning = %q, want three checked and one skipped", summary, warning)
	}
	if requests.Load() != 3 {
		t.Fatalf("requests = %d, want 3 selected provenance requests", requests.Load())
	}
	if files[1].ProvenanceChecked {
		t.Fatalf("linux wheel = %+v, want skipped non-target file", files[1])
	}
}

func TestPrepareProvenanceMarksCompatibilityFailureWithoutGuessingWheels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	oldIntegrityBase := IntegrityBaseURL
	IntegrityBaseURL = server.URL
	defer func() { IntegrityBaseURL = oldIntegrityBase }()

	files := provenanceFixtureFiles()
	summary, warning := prepareProvenance(context.Background(), server.Client(), "pkg", "1.0.0", files, Options{
		ProvenanceScopes: []string{ProvenanceScopeInstallTarget},
		Target:           TargetOptions{PythonExecutable: "missing-python", TargetPlatform: "win_amd64"},
		RunCommand: func(context.Context, string, ...string) ([]byte, error) {
			return nil, errors.New("not found")
		},
	})

	if summary.UsedFallback || summary.CompatibilityError == "" || !strings.Contains(warning, "cannot be confirmed") {
		t.Fatalf("summary = %+v warning = %q, want visible compatibility failure", summary, warning)
	}
	if summary.CheckedCompatibleFiles != 1 || summary.SkippedNonTargetFiles != 3 {
		t.Fatalf("summary = %+v, want only source distribution selected", summary)
	}
}

func TestSelectPreferredArtifactUsesTagPriorityThenSdistFallback(t *testing.T) {
	files := []report.PyPIReleaseFile{
		{Filename: "pkg-1.0.0-cp311-cp311-win_amd64.whl", PackageType: "bdist_wheel", URL: "https://example/win", Digests: map[string]string{"sha256": "win"}},
		{Filename: "pkg-1.0.0-py3-none-any.whl", PackageType: "bdist_wheel", URL: "https://example/any", Digests: map[string]string{"sha256": "any"}},
		{Filename: "pkg-1.0.0.tar.gz", PackageType: "sdist", URL: "https://example/sdist", Digests: map[string]string{"sha256": "sdist"}},
	}
	options := Options{RunCommand: func(context.Context, string, ...string) ([]byte, error) {
		return []byte("Compatible tags: 2\n  py3-none-any\n  cp311-cp311-win_amd64\n"), nil
	}}
	candidate, err := selectPreferredArtifact(context.Background(), files, options)
	if err != nil {
		t.Fatalf("selectPreferredArtifact returned error: %v", err)
	}
	if candidate.Filename != "pkg-1.0.0-py3-none-any.whl" {
		t.Fatalf("candidate = %+v, want highest-priority compatible wheel", candidate)
	}

	options.RunCommand = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("missing") }
	candidate, err = selectPreferredArtifact(context.Background(), files, options)
	if err != nil || candidate.Filename != "pkg-1.0.0.tar.gz" {
		t.Fatalf("candidate = %+v error = %v, want sdist fallback", candidate, err)
	}
}

func TestAnnotateProvenanceLimitsConcurrency(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		active.Add(-1)
		http.NotFound(w, r)
	}))
	defer server.Close()

	oldIntegrityBase := IntegrityBaseURL
	IntegrityBaseURL = server.URL
	defer func() { IntegrityBaseURL = oldIntegrityBase }()

	files := make([]report.PyPIReleaseFile, 8)
	selected := make([]int, len(files))
	for i := range files {
		files[i].Filename = fmt.Sprintf("pkg-1.0.0-%d.tar.gz", i)
		selected[i] = i
	}
	annotateProvenance(context.Background(), server.Client(), "pkg", "1.0.0", files, selected)

	if maximum.Load() > 4 {
		t.Fatalf("maximum concurrency = %d, want at most 4", maximum.Load())
	}
	if maximum.Load() < 2 {
		t.Fatalf("maximum concurrency = %d, want concurrent requests", maximum.Load())
	}
}

func provenanceFixtureFiles() []report.PyPIReleaseFile {
	return []report.PyPIReleaseFile{
		{Filename: "pkg-1.0.0-cp311-cp311-win_amd64.whl", PackageType: "bdist_wheel"},
		{Filename: "pkg-1.0.0-cp311-cp311-linux_x86_64.whl", PackageType: "bdist_wheel"},
		{Filename: "pkg-1.0.0-py3-none-any.whl", PackageType: "bdist_wheel"},
		{Filename: "pkg-1.0.0.tar.gz", PackageType: "sdist"},
	}
}

func TestFetchMetadataWithArtifactOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "sourcegate/0.6.5" {
			t.Fatalf("user agent = %q, want sourcegate/0.6.5", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/requests/json":
			w.Write([]byte(`{
				"info": {
					"name": "requests",
					"version": "2.32.3",
					"summary": "Python HTTP for Humans.",
					"requires_dist": ["urllib3>=1.21.1", "charset-normalizer ; python_version >= '3'"]
				},
				"releases": {
					"2.32.1": [{
						"filename": "requests-2.32.1-py3-none-any.whl",
						"packagetype": "bdist_wheel",
						"python_version": "py3",
						"requires_python": ">=3.8",
						"size": 1000,
						"upload_time_iso_8601": "2024-05-20T00:00:00.000000Z",
						"digests": {"sha256": "old"}
					}],
					"2.32.2": [{
						"filename": "requests-2.32.2-py3-none-any.whl",
						"packagetype": "bdist_wheel",
						"python_version": "py3",
						"requires_python": ">=3.8",
						"size": 1100,
						"upload_time_iso_8601": "2024-05-21T00:00:00.000000Z",
						"digests": {"sha256": "previous"}
					}],
					"2.32.3": [{
						"filename": "requests-2.32.3-py3-none-any.whl",
						"packagetype": "bdist_wheel",
						"python_version": "py3",
						"requires_python": ">=3.8",
						"size": 1200,
						"upload_time_iso_8601": "2024-05-29T00:00:00.000000Z",
						"digests": {"sha256": "latest-wheel"}
					}, {
						"filename": "requests-2.32.3.tar.gz",
						"packagetype": "sdist",
						"python_version": "source",
						"requires_python": ">=3.8",
						"size": 2200,
						"upload_time_iso_8601": "2024-05-29T00:01:00.000000Z",
						"digests": {"sha256": "latest-sdist"}
					}]
				}
			}`))
		case "/requests/2.32.2/json":
			w.Write([]byte(`{
				"info": {
					"name": "requests",
					"version": "2.32.2",
					"requires_dist": ["certifi>=2024.0.0"]
				},
				"urls": []
			}`))
		case "/integrity/requests/2.32.3/requests-2.32.3-py3-none-any.whl/provenance":
			w.Write([]byte(`{"attestation_bundles": [], "version": 1}`))
		case "/integrity/requests/2.32.3/requests-2.32.3.tar.gz/provenance":
			http.NotFound(w, r)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	oldBase := BaseURL
	oldIntegrityBase := IntegrityBaseURL
	BaseURL = server.URL
	IntegrityBaseURL = server.URL + "/integrity"
	defer func() {
		BaseURL = oldBase
		IntegrityBaseURL = oldIntegrityBase
	}()

	report, err := NewWithOptions(server.Client(), Options{
		HistoryVersions:   1,
		FetchDependencies: true,
		ProvenanceScopes:  []string{ProvenanceScopeAllArtifacts},
	}).FetchMetadata(context.Background(), ecosystem.PackageSpec{Name: "requests"})
	if err != nil {
		t.Fatalf("FetchMetadata returned error: %v", err)
	}

	if !report.PyPISelectedRelease.DependenciesKnown {
		t.Fatalf("latest dependencies known = false, want true")
	}
	if strings.Join(report.PyPISelectedRelease.Dependencies, ",") != "charset-normalizer,urllib3" {
		t.Fatalf("latest dependencies = %v, want normalized names", report.PyPISelectedRelease.Dependencies)
	}
	if len(report.PyPISelectedRelease.Files) != 2 {
		t.Fatalf("latest files = %+v, want 2 files", report.PyPISelectedRelease.Files)
	}
	if !report.PyPISelectedRelease.Files[0].ProvenanceChecked || !report.PyPISelectedRelease.Files[0].ProvenanceAvailable {
		t.Fatalf("wheel provenance = %+v, want available", report.PyPISelectedRelease.Files[0])
	}
	if !report.PyPISelectedRelease.Files[1].ProvenanceChecked || report.PyPISelectedRelease.Files[1].ProvenanceAvailable {
		t.Fatalf("sdist provenance = %+v, want checked missing", report.PyPISelectedRelease.Files[1])
	}
	if len(report.PyPIReleaseHistory) != 1 {
		t.Fatalf("history = %+v, want 1 release", report.PyPIReleaseHistory)
	}
	if report.PyPIReleaseHistory[0].Version != "2.32.2" {
		t.Fatalf("history version = %q, want 2.32.2", report.PyPIReleaseHistory[0].Version)
	}
	if !report.PyPIReleaseHistory[0].DependenciesKnown || strings.Join(report.PyPIReleaseHistory[0].Dependencies, ",") != "certifi" {
		t.Fatalf("history dependencies = %+v, known=%v, want certifi", report.PyPIReleaseHistory[0].Dependencies, report.PyPIReleaseHistory[0].DependenciesKnown)
	}
}

func TestFetchMetadataSelectsExactVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/requests/json":
			w.Write([]byte(`{
				"info": {
					"name": "requests",
					"version": "2.32.3",
					"summary": "Latest summary",
					"requires_dist": ["latest-dep>=1"]
				},
				"releases": {
					"2.31.0": [{
						"filename": "requests-2.31.0.tar.gz",
						"packagetype": "sdist",
						"size": 1000,
						"upload_time_iso_8601": "2023-05-22T00:00:00.000000Z",
						"digests": {"sha256": "selected"}
					}],
					"2.32.3": [{
						"filename": "requests-2.32.3.tar.gz",
						"packagetype": "sdist",
						"size": 2000,
						"upload_time_iso_8601": "2024-05-29T00:00:00.000000Z",
						"digests": {"sha256": "latest"}
					}]
				}
			}`))
		case "/requests/2.31.0/json":
			w.Write([]byte(`{
				"info": {
					"name": "requests",
					"version": "2.31.0",
					"summary": "Selected summary",
					"license": "Apache-2.0",
					"requires_dist": ["urllib3>=1.21.1"]
				},
				"urls": [{
					"filename": "requests-2.31.0-py3-none-any.whl",
					"packagetype": "bdist_wheel",
					"size": 900,
					"upload_time_iso_8601": "2023-05-22T00:01:00.000000Z",
					"digests": {"sha256": "selected-wheel"}
				}]
			}`))
		case "/integrity/requests/2.31.0/requests-2.31.0-py3-none-any.whl/provenance":
			http.NotFound(w, r)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	oldBase := BaseURL
	oldIntegrityBase := IntegrityBaseURL
	BaseURL = server.URL
	IntegrityBaseURL = server.URL + "/integrity"
	defer func() {
		BaseURL = oldBase
		IntegrityBaseURL = oldIntegrityBase
	}()

	report, err := NewWithOptions(server.Client(), Options{
		ProvenanceScopes: []string{ProvenanceScopeAllArtifacts},
	}).FetchMetadata(context.Background(), ecosystem.PackageSpec{Name: "requests", Version: "2.31.0"})
	if err != nil {
		t.Fatalf("FetchMetadata returned error: %v", err)
	}

	if report.SelectedVersion != "2.31.0" || report.SelectedPublishedAt != "2023-05-22T00:01:00.000000Z" {
		t.Fatalf("selected release = %s %s, want version-specific release", report.SelectedVersion, report.SelectedPublishedAt)
	}
	if report.Description != "Selected summary" || report.License != "Apache-2.0" {
		t.Fatalf("metadata = %q %q, want version-specific metadata", report.Description, report.License)
	}
	if strings.Join(report.PyPISelectedRelease.Dependencies, ",") != "urllib3" {
		t.Fatalf("dependencies = %v, want version-specific dependencies", report.PyPISelectedRelease.Dependencies)
	}
	if len(report.PyPISelectedRelease.Files) != 1 || report.PyPISelectedRelease.Files[0].Filename != "requests-2.31.0-py3-none-any.whl" {
		t.Fatalf("files = %+v, want version-specific URLs", report.PyPISelectedRelease.Files)
	}
	if !report.PyPISelectedRelease.Files[0].ProvenanceChecked {
		t.Fatalf("selected file provenance was not checked: %+v", report.PyPISelectedRelease.Files[0])
	}
}

func TestFetchMetadataRejectsMissingExactVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"info": {"name": "requests", "version": "2.32.3"},
			"releases": {"2.32.3": [{"upload_time_iso_8601": "2024-05-29T00:00:00.000000Z"}]}
		}`))
	}))
	defer server.Close()

	oldBase := BaseURL
	BaseURL = server.URL
	defer func() { BaseURL = oldBase }()

	_, err := New(server.Client()).FetchMetadata(context.Background(), ecosystem.PackageSpec{Name: "requests", Version: "2.31.0"})
	if err == nil || !strings.Contains(err.Error(), "PyPI package version not found") {
		t.Fatalf("error = %v, want missing version error", err)
	}
}
