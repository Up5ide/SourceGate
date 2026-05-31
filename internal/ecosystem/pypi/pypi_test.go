package pypi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/requests/json" {
			t.Fatalf("path = %q, want /requests/json", r.URL.Path)
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

	report, err := New(server.Client()).FetchMetadata(context.Background(), "requests")
	if err != nil {
		t.Fatalf("FetchMetadata returned error: %v", err)
	}

	if report.Name != "requests" || report.LatestVersion != "2.32.3" || report.VersionCount != 2 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.LatestPublishedAt != "2024-05-29T00:00:00.000000Z" {
		t.Fatalf("latest published = %q", report.LatestPublishedAt)
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

func TestFetchMetadataWithArtifactOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		HistoryVersions: 1,
		CheckProvenance: true,
	}).FetchMetadata(context.Background(), "requests")
	if err != nil {
		t.Fatalf("FetchMetadata returned error: %v", err)
	}

	if !report.PyPILatestRelease.DependenciesKnown {
		t.Fatalf("latest dependencies known = false, want true")
	}
	if strings.Join(report.PyPILatestRelease.Dependencies, ",") != "charset-normalizer,urllib3" {
		t.Fatalf("latest dependencies = %v, want normalized names", report.PyPILatestRelease.Dependencies)
	}
	if len(report.PyPILatestRelease.Files) != 2 {
		t.Fatalf("latest files = %+v, want 2 files", report.PyPILatestRelease.Files)
	}
	if !report.PyPILatestRelease.Files[0].ProvenanceChecked || !report.PyPILatestRelease.Files[0].ProvenanceAvailable {
		t.Fatalf("wheel provenance = %+v, want available", report.PyPILatestRelease.Files[0])
	}
	if !report.PyPILatestRelease.Files[1].ProvenanceChecked || report.PyPILatestRelease.Files[1].ProvenanceAvailable {
		t.Fatalf("sdist provenance = %+v, want checked missing", report.PyPILatestRelease.Files[1])
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
