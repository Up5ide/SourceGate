package sourcegate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchNPMMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lodash" {
			t.Fatalf("path = %q, want /lodash", r.URL.Path)
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
				"4.17.20": "2020-02-20T15:42:16.891Z",
				"4.17.21": "2021-02-20T15:42:16.891Z"
			},
			"versions": {"4.17.20": {}, "4.17.21": {}},
			"homepage": "https://lodash.com/",
			"repository": {"url": "git+https://github.com/lodash/lodash.git"},
			"bugs": {"url": "https://github.com/lodash/lodash/issues"}
		}`))
	}))
	defer server.Close()

	oldBase := npmRegistryBaseURL
	npmRegistryBaseURL = server.URL
	defer func() { npmRegistryBaseURL = oldBase }()

	report, err := FetchNPMMetadata(context.Background(), server.Client(), "lodash")
	if err != nil {
		t.Fatalf("FetchNPMMetadata returned error: %v", err)
	}

	if report.Name != "lodash" || report.LatestVersion != "4.17.21" || report.VersionCount != 2 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.LatestPublishedAt != "2021-02-20T15:42:16.891Z" {
		t.Fatalf("latest published = %q", report.LatestPublishedAt)
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
}

func TestFetchPyPIMetadata(t *testing.T) {
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

	oldBase := pypiBaseURL
	pypiBaseURL = server.URL
	defer func() { pypiBaseURL = oldBase }()

	report, err := FetchPyPIMetadata(context.Background(), server.Client(), "requests")
	if err != nil {
		t.Fatalf("FetchPyPIMetadata returned error: %v", err)
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
