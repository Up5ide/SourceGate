package pypi

import (
	"context"
	"net/http"
	"net/http/httptest"
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
