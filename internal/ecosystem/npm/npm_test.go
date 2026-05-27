package npm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchMetadata(t *testing.T) {
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

	oldBase := RegistryBaseURL
	RegistryBaseURL = server.URL
	defer func() { RegistryBaseURL = oldBase }()

	report, err := New(server.Client()).FetchMetadata(context.Background(), "lodash")
	if err != nil {
		t.Fatalf("FetchMetadata returned error: %v", err)
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
