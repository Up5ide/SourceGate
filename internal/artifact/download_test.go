package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/sourcegate/sourcegate/internal/report"
)

func TestDownloadAndVerifyDownloadsVerifiesAndDeletesTempFile(t *testing.T) {
	content := []byte("verified artifact")
	sum := sha256.Sum256(content)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(content)
	}))
	defer server.Close()
	tempDir := t.TempDir()
	t.Setenv("TMP", tempDir)
	t.Setenv("TEMP", tempDir)

	var usedPath string
	summary, err := DownloadAndVerify(context.Background(), server.Client(), report.ArtifactCandidate{
		URL:             server.URL + "/artifact.tgz",
		Filename:        "artifact.tgz",
		PackageType:     "npm-tarball",
		ExpectedSize:    int64(len(content)),
		DigestAlgorithm: "sha256",
		DigestValue:     hex.EncodeToString(sum[:]),
	}, func(path string) error {
		usedPath = path
		downloaded, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if string(downloaded) != string(content) {
			t.Fatalf("temporary artifact content = %q, want %q", downloaded, content)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("DownloadAndVerify returned error: %v", err)
	}
	if summary.Status != report.ArtifactDownloadStatusVerified || !summary.DigestVerified || summary.DownloadedSize != int64(len(content)) {
		t.Fatalf("summary = %+v, want verified download", summary)
	}
	if entries, err := os.ReadDir(tempDir); err != nil || len(entries) != 0 {
		t.Fatalf("temporary directory entries = %v error = %v, want empty", entries, err)
	}
	if usedPath == "" {
		t.Fatalf("verified temporary artifact was not exposed to callback")
	}
}

func TestDownloadAndVerifyRejectsUnsafeOrUnverifiedDownloads(t *testing.T) {
	content := []byte("artifact")
	sum := sha256.Sum256(content)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oversized":
			w.Header().Set("Content-Length", "104857601")
		case "/failed":
			http.Error(w, "no", http.StatusBadGateway)
		default:
			w.Write(content)
		}
	}))
	defer server.Close()

	valid := report.ArtifactCandidate{
		URL:             server.URL + "/artifact",
		Filename:        "artifact.tgz",
		ExpectedSize:    int64(len(content)),
		DigestAlgorithm: "sha256",
		DigestValue:     hex.EncodeToString(sum[:]),
	}
	cases := map[string]report.ArtifactCandidate{
		"invalid URL":      {URL: "file:///tmp/artifact", Filename: "artifact", DigestAlgorithm: "sha256", DigestValue: valid.DigestValue},
		"missing digest":   {URL: server.URL, Filename: "artifact", DigestAlgorithm: "sha256"},
		"digest mismatch":  withCandidate(valid, func(value *report.ArtifactCandidate) { value.DigestValue = strings.Repeat("0", 64) }),
		"size mismatch":    withCandidate(valid, func(value *report.ArtifactCandidate) { value.ExpectedSize++ }),
		"expected too big": withCandidate(valid, func(value *report.ArtifactCandidate) { value.ExpectedSize = MaxDownloadSize + 1 }),
		"response too big": withCandidate(valid, func(value *report.ArtifactCandidate) { value.URL = server.URL + "/oversized"; value.ExpectedSize = 0 }),
		"download failure": withCandidate(valid, func(value *report.ArtifactCandidate) { value.URL = server.URL + "/failed" }),
	}

	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			tempDir := t.TempDir()
			t.Setenv("TMP", tempDir)
			t.Setenv("TEMP", tempDir)
			if _, err := DownloadAndVerify(context.Background(), server.Client(), candidate, nil); err == nil {
				t.Fatalf("DownloadAndVerify returned nil error")
			}
			if entries, err := os.ReadDir(tempDir); err != nil || len(entries) != 0 {
				t.Fatalf("temporary directory entries = %v error = %v, want empty", entries, err)
			}
		})
	}
}

func withCandidate(candidate report.ArtifactCandidate, change func(*report.ArtifactCandidate)) report.ArtifactCandidate {
	change(&candidate)
	return candidate
}
