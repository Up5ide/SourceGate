package app

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sourcegate/sourcegate/internal/cli"
	"github.com/sourcegate/sourcegate/internal/config"
	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/ecosystem/npm"
	"github.com/sourcegate/sourcegate/internal/ecosystem/pypi"
	"github.com/sourcegate/sourcegate/internal/report"
)

func TestAdapterForRoutesSupportedEcosystems(t *testing.T) {
	app := New(&http.Client{}, nil, nil)

	npmAdapter, err := app.adapterFor(cli.InstallRequest{Ecosystem: ecosystem.NPM}, config.Config{})
	if err != nil {
		t.Fatalf("adapterFor npm returned error: %v", err)
	}
	if _, ok := npmAdapter.(*npm.Adapter); !ok {
		t.Fatalf("npm adapter type = %T", npmAdapter)
	}

	pypiAdapter, err := app.adapterFor(cli.InstallRequest{Ecosystem: ecosystem.PyPI}, config.Config{})
	if err != nil {
		t.Fatalf("adapterFor pypi returned error: %v", err)
	}
	if _, ok := pypiAdapter.(*pypi.Adapter); !ok {
		t.Fatalf("pypi adapter type = %T", pypiAdapter)
	}
}

func TestRunRendersJSONFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lodash" {
			t.Fatalf("path = %q, want /lodash", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"name": "lodash",
			"dist-tags": {"latest": "4.17.21"},
			"time": {"4.17.21": "2021-02-20T15:42:16.891Z"},
			"versions": {"4.17.21": {}}
		}`))
	}))
	defer server.Close()

	oldBase := npm.RegistryBaseURL
	npm.RegistryBaseURL = server.URL
	defer func() { npm.RegistryBaseURL = oldBase }()

	oldWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd returned error: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("Chdir returned error: %v", err)
	}
	defer func() {
		if err := os.Chdir(oldWorkingDirectory); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()

	var out bytes.Buffer
	var errOut bytes.Buffer
	result, err := New(server.Client(), &out, &errOut).Run(context.Background(), []string{"--format", "json", "npm", "install", "lodash"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.ExitCode != ExitClean {
		t.Fatalf("exit code = %d, want %d", result.ExitCode, ExitClean)
	}
	if errOut.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", errOut.String())
	}

	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
	}
	reportValue := decoded["report"].(map[string]any)
	if reportValue["selected_version"] != "4.17.21" {
		t.Fatalf("report = %+v, want selected version", reportValue)
	}
}

func TestRunDebugDoesNotChangePyPIFetchBehavior(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/requests/json":
			w.Write([]byte(`{
				"info": {"name": "requests", "version": "2.0.0", "requires_dist": []},
				"releases": {
					"1.0.0": [{"filename": "requests-1.0.0.tar.gz", "packagetype": "sdist", "upload_time_iso_8601": "2025-01-01T00:00:00Z"}],
					"2.0.0": [{"filename": "requests-2.0.0.tar.gz", "packagetype": "sdist", "upload_time_iso_8601": "2026-01-01T00:00:00Z"}]
				}
			}`))
		case "/requests/1.0.0/json":
			w.Write([]byte(`{"info": {"name": "requests", "version": "1.0.0", "requires_dist": []}}`))
		case "/integrity/requests/2.0.0/requests-2.0.0.tar.gz/provenance":
			http.NotFound(w, r)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	oldBase := pypi.BaseURL
	oldIntegrityBase := pypi.IntegrityBaseURL
	pypi.BaseURL = server.URL
	pypi.IntegrityBaseURL = server.URL + "/integrity"
	defer func() {
		pypi.BaseURL = oldBase
		pypi.IntegrityBaseURL = oldIntegrityBase
	}()

	oldWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd returned error: %v", err)
	}
	tempDirectory := t.TempDir()
	configData, err := json.Marshal(config.Config{Policy: config.PolicyConfig{
		Alert: config.PolicyTierConfig{
			PyPIArtifactHistoryVersions: 1,
			PyPIArtifactShapeChange:     true,
			PyPIProvenanceRequired:      true,
			PyPIProvenanceScope:         "install-target",
		},
	}})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDirectory, config.DefaultPath), configData, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.Chdir(tempDirectory); err != nil {
		t.Fatalf("Chdir returned error: %v", err)
	}
	defer func() {
		if err := os.Chdir(oldWorkingDirectory); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()

	var normalOutput bytes.Buffer
	if _, err := New(server.Client(), &normalOutput, &bytes.Buffer{}).Run(context.Background(), []string{"pip", "install", "requests"}); err != nil {
		t.Fatalf("normal Run returned error: %v", err)
	}
	normalPaths := append([]string(nil), paths...)

	paths = nil
	var debugOutput bytes.Buffer
	if _, err := New(server.Client(), &debugOutput, &bytes.Buffer{}).Run(context.Background(), []string{"--debug", "pip", "install", "requests"}); err != nil {
		t.Fatalf("debug Run returned error: %v", err)
	}
	if !reflect.DeepEqual(paths, normalPaths) {
		t.Fatalf("debug request paths = %v, want same paths as normal run %v", paths, normalPaths)
	}
	if strings.Contains(normalOutput.String(), "Debug Evaluation Trace:") {
		t.Fatalf("normal output unexpectedly includes debug trace:\n%s", normalOutput.String())
	}
	if !strings.Contains(debugOutput.String(), "Debug Evaluation Trace:") {
		t.Fatalf("debug output missing trace:\n%s", debugOutput.String())
	}
}

func TestRunInspectDownloadsVerifiedArtifactAndDeletesTempFile(t *testing.T) {
	content := []byte("npm artifact")
	sum := sha512.Sum512(content)
	var artifactRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lodash":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"name": "lodash",
				"dist-tags": {"latest": "4.17.21"},
				"time": {"4.17.21": "2021-02-20T15:42:16.891Z"},
				"versions": {"4.17.21": {"dist": {
					"tarball": "` + serverURLPlaceholder + `/artifact.tgz",
					"integrity": "sha512-` + base64.StdEncoding.EncodeToString(sum[:]) + `"
				}}}
			}`))
		case "/artifact.tgz":
			artifactRequests++
			w.Write(content)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	oldBase := npm.RegistryBaseURL
	npm.RegistryBaseURL = server.URL
	defer func() { npm.RegistryBaseURL = oldBase }()

	tempDirectory := t.TempDir()
	t.Setenv("TMP", tempDirectory)
	t.Setenv("TEMP", tempDirectory)
	withWorkingDirectory(t, t.TempDir())

	if result, err := New(rewritePlaceholderClient(server.Client(), server.URL), &bytes.Buffer{}, &bytes.Buffer{}).Run(context.Background(), []string{"npm", "install", "lodash"}); err != nil {
		t.Fatalf("normal Run returned error: %v", err)
	} else if artifactRequests != 0 || result.Report.ArtifactDownload != nil {
		t.Fatalf("normal run artifact requests = %d summary = %+v, want metadata-only", artifactRequests, result.Report.ArtifactDownload)
	}

	var out bytes.Buffer
	result, err := New(rewritePlaceholderClient(server.Client(), server.URL), &out, &bytes.Buffer{}).Run(context.Background(), []string{"--inspect", "npm", "install", "lodash"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if artifactRequests != 1 || result.Report.ArtifactDownload == nil || result.Report.ArtifactDownload.Status != report.ArtifactDownloadStatusVerified {
		t.Fatalf("artifact requests = %d summary = %+v, want verified download", artifactRequests, result.Report.ArtifactDownload)
	}
	if entries, err := os.ReadDir(tempDirectory); err != nil || len(entries) != 0 {
		t.Fatalf("temporary directory entries = %v error = %v, want empty", entries, err)
	}
	if !strings.Contains(out.String(), "Status: DOWNLOADED_VERIFIED") {
		t.Fatalf("output missing artifact status:\n%s", out.String())
	}
}

func TestRunInspectSkipsArtifactDownloadWhenMetadataBlocks(t *testing.T) {
	var artifactRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pkg":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"name": "pkg",
				"dist-tags": {"latest": "1.0.0"},
				"time": {"1.0.0": "2026-06-14T00:00:00Z"},
				"versions": {"1.0.0": {"dist": {
					"tarball": "https://example.invalid/artifact.tgz",
					"integrity": "sha512-ZGVm"
				}}}
			}`))
		case "/artifact.tgz":
			artifactRequests++
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	oldBase := npm.RegistryBaseURL
	npm.RegistryBaseURL = server.URL
	defer func() { npm.RegistryBaseURL = oldBase }()

	workspace := t.TempDir()
	configData, err := json.Marshal(config.Config{Policy: config.PolicyConfig{
		Block: config.PolicyTierConfig{MinimumDaysSinceLatestRelease: 365},
	}})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, config.DefaultPath), configData, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	withWorkingDirectory(t, workspace)

	var out bytes.Buffer
	result, err := New(server.Client(), &out, &bytes.Buffer{}).Run(context.Background(), []string{"--inspect", "npm", "install", "pkg"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if artifactRequests != 0 || result.Report.ArtifactDownload == nil || result.Report.ArtifactDownload.Status != report.ArtifactDownloadStatusSkippedBlocked {
		t.Fatalf("artifact requests = %d summary = %+v, want blocked skip", artifactRequests, result.Report.ArtifactDownload)
	}
}

func TestExitCodeForReportUsesHighestSeverity(t *testing.T) {
	cases := []struct {
		name     string
		findings []string
		want     int
	}{
		{name: "clean", want: ExitClean},
		{name: "inform", findings: []string{"INFORM"}, want: ExitInformFinding},
		{name: "alert", findings: []string{"INFORM", "ALERT"}, want: ExitAlertFinding},
		{name: "block", findings: []string{"ALERT", "BLOCK"}, want: ExitBlockFinding},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := reportWithSeverities(tc.findings...)
			if got := ExitCodeForReport(report); got != tc.want {
				t.Fatalf("exit code = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRunReturnsOperationalExitCodeOnUsageError(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	result, err := New(&http.Client{}, &out, &errOut).Run(context.Background(), []string{"npm", "install"})
	if err == nil {
		t.Fatalf("Run returned nil error, want usage error")
	}
	if result.ExitCode != ExitOperationalError {
		t.Fatalf("exit code = %d, want %d", result.ExitCode, ExitOperationalError)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want no partial output", out.String())
	}
	if !strings.Contains(errOut.String(), "Usage:") {
		t.Fatalf("stderr = %q, want usage text", errOut.String())
	}
}

func reportWithSeverities(severities ...string) report.PackageReport {
	findings := make([]report.Finding, 0, len(severities))
	for _, severity := range severities {
		findings = append(findings, report.Finding{Severity: severity, Message: "finding"})
	}
	return report.PackageReport{Findings: findings}
}

func TestEffectivePyPITargetAppliesCLIOverrides(t *testing.T) {
	target := effectivePyPITarget(config.PyPIRuntimeConfig{
		TargetPlatform: "linux_x86_64",
		PythonVersion:  "3.12",
		Implementation: "cp",
		ABIs:           []string{"cp312"},
	}, cli.PyPIRuntimeOptions{
		PythonExecutable: "py",
		TargetPlatform:   "win_amd64",
		ABIs:             []string{"cp311", "abi3"},
	})

	if target.PythonExecutable != "py" || target.TargetPlatform != "win_amd64" || target.PythonVersion != "3.12" || target.Implementation != "cp" {
		t.Fatalf("target = %+v, want CLI values over config defaults", target)
	}
	if !reflect.DeepEqual(target.ABIs, []string{"cp311", "abi3"}) {
		t.Fatalf("target ABIs = %v, want CLI replacement", target.ABIs)
	}
}

func TestPyPIProvenanceScopesReturnsEnabledTierUnion(t *testing.T) {
	scopes := pypiProvenanceScopes(config.PolicyConfig{
		Inform: config.PolicyTierConfig{PyPIProvenanceRequired: true, PyPIProvenanceScope: "install-target"},
		Alert:  config.PolicyTierConfig{PyPIProvenanceRequired: true, PyPIProvenanceScope: "all-artifacts"},
		Block:  config.PolicyTierConfig{PyPIProvenanceRequired: false},
	})

	if len(scopes) != 2 {
		t.Fatalf("scopes = %v, want two enabled scopes", scopes)
	}
}

func TestPyPIDependencyHistoryEnabledOnlyWhenDependencyCheckConfigured(t *testing.T) {
	if pypiDependencyHistoryEnabled(config.PolicyConfig{
		Alert: config.PolicyTierConfig{PyPIArtifactShapeChange: true},
	}) {
		t.Fatalf("dependency history enabled for artifact-only policy")
	}
	if !pypiDependencyHistoryEnabled(config.PolicyConfig{
		Block: config.PolicyTierConfig{PyPIDependencyChange: true},
	}) {
		t.Fatalf("dependency history disabled for dependency policy")
	}
}

const serverURLPlaceholder = "http://sourcegate-test-server"

func rewritePlaceholderClient(client *http.Client, serverURL string) *http.Client {
	copy := *client
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	copy.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if strings.HasPrefix(req.URL.String(), serverURLPlaceholder) {
			rewritten, err := http.NewRequestWithContext(req.Context(), req.Method, strings.Replace(req.URL.String(), serverURLPlaceholder, serverURL, 1), req.Body)
			if err != nil {
				return nil, err
			}
			rewritten.Header = req.Header.Clone()
			req = rewritten
		}
		return transport.RoundTrip(req)
	})
	return &copy
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func withWorkingDirectory(t *testing.T, directory string) {
	t.Helper()
	oldWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd returned error: %v", err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatalf("Chdir returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWorkingDirectory); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})
}
