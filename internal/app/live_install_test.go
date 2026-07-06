package app

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sourcegate/sourcegate/internal/config"
)

const liveInstallEnv = "SOURCEGATE_LIVE_INSTALL"

func TestLiveInstallNPMCleanPackage(t *testing.T) {
	requireLiveInstall(t)
	requireExecutable(t, "npm")

	workspace := prepareLiveNPMWorkspace(t)
	result := runLiveInstall(t, workspace, []string{"--mode", "install", "npm", "install", "lodash@4.17.21"})

	if result.ExitCode != ExitClean || result.Report.Install == nil || !result.Report.Install.Executed {
		t.Fatalf("exit = %d install = %+v, want clean executed install", result.ExitCode, result.Report.Install)
	}
	if _, err := os.Stat(filepath.Join(workspace, "node_modules", "lodash", "package.json")); err != nil {
		t.Fatalf("lodash was not installed in temp workspace: %v", err)
	}
}

func TestLiveInstallNPMAlertStillInstalls(t *testing.T) {
	requireLiveInstall(t)
	requireExecutable(t, "npm")

	workspace := prepareLiveNPMWorkspace(t)
	writeLiveConfig(t, workspace, `{"policy":{"alert":{"groups":{"npm_lifecycle":true}}}}`)
	result := runLiveInstall(t, workspace, []string{"--mode", "install", "npm", "install", "core-js@3.49.0"})

	if result.ExitCode != ExitAlertFinding || result.Report.Install == nil || !result.Report.Install.Executed {
		t.Fatalf("exit = %d install = %+v, want alert executed install", result.ExitCode, result.Report.Install)
	}
	if _, err := os.Stat(filepath.Join(workspace, "node_modules", "core-js", "package.json")); err != nil {
		t.Fatalf("core-js was not installed in temp workspace: %v", err)
	}
}

func TestLiveInstallNPMForcedBlockSkipsInstall(t *testing.T) {
	requireLiveInstall(t)
	requireExecutable(t, "npm")

	workspace := prepareLiveNPMWorkspace(t)
	writeLiveConfig(t, workspace, `{"policy":{"block":{"checks":{"private_packages":{"npm":["lodash"]}}}}}`)
	result := runLiveInstall(t, workspace, []string{"--mode", "install", "npm", "install", "lodash@4.17.21"})

	if result.ExitCode != ExitBlockFinding || result.Report.Install == nil || result.Report.Install.Executed {
		t.Fatalf("exit = %d install = %+v, want block skipped install", result.ExitCode, result.Report.Install)
	}
	if _, err := os.Stat(filepath.Join(workspace, "node_modules", "lodash")); !os.IsNotExist(err) {
		t.Fatalf("lodash install directory exists or stat failed unexpectedly: %v", err)
	}
}

func TestLiveInstallPyPICleanPackage(t *testing.T) {
	requireLiveInstall(t)

	workspace := prepareLivePyPIWorkspace(t)
	result := runLiveInstall(t, workspace, []string{"--mode", "install", "pip", "install", "requests==2.34.2"})

	if result.ExitCode != ExitClean || result.Report.Install == nil || !result.Report.Install.Executed {
		t.Fatalf("exit = %d install = %+v, want clean executed install", result.ExitCode, result.Report.Install)
	}
	assertPythonImport(t, "requests")
}

func TestLiveInstallPyPINativeArtifactSignal(t *testing.T) {
	requireLiveInstall(t)

	workspace := prepareLivePyPIWorkspace(t)
	writeLiveConfig(t, workspace, `{"policy":{"alert":{"checks":{"artifact_suspicious_file_types":true}}}}`)
	result := runLiveInstall(t, workspace, []string{"--mode", "install", "pip", "install", "cryptography==48.0.0"})

	if result.ExitCode != ExitAlertFinding || result.Report.Install == nil || !result.Report.Install.Executed {
		t.Fatalf("exit = %d install = %+v, want alert executed install", result.ExitCode, result.Report.Install)
	}
	if result.Report.ArtifactInspection == nil || result.Report.ArtifactInspection.SuspiciousFileTypeCount == 0 {
		t.Fatalf("artifact inspection = %+v, want native artifact signal", result.Report.ArtifactInspection)
	}
	assertPythonImport(t, "cryptography")
}

func TestLiveInstallPyPIForcedBlockSkipsInstall(t *testing.T) {
	requireLiveInstall(t)

	workspace := prepareLivePyPIWorkspace(t)
	writeLiveConfig(t, workspace, `{"policy":{"block":{"checks":{"private_packages":{"pypi":["requests"]}}}}}`)
	result := runLiveInstall(t, workspace, []string{"--mode", "install", "pip", "install", "requests==2.34.2"})

	if result.ExitCode != ExitBlockFinding || result.Report.Install == nil || result.Report.Install.Executed {
		t.Fatalf("exit = %d install = %+v, want block skipped install", result.ExitCode, result.Report.Install)
	}
	if pythonImportSucceeds("requests") {
		t.Fatalf("requests import succeeded after blocked install")
	}
}

func requireLiveInstall(t *testing.T) {
	t.Helper()
	if os.Getenv(liveInstallEnv) != "1" {
		t.Skipf("set %s=1 to run live install smoke tests", liveInstallEnv)
	}
}

func requireExecutable(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s is not available on PATH: %v", name, err)
	}
}

func prepareLiveNPMWorkspace(t *testing.T) string {
	t.Helper()
	workspace := t.TempDir()
	t.Setenv("npm_config_cache", filepath.Join(workspace, ".npm-cache"))
	t.Setenv("npm_config_audit", "false")
	t.Setenv("npm_config_fund", "false")
	return workspace
}

func prepareLivePyPIWorkspace(t *testing.T) string {
	t.Helper()
	workspace := t.TempDir()
	python := firstAvailablePython(t)
	venv := filepath.Join(workspace, ".venv")
	cmd := exec.Command(python, "-m", "venv", venv)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("create venv failed: %v\n%s", err, string(output))
	}
	scriptsDir := "bin"
	if runtime.GOOS == "windows" {
		scriptsDir = "Scripts"
	}
	t.Setenv("PATH", filepath.Join(venv, scriptsDir)+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PIP_CACHE_DIR", filepath.Join(workspace, ".pip-cache"))
	t.Setenv("PIP_DISABLE_PIP_VERSION_CHECK", "1")
	requireExecutable(t, "pip")
	requireExecutable(t, "python")
	return workspace
}

func firstAvailablePython(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python", "python3", "py"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	t.Skip("no Python executable available for live PyPI install test")
	return ""
}

func writeLiveConfig(t *testing.T, workspace, override string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(workspace, config.DefaultPath), groupedConfigJSON(t, override), 0600); err != nil {
		t.Fatalf("write live test config: %v", err)
	}
}

func runLiveInstall(t *testing.T, workspace string, args []string) RunResult {
	t.Helper()
	oldWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(workspace); err != nil {
		t.Fatalf("chdir live workspace: %v", err)
	}
	defer func() {
		if err := os.Chdir(oldWorkingDirectory); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var out bytes.Buffer
	var errOut bytes.Buffer
	result, err := New(&http.Client{Timeout: 30 * time.Second}, &out, &errOut).Run(ctx, args)
	if err != nil {
		t.Fatalf("Run returned error: %v\nstderr:\n%s\nstdout:\n%s", err, errOut.String(), out.String())
	}
	return result
}

func assertPythonImport(t *testing.T, module string) {
	t.Helper()
	if !pythonImportSucceeds(module) {
		t.Fatalf("python import %s failed", module)
	}
}

func pythonImportSucceeds(module string) bool {
	cmd := exec.Command("python", "-c", "import "+module)
	output, err := cmd.CombinedOutput()
	return err == nil && !strings.Contains(string(output), "ModuleNotFoundError")
}
