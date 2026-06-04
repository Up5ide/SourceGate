package cli

import (
	"testing"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
)

func TestParseInstallCommandNPM(t *testing.T) {
	req, err := ParseInstallCommand([]string{"npm", "install", "lodash"})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}

	if req.Ecosystem != ecosystem.NPM {
		t.Fatalf("ecosystem = %q, want %q", req.Ecosystem, ecosystem.NPM)
	}
	if req.Package != "lodash" {
		t.Fatalf("package = %q, want lodash", req.Package)
	}
}

func TestParseInstallCommandPip(t *testing.T) {
	req, err := ParseInstallCommand([]string{"pip", "install", "requests"})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}

	if req.Ecosystem != ecosystem.PyPI {
		t.Fatalf("ecosystem = %q, want %q", req.Ecosystem, ecosystem.PyPI)
	}
	if req.Package != "requests" {
		t.Fatalf("package = %q, want requests", req.Package)
	}
}

func TestParseInstallCommandDebug(t *testing.T) {
	req, err := ParseInstallCommand([]string{"--debug", "npm", "install", "lodash"})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}
	if !req.Debug {
		t.Fatalf("debug = false, want true")
	}
}

func TestParseInstallCommandPyPIRuntimeOptions(t *testing.T) {
	req, err := ParseInstallCommand([]string{
		"--abi", "cp311",
		"--debug",
		"--python", "py",
		"--target-platform", "win_amd64",
		"--python-version", "3.11",
		"--implementation", "cp",
		"--abi", "abi3",
		"pip", "install", "cryptography",
	})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}
	if !req.Debug || req.PyPIRuntime.PythonExecutable != "py" || req.PyPIRuntime.TargetPlatform != "win_amd64" {
		t.Fatalf("request = %+v, want debug runtime overrides", req)
	}
	if len(req.PyPIRuntime.ABIs) != 2 || req.PyPIRuntime.ABIs[0] != "cp311" || req.PyPIRuntime.ABIs[1] != "abi3" {
		t.Fatalf("ABIs = %v, want repeated values", req.PyPIRuntime.ABIs)
	}
}

func TestParseInstallCommandRejectsUnsupportedShapes(t *testing.T) {
	cases := [][]string{
		{"npm", "install"},
		{"npm", "view", "lodash"},
		{"pip", "install", "-r"},
		{"cargo", "install", "ripgrep"},
		{"npm", "install", "lodash", "--debug"},
		{"--debug", "--debug", "npm", "install", "lodash"},
		{"--verbose", "npm", "install", "lodash"},
		{"--python", "py", "npm", "install", "lodash"},
		{"--target-platform", "win_amd64", "npm", "install", "lodash"},
		{"--python", "py", "--python", "python", "pip", "install", "requests"},
		{"--python", "--debug", "pip", "install", "requests"},
	}

	for _, args := range cases {
		if _, err := ParseInstallCommand(args); err == nil {
			t.Fatalf("ParseInstallCommand(%v) returned nil error", args)
		}
	}
}
