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
	if req.Package.Name != "lodash" || req.Package.Version != "" {
		t.Fatalf("package = %+v, want unversioned lodash", req.Package)
	}
	if req.OutputFormat != OutputFormatHuman {
		t.Fatalf("output format = %q, want human", req.OutputFormat)
	}
	if req.Mode != ModeMetadata {
		t.Fatalf("mode = %q, want metadata", req.Mode)
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
	if req.Package.Name != "requests" || req.Package.Version != "" {
		t.Fatalf("package = %+v, want unversioned requests", req.Package)
	}
}

func TestParseInstallCommandNPMExactVersion(t *testing.T) {
	req, err := ParseInstallCommand([]string{"npm", "install", "lodash@4.17.21"})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}
	if req.Package.Name != "lodash" || req.Package.Version != "4.17.21" {
		t.Fatalf("package = %+v, want lodash 4.17.21", req.Package)
	}
}

func TestParseInstallCommandNPMScopedExactVersion(t *testing.T) {
	req, err := ParseInstallCommand([]string{"npm", "install", "@scope/pkg@1.2.3"})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}
	if req.Package.Name != "@scope/pkg" || req.Package.Version != "1.2.3" {
		t.Fatalf("package = %+v, want scoped exact package", req.Package)
	}
}

func TestParseInstallCommandNPMScopedUnversioned(t *testing.T) {
	req, err := ParseInstallCommand([]string{"npm", "install", "@scope/pkg"})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}
	if req.Package.Name != "@scope/pkg" || req.Package.Version != "" {
		t.Fatalf("package = %+v, want scoped unversioned package", req.Package)
	}
}

func TestParseInstallCommandPyPIExactVersion(t *testing.T) {
	req, err := ParseInstallCommand([]string{"pip", "install", "requests==2.31.0"})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}
	if req.Package.Name != "requests" || req.Package.Version != "2.31.0" {
		t.Fatalf("package = %+v, want requests 2.31.0", req.Package)
	}
}

func TestParseInstallCommandPyPIExactVersionWithEpoch(t *testing.T) {
	req, err := ParseInstallCommand([]string{"pip", "install", "pkg==1!2.0"})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}
	if req.Package.Name != "pkg" || req.Package.Version != "1!2.0" {
		t.Fatalf("package = %+v, want pkg 1!2.0", req.Package)
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

func TestParseInstallCommandInspect(t *testing.T) {
	req, err := ParseInstallCommand([]string{"--inspect", "--debug", "npm", "install", "lodash"})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}
	if !req.Inspect || !req.Debug {
		t.Fatalf("request = %+v, want inspect and debug", req)
	}
	if req.Mode != ModeArtifact {
		t.Fatalf("mode = %q, want artifact", req.Mode)
	}
}

func TestParseInstallCommandModeArtifact(t *testing.T) {
	req, err := ParseInstallCommand([]string{"--mode", "artifact", "npm", "install", "lodash"})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}
	if req.Mode != ModeArtifact || req.Inspect {
		t.Fatalf("request = %+v, want artifact mode without deprecated inspect flag", req)
	}
}

func TestParseInstallCommandModeInstall(t *testing.T) {
	req, err := ParseInstallCommand([]string{"--mode", "install", "pip", "install", "requests"})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}
	if req.Mode != ModeInstall {
		t.Fatalf("mode = %q, want install", req.Mode)
	}
}

func TestParseInstallCommandInfoActions(t *testing.T) {
	cases := map[string]struct {
		args       []string
		wantAction string
		wantConfig string
		wantPreset string
	}{
		"help":                {args: []string{"--help"}, wantAction: ActionHelp},
		"version":             {args: []string{"--version"}, wantAction: ActionVersion},
		"print config":        {args: []string{"--config", "strict.json", "--print-config"}, wantAction: ActionPrintConfig, wantConfig: "strict.json"},
		"print preset config": {args: []string{"--preset", "balanced", "--print-config"}, wantAction: ActionPrintConfig, wantPreset: "balanced"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req, err := ParseInstallCommand(tc.args)
			if err != nil {
				t.Fatalf("ParseInstallCommand returned error: %v", err)
			}
			if req.Action != tc.wantAction || req.ConfigPath != tc.wantConfig || req.Preset != tc.wantPreset {
				t.Fatalf("request = %+v, want action %q config %q preset %q", req, tc.wantAction, tc.wantConfig, tc.wantPreset)
			}
		})
	}
}

func TestParseInstallCommandConfigSubcommands(t *testing.T) {
	cases := map[string]struct {
		args       []string
		wantAction string
		wantConfig string
		wantPreset string
		wantFormat string
	}{
		"test":        {args: []string{"config", "test"}, wantAction: ActionConfigTest},
		"test config": {args: []string{"config", "test", "--config", "strict.json"}, wantAction: ActionConfigTest, wantConfig: "strict.json"},
		"explain":     {args: []string{"config", "explain"}, wantAction: ActionConfigExplain},
		"preset":      {args: []string{"config", "preset", "balanced"}, wantAction: ActionConfigPreset, wantPreset: "balanced", wantFormat: "compact"},
		"preset full": {args: []string{"config", "preset", "strict", "--format", "full"}, wantAction: ActionConfigPreset, wantPreset: "strict", wantFormat: "full"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req, err := ParseInstallCommand(tc.args)
			if err != nil {
				t.Fatalf("ParseInstallCommand returned error: %v", err)
			}
			if req.Action != tc.wantAction || req.ConfigPath != tc.wantConfig || req.ConfigPreset != tc.wantPreset || req.PresetFormat != tc.wantFormat {
				t.Fatalf("request = %+v, want action %q config %q preset %q format %q", req, tc.wantAction, tc.wantConfig, tc.wantPreset, tc.wantFormat)
			}
		})
	}
}

func TestParseInstallCommandJSONFormat(t *testing.T) {
	req, err := ParseInstallCommand([]string{"--format", "json", "npm", "install", "lodash"})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}
	if req.OutputFormat != OutputFormatJSON {
		t.Fatalf("output format = %q, want json", req.OutputFormat)
	}
}

func TestParseInstallCommandReportFormat(t *testing.T) {
	req, err := ParseInstallCommand([]string{"--format", "report", "npm", "install", "lodash"})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}
	if req.OutputFormat != OutputFormatReport || req.ReportVerbose {
		t.Fatalf("request = %+v, want report format without verbose", req)
	}
}

func TestParseInstallCommandReportVerbose(t *testing.T) {
	req, err := ParseInstallCommand([]string{"--format", "report", "-v", "npm", "install", "lodash"})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}
	if req.OutputFormat != OutputFormatReport || !req.ReportVerbose {
		t.Fatalf("request = %+v, want verbose report format", req)
	}
}

func TestParseInstallCommandPyPIRuntimeOptions(t *testing.T) {
	req, err := ParseInstallCommand([]string{
		"--abi", "cp311",
		"--debug",
		"--format", "human",
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
	if !req.Debug || req.OutputFormat != OutputFormatHuman || req.PyPIRuntime.PythonExecutable != "py" || req.PyPIRuntime.TargetPlatform != "win_amd64" {
		t.Fatalf("request = %+v, want debug runtime overrides", req)
	}
	if len(req.PyPIRuntime.ABIs) != 2 || req.PyPIRuntime.ABIs[0] != "cp311" || req.PyPIRuntime.ABIs[1] != "abi3" {
		t.Fatalf("ABIs = %v, want repeated values", req.PyPIRuntime.ABIs)
	}
}

func TestParseInstallCommandPresetRuntime(t *testing.T) {
	req, err := ParseInstallCommand([]string{"--preset", "balanced", "npm", "install", "lodash"})
	if err != nil {
		t.Fatalf("ParseInstallCommand returned error: %v", err)
	}
	if req.Preset != "balanced" || req.Ecosystem != ecosystem.NPM {
		t.Fatalf("request = %+v, want balanced npm request", req)
	}
}

func TestParseInstallCommandRejectsUnsupportedShapes(t *testing.T) {
	cases := [][]string{
		{"npm", "install"},
		{"npm", "view", "lodash"},
		{"pip", "install", "-r"},
		{"cargo", "install", "ripgrep"},
		{"npm", "install", "lodash", "--debug"},
		{"npm", "install", "lodash@"},
		{"npm", "install", "lodash@latest"},
		{"npm", "install", "lodash@^4.17.21"},
		{"pip", "install", "requests=="},
		{"pip", "install", "requests>=2.0.0"},
		{"pip", "install", "requests[socks]==2.31.0"},
		{"pip", "install", "requests==2.31.0,==2.32.0"},
		{"--debug", "--debug", "npm", "install", "lodash"},
		{"--inspect", "--inspect", "npm", "install", "lodash"},
		{"--inspect", "--mode", "artifact", "npm", "install", "lodash"},
		{"--mode", "artifact", "--inspect", "npm", "install", "lodash"},
		{"--mode", "files", "npm", "install", "lodash"},
		{"--mode", "npm", "install", "lodash"},
		{"--format", "xml", "npm", "install", "lodash"},
		{"--format", "json", "--format", "human", "npm", "install", "lodash"},
		{"--format", "npm", "install", "lodash"},
		{"-v", "npm", "install", "lodash"},
		{"--format", "json", "-v", "npm", "install", "lodash"},
		{"--format", "report", "-v", "-v", "npm", "install", "lodash"},
		{"--debug", "--format", "report", "npm", "install", "lodash"},
		{"--format", "report", "--debug", "npm", "install", "lodash"},
		{"--config", "strict.json", "--preset", "balanced", "npm", "install", "lodash"},
		{"--preset", "paranoid", "npm", "install", "lodash"},
		{"config"},
		{"config", "preset"},
		{"config", "preset", "paranoid"},
		{"config", "preset", "balanced", "--format", "json"},
		{"--config", "strict.json", "config", "preset", "balanced"},
		{"config", "test", "--preset", "balanced"},
		{"-x", "npm", "install", "lodash"},
		{"--verbose", "npm", "install", "lodash"},
		{"--python", "py", "npm", "install", "lodash"},
		{"--target-platform", "win_amd64", "npm", "install", "lodash"},
		{"--python", "py", "--python", "python", "pip", "install", "requests"},
		{"--python", "--debug", "pip", "install", "requests"},
		{"--help", "npm", "install", "lodash"},
		{"--help", "--version"},
		{"--version", "--debug"},
		{"--help", "--config", "strict.json"},
		{"--print-config", "--debug"},
	}

	for _, args := range cases {
		if _, err := ParseInstallCommand(args); err == nil {
			t.Fatalf("ParseInstallCommand(%v) returned nil error", args)
		}
	}
}
