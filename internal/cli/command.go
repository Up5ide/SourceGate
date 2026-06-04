package cli

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/version"
	"github.com/sourcegate/sourcegate/internal/versioning"
)

type InstallRequest struct {
	Ecosystem    ecosystem.Ecosystem
	Manager      string
	Command      string
	Package      ecosystem.PackageSpec
	Debug        bool
	OutputFormat string
	PyPIRuntime  PyPIRuntimeOptions
}

type PyPIRuntimeOptions struct {
	PythonExecutable string
	TargetPlatform   string
	PythonVersion    string
	Implementation   string
	ABIs             []string
}

func ParseInstallCommand(args []string) (InstallRequest, error) {
	req := InstallRequest{OutputFormat: OutputFormatHuman}
	seen := make(map[string]bool)
	for len(args) > 0 && strings.HasPrefix(strings.TrimSpace(args[0]), "-") {
		option := strings.TrimSpace(args[0])
		args = args[1:]
		if option == "--abi" {
			value, remaining, err := optionValue(option, args)
			if err != nil {
				return InstallRequest{}, err
			}
			req.PyPIRuntime.ABIs = append(req.PyPIRuntime.ABIs, value)
			args = remaining
			continue
		}
		if seen[option] {
			return InstallRequest{}, fmt.Errorf("sourcegate option %q cannot be repeated", option)
		}
		seen[option] = true
		switch option {
		case "--debug":
			req.Debug = true
		case "--format":
			value, remaining, err := optionValue(option, args)
			if err != nil {
				return InstallRequest{}, err
			}
			if value != OutputFormatHuman && value != OutputFormatJSON {
				return InstallRequest{}, fmt.Errorf("unsupported output format %q: supported formats are human and json", value)
			}
			req.OutputFormat = value
			args = remaining
		case "--python":
			value, remaining, err := optionValue(option, args)
			if err != nil {
				return InstallRequest{}, err
			}
			req.PyPIRuntime.PythonExecutable = value
			args = remaining
		case "--target-platform":
			value, remaining, err := optionValue(option, args)
			if err != nil {
				return InstallRequest{}, err
			}
			req.PyPIRuntime.TargetPlatform = value
			args = remaining
		case "--python-version":
			value, remaining, err := optionValue(option, args)
			if err != nil {
				return InstallRequest{}, err
			}
			req.PyPIRuntime.PythonVersion = value
			args = remaining
		case "--implementation":
			value, remaining, err := optionValue(option, args)
			if err != nil {
				return InstallRequest{}, err
			}
			req.PyPIRuntime.Implementation = value
			args = remaining
		default:
			return InstallRequest{}, fmt.Errorf("unsupported sourcegate option %q", option)
		}
	}

	if len(args) != 3 {
		return InstallRequest{}, fmt.Errorf("expected command shape: sourcegate [options] <npm|pip> install <package>")
	}

	manager := strings.ToLower(strings.TrimSpace(args[0]))
	command := strings.ToLower(strings.TrimSpace(args[1]))
	rawPackage := strings.TrimSpace(args[2])

	if command != "install" {
		return InstallRequest{}, fmt.Errorf("unsupported command %q: only install is supported", args[1])
	}
	if rawPackage == "" {
		return InstallRequest{}, fmt.Errorf("package name is required")
	}
	if strings.HasPrefix(rawPackage, "-") {
		return InstallRequest{}, fmt.Errorf("package options are not supported in version %s: %s", version.Current, rawPackage)
	}

	switch manager {
	case "npm":
		if req.hasPyPIRuntimeOptions() {
			return InstallRequest{}, fmt.Errorf("PyPI target options are only supported with pip commands")
		}
		req.Ecosystem = ecosystem.NPM
		spec, err := parseNPMPackageSpec(rawPackage)
		if err != nil {
			return InstallRequest{}, err
		}
		req.Package = spec
	case "pip":
		req.Ecosystem = ecosystem.PyPI
		spec, err := parsePyPIPackageSpec(rawPackage)
		if err != nil {
			return InstallRequest{}, err
		}
		req.Package = spec
	default:
		return InstallRequest{}, fmt.Errorf("unsupported package manager %q: supported managers are npm and pip", args[0])
	}
	req.Manager = manager
	req.Command = command
	return req, nil
}

const (
	OutputFormatHuman = "human"
	OutputFormatJSON  = "json"
)

var pypiPackageNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func parseNPMPackageSpec(value string) (ecosystem.PackageSpec, error) {
	name := value
	versionValue := ""
	if index := npmVersionSeparator(value); index >= 0 {
		name = value[:index]
		versionValue = value[index+1:]
		if versionValue == "" {
			return ecosystem.PackageSpec{}, fmt.Errorf("npm package version is required after @")
		}
		if !versioning.ValidNPMVersion(versionValue) {
			return ecosystem.PackageSpec{}, fmt.Errorf("unsupported npm version %q: only exact semantic versions are supported", versionValue)
		}
	}
	if strings.TrimSpace(name) == "" {
		return ecosystem.PackageSpec{}, fmt.Errorf("npm package name is required")
	}
	return ecosystem.PackageSpec{Name: name, Version: versionValue}, nil
}

func npmVersionSeparator(value string) int {
	index := strings.LastIndex(value, "@")
	if index <= 0 {
		return -1
	}
	if strings.HasPrefix(value, "@") && !strings.Contains(value[:index], "/") {
		return -1
	}
	return index
}

func parsePyPIPackageSpec(value string) (ecosystem.PackageSpec, error) {
	if !strings.Contains(value, "==") && strings.ContainsAny(value, "[]<>~=!,") {
		return ecosystem.PackageSpec{}, fmt.Errorf("unsupported PyPI package spec %q: only exact == versions are supported", value)
	}
	parts := strings.Split(value, "==")
	if len(parts) > 2 {
		return ecosystem.PackageSpec{}, fmt.Errorf("unsupported PyPI package spec %q: only one exact == version is supported", value)
	}
	name := strings.TrimSpace(parts[0])
	if name == "" {
		return ecosystem.PackageSpec{}, fmt.Errorf("PyPI package name is required")
	}
	if !pypiPackageNamePattern.MatchString(name) {
		return ecosystem.PackageSpec{}, fmt.Errorf("unsupported PyPI package name %q", name)
	}
	spec := ecosystem.PackageSpec{Name: name}
	if len(parts) == 2 {
		versionValue := strings.TrimSpace(parts[1])
		if versionValue == "" {
			return ecosystem.PackageSpec{}, fmt.Errorf("PyPI package version is required after ==")
		}
		if !versioning.ValidPyPIVersion(versionValue) {
			return ecosystem.PackageSpec{}, fmt.Errorf("unsupported PyPI version %q: only exact PEP 440 versions are supported", versionValue)
		}
		spec.Version = versionValue
	}
	return spec, nil
}

func optionValue(option string, args []string) (string, []string, error) {
	if len(args) == 0 || strings.HasPrefix(strings.TrimSpace(args[0]), "-") {
		return "", args, fmt.Errorf("sourcegate option %q requires a value", option)
	}
	value := strings.TrimSpace(args[0])
	if value == "" {
		return "", args, fmt.Errorf("sourcegate option %q requires a value", option)
	}
	return value, args[1:], nil
}

func (req InstallRequest) hasPyPIRuntimeOptions() bool {
	return req.PyPIRuntime.PythonExecutable != "" ||
		req.PyPIRuntime.TargetPlatform != "" ||
		req.PyPIRuntime.PythonVersion != "" ||
		req.PyPIRuntime.Implementation != "" ||
		len(req.PyPIRuntime.ABIs) > 0
}
