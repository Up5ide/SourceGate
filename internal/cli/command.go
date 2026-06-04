package cli

import (
	"fmt"
	"strings"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/version"
)

type InstallRequest struct {
	Ecosystem   ecosystem.Ecosystem
	Manager     string
	Command     string
	Package     string
	Debug       bool
	PyPIRuntime PyPIRuntimeOptions
}

type PyPIRuntimeOptions struct {
	PythonExecutable string
	TargetPlatform   string
	PythonVersion    string
	Implementation   string
	ABIs             []string
}

func ParseInstallCommand(args []string) (InstallRequest, error) {
	var req InstallRequest
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
	pkg := strings.TrimSpace(args[2])

	if command != "install" {
		return InstallRequest{}, fmt.Errorf("unsupported command %q: only install is supported", args[1])
	}
	if pkg == "" {
		return InstallRequest{}, fmt.Errorf("package name is required")
	}
	if strings.HasPrefix(pkg, "-") {
		return InstallRequest{}, fmt.Errorf("package options are not supported in version %s: %s", version.Current, pkg)
	}

	switch manager {
	case "npm":
		if req.hasPyPIRuntimeOptions() {
			return InstallRequest{}, fmt.Errorf("PyPI target options are only supported with pip commands")
		}
		req.Ecosystem = ecosystem.NPM
	case "pip":
		req.Ecosystem = ecosystem.PyPI
	default:
		return InstallRequest{}, fmt.Errorf("unsupported package manager %q: supported managers are npm and pip", args[0])
	}
	req.Manager = manager
	req.Command = command
	req.Package = pkg
	return req, nil
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
