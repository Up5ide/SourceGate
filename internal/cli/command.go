package cli

import (
	"fmt"
	"strings"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
)

type InstallRequest struct {
	Ecosystem ecosystem.Ecosystem
	Manager   string
	Command   string
	Package   string
}

func ParseInstallCommand(args []string) (InstallRequest, error) {
	if len(args) != 3 {
		return InstallRequest{}, fmt.Errorf("expected command shape: sourcegate <npm|pip> install <package>")
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
		return InstallRequest{}, fmt.Errorf("package options are not supported in version 0.1: %s", pkg)
	}

	switch manager {
	case "npm":
		return InstallRequest{
			Ecosystem: ecosystem.NPM,
			Manager:   manager,
			Command:   command,
			Package:   pkg,
		}, nil
	case "pip":
		return InstallRequest{
			Ecosystem: ecosystem.PyPI,
			Manager:   manager,
			Command:   command,
			Package:   pkg,
		}, nil
	default:
		return InstallRequest{}, fmt.Errorf("unsupported package manager %q: supported managers are npm and pip", args[0])
	}
}
