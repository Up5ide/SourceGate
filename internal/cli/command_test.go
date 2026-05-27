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

func TestParseInstallCommandRejectsUnsupportedShapes(t *testing.T) {
	cases := [][]string{
		{"npm", "install"},
		{"npm", "view", "lodash"},
		{"pip", "install", "-r"},
		{"cargo", "install", "ripgrep"},
	}

	for _, args := range cases {
		if _, err := ParseInstallCommand(args); err == nil {
			t.Fatalf("ParseInstallCommand(%v) returned nil error", args)
		}
	}
}
