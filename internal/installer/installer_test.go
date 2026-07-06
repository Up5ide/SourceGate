package installer

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/report"
)

func TestRunnerBuildsNPMCommand(t *testing.T) {
	var gotName string
	var gotArgs []string
	runner := Runner{
		Timeout: time.Minute,
		RunCommand: func(_ context.Context, name string, args []string) CommandResult {
			gotName = name
			gotArgs = append([]string(nil), args...)
			return CommandResult{ExitCodeKnown: true, ExitCode: 0}
		},
	}

	summary := runner.Install(context.Background(), Request{
		Ecosystem:       ecosystem.NPM,
		Manager:         "npm",
		PackageName:     "lodash",
		SelectedVersion: "4.17.21",
	})

	if gotName != "npm" || !reflect.DeepEqual(gotArgs, []string{"install", "lodash@4.17.21"}) {
		t.Fatalf("command = %s %v, want npm install exact package", gotName, gotArgs)
	}
	if summary.Status != report.InstallStatusExecutedSuccess || !summary.Executed || summary.PackageManagerExitCode == nil || *summary.PackageManagerExitCode != 0 {
		t.Fatalf("summary = %+v, want successful executed install", summary)
	}
}

func TestRunnerBuildsPipCommand(t *testing.T) {
	var gotName string
	var gotArgs []string
	runner := Runner{
		Timeout: time.Minute,
		RunCommand: func(_ context.Context, name string, args []string) CommandResult {
			gotName = name
			gotArgs = append([]string(nil), args...)
			return CommandResult{ExitCodeKnown: true, ExitCode: 0}
		},
	}

	summary := runner.Install(context.Background(), Request{
		Ecosystem:       ecosystem.PyPI,
		Manager:         "pip",
		PackageName:     "requests",
		SelectedVersion: "2.34.2",
	})

	if gotName != "pip" || !reflect.DeepEqual(gotArgs, []string{"install", "requests==2.34.2"}) {
		t.Fatalf("command = %s %v, want pip install exact package", gotName, gotArgs)
	}
	if summary.Status != report.InstallStatusExecutedSuccess || summary.PackageSpec != "requests==2.34.2" {
		t.Fatalf("summary = %+v, want successful pip install summary", summary)
	}
}

func TestRunnerDoesNotInvokeShell(t *testing.T) {
	var gotName string
	runner := Runner{
		RunCommand: func(_ context.Context, name string, _ []string) CommandResult {
			gotName = strings.ToLower(name)
			return CommandResult{ExitCodeKnown: true, ExitCode: 0}
		},
	}

	_ = runner.Install(context.Background(), Request{
		Ecosystem:       ecosystem.NPM,
		Manager:         "npm",
		PackageName:     "left-pad",
		SelectedVersion: "1.3.0",
	})

	for _, shellName := range []string{"cmd", "powershell", "sh", "bash"} {
		if gotName == shellName {
			t.Fatalf("runner invoked shell %q", gotName)
		}
	}
	if gotName != "npm" {
		t.Fatalf("runner invoked %q, want npm directly", gotName)
	}
}

func TestRunnerReportsFailedInstall(t *testing.T) {
	runner := Runner{
		RunCommand: func(_ context.Context, _ string, _ []string) CommandResult {
			return CommandResult{
				ExitCodeKnown: true,
				ExitCode:      1,
				Stderr:        "install failed",
				Err:           errors.New("exit status 1"),
			}
		},
	}

	summary := runner.Install(context.Background(), Request{
		Ecosystem:       ecosystem.NPM,
		Manager:         "npm",
		PackageName:     "pkg",
		SelectedVersion: "1.0.0",
	})

	if summary.Status != report.InstallStatusExecutedFailed || !summary.Executed || summary.PackageManagerExitCode == nil || *summary.PackageManagerExitCode != 1 || summary.Message != "install failed" {
		t.Fatalf("summary = %+v, want failed install summary", summary)
	}
}

func TestRunnerReportsTimedOutInstall(t *testing.T) {
	runner := Runner{
		Timeout: time.Second,
		RunCommand: func(_ context.Context, _ string, _ []string) CommandResult {
			return CommandResult{Err: context.DeadlineExceeded, TimedOut: true}
		},
	}

	summary := runner.Install(context.Background(), Request{
		Ecosystem:       ecosystem.PyPI,
		Manager:         "pip",
		PackageName:     "pkg",
		SelectedVersion: "1.0.0",
	})

	if summary.Status != report.InstallStatusTimedOut || !summary.Executed || !strings.Contains(summary.Message, "timed out") {
		t.Fatalf("summary = %+v, want timed out install summary", summary)
	}
}
