package installer

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/sourcegate/sourcegate/internal/ecosystem"
	"github.com/sourcegate/sourcegate/internal/report"
)

const (
	DefaultTimeout = 5 * time.Minute
	maxOutputBytes = 4096
)

type Request struct {
	Ecosystem       ecosystem.Ecosystem
	Manager         string
	PackageName     string
	SelectedVersion string
}

type CommandResult struct {
	ExitCode      int
	ExitCodeKnown bool
	Stdout        string
	Stderr        string
	Err           error
	TimedOut      bool
}

type CommandFunc func(ctx context.Context, name string, args []string) CommandResult

type Runner struct {
	Timeout    time.Duration
	RunCommand CommandFunc
}

func New() Runner {
	return Runner{Timeout: DefaultTimeout}
}

func (r Runner) Install(ctx context.Context, req Request) report.InstallSummary {
	start := time.Now()
	exactSpec, err := ExactPackageSpec(req)
	summary := report.InstallSummary{
		Status:      report.InstallStatusExecutedFailed,
		Manager:     strings.TrimSpace(req.Manager),
		PackageSpec: exactSpec,
	}
	if err != nil {
		summary.Message = err.Error()
		summary.DurationMilliseconds = durationMilliseconds(start)
		return summary
	}

	name, args, err := commandFor(req.Ecosystem, exactSpec)
	if err != nil {
		summary.Message = err.Error()
		summary.DurationMilliseconds = durationMilliseconds(start)
		return summary
	}

	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	installCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runCommand := r.RunCommand
	if runCommand == nil {
		runCommand = runExecCommand
	}
	result := runCommand(installCtx, name, args)

	summary.Executed = true
	summary.DurationMilliseconds = durationMilliseconds(start)
	if result.ExitCodeKnown {
		exitCode := result.ExitCode
		summary.PackageManagerExitCode = &exitCode
	}

	if result.TimedOut || errors.Is(installCtx.Err(), context.DeadlineExceeded) {
		summary.Status = report.InstallStatusTimedOut
		summary.Message = fmt.Sprintf("package-manager install timed out after %s", timeout)
		return summary
	}
	if result.Err != nil || (result.ExitCodeKnown && result.ExitCode != 0) {
		summary.Status = report.InstallStatusExecutedFailed
		summary.Message = failureMessage(result)
		return summary
	}

	summary.Status = report.InstallStatusExecutedSuccess
	summary.Message = "package-manager install completed successfully"
	return summary
}

func ExactPackageSpec(req Request) (string, error) {
	name := strings.TrimSpace(req.PackageName)
	version := strings.TrimSpace(req.SelectedVersion)
	if name == "" {
		return "", fmt.Errorf("install package name is unavailable")
	}
	if version == "" {
		return "", fmt.Errorf("install package version is unavailable")
	}
	switch req.Ecosystem {
	case ecosystem.NPM:
		return name + "@" + version, nil
	case ecosystem.PyPI:
		return name + "==" + version, nil
	default:
		return "", fmt.Errorf("unsupported install ecosystem: %s", req.Ecosystem)
	}
}

func commandFor(ecosystemValue ecosystem.Ecosystem, exactSpec string) (string, []string, error) {
	switch ecosystemValue {
	case ecosystem.NPM:
		return "npm", []string{"install", exactSpec}, nil
	case ecosystem.PyPI:
		return "pip", []string{"install", exactSpec}, nil
	default:
		return "", nil, fmt.Errorf("unsupported install ecosystem: %s", ecosystemValue)
	}
}

func runExecCommand(ctx context.Context, name string, args []string) CommandResult {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout cappedWriter
	var stderr cappedWriter
	stdout.limit = maxOutputBytes
	stderr.limit = maxOutputBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := CommandResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Err:      err,
		TimedOut: errors.Is(ctx.Err(), context.DeadlineExceeded),
	}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
		result.ExitCodeKnown = true
	}
	return result
}

type cappedWriter struct {
	limit int
	data  []byte
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	originalLength := len(p)
	if w.limit <= 0 || len(w.data) >= w.limit {
		return originalLength, nil
	}
	remaining := w.limit - len(w.data)
	if len(p) > remaining {
		p = p[:remaining]
	}
	w.data = append(w.data, p...)
	return originalLength, nil
}

func (w *cappedWriter) String() string {
	return strings.TrimSpace(string(w.data))
}

func failureMessage(result CommandResult) string {
	if strings.TrimSpace(result.Stderr) != "" {
		return result.Stderr
	}
	if strings.TrimSpace(result.Stdout) != "" {
		return result.Stdout
	}
	if result.Err != nil {
		return result.Err.Error()
	}
	if result.ExitCodeKnown {
		return fmt.Sprintf("package manager exited with code %d", result.ExitCode)
	}
	return "package-manager install failed"
}

func durationMilliseconds(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}
