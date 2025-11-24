package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// CommandExecutor handles system command execution with safety
type CommandExecutor struct {
	verbose     bool
	timeout     time.Duration
	dryRun      bool
	environment []string
}

func NewCommandExecutor(verbose, dryRun bool) *CommandExecutor {
	return &CommandExecutor{
		verbose:     verbose,
		timeout:     30 * time.Second,
		dryRun:      dryRun,
		environment: os.Environ(),
	}
}

// SetTimeout sets command execution timeout
func (ce *CommandExecutor) SetTimeout(timeout time.Duration) {
	ce.timeout = timeout
}

// SetEnvironment sets custom environment variables
func (ce *CommandExecutor) SetEnvironment(env []string) {
	ce.environment = env
}

// IsDryRun returns true if the executor is in dry-run mode
func (ce *CommandExecutor) IsDryRun() bool {
	return ce.dryRun
}

// RunCommand executes a system command with proper error handling
func (ce *CommandExecutor) RunCommand(name string, args ...string) error {
	if ce.dryRun {
		fmt.Printf("[DRY-RUN] Would execute: %s %s\n", name, strings.Join(args, " "))
		return nil
	}

	if ce.verbose {
		fmt.Printf("Running: %s %s\n", name, strings.Join(args, " "))
	}

	cmd := exec.Command(name, args...)
	cmd.Env = ce.environment
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Set timeout
	if ce.timeout > 0 {
		timer := time.AfterFunc(ce.timeout, func() {
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
		})
		defer timer.Stop()
	}

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return fmt.Errorf("command failed with exit code %d: %s", status.ExitStatus(), err.Error())
			}
		}
		return fmt.Errorf("command failed: %s %s: %w", name, strings.Join(args, " "), err)
	}

	return nil
}

// RunCommandWithOutput executes a command and returns output
func (ce *CommandExecutor) RunCommandWithOutput(name string, args ...string) (string, error) {
	if ce.dryRun {
		fmt.Printf("[DRY-RUN] Would execute: %s %s\n", name, strings.Join(args, " "))
		return "", nil
	}

	if ce.verbose {
		fmt.Printf("Running: %s %s\n", name, strings.Join(args, " "))
	}

	cmd := exec.Command(name, args...)
	cmd.Env = ce.environment

	// Set timeout
	if ce.timeout > 0 {
		timer := time.AfterFunc(ce.timeout, func() {
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
		})
		defer timer.Stop()
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return "", fmt.Errorf("command failed with exit code %d: %s\nOutput: %s", status.ExitStatus(), err.Error(), string(output))
			}
		}
		return "", fmt.Errorf("command failed: %s %s: %w\nOutput: %s", name, strings.Join(args, " "), err, string(output))
	}

	return strings.TrimSpace(string(output)), nil
}

// CommandExists checks if a command is available in PATH
func CommandExists(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

// IsRoot checks if running as root
func IsRoot() bool {
	return os.Geteuid() == 0
}

// ValidatePort checks if a port is valid and available
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", port)
	}

	// Check if port is in use
	cmd := exec.Command("ss", "-tlnp")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to check port usage: %w", err)
	}

	if strings.Contains(string(output), fmt.Sprintf(":%d ", port)) {
		return fmt.Errorf("port %d is already in use", port)
	}

	return nil
}

// GetServiceStatus returns the status of a system service
func GetServiceStatus(service string) (string, error) {
	cmd := exec.Command("systemctl", "is-active", service)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "inactive", nil
	}
	return strings.TrimSpace(string(output)), nil
}

// IsServiceEnabled checks if a service is enabled
func IsServiceEnabled(service string) (bool, error) {
	cmd := exec.Command("systemctl", "is-enabled", service)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.TrimSpace(string(output)) == "enabled", nil
}

// WaitForService waits for a service to be in a specific state
func WaitForService(service, state string, timeout time.Duration) error {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	timeoutChan := time.After(timeout)

	for {
		select {
		case <-timeoutChan:
			return fmt.Errorf("timeout waiting for service %s to be %s", service, state)
		case <-ticker.C:
			status, err := GetServiceStatus(service)
			if err == nil && status == state {
				return nil
			}
		}
	}
}
