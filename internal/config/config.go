package config

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Config struct {
	SSHPort      int
	WhitelistIP  string
	GeoBlock     string
	Verbose      bool
	Distribution string
	PackageMgr   string
}

func New() (*Config, error) {
	cfg := &Config{
		SSHPort: 2222, // Default custom SSH port
		Verbose: false,
	}

	// Detect Linux distribution
	distro, err := detectDistribution()
	if err != nil {
		return nil, fmt.Errorf("could not detect Linux distribution: %w", err)
	}
	cfg.Distribution = distro

	// Set package manager based on distribution
	cfg.PackageMgr = getPackageManager(distro)

	return cfg, nil
}

func detectDistribution() (string, error) {
	// Try to read from /etc/os-release
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		content := string(data)
		for _, line := range strings.Split(content, "\n") {
			if strings.HasPrefix(line, "ID=") {
				return strings.TrimPrefix(line, "ID="), nil
			}
		}
	}

	// Fallback methods
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return "debian", nil
	}
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		return "rhel", nil
	}
	if _, err := os.Stat("/etc/arch-release"); err == nil {
		return "arch", nil
	}

	return "unknown", fmt.Errorf("could not determine Linux distribution")
}

func getPackageManager(distro string) string {
	switch distro {
	case "ubuntu", "debian":
		return "apt"
	case "centos", "rhel", "fedora":
		return "yum" // Use yum for compatibility (dnf for newer systems)
	case "arch":
		return "pacman"
	default:
		return "apt" // Default to apt
	}
}

func (c *Config) RunCommand(name string, args ...string) error {
	if c.Verbose {
		fmt.Printf("Running: %s %s\n", name, strings.Join(args, " "))
	}

	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command failed: %s %s: %w", name, strings.Join(args, " "), err)
	}

	return nil
}

func (c *Config) RunCommandWithOutput(name string, args ...string) (string, error) {
	if c.Verbose {
		fmt.Printf("Running: %s %s\n", name, strings.Join(args, " "))
	}

	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("command failed: %s %s: %w\nOutput: %s", name, strings.Join(args, " "), err, string(output))
	}

	return strings.TrimSpace(string(output)), nil
}

func (c *Config) InstallPackage(packages ...string) error {
	switch c.PackageMgr {
	case "apt":
		args := []string{"update"}
		if err := c.RunCommand("apt", args...); err != nil {
			return fmt.Errorf("failed to update package list: %w", err)
		}
		args = []string{"install", "-y"}
		args = append(args, packages...)
		return c.RunCommand("apt", args...)

	case "yum":
		args := []string{"install", "-y"}
		args = append(args, packages...)
		return c.RunCommand("yum", args...)

	case "pacman":
		args := []string{"-S", "--noconfirm"}
		args = append(args, packages...)
		return c.RunCommand("pacman", args...)

	default:
		return fmt.Errorf("unsupported package manager: %s", c.PackageMgr)
	}
}

func (c *Config) ServiceExists(service string) bool {
	_, err := c.RunCommandWithOutput("systemctl", "status", service)
	return err == nil
}

func (c *Config) ServiceEnabled(service string) bool {
	output, err := c.RunCommandWithOutput("systemctl", "is-enabled", service)
	return err == nil && strings.TrimSpace(output) == "enabled"
}

func (c *Config) EnableService(service string) error {
	return c.RunCommand("systemctl", "enable", "--now", service)
}

func (c *Config) RestartService(service string) error {
	return c.RunCommand("systemctl", "restart", service)
}

func (c *Config) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (c *Config) WriteFile(path, content string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		return fmt.Errorf("failed to write to file %s: %w", path, err)
	}

	return nil
}

func (c *Config) ReadFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return string(data), nil
}
