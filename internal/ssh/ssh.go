package ssh

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"server-config/internal/config"
)

const (
	sshConfigPath = "/etc/ssh/sshd_config"
	sshService    = "ssh"
)

func InstallAndConfigure(cfg *config.Config) error {
	fmt.Println("Installing SSH packages...")
	if err := installSSHPackages(cfg); err != nil {
		return fmt.Errorf("failed to install SSH packages: %w", err)
	}

	fmt.Println("Configuring SSH daemon...")
	if err := configureSSH(cfg); err != nil {
		return fmt.Errorf("failed to configure SSH: %w", err)
	}

	fmt.Println("Setting up SSH keys...")
	if err := setupSSHKeys(cfg); err != nil {
		return fmt.Errorf("failed to setup SSH keys: %w", err)
	}

	fmt.Println("Restarting SSH service...")
	if err := cfg.RestartService(sshService); err != nil {
		return fmt.Errorf("failed to restart SSH service: %w", err)
	}

	return nil
}

func installSSHPackages(cfg *config.Config) error {
	packages := []string{"openssh-server", "openssh-client"}

	if !cfg.ServiceExists(sshService) {
		if err := cfg.InstallPackage(packages...); err != nil {
			return fmt.Errorf("failed to install SSH packages: %w", err)
		}
	}

	return nil
}

func configureSSH(cfg *config.Config) error {
	// Backup original configuration
	if err := backupSSHConfig(cfg); err != nil {
		return fmt.Errorf("failed to backup SSH config: %w", err)
	}

	// Read current configuration
	currentConfig, err := cfg.ReadFile(sshConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH config: %w", err)
	}

	// Create new hardened configuration
	newConfig := generateHardenedSSHConfig(cfg, currentConfig)

	// Write new configuration
	if err := cfg.WriteFile(sshConfigPath, newConfig); err != nil {
		return fmt.Errorf("failed to write SSH config: %w", err)
	}

	// Set proper permissions
	if err := cfg.RunCommand("chmod", "600", sshConfigPath); err != nil {
		return fmt.Errorf("failed to set SSH config permissions: %w", err)
	}

	return nil
}

func backupSSHConfig(cfg *config.Config) error {
	backupDir := "/etc/server-config-backup"
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return err
	}

	backupPath := filepath.Join(backupDir, "sshd_config.original")
	if !cfg.FileExists(backupPath) {
		if err := cfg.RunCommand("cp", sshConfigPath, backupPath); err != nil {
			return fmt.Errorf("failed to backup SSH config: %w", err)
		}
	}

	return nil
}

func generateHardenedSSHConfig(cfg *config.Config, currentConfig string) string {
	lines := strings.Split(currentConfig, "\n")
	var newLines []string

	// Configuration map with values
	configMap := map[string]string{
		"Port":                            strconv.Itoa(cfg.SSHPort),
		"Protocol":                        "2",
		"PermitRootLogin":                 "no",
		"PasswordAuthentication":          "no",
		"PermitEmptyPasswords":            "no",
		"ChallengeResponseAuthentication": "no",
		"PubkeyAuthentication":            "yes",
		"AuthorizedKeysFile":              ".ssh/authorized_keys",
		"UsePAM":                          "yes",
		"X11Forwarding":                   "no",
		"PrintMotd":                       "no",
		"PrintLastLog":                    "yes",
		"TCPKeepAlive":                    "yes",
		"UsePrivilegeSeparation":          "yes",
		"Subsystem":                       "sftp /usr/lib/openssh/sftp-server",
		"ClientAliveInterval":             "300",
		"ClientAliveCountMax":             "2",
		"MaxAuthTries":                    "3",
		"LoginGraceTime":                  "30",
		"MaxStartups":                     "10:30:60",
		"Banner":                          "/etc/ssh/banner",
		"IgnoreRhosts":                    "yes",
		"HostbasedAuthentication":         "no",
		"PermitUserEnvironment":           "no",
	}

	// Additional security options for specific configurations
	if cfg.SSHPort != 22 {
		configMap["Port"] = strconv.Itoa(cfg.SSHPort)
	}

	// Process existing configuration
	processedKeys := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			newLines = append(newLines, line)
			continue
		}

		// Parse key-value pairs
		if parts := strings.Fields(line); len(parts) >= 2 {
			key := parts[0]
			if newValue, exists := configMap[key]; exists {
				newLines = append(newLines, fmt.Sprintf("%s %s", key, newValue))
				processedKeys[key] = true
				delete(configMap, key)
			} else {
				newLines = append(newLines, line)
			}
		}
	}

	// Add new configurations that weren't in the original file
	for key, value := range configMap {
		newLines = append(newLines, fmt.Sprintf("%s %s", key, value))
	}

	return strings.Join(newLines, "\n")
}

func setupSSHKeys(cfg *config.Config) error {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create SSH directory: %w", err)
	}

	// Generate SSH key pair if it doesn't exist
	keyPath := filepath.Join(sshDir, "id_ed25519")
	publicKeyPath := keyPath + ".pub"

	if !cfg.FileExists(keyPath) {
		fmt.Println("Generating new SSH key pair...")
		if err := cfg.RunCommand("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", "server-config-key"); err != nil {
			return fmt.Errorf("failed to generate SSH key pair: %w", err)
		}
	}

	// Ensure proper permissions
	if err := cfg.RunCommand("chmod", "600", keyPath); err != nil {
		return fmt.Errorf("failed to set private key permissions: %w", err)
	}
	if err := cfg.RunCommand("chmod", "644", publicKeyPath); err != nil {
		return fmt.Errorf("failed to set public key permissions: %w", err)
	}

	// Add public key to authorized_keys
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	publicKey, err := cfg.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}

	// Read existing authorized keys
	var authorizedKeys string
	if cfg.FileExists(authorizedKeysPath) {
		authorizedKeys, err = cfg.ReadFile(authorizedKeysPath)
		if err != nil {
			return fmt.Errorf("failed to read authorized keys: %w", err)
		}
	}

	// Add new key if not already present
	if !strings.Contains(authorizedKeys, publicKey) {
		authorizedKeys += publicKey + "\n"
		if err := cfg.WriteFile(authorizedKeysPath, authorizedKeys); err != nil {
			return fmt.Errorf("failed to write authorized keys: %w", err)
		}
	}

	// Set proper permissions for authorized_keys
	if err := cfg.RunCommand("chmod", "600", authorizedKeysPath); err != nil {
		return fmt.Errorf("failed to set authorized keys permissions: %w", err)
	}

	// Create SSH banner
	bannerPath := "/etc/ssh/banner"
	bannerContent := `***************************************************************************
                            AUTHORIZED ACCESS ONLY
***************************************************************************

This system is for authorized users only. Individual use of this system
and/or network without authority from the system owner is strictly
prohibited. Unauthorized access is a violation of state and federal,
civil and criminal laws.

***************************************************************************
`
	if err := cfg.WriteFile(bannerPath, bannerContent); err != nil {
		return fmt.Errorf("failed to create SSH banner: %w", err)
	}

	return nil
}

func ValidateConfiguration(cfg *config.Config) error {
	fmt.Println("Validating SSH configuration...")

	// Check if SSH service is running
	if !cfg.ServiceExists(sshService) {
		return fmt.Errorf("SSH service is not installed")
	}

	// Check if SSH is configured to use the custom port
	configContent, err := cfg.ReadFile(sshConfigPath)
	if err != nil {
		return fmt.Errorf("could not read SSH configuration: %w", err)
	}

	if !strings.Contains(configContent, fmt.Sprintf("Port %d", cfg.SSHPort)) {
		return fmt.Errorf("SSH is not configured to use port %d", cfg.SSHPort)
	}

	// Check security configurations
	securityConfigs := []string{
		"PermitRootLogin no",
		"PasswordAuthentication no",
		"PubkeyAuthentication yes",
	}

	for _, config := range securityConfigs {
		if !strings.Contains(configContent, config) {
			return fmt.Errorf("SSH security configuration missing: %s", config)
		}
	}

	// Check if SSH keys exist
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}

	keyPath := filepath.Join(homeDir, ".ssh", "id_ed25519")
	if !cfg.FileExists(keyPath) {
		return fmt.Errorf("SSH private key not found at %s", keyPath)
	}

	fmt.Printf("✓ SSH is properly configured on port %d\n", cfg.SSHPort)
	fmt.Println("✓ SSH security hardening is applied")
	fmt.Println("✓ SSH key pair is configured")

	return nil
}
