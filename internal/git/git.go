package git

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"server-config/internal/config"
)

func InstallAndConfigure(cfg *config.Config) error {
	fmt.Println("Configuring Git with SSH key authentication...")

	// Install Git if not already installed
	if err := installGit(cfg); err != nil {
		return fmt.Errorf("failed to install Git: %w", err)
	}

	// Configure Git global settings
	if err := configureGitSettings(cfg); err != nil {
		return fmt.Errorf("failed to configure Git settings: %w", err)
	}

	// Generate SSH keys for Git operations
	if err := setupGitSSHKeys(cfg); err != nil {
		return fmt.Errorf("failed to setup Git SSH keys: %w", err)
	}

	// Configure SSH for Git operations
	if err := configureSSHForGit(cfg); err != nil {
		return fmt.Errorf("failed to configure SSH for Git: %w", err)
	}

	// Set up Git SSH configuration
	if err := setupGitSSHConfig(cfg); err != nil {
		return fmt.Errorf("failed to setup Git SSH configuration: %w", err)
	}

	fmt.Println("✓ Git configured with SSH key authentication")
	return nil
}

func installGit(cfg *config.Config) error {
	// Check if Git is already installed
	if _, err := cfg.RunCommandWithOutput("git", "--version"); err == nil {
		fmt.Println("Git is already installed")
		return nil
	}

	fmt.Println("Installing Git...")
	return cfg.InstallPackage("git")
}

func configureGitSettings(cfg *config.Config) error {
	fmt.Println("Configuring Git global settings...")

	// Get user information for Git configuration
	username := getUsernameFromUser()
	email := getEmailFromUser()

	// Set Git user name
	if err := cfg.RunCommand("git", "config", "--global", "user.name", username); err != nil {
		return fmt.Errorf("failed to set Git user name: %w", err)
	}

	// Set Git user email
	if err := cfg.RunCommand("git", "config", "--global", "user.email", email); err != nil {
		return fmt.Errorf("failed to set Git user email: %w", err)
	}

	// Configure Git to use SSH
	if err := cfg.RunCommand("git", "config", "--global", "core.sshCommand", "ssh -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes"); err != nil {
		return fmt.Errorf("failed to configure Git SSH command: %w", err)
	}

	// Set default branch name to main
	if err := cfg.RunCommand("git", "config", "--global", "init.defaultBranch", "main"); err != nil {
		return fmt.Errorf("failed to set default branch: %w", err)
	}

	// Configure Git to always rebase when pulling
	if err := cfg.RunCommand("git", "config", "--global", "pull.rebase", "true"); err != nil {
		return fmt.Errorf("failed to configure pull rebase: %w", err)
	}

	// Configure GPG signing if desired
	if configureGPG() {
		if err := configureGPGSigning(cfg); err != nil {
			return fmt.Errorf("failed to configure GPG signing: %w", err)
		}
	}

	return nil
}

func setupGitSSHKeys(cfg *config.Config) error {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}

	gitSSHDir := filepath.Join(homeDir, ".ssh", "git")
	if err := os.MkdirAll(gitSSHDir, 0700); err != nil {
		return fmt.Errorf("failed to create Git SSH directory: %w", err)
	}

	// Generate dedicated SSH key for Git operations
	gitKeyPath := filepath.Join(gitSSHDir, "id_ed25519_git")
	gitPublicKeyPath := gitKeyPath + ".pub"

	if !cfg.FileExists(gitKeyPath) {
		fmt.Println("Generating SSH key pair for Git operations...")

		// Generate Ed25519 key pair using system command
		if err := generateSSHKeyPairSystem(cfg, gitKeyPath); err != nil {
			return fmt.Errorf("failed to generate Git SSH key pair: %w", err)
		}
	}

	// Set proper permissions
	if err := cfg.RunCommand("chmod", "600", gitKeyPath); err != nil {
		return fmt.Errorf("failed to set Git private key permissions: %w", err)
	}
	if err := cfg.RunCommand("chmod", "644", gitPublicKeyPath); err != nil {
		return fmt.Errorf("failed to set Git public key permissions: %w", err)
	}

	// Display public key for user to add to Git providers
	publicKey, err := cfg.ReadFile(gitPublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read Git public key: %w", err)
	}

	fmt.Println("\n" + "="*60)
	fmt.Println("GIT SSH PUBLIC KEY")
	fmt.Println("=" * 60)
	fmt.Printf("Add this SSH key to your Git providers (GitHub, GitLab, etc.):\n\n")
	fmt.Println(publicKey)
	fmt.Println("=" * 60)
	fmt.Println("\nInstructions:")
	fmt.Println("1. Copy the public key above")
	fmt.Println("2. Go to your Git provider's SSH keys settings")
	fmt.Println("3. Add the new SSH key")
	fmt.Println("4. Test your connection with: ssh -T git@github.com")
	fmt.Println()

	return nil
}

func generateSSHKeyPairSystem(cfg *config.Config, keyPath string) error {
	// Use system ssh-keygen command to generate Ed25519 key
	return cfg.RunCommand("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", "git@server-config")
}

func configureSSHForGit(cfg *config.Config) error {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}

	sshConfigPath := filepath.Join(homeDir, ".ssh", "config")

	// Create SSH config for Git operations
	sshConfig := `# Git SSH Configuration
# Generated by server-config

# GitHub configuration
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/git/id_ed25519_git
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    PreferredAuthentications publickey

# GitLab configuration
Host gitlab.com
    HostName gitlab.com
    User git
    IdentityFile ~/.ssh/git/id_ed25519_git
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    PreferredAuthentications publickey

# Bitbucket configuration
Host bitbucket.org
    HostName bitbucket.org
    User git
    IdentityFile ~/.ssh/git/id_ed25519_git
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    PreferredAuthentications publickey

# Custom Git servers (add more as needed)
Host *
    IdentityFile ~/.ssh/git/id_ed25519_git
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    PreferredAuthentications publickey
`

	// Read existing SSH config if it exists
	var existingConfig string
	if cfg.FileExists(sshConfigPath) {
		existingConfig, err := cfg.ReadFile(sshConfigPath)
		if err != nil {
			return fmt.Errorf("failed to read existing SSH config: %w", err)
		}
	}

	// Append our Git configuration if it doesn't already exist
	if !strings.Contains(existingConfig, "# Git SSH Configuration") {
		fullConfig := existingConfig + "\n" + sshConfig
		if err := cfg.WriteFile(sshConfigPath, fullConfig); err != nil {
			return fmt.Errorf("failed to write SSH config: %w", err)
		}
	}

	// Set proper permissions
	if err := cfg.RunCommand("chmod", "600", sshConfigPath); err != nil {
		return fmt.Errorf("failed to set SSH config permissions: %w", err)
	}

	return nil
}

func setupGitSSHConfig(cfg *config.Config) error {
	fmt.Println("Setting up Git SSH configuration...")

	// Configure Git to use SSH by default for GitHub, GitLab, etc.
	gitRemotes := map[string]string{
		"github.com":    "git@github.com:",
		"gitlab.com":    "git@gitlab.com:",
		"bitbucket.org": "git@bitbucket.org:",
	}

	for domain, prefix := range gitRemotes {
		if err := cfg.RunCommand("git", "config", "--global", fmt.Sprintf("url.%s.insteadOf", prefix), fmt.Sprintf("https://%s/", domain)); err != nil {
			return fmt.Errorf("failed to configure Git URL rewriting for %s: %w", domain, err)
		}
	}

	return nil
}

func configureGPGSigning(cfg *config.Config) error {
	fmt.Println("Configuring GPG for commit signing...")

	// Install GPG if not already installed
	if err := cfg.InstallPackage("gnupg", "gnupg2"); err != nil {
		return fmt.Errorf("failed to install GPG: %w", err)
	}

	// Generate GPG key if one doesn't exist
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}

	gpgDir := filepath.Join(homeDir, ".gnupg")
	if err := os.MkdirAll(gpgDir, 0700); err != nil {
		return fmt.Errorf("failed to create GPG directory: %w", err)
	}

	// Check if GPG key already exists
	output, err := cfg.RunCommandWithOutput("gpg", "--list-secret-keys", "--keyid-format", "long")
	if err != nil || !strings.Contains(output, "sec") {
		fmt.Println("Generating GPG key for commit signing...")
		// Generate GPG key with default settings
		if err := cfg.RunCommand("gpg", "--batch", "--gen-key", `/usr/share/doc/git/contrib/workdir/gpg-signkey.template`); err != nil {
			return fmt.Errorf("failed to generate GPG key: %w", err)
		}
	}

	// Get the GPG key ID
	output, err = cfg.RunCommandWithOutput("gpg", "--list-secret-keys", "--keyid-format", "long")
	if err != nil {
		return fmt.Errorf("failed to list GPG keys: %w", err)
	}

	// Extract key ID (simplified extraction)
	lines := strings.Split(output, "\n")
	var keyID string
	for _, line := range lines {
		if strings.Contains(line, "sec") && strings.Contains(line, "RSA") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "RSA" && i+1 < len(parts) {
					keyID = parts[i+1]
					break
				}
			}
		}
	}

	if keyID != "" {
		// Configure Git to use this GPG key
		if err := cfg.RunCommand("git", "config", "--global", "user.signingkey", keyID); err != nil {
			return fmt.Errorf("failed to set GPG signing key: %w", err)
		}

		// Enable commit signing by default
		if err := cfg.RunCommand("git", "config", "--global", "commit.gpgsign", "true"); err != nil {
			return fmt.Errorf("failed to enable GPG signing: %w", err)
		}

		fmt.Printf("✓ GPG key configured for commit signing: %s\n", keyID)
	}

	return nil
}

func getUsernameFromUser() string {
	// Try to get username from environment or use default
	if username := os.Getenv("GIT_USER_NAME"); username != "" {
		return username
	}
	if username := os.Getenv("USER"); username != "" {
		return username
	}
	return "Server Admin"
}

func getEmailFromUser() string {
	// Try to get email from environment or construct default
	if email := os.Getenv("GIT_USER_EMAIL"); email != "" {
		return email
	}
	hostname, _ := os.Hostname()
	username := getUsernameFromUser()
	return fmt.Sprintf("%s@%s.local", strings.ToLower(strings.ReplaceAll(username, " ", ".")), hostname)
}

func configureGPG() bool {
	// Check environment variable or default to true for servers
	if gpg := os.Getenv("GIT_CONFIGURE_GPG"); gpg != "" {
		return gpg == "true" || gpg == "1"
	}
	return true // Default to enabling GPG for security
}
