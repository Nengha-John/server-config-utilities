package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"server-config/internal/config"
	"server-config/internal/fail2ban"
	"server-config/internal/firewall"
	"server-config/internal/ssh"
	"server-config/internal/utils"
	"server-config/internal/validation"
)

var (
	sshPort        = flag.Int("ssh-port", 2222, "Custom SSH port")
	whitelistIP    = flag.String("whitelist-ip", "", "IP to whitelist for SSH")
	geoBlock       = flag.String("geo-block", "", "Comma-separated country codes to block")
	fail2banOnly   = flag.Bool("fail2ban", false, "Install and configure only Fail2Ban")
	firewallOnly   = flag.Bool("firewall", false, "Install and configure only firewall")
	sshOnly        = flag.Bool("ssh-only", false, "Install and configure only SSH")
	backupConfig   = flag.Bool("backup", false, "Backup current configurations")
	rollbackConfig = flag.Bool("rollback", false, "Rollback to backup")
	validateConfig = flag.Bool("validate", false, "Validate current security posture")
	verbose        = flag.Bool("verbose", false, "Verbose output")
	dryRun         = flag.Bool("dry-run", false, "Show what would be done without making changes")
	force          = flag.Bool("force", false, "Skip safety warnings and proceed")
)

func main() {
	flag.Parse()

	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	// Setup signal handling for graceful shutdown
	ctx, cancel := setupSignalHandling()
	defer cancel()

	// Initialize configuration
	cfg, err := config.New()
	if err != nil {
		log.Fatalf("Failed to initialize configuration: %v", err)
	}

	// Override with command line flags and validate inputs
	cfg.SSHPort = *sshPort
	cfg.WhitelistIP = sanitizeInput(*whitelistIP)
	cfg.GeoBlock = sanitizeInput(*geoBlock)
	cfg.Verbose = *verbose

	// Validate inputs
	if err := utils.ValidatePort(cfg.SSHPort); err != nil {
		log.Fatalf("Invalid SSH port: %v", err)
	}

	if err := validateIPList(cfg.WhitelistIP); err != nil {
		log.Fatalf("Invalid whitelist IP: %v", err)
	}

	if err := validateCountryCodes(cfg.GeoBlock); err != nil {
		log.Fatalf("Invalid country codes: %v", err)
	}

	// Initialize command executor
	cmdExecutor := utils.NewCommandExecutor(*verbose, *dryRun)

	// Create backup directory (skip in dry-run mode)
	backupDir := "/etc/server-config-backup"
	if !*dryRun {
		if err := ensureDirectory(backupDir, 0755); err != nil {
			log.Fatalf("Failed to create backup directory: %v", err)
		}
	}

	// Ensure we're running as root
	if os.Geteuid() != 0 && !*dryRun {
		log.Fatal("This program must be run as root for system configuration changes")
	}

	// Initialize validator
	validator := validation.NewValidator(cfg)

	// Perform pre-flight validation
	if !*force && !*dryRun {
		if err := validator.ValidatePreConditions(); err != nil {
			log.Fatalf("Pre-flight validation failed: %v\nUse --force to skip safety checks", err)
		}
	}

	switch {
	case *backupConfig:
		if err := createBackup(ctx, backupDir, cmdExecutor); err != nil {
			log.Fatalf("Backup failed: %v", err)
		}
		fmt.Println("✓ Configuration backed up successfully")

	case *rollbackConfig:
		if err := rollbackFromBackup(ctx, backupDir, cmdExecutor); err != nil {
			log.Fatalf("Rollback failed: %v", err)
		}
		fmt.Println("✓ Configuration rolled back successfully")

	case *validateConfig:
		if err := validateSecurity(ctx, cfg, validator, cmdExecutor); err != nil {
			log.Fatalf("Validation failed: %v", err)
		}
		fmt.Println("✓ Security configuration is valid")

	case *fail2banOnly:
		if err := atomicOperation(ctx, "fail2ban", cfg, backupDir, validator, cmdExecutor, func() error {
			return fail2ban.InstallAndConfigure(cfg)
		}); err != nil {
			log.Fatalf("Fail2Ban configuration failed: %v", err)
		}
		fmt.Println("✓ Fail2Ban configured successfully")

	case *firewallOnly:
		if err := atomicOperation(ctx, "firewall", cfg, backupDir, validator, cmdExecutor, func() error {
			return firewall.InstallAndConfigure(cfg)
		}); err != nil {
			log.Fatalf("Firewall configuration failed: %v", err)
		}
		fmt.Println("✓ Firewall configured successfully")

	case *sshOnly:
		if err := atomicOperation(ctx, "ssh", cfg, backupDir, validator, cmdExecutor, func() error {
			return ssh.InstallAndConfigure(cfg)
		}); err != nil {
			log.Fatalf("SSH configuration failed: %v", err)
		}
		fmt.Println("✓ SSH configured successfully")

	default:
		// Full installation with atomic operations
		fmt.Println("Starting comprehensive server security configuration...")

		if err := fullInstallation(ctx, cfg, backupDir, validator, cmdExecutor); err != nil {
			log.Fatalf("Full installation failed: %v", err)
		}

		fmt.Println("✓ Server security configuration completed successfully")
		printSecuritySummary(cfg)
	}
}

// setupSignalHandling sets up context and signal handling for graceful shutdown
func setupSignalHandling() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, initiating graceful shutdown...", sig)
		cancel()
	}()

	return ctx, cancel
}

// ensureDirectory creates a directory with proper permissions
func ensureDirectory(path string, perm os.FileMode) error {
	if err := os.MkdirAll(path, perm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}
	return nil
}

// atomicOperation performs an operation with backup and rollback capability
func atomicOperation(ctx context.Context, operationName string, cfg *config.Config, backupDir string, validator *validation.Validator, cmdExecutor *utils.CommandExecutor, operation func() error) error {
	// Create timestamped backup
	timestamp := time.Now().Format("20060102-150405")
	operationBackupDir := filepath.Join(backupDir, operationName+"-"+timestamp)

	if err := createBackup(ctx, operationBackupDir, cmdExecutor); err != nil {
		return fmt.Errorf("failed to create backup for %s: %w", operationName, err)
	}

	// Perform the operation
	if err := operation(); err != nil {
		// Rollback on failure
		log.Printf("Operation %s failed, attempting rollback...", operationName)
		if rollbackErr := rollbackOperation(ctx, operationBackupDir, cmdExecutor); rollbackErr != nil {
			return fmt.Errorf("operation failed: %v, rollback also failed: %w", err, rollbackErr)
		}
		return fmt.Errorf("operation failed: %v (rollback completed)", err)
	}

	// Validate post-conditions
	if err := validator.ValidatePostConditions(); err != nil {
		log.Printf("Post-validation failed for %s, attempting rollback...", operationName)
		if rollbackErr := rollbackOperation(ctx, operationBackupDir, cmdExecutor); rollbackErr != nil {
			return fmt.Errorf("post-validation failed: %v, rollback also failed: %w", err, rollbackErr)
		}
		return fmt.Errorf("post-validation failed: %v (rollback completed)", err)
	}

	fmt.Printf("  ✓ %s operation completed and validated\n", strings.Title(operationName))
	return nil
}

// fullInstallation performs complete security setup with atomic operations
func fullInstallation(ctx context.Context, cfg *config.Config, backupDir string, validator *validation.Validator, cmdExecutor *utils.CommandExecutor) error {
	// Create full backup before starting
	timestamp := time.Now().Format("20060102-150405")
	fullBackupDir := filepath.Join(backupDir, "full-"+timestamp)

	if err := createBackup(ctx, fullBackupDir, cmdExecutor); err != nil {
		return fmt.Errorf("failed to create full backup: %w", err)
	}

	operations := []struct {
		name string
		fn   func() error
	}{
		{"ssh", func() error { return ssh.InstallAndConfigure(cfg) }},
		{"fail2ban", func() error { return fail2ban.InstallAndConfigure(cfg) }},
		{"firewall", func() error { return firewall.InstallAndConfigure(cfg) }},
	}

	for i, op := range operations {
		select {
		case <-ctx.Done():
			return fmt.Errorf("operation cancelled by user")
		default:
			fmt.Printf("%d. Configuring %s...\n", i+1, strings.Title(op.name))

			if err := atomicOperation(ctx, op.name, cfg, backupDir, validator, cmdExecutor, op.fn); err != nil {
				return fmt.Errorf("%s setup failed: %w", strings.Title(op.name), err)
			}
		}
	}

	// Final comprehensive validation
	if err := validator.ValidatePostConditions(); err != nil {
		return fmt.Errorf("final validation failed: %w", err)
	}

	return nil
}

// createBackup creates a backup of configuration files
func createBackup(ctx context.Context, backupDir string, cmdExecutor *utils.CommandExecutor) error {
	fmt.Println("Creating configuration backups...")

	// Skip backup in dry-run mode
	if cmdExecutor != nil && cmdExecutor.IsDryRun() {
		fmt.Println("  [DRY-RUN] Would create configuration backups")
		return nil
	}

	configs := []struct {
		src  string
		desc string
	}{
		{"/etc/ssh/sshd_config", "SSH configuration"},
		{"/etc/fail2ban/jail.local", "Fail2Ban local configuration"},
		{"/etc/fail2ban/jail.conf", "Fail2Ban main configuration"},
		{"/etc/ufw/user.rules", "UFW user rules"},
		{"/etc/iptables/rules.v4", "iptables rules"},
		{"/etc/sysctl.conf", "System kernel parameters"},
	}

	for _, config := range configs {
		select {
		case <-ctx.Done():
			return fmt.Errorf("backup cancelled by user")
		default:
			if _, err := os.Stat(config.src); err == nil {
				backupPath := filepath.Join(backupDir, filepath.Base(config.src))

				if err := copyFileSafe(config.src, backupPath); err != nil {
					log.Printf("Warning: Could not backup %s: %v", config.desc, err)
				} else {
					fmt.Printf("  ✓ Backed up %s\n", config.desc)
				}
			}
		}
	}

	return nil
}

// rollbackFromBackup restores configuration from backup
func rollbackFromBackup(ctx context.Context, backupDir string, cmdExecutor *utils.CommandExecutor) error {
	fmt.Println("Rolling back configuration from backup...")

	// Skip rollback in dry-run mode
	if cmdExecutor != nil && cmdExecutor.IsDryRun() {
		fmt.Println("  [DRY-RUN] Would rollback configuration from backup")
		return nil
	}

	configs := []struct {
		backupFile string
		targetFile string
		service    string
	}{
		{"sshd_config", "/etc/ssh/sshd_config", "ssh"},
		{"jail.local", "/etc/fail2ban/jail.local", "fail2ban"},
		{"jail.conf", "/etc/fail2ban/jail.conf", "fail2ban"},
		{"user.rules", "/etc/ufw/user.rules", "ufw"},
		{"rules.v4", "/etc/iptables/rules.v4", "iptables"},
	}

	restartedServices := make(map[string]bool)

	for _, config := range configs {
		select {
		case <-ctx.Done():
			return fmt.Errorf("rollback cancelled by user")
		default:
			backupPath := filepath.Join(backupDir, config.backupFile)

			if _, err := os.Stat(backupPath); err == nil {
				if err := copyFileSafe(backupPath, config.targetFile); err != nil {
					log.Printf("Warning: Could not restore %s: %v", config.targetFile, err)
					continue
				}

				fmt.Printf("  ✓ Restored %s\n", config.targetFile)

				// Mark service for restart (avoid duplicates)
				if config.service != "" && !restartedServices[config.service] {
					restartedServices[config.service] = true
				}
			} else {
				log.Printf("Warning: Backup file not found: %s", backupPath)
			}
		}
	}

	// Restart services
	for service := range restartedServices {
		select {
		case <-ctx.Done():
			return fmt.Errorf("service restart cancelled by user")
		default:
			if err := cmdExecutor.RunCommand("systemctl", "restart", service); err != nil {
				log.Printf("Warning: Could not restart %s: %v", service, err)
			} else {
				fmt.Printf("  ✓ Restarted %s service\n", service)
			}
		}
	}

	return nil
}

// rollbackOperation performs rollback for a specific operation
func rollbackOperation(ctx context.Context, backupDir string, cmdExecutor *utils.CommandExecutor) error {
	return rollbackFromBackup(ctx, backupDir, cmdExecutor)
}

// validateSecurity performs comprehensive security validation
func validateSecurity(ctx context.Context, cfg *config.Config, validator *validation.Validator, cmdExecutor *utils.CommandExecutor) error {
	fmt.Println("Validating security configuration...")

	validations := []struct {
		name string
		fn   func() error
	}{
		{"SSH configuration", func() error { return ssh.ValidateConfiguration(cfg) }},
		{"Fail2Ban configuration", func() error { return fail2ban.ValidateConfiguration(cfg) }},
		{"Firewall configuration", func() error { return firewall.ValidateConfiguration(cfg) }},
	}

	for _, validation := range validations {
		select {
		case <-ctx.Done():
			return fmt.Errorf("validation cancelled by user")
		default:
			if err := validation.fn(); err != nil {
				return fmt.Errorf("%s validation failed: %w", validation.name, err)
			}
			fmt.Printf("  ✓ %s is valid\n", validation.name)
		}
	}

	// Perform connectivity tests
	if err := performConnectivityTests(ctx, cfg, cmdExecutor); err != nil {
		log.Printf("Warning: Connectivity tests failed: %v", err)
	}

	return nil
}

func printSecuritySummary(cfg *config.Config) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("SECURITY CONFIGURATION SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("SSH Port:        %d\n", cfg.SSHPort)
	if cfg.WhitelistIP != "" {
		fmt.Printf("Whitelisted IP:  %s\n", cfg.WhitelistIP)
	}
	if cfg.GeoBlock != "" {
		fmt.Printf("Blocked Countries: %s\n", cfg.GeoBlock)
	}
	fmt.Println("\nServices Status:")
	fmt.Println("  ✓ SSH: Hardened and running on custom port")
	fmt.Println("  ✓ Fail2Ban: Active with comprehensive rules")
	fmt.Println("  ✓ Firewall: Configured with strict access rules")
	fmt.Println("\nOpen Ports:")
	fmt.Println("  • HTTP (80) - Rate limited")
	fmt.Println("  • HTTPS (443) - Rate limited")
	fmt.Printf("  • SSH (%d) - Key-based authentication only\n", cfg.SSHPort)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Server security hardening completed successfully!")
	fmt.Println("Remember to test SSH access before closing this session.")
}

// copyFileSafe safely copies a file with proper permissions and atomic operations
func copyFileSafe(src, dst string) error {
	// Ensure source file exists
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return fmt.Errorf("source file does not exist: %s", src)
	}

	// Create destination directory if it doesn't exist
	dstDir := filepath.Dir(dst)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Open source file
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	// Create temporary destination file
	tempDst := dst + ".tmp"
	dstFile, err := os.OpenFile(tempDst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}

	// Copy file content
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		dstFile.Close()
		os.Remove(tempDst)
		return fmt.Errorf("failed to copy file content: %w", err)
	}

	// Ensure data is written to disk
	if err := dstFile.Sync(); err != nil {
		dstFile.Close()
		os.Remove(tempDst)
		return fmt.Errorf("failed to sync file: %w", err)
	}

	dstFile.Close()

	// Get source file permissions
	srcInfo, err := os.Stat(src)
	if err != nil {
		os.Remove(tempDst)
		return fmt.Errorf("failed to get source file info: %w", err)
	}

	// Set file permissions
	if err := os.Chmod(tempDst, srcInfo.Mode()); err != nil {
		os.Remove(tempDst)
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempDst, dst); err != nil {
		os.Remove(tempDst)
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}

	return nil
}

// performConnectivityTests validates system connectivity
func performConnectivityTests(ctx context.Context, cfg *config.Config, cmdExecutor *utils.CommandExecutor) error {
	fmt.Println("Performing connectivity tests...")

	tests := []struct {
		name string
		test func() error
	}{
		{
			"Local SSH connectivity",
			func() error {
				conn, err := utils.NewCommandExecutor(false, false).RunCommandWithOutput("nc", "-zv", "127.0.0.1", fmt.Sprintf("%d", cfg.SSHPort))
				if err != nil {
					return fmt.Errorf("cannot connect to local SSH on port %d: %w", cfg.SSHPort, err)
				}
				_ = conn // Ignore output, just check connection
				return nil
			},
		},
		{
			"DNS resolution",
			func() error {
				output, err := utils.NewCommandExecutor(false, false).RunCommandWithOutput("nslookup", "google.com")
				if err != nil {
					return fmt.Errorf("DNS resolution failed: %w", err)
				}
				_ = output // Ignore output, just check resolution
				return nil
			},
		},
		{
			"Network connectivity",
			func() error {
				// Test basic internet connectivity using ping
				cmd := cmdExecutor.RunCommand("ping", "-c", "1", "-W", "5", "8.8.8.8")
				return cmd
			},
		},
	}

	for _, test := range tests {
		select {
		case <-ctx.Done():
			return fmt.Errorf("connectivity tests cancelled by user")
		default:
			if err := test.test(); err != nil {
				log.Printf("Warning: %s test failed: %v", test.name, err)
			} else {
				fmt.Printf("  ✓ %s test passed\n", test.name)
			}
		}
	}

	return nil
}

// sanitizeInput validates and sanitizes user input
func sanitizeInput(input string) string {
	// Remove potentially dangerous characters
	dangerous := []string{";", "&", "|", "`", "$", "(", ")", "<", ">", "\"", "'"}
	sanitized := input

	for _, char := range dangerous {
		sanitized = strings.ReplaceAll(sanitized, char, "")
	}

	return strings.TrimSpace(sanitized)
}

// validateIPList validates a list of IP addresses and CIDR ranges
func validateIPList(ipList string) error {
	if ipList == "" {
		return nil
	}

	ips := strings.Split(ipList, ",")
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}

		// Check if it's a CIDR notation
		if strings.Contains(ip, "/") {
			_, _, err := net.ParseCIDR(ip)
			if err != nil {
				return fmt.Errorf("invalid CIDR notation: %s", ip)
			}
		} else {
			// Regular IP address
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("invalid IP address: %s", ip)
			}
		}
	}

	return nil
}

// validateCountryCodes validates ISO country codes
func validateCountryCodes(countries string) error {
	if countries == "" {
		return nil
	}

	codes := strings.Split(countries, ",")
	validCode := regexp.MustCompile(`^[A-Z]{2}$`)

	for _, code := range codes {
		code = strings.TrimSpace(strings.ToUpper(code))
		if !validCode.MatchString(code) {
			return fmt.Errorf("invalid country code: %s (must be 2-letter ISO code)", code)
		}
	}

	return nil
}
