package validation

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"server-config/internal/config"
	"server-config/internal/utils"
)

// Validator performs comprehensive system validation
type Validator struct {
	cfg *config.Config
}

func NewValidator(cfg *config.Config) *Validator {
	return &Validator{cfg: cfg}
}

// ValidatePreConditions checks system pre-conditions before making changes
func (v *Validator) ValidatePreConditions() error {
	var errors []string

	// Check root privileges
	if !utils.IsRoot() {
		errors = append(errors, "must be run as root")
	}

	// Check essential commands
	essentialCommands := []string{"systemctl", "sshd", "ufw", "iptables", "fail2ban-client"}
	for _, cmd := range essentialCommands {
		if !utils.CommandExists(cmd) {
			errors = append(errors, fmt.Sprintf("essential command not found: %s", cmd))
		}
	}

	// Validate SSH port
	if err := utils.ValidatePort(v.cfg.SSHPort); err != nil {
		errors = append(errors, err.Error())
	}

	// Validate whitelist IP if provided
	if v.cfg.WhitelistIP != "" {
		if err := v.validateIPAddresses(v.cfg.WhitelistIP); err != nil {
			errors = append(errors, err.Error())
		}
	}

	// Validate geo block countries if provided
	if v.cfg.GeoBlock != "" {
		if err := v.validateCountryCodes(v.cfg.GeoBlock); err != nil {
			errors = append(errors, err.Error())
		}
	}

	// Check file system permissions
	if err := v.validateFilePermissions(); err != nil {
		errors = append(errors, err.Error())
	}

	// Check network connectivity
	if err := v.validateNetworkConnectivity(); err != nil {
		errors = append(errors, err.Error())
	}

	// Check system resources
	if err := v.validateSystemResources(); err != nil {
		errors = append(errors, err.Error())
	}

	if len(errors) > 0 {
		return fmt.Errorf("pre-condition validation failed:\n%s", strings.Join(errors, "\n"))
	}

	return nil
}

// ValidatePostConditions checks system state after making changes
func (v *Validator) ValidatePostConditions() error {
	var errors []string

	// Validate SSH configuration
	if err := v.validateSSHConfiguration(); err != nil {
		errors = append(errors, fmt.Sprintf("SSH validation failed: %v", err))
	}

	// Validate firewall configuration
	if err := v.validateFirewallConfiguration(); err != nil {
		errors = append(errors, fmt.Sprintf("firewall validation failed: %v", err))
	}

	// Validate Fail2Ban configuration
	if err := v.validateFail2BanConfiguration(); err != nil {
		errors = append(errors, fmt.Sprintf("Fail2Ban validation failed: %v", err))
	}

	// Validate service states
	if err := v.validateServiceStates(); err != nil {
		errors = append(errors, fmt.Sprintf("service validation failed: %v", err))
	}

	// Validate port bindings
	if err := v.validatePortBindings(); err != nil {
		errors = append(errors, fmt.Sprintf("port binding validation failed: %v", err))
	}

	if len(errors) > 0 {
		return fmt.Errorf("post-condition validation failed:\n%s", strings.Join(errors, "\n"))
	}

	return nil
}

// validateIPAddresses validates one or more IP addresses
func (v *Validator) validateIPAddresses(ipList string) error {
	ips := strings.Split(ipList, ",")
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)

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
func (v *Validator) validateCountryCodes(countries string) error {
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

// validateFilePermissions checks if we can write to essential config files
func (v *Validator) validateFilePermissions() error {
	configFiles := []string{
		"/etc/ssh/sshd_config",
		"/etc/fail2ban/jail.local",
		"/etc/ufw/user.rules",
	}

	for _, file := range configFiles {
		// Test if we can create/modify files in the directory
		dir := filepath.Dir(file)
		testFile := filepath.Join(dir, ".server-config-test")

		if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
			return fmt.Errorf("cannot write to %s: %w", dir, err)
		}

		if err := os.Remove(testFile); err != nil {
			return fmt.Errorf("cannot remove test file in %s: %w", dir, err)
		}
	}

	return nil
}

// validateNetworkConnectivity checks basic network connectivity
func (v *Validator) validateNetworkConnectivity() error {
	// Check if we can resolve DNS
	if _, err := net.LookupHost("google.com"); err != nil {
		return fmt.Errorf("DNS resolution failed: %w", err)
	}

	// Check if loopback interface is working
	conn, err := net.Dial("tcp", "127.0.0.1:22")
	if err != nil {
		// This is expected if SSH isn't running on port 22, so don't fail
	} else {
		conn.Close()
	}

	return nil
}

// validateSystemResources checks minimum system requirements
func (v *Validator) validateSystemResources() error {
	// Check available disk space (minimum 100MB)
	var stat syscall.Statfs_t
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("cannot get working directory: %w", err)
	}

	if err := syscall.Statfs(wd, &stat); err != nil {
		return fmt.Errorf("cannot get filesystem stats: %w", err)
	}

	availableSpace := stat.Bavail * uint64(stat.Bsize)
	minSpace := uint64(100 * 1024 * 1024) // 100MB

	if availableSpace < minSpace {
		return fmt.Errorf("insufficient disk space: available %d bytes, minimum %d bytes", availableSpace, minSpace)
	}

	return nil
}

// validateSSHConfiguration validates SSH settings
func (v *Validator) validateSSHConfiguration() error {
	if !v.cfg.FileExists("/etc/ssh/sshd_config") {
		return fmt.Errorf("SSH configuration file not found")
	}

	content, err := v.cfg.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return fmt.Errorf("cannot read SSH configuration: %w", err)
	}

	// Check essential security settings
	requiredSettings := []string{
		fmt.Sprintf("Port %d", v.cfg.SSHPort),
		"Protocol 2",
		"PermitRootLogin no",
		"PasswordAuthentication no",
		"PubkeyAuthentication yes",
	}

	for _, setting := range requiredSettings {
		if !strings.Contains(content, setting) {
			return fmt.Errorf("missing SSH security setting: %s", setting)
		}
	}

	// Validate SSH configuration syntax
	output, err := v.cfg.RunCommandWithOutput("sshd", "-t")
	if err != nil {
		return fmt.Errorf("SSH configuration syntax error: %s", output)
	}

	return nil
}

// validateFirewallConfiguration validates firewall settings
func (v *Validator) validateFirewallConfiguration() error {
	var statusOutput string
	var err error

	switch v.cfg.Distribution {
	case "ubuntu", "debian":
		statusOutput, err = v.cfg.RunCommandWithOutput("ufw", "status", "verbose")
		if err != nil {
			return fmt.Errorf("cannot get UFW status: %w", err)
		}

		// Check if UFW is active
		if !strings.Contains(statusOutput, "Status: active") {
			return fmt.Errorf("UFW is not active")
		}

		// Check if essential ports are open
		if !strings.Contains(statusOutput, fmt.Sprintf("%d/tcp", v.cfg.SSHPort)) {
			return fmt.Errorf("SSH port %d is not open in UFW", v.cfg.SSHPort)
		}

		if !strings.Contains(statusOutput, "80/tcp") {
			return fmt.Errorf("HTTP port 80 is not open in UFW")
		}

		if !strings.Contains(statusOutput, "443/tcp") {
			return fmt.Errorf("HTTPS port 443 is not open in UFW")
		}

		// Check default policy
		if !strings.Contains(statusOutput, "Default: deny (incoming)") {
			return fmt.Errorf("UFW default incoming policy is not set to deny")
		}

	case "centos", "rhel", "fedora":
		if !v.cfg.ServiceEnabled("firewalld") {
			return fmt.Errorf("firewalld is not enabled")
		}

		// Check if firewalld is running
		status, err := utils.GetServiceStatus("firewalld")
		if err != nil || status != "active" {
			return fmt.Errorf("firewalld is not running")
		}

		// Check if ports are open
		output, err := v.cfg.RunCommandWithOutput("firewall-cmd", "--list-ports")
		if err != nil {
			return fmt.Errorf("cannot list firewalld ports: %w", err)
		}

		if !strings.Contains(output, fmt.Sprintf("%d/tcp", v.cfg.SSHPort)) {
			return fmt.Errorf("SSH port %d is not open in firewalld", v.cfg.SSHPort)
		}
	}

	return nil
}

// validateFail2BanConfiguration validates Fail2Ban settings
func (v *Validator) validateFail2BanConfiguration() error {
	if !v.cfg.ServiceExists("fail2ban") {
		return fmt.Errorf("fail2ban is not installed")
	}

	// Check if fail2ban is running
	status, err := utils.GetServiceStatus("fail2ban")
	if err != nil || status != "active" {
		return fmt.Errorf("fail2ban is not running")
	}

	// Check configuration file
	if !v.cfg.FileExists("/etc/fail2ban/jail.local") {
		return fmt.Errorf("fail2ban jail.local configuration not found")
	}

	// Test fail2ban configuration
	output, err := v.cfg.RunCommandWithOutput("fail2ban-client", "test")
	if err != nil {
		return fmt.Errorf("fail2ban configuration test failed: %s", output)
	}

	// Check if SSH jail is active
	output, err = v.cfg.RunCommandWithOutput("fail2ban-client", "status", "sshd")
	if err != nil {
		return fmt.Errorf("cannot get SSH jail status: %w", err)
	}

	if !strings.Contains(output, "Status") {
		return fmt.Errorf("SSH jail is not active")
	}

	return nil
}

// validateServiceStates validates critical service states
func (v *Validator) validateServiceStates() error {
	services := map[string]bool{
		"ssh":      true, // Should be active
		"fail2ban": true, // Should be active if fail2ban was configured
	}

	for service, shouldBeActive := range services {
		if !v.cfg.ServiceExists(service) {
			if shouldBeActive {
				return fmt.Errorf("required service %s is not installed", service)
			}
			continue
		}

		status, err := utils.GetServiceStatus(service)
		if err != nil {
			return fmt.Errorf("cannot get status for service %s: %w", service, err)
		}

		if shouldBeActive && status != "active" {
			return fmt.Errorf("service %s is not active (status: %s)", service, status)
		}
	}

	return nil
}

// validatePortBindings validates that required ports are properly bound
func (v *Validator) validatePortBindings() error {
	// Check if SSH is listening on the correct port
	output, err := v.cfg.RunCommandWithOutput("ss", "-tlnp")
	if err != nil {
		return fmt.Errorf("cannot check port bindings: %w", err)
	}

	// Check SSH port
	sshPortPattern := fmt.Sprintf(":%d ", v.cfg.SSHPort)
	if !strings.Contains(output, sshPortPattern) {
		return fmt.Errorf("SSH is not listening on port %d", v.cfg.SSHPort)
	}

	// Optional: Check if web servers are listening (not required for all setups)
	// if strings.Contains(output, ":80 ") {
	//     fmt.Println("HTTP server detected on port 80")
	// }
	// if strings.Contains(output, ":443 ") {
	//     fmt.Println("HTTPS server detected on port 443")
	// }

	return nil
}

// PerformConnectivityTests performs network connectivity tests
func (v *Validator) PerformConnectivityTests() error {
	// Test local loopback
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", v.cfg.SSHPort), 5*time.Second)
	if err != nil {
		return fmt.Errorf("cannot connect to local SSH on port %d: %w", v.cfg.SSHPort, err)
	}
	conn.Close()

	// Test DNS resolution
	if _, err := net.LookupHost("github.com"); err != nil {
		fmt.Printf("Warning: Cannot resolve github.com: %v\n", err)
	}

	// Test internet connectivity (optional)
	conn, err = net.DialTimeout("tcp", "8.8.8.8:53", 5*time.Second)
	if err != nil {
		fmt.Printf("Warning: Cannot connect to DNS server: %v\n", err)
	} else {
		conn.Close()
	}

	return nil
}
