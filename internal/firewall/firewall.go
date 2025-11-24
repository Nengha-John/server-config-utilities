package firewall

import (
	"fmt"
	"strings"

	"server-config/internal/config"
)

func InstallAndConfigure(cfg *config.Config) error {
	fmt.Println("Configuring firewall...")

	// Determine and configure the appropriate firewall
	switch cfg.Distribution {
	case "ubuntu", "debian":
		return configureUFW(cfg)
	case "centos", "rhel", "fedora":
		return configureFirewalld(cfg)
	case "arch":
		return configureIPTables(cfg)
	default:
		// Default to UFW for unknown distributions
		return configureUFW(cfg)
	}
}

func configureUFW(cfg *config.Config) error {
	fmt.Println("Installing and configuring UFW...")

	// Install UFW
	if err := cfg.InstallPackage("ufw"); err != nil {
		return fmt.Errorf("failed to install UFW: %w", err)
	}

	// Reset existing rules
	fmt.Println("Resetting existing firewall rules...")
	if err := cfg.RunCommand("ufw", "--force", "reset"); err != nil {
		return fmt.Errorf("failed to reset UFW: %w", err)
	}

	// Set default policies
	fmt.Println("Setting default firewall policies...")
	if err := cfg.RunCommand("ufw", "default", "deny", "incoming"); err != nil {
		return fmt.Errorf("failed to set default incoming policy: %w", err)
	}
	if err := cfg.RunCommand("ufw", "default", "allow", "outgoing"); err != nil {
		return fmt.Errorf("failed to set default outgoing policy: %w", err)
	}
	if err := cfg.RunCommand("ufw", "default", "deny", "forwarded"); err != nil {
		return fmt.Errorf("failed to set default forwarded policy: %w", err)
	}

	// Allow SSH on custom port
	fmt.Printf("Allowing SSH on port %d...\n", cfg.SSHPort)
	if cfg.WhitelistIP != "" {
		fmt.Printf("Restricting SSH access to IP: %s\n", cfg.WhitelistIP)
		if err := cfg.RunCommand("ufw", "allow", "from", cfg.WhitelistIP, "to", "any", "port", fmt.Sprintf("%d", cfg.SSHPort), "proto", "tcp"); err != nil {
			return fmt.Errorf("failed to allow SSH from whitelist IP: %w", err)
		}
	} else {
		if err := cfg.RunCommand("ufw", "limit", fmt.Sprintf("%d/tcp", cfg.SSHPort), "comment", "SSH rate limit"); err != nil {
			return fmt.Errorf("failed to allow SSH port: %w", err)
		}
	}

	// Allow HTTP with rate limiting
	fmt.Println("Allowing HTTP (port 80) with rate limiting...")
	if err := cfg.RunCommand("ufw", "limit", "80/tcp", "comment", "HTTP rate limit"); err != nil {
		return fmt.Errorf("failed to allow HTTP port: %w", err)
	}

	// Allow HTTPS with rate limiting
	fmt.Println("Allowing HTTPS (port 443) with rate limiting...")
	if err := cfg.RunCommand("ufw", "limit", "443/tcp", "comment", "HTTPS rate limit"); err != nil {
		return fmt.Errorf("failed to allow HTTPS port: %w", err)
	}

	// Add advanced rate limiting rules
	if err := addAdvancedRateLimitingRules(cfg); err != nil {
		return fmt.Errorf("failed to add advanced rate limiting rules: %w", err)
	}

	// Enable logging
	fmt.Println("Enabling firewall logging...")
	if err := cfg.RunCommand("ufw", "logging", "on"); err != nil {
		return fmt.Errorf("failed to enable UFW logging: %w", err)
	}

	// Enable firewall
	fmt.Println("Enabling firewall...")
	if err := cfg.RunCommand("ufw", "--force", "enable"); err != nil {
		return fmt.Errorf("failed to enable UFW: %w", err)
	}

	// Show status
	if cfg.Verbose {
		if err := cfg.RunCommand("ufw", "status", "verbose"); err != nil {
			return fmt.Errorf("failed to show UFW status: %w", err)
		}
	}

	return nil
}

func configureFirewalld(cfg *config.Config) error {
	fmt.Println("Installing and configuring firewalld...")

	// Install firewalld
	if err := cfg.InstallPackage("firewalld"); err != nil {
		return fmt.Errorf("failed to install firewalld: %w", err)
	}

	// Start and enable firewalld
	if err := cfg.EnableService("firewalld"); err != nil {
		return fmt.Errorf("failed to start firewalld: %w", err)
	}

	// Set default zone to public
	if err := cfg.RunCommand("firewall-cmd", "--set-default-zone=public", "--permanent"); err != nil {
		return fmt.Errorf("failed to set default zone: %w", err)
	}

	// Remove all existing services from public zone
	services := []string{"ssh", "dhcpv6-client", "mdns"}
	for _, service := range services {
		cfg.RunCommand("firewall-cmd", "--zone=public", "--remove-service="+service, "--permanent")
	}

	// Allow SSH on custom port
	fmt.Printf("Allowing SSH on port %d...\n", cfg.SSHPort)
	if cfg.WhitelistIP != "" {
		fmt.Printf("Restricting SSH access to IP: %s\n", cfg.WhitelistIP)
		if err := cfg.RunCommand("firewall-cmd", "--permanent", "--zone=public", "--add-rich-rule=rule family='ipv4' source address='"+cfg.WhitelistIP+"' port protocol='tcp' port='"+fmt.Sprintf("%d", cfg.SSHPort)+"' accept"); err != nil {
			return fmt.Errorf("failed to allow SSH from whitelist IP: %w", err)
		}
	} else {
		if err := cfg.RunCommand("firewall-cmd", "--permanent", "--zone=public", "--add-port="+fmt.Sprintf("%d/tcp", cfg.SSHPort)); err != nil {
			return fmt.Errorf("failed to allow SSH port: %w", err)
		}
	}

	// Allow HTTP and HTTPS
	fmt.Println("Allowing HTTP and HTTPS...")
	if err := cfg.RunCommand("firewall-cmd", "--permanent", "--zone=public", "--add-service=http"); err != nil {
		return fmt.Errorf("failed to allow HTTP: %w", err)
	}
	if err := cfg.RunCommand("firewall-cmd", "--permanent", "--zone=public", "--add-service=https"); err != nil {
		return fmt.Errorf("failed to allow HTTPS: %w", err)
	}

	// Add rate limiting
	if err := addFirewalldRateLimiting(cfg); err != nil {
		return fmt.Errorf("failed to add firewalld rate limiting: %w", err)
	}

	// Reload firewall
	fmt.Println("Reloading firewall configuration...")
	if err := cfg.RunCommand("firewall-cmd", "--reload"); err != nil {
		return fmt.Errorf("failed to reload firewalld: %w", err)
	}

	return nil
}

func configureIPTables(cfg *config.Config) error {
	fmt.Println("Installing and configuring iptables...")

	// Install iptables
	if err := cfg.InstallPackage("iptables", "iptables-persistent"); err != nil {
		return fmt.Errorf("failed to install iptables: %w", err)
	}

	// Generate iptables rules
	rules := generateIPTablesRules(cfg)

	// Create temporary rules file
	rulesFile := "/tmp/iptables.rules"
	if err := cfg.WriteFile(rulesFile, rules); err != nil {
		return fmt.Errorf("failed to write iptables rules: %w", err)
	}

	// Apply rules
	fmt.Println("Applying iptables rules...")
	if err := cfg.RunCommand("iptables-restore", rulesFile); err != nil {
		return fmt.Errorf("failed to apply iptables rules: %w", err)
	}

	// Save rules
	fmt.Println("Saving iptables rules...")
	if err := cfg.RunCommand("iptables-save", ">", "/etc/iptables/rules.v4"); err != nil {
		return fmt.Errorf("failed to save iptables rules: %w", err)
	}

	// Enable iptables service
	if err := cfg.EnableService("netfilter-persistent"); err != nil {
		return fmt.Errorf("failed to enable iptables service: %w", err)
	}

	// Clean up temporary file
	cfg.RunCommand("rm", rulesFile)

	return nil
}

func generateIPTablesRules(cfg *config.Config) string {
	rules := `# Generated by server-config
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Allow loopback
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow SSH on custom port`

	if cfg.WhitelistIP != "" {
		rules += fmt.Sprintf(`
-A INPUT -p tcp -s %s --dport %d -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT`, cfg.WhitelistIP, cfg.SSHPort)
	} else {
		rules += fmt.Sprintf(`
-A INPUT -p tcp --dport %d -m conntrack --ctstate NEW -m recent --set --name ssh_attempts
-A INPUT -p tcp --dport %d -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --rttl --name ssh_attempts -j DROP
-A INPUT -p tcp --dport %d -m conntrack --ctstate NEW -j ACCEPT`, cfg.SSHPort, cfg.SSHPort, cfg.SSHPort)
	}

	rules += `

# Allow HTTP with rate limiting
-A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m recent --set --name http_attempts
-A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 20 --rttl --name http_attempts -j DROP
-A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT

# Allow HTTPS with rate limiting
-A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m recent --set --name https_attempts
-A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 20 --rttl --name https_attempts -j DROP
-A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Drop invalid packets
-A INPUT -m conntrack --ctstate INVALID -j DROP

# Protection against common attacks
-A INPUT -p tcp --tcp-flags ALL NONE -j DROP
-A INPUT -p tcp --tcp-flags ALL ALL -j DROP
-A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
-A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
-A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
-A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# ICMP rate limiting
-A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
-A INPUT -p icmp --icmp-type echo-request -j DROP

# Logging
-A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

COMMIT
`

	return rules
}

func addAdvancedRateLimitingRules(cfg *config.Config) error {
	// Additional UFW rules for enhanced security

	// Block port scans
	fmt.Println("Adding port scan protection...")
	if err := cfg.RunCommand("ufw", "insert", "1", "deny", "tcp", "from", "any", "to", "any", "port", "0:19"); err != nil {
		return fmt.Errorf("failed to block low ports: %w", err)
	}

	// Limit new connections per minute
	fmt.Println("Adding connection rate limiting...")
	if err := cfg.RunCommand("ufw", "limit", "in", "tcp", "from", "any", "to", "any", "port", "0:65535", "comment", "Limit new connections"); err != nil {
		return fmt.Errorf("failed to add connection limiting: %w", err)
	}

	// Block common attack patterns
	commonPorts := []string{"21", "23", "25", "53", "135", "137", "138", "139", "445", "1433", "1521", "3306", "3389", "5432", "5900", "6379", "27017"}
	for _, port := range commonPorts {
		if port == fmt.Sprintf("%d", cfg.SSHPort) {
			continue // Skip if it's our SSH port
		}
		if err := cfg.RunCommand("ufw", "deny", port+"/tcp", "comment", "Block unused service"); err != nil {
			fmt.Printf("Warning: Could not block port %s: %v\n", port, err)
		}
	}

	return nil
}

func addFirewalldRateLimiting(cfg *config.Config) error {
	fmt.Println("Adding advanced rate limiting rules...")

	// Add rich rules for rate limiting
	richRules := []string{
		"rule service name='ssh' log prefix='ssh' level='notice' limit value='4/m' accept",
		"rule service name='http' log prefix='http' level='notice' limit value='20/m' accept",
		"rule service name='https' log prefix='https' level='notice' limit value='20/m' accept",
	}

	for _, rule := range richRules {
		if err := cfg.RunCommand("firewall-cmd", "--permanent", "--zone=public", "--add-rich-rule", rule); err != nil {
			fmt.Printf("Warning: Could not add rich rule %s: %v\n", rule, err)
		}
	}

	return nil
}

func ValidateConfiguration(cfg *config.Config) error {
	fmt.Println("Validating firewall configuration...")

	var firewallTool string
	var statusCommand []string

	// Determine which firewall tool is being used
	switch cfg.Distribution {
	case "ubuntu", "debian":
		firewallTool = "UFW"
		statusCommand = []string{"ufw", "status", "verbose"}
	case "centos", "rhel", "fedora":
		firewallTool = "Firewalld"
		statusCommand = []string{"firewall-cmd", "--state"}
	default:
		firewallTool = "UFW"
		statusCommand = []string{"ufw", "status", "verbose"}
	}

	// Check firewall status
	output, err := cfg.RunCommandWithOutput(statusCommand[0], statusCommand[1:]...)
	if err != nil {
		return fmt.Errorf("%s is not running: %w", firewallTool, err)
	}

	fmt.Printf("✓ %s is running\n", firewallTool)

	// Validate that required ports are open
	requiredPorts := map[int]string{
		cfg.SSHPort: "SSH",
		80:          "HTTP",
		443:         "HTTPS",
	}

	for port, service := range requiredPorts {
		if firewallTool == "UFW" {
			if !strings.Contains(output, fmt.Sprintf("%d/tcp", port)) {
				return fmt.Errorf("%s port %d is not open", service, port)
			}
		} else {
			// For firewalld, check if port is allowed
			portOutput, err := cfg.RunCommandWithOutput("firewall-cmd", "--list-ports")
			if err == nil && !strings.Contains(portOutput, fmt.Sprintf("%d/tcp", port)) {
				return fmt.Errorf("%s port %d is not open", service, port)
			}
		}
		fmt.Printf("✓ %s port %d is open\n", service, port)
	}

	// Check that default policy is deny incoming
	if firewallTool == "UFW" {
		if !strings.Contains(output, "Default: deny (incoming)") {
			return fmt.Errorf("Default incoming policy is not set to deny")
		}
		fmt.Println("✓ Default incoming policy is set to deny")
	}

	// Test connectivity to essential services
	fmt.Println("Testing connectivity to essential services...")

	// Test SSH on custom port (this would need actual connectivity testing)
	// For now, just check if the port is listening
	sshListening, err := cfg.RunCommandWithOutput("ss", "-tlnp")
	if err == nil && strings.Contains(sshListening, fmt.Sprintf(":%d", cfg.SSHPort)) {
		fmt.Printf("✓ SSH is listening on port %d\n", cfg.SSHPort)
	} else {
		fmt.Printf("⚠ SSH may not be listening on port %d\n", cfg.SSHPort)
	}

	fmt.Println("✓ Firewall configuration is valid")
	return nil
}
