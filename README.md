# Server Security Configuration Tool

A comprehensive Go-based automation tool for hardening Linux server security following industry best practices. This tool provides enterprise-grade security hardening with automated configuration of SSH, Fail2Ban, firewall rules, and Git security.

## 🚀 Features

### 🔐 SSH Security
- **Custom SSH Port**: Change from default port 22 to customizable port (default: 2222)
- **Key-Based Authentication**: Disable password authentication, enforce SSH keys only
- **SSH Hardening**: Comprehensive security configurations including banners, rate limiting, and access controls
- **Ed25519 Keys**: Generate secure SSH key pairs using modern cryptography

### 🛡️ Firewall Protection
- **Strict Access Control**: Default deny policy with only essential ports open (80, 443, custom SSH)
- **Rate Limiting**: Advanced rate limiting to prevent DDoS and brute force attacks
- **Multi-Firewall Support**: UFW (Ubuntu/Debian), firewalld (RHEL/CentOS), iptables (Arch)
- **Port Security**: Block unused services and common attack vectors

### 🚨 Fail2Ban Integration
- **Comprehensive Rules**: Pre-configured jails for SSH, web servers, email, databases
- **Custom Filters**: Advanced detection for SQL injection, XSS, web shells, and more
- **Progressive Banning**: Escalating ban durations for repeat offenders
- **Real-time Protection**: Instant response to security threats

### 🔑 Git Security
- **SSH Key Management**: Dedicated SSH keys for Git operations
- **GPG Commit Signing**: Optional automatic commit signing
- **Secure Configuration**: Hardened Git settings for security
- **Multi-Platform Support**: GitHub, GitLab, Bitbucket configurations

### 🔄 Backup & Recovery
- **Configuration Backups**: Automatic backup before making changes
- **Rollback Capability**: Restore previous configurations if needed
- **Timestamped Backups**: Multiple restore points with metadata
- **Service Management**: Automated service restarts after changes

## 📋 System Requirements

- **Linux Distribution**: Ubuntu, Debian, CentOS, RHEL, Fedora, Arch Linux
- **Root Access**: Required for system configuration changes
- **Go Runtime**: For building from source (v1.19+ recommended)
- **Package Manager**: APT, YUM/DNF, or Pacman

## 🛠️ Installation

### From Source
```bash
# Clone the repository
git clone https://github.com/your-org/server-config.git
cd server-config

# Build the binary
go build -o server-config cmd/server-config/main.go

# Install system-wide (optional)
sudo cp server-config /usr/local/bin/
sudo chmod +x /usr/local/bin/server-config
```

### Using Go Install
```bash
go install github.com/your-org/server-config/cmd/server-config@latest
```

## 🚀 Quick Start

### Basic Usage
```bash
# Run with default settings (SSH port 2222)
sudo server-config install

# Use custom SSH port
sudo server-config install --ssh-port 3333

# Restrict SSH access to specific IP
sudo server-config install --ssh-port 2222 --whitelist-ip 192.168.1.100

# Enable verbose output
sudo server-config install --verbose
```

### Individual Components
```bash
# Configure only SSH
sudo server-config install --ssh-only --ssh-port 2222

# Configure only Fail2Ban
sudo server-config install --fail2ban

# Configure only firewall
sudo server-config install --firewall
```

### Configuration Management
```bash
# Backup current configurations
sudo server-config backup

# Restore from backup
sudo server-config rollback

# Validate security configuration
sudo server-config validate
```

## 📖 Command Reference

### Global Options
```bash
--ssh-port <port>       Custom SSH port (default: 2222)
--whitelist-ip <ip>     IP address to whitelist for SSH
--geo-block <countries> Comma-separated country codes to block
--verbose              Enable detailed output
```

### Commands

#### `install`
Full security hardening installation
```bash
sudo server-config install [options]
```

#### `backup`
Create timestamped backup of current configurations
```bash
sudo server-config backup
```

#### `rollback`
Restore configuration from latest backup
```bash
sudo server-config rollback
```

#### `validate`
Validate current security configuration
```bash
sudo server-config validate
```

## 🔧 Configuration Examples

### Basic Web Server Setup
```bash
sudo server-config install \
  --ssh-port 2222 \
  --verbose
```

### High-Security Environment
```bash
sudo server-config install \
  --ssh-port 4422 \
  --whitelist-ip 203.0.113.0/24 \
  --geo-block CN,RU,KP,NP \
  --verbose
```

### Development Environment
```bash
# Individual component setup for development
sudo server-config install --ssh-only --ssh-port 2222
sudo server-config install --fail2ban
sudo server-config install --firewall
```

### Git Security Setup
```bash
# Configure Git with SSH keys (includes in full install)
sudo server-config install --ssh-port 2222

# Or configure Git separately
export GIT_USER_NAME="Your Name"
export GIT_USER_EMAIL="your.email@example.com"
sudo server-config install --ssh-only
```

## 📁 Project Structure

```
server-config/
├── cmd/
│   └── server-config/          # Main CLI application
├── internal/
│   ├── config/                 # Configuration management
│   ├── fail2ban/               # Fail2Ban configuration
│   ├── firewall/               # Firewall management
│   ├── git/                    # Git security setup
│   ├── ssh/                    # SSH hardening
│   └── utils/                  # Shared utilities
├── configs/                    # Configuration templates
├── scripts/                    # Support scripts
├── docs/                       # Documentation
├── README.md                   # This file
└── go.mod                      # Go module file
```

## 🔒 Security Features

### SSH Hardening
- ✅ Custom port configuration
- ✅ Disable password authentication
- ✅ Disable root login
- ✅ Protocol 2 only
- ✅ Key-based authentication
- ✅ Connection rate limiting
- ✅ Login grace time limits
- ✅ Security banners
- ✅ Host-based authentication disabled

### Firewall Rules
- ✅ Default deny policy
- ✅ HTTP (80) rate limiting
- ✅ HTTPS (443) rate limiting
- ✅ Custom SSH port access
- ✅ IP whitelisting support
- ✅ SYN flood protection
- ✅ Port scan detection
- ✅ Invalid packet blocking

### Fail2Ban Protection
- ✅ SSH brute force protection
- ✅ Web server attack detection
- ✅ Email service protection
- ✅ Database security
- ✅ Custom threat filters
- ✅ SQL injection detection
- ✅ XSS attack prevention
- ✅ Web shell detection

### Git Security
- ✅ Dedicated SSH keys
- ✅ GPG commit signing
- ✅ Secure URL configuration
- ✅ Multi-platform support
- ✅ SSH configuration hardening

## 🔄 Backup & Recovery

### Automatic Backups
Every installation automatically creates:
- Timestamped backup directory
- Configuration file copies
- System metadata
- SSH port information

### Manual Backup Operations
```bash
# Create backup
sudo server-config backup

# List available backups
ls -la /etc/server-config-backup/

# Restore from backup
sudo server-config rollback
```

### What Gets Backed Up
- SSH configuration (`/etc/ssh/sshd_config`)
- Fail2Ban rules (`/etc/fail2ban/jail.*`)
- Firewall rules (`/etc/ufw/`, `/etc/iptables/`)
- User SSH/Git configurations
- Service configurations

## 🚨 Important Notes

### ⚠️ Critical Warning
**Always test SSH access before closing your current session!**

```bash
# Test new SSH connection in a separate terminal
ssh -p 2222 user@your-server

# Keep original session open until verified working
```

### 🔑 SSH Key Management
- Backup your SSH keys before running this tool
- Ensure you have access to the new SSH key that will be generated
- Add the Git SSH key to your Git providers immediately after setup

### 🌐 Network Considerations
- Ensure your firewall/infrastructure allows the custom SSH port
- Update any load balancers or security groups accordingly
- Consider IP whitelisting for additional security

### 🔄 Service Impact
- SSH service will be restarted
- Existing SSH sessions will remain active
- Firewall rules will be reloaded
- Fail2Ban will restart with new configuration

## 🛠️ Troubleshooting

### Common Issues

#### SSH Connection Refused
```bash
# Check SSH status
sudo systemctl status ssh

# Check SSH configuration
sudo sshd -t

# Check port binding
sudo ss -tlnp | grep ssh
```

#### Firewall Blocking Access
```bash
# Check firewall status
sudo ufw status verbose  # Ubuntu/Debian
sudo firewall-cmd --list-all  # RHEL/CentOS

# Temporarily disable for testing
sudo ufw disable  # Ubuntu/Debian
sudo systemctl stop firewalld  # RHEL/CentOS
```

#### Fail2Ban Not Working
```bash
# Check Fail2Ban status
sudo fail2ban-client status

# Test configuration
sudo fail2ban-client test

# Check logs
sudo tail -f /var/log/fail2ban.log
```

### Rollback Procedure
If you experience issues after configuration:

```bash
# Emergency rollback
sudo server-config rollback

# Restart services
sudo systemctl restart ssh fail2ban ufw

# Verify SSH access
ssh -p 22 user@your-server  # Test with original port
```

## 📚 Advanced Usage

### Custom Configuration
You can modify the generated configurations in:
- `/etc/ssh/sshd_config` - SSH settings
- `/etc/fail2ban/jail.local` - Fail2Ban rules
- `/etc/ufw/` or `/etc/firewalld/` - Firewall rules

### Environment Variables
```bash
export GIT_USER_NAME="Your Name"
export GIT_USER_EMAIL="your.email@example.com"
export GIT_CONFIGURE_GPG="true"
sudo server-config install
```

### Integration with CI/CD
```bash
# Non-interactive mode for automation
sudo server-config install --ssh-port 2222 --verbose < /dev/null

# Validation before deployment
sudo server-config validate && echo "Security OK"
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Fail2Ban](https://www.fail2ban.org/) - Intrusion prevention software
- [UFW](https://help.ubuntu.com/community/UFW) - Uncomplicated Firewall
- [OpenSSH](https://www.openssh.com/) - Secure Shell protocol
- [Git](https://git-scm.com/) - Version control system

## 📞 Support

For support, bug reports, or feature requests:
- Create an issue on GitHub
- Check the troubleshooting section above
- Review the logs in `/var/log/`

---

**Remember**: Security is an ongoing process. Regular updates and monitoring are essential for maintaining server security.
