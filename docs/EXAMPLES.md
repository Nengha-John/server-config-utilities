# Server Configuration Examples

This document provides comprehensive examples for different server security scenarios and use cases.

## Table of Contents
- [Basic Setup Examples](#basic-setup-examples)
- [Production Environment Examples](#production-environment-examples)
- [Development Environment Examples](#development-environment-examples)
- [High Security Examples](#high-security-examples)
- [Multi-Server Deployments](#multi-server-deployments)
- [Custom Configurations](#custom-configurations)
- [Troubleshooting Examples](#troubleshooting-examples)

## Basic Setup Examples

### Standard Web Server
Perfect for a typical web hosting environment.

```bash
# Basic web server setup
sudo server-config install --ssh-port 2222

# What this does:
# - Changes SSH port to 2222
# - Enables Fail2Ban with web server protection
# - Configures firewall (ports 80, 443, 2222 only)
# - Sets up Git SSH keys
```

### Minimal Server
For minimal VPS or container environments.

```bash
# Minimal setup - SSH hardening only
sudo server-config install --ssh-only --ssh-port 2222

# Add security monitoring later
sudo server-config install --fail2ban

# Add firewall last
sudo server-config install --firewall
```

### API Server
For REST API servers that don't serve web content.

```bash
# API server - only HTTPS and SSH
sudo server-config install --ssh-port 2222

# Then manually close HTTP port in firewall
sudo ufw deny 80/tcp
```

## Production Environment Examples

### E-commerce Production
High-security setup for e-commerce platforms.

```bash
sudo server-config install \
  --ssh-port 4422 \
  --whitelist-ip 203.0.113.0/24 \
  --geo-block CN,RU,KP,NP,IR \
  --verbose
```

**Explanation:**
- Custom SSH port (4422) for security through obscurity
- SSH access restricted to corporate IP range
- Block countries known for fraudulent activity
- Verbose output for deployment verification

### Enterprise Environment
For enterprise deployments with compliance requirements.

```bash
# Enterprise setup with compliance logging
sudo server-config install \
  --ssh-port 3322 \
  --whitelist-ip 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 \
  --verbose

# Additional enterprise configurations
sudo ufw logging on
sudo ufw default deny incoming
sudo systemctl enable auditd
```

### High-Traffic Website
For websites with high traffic volumes.

```bash
# High-traffic setup with optimized rate limiting
sudo server-config install --ssh-port 2222

# Additional tuning for high traffic
sudo ufw limit 80/tcp comment 'HTTP high-traffic'
sudo ufw limit 443/tcp comment 'HTTPS high-traffic'

# Custom Fail2Ban rules for high traffic
echo '[apache-overflows]
enabled = true
port = http,https
filter = apache-overflows
logpath = /var/log/apache2/error.log
maxretry = 10
bantime = 600' | sudo tee -a /etc/fail2ban/jail.local

sudo systemctl restart fail2ban
```

## Development Environment Examples

### Development Server
Secure but accessible development environment.

```bash
# Development setup with developer-friendly settings
sudo server-config install --ssh-port 2222

# Allow additional development tools
sudo ufw allow 3000/tcp comment 'Node.js development'
sudo ufw allow 8080/tcp comment 'Alternative web server'
sudo ufw allow 9000/tcp comment 'Development port'

# Less aggressive Fail2Ban for development
sudo sed -i 's/maxretry = 3/maxretry = 10/' /etc/fail2ban/jail.local
sudo sed -i 's/bantime = 3600/bantime = 600/' /etc/fail2ban/jail.local
sudo systemctl restart fail2ban
```

### CI/CD Runner
For GitLab Runners, GitHub Actions, or similar CI/CD systems.

```bash
# CI/CD runner setup
sudo server-config install --ssh-port 2222

# Allow CI/CD platform IPs (example for GitHub)
sudo ufw allow from 192.30.252.0/22 to any port 22
sudo ufw allow from 185.199.108.0/22 to any port 22
sudo ufw allow from 140.82.112.0/20 to any port 22

# Allow Docker and build tools
sudo ufw allow from 172.17.0.0/16 to any port 22  # Docker bridge
```

### Database Server
For database servers with limited access.

```bash
# Database server with restricted access
sudo server-config install --ssh-port 2222

# Allow database access from application servers only
sudo ufw allow from 10.0.1.10 to any port 3306  # MySQL
sudo ufw allow from 10.0.1.10 to any port 5432  # PostgreSQL
sudo ufw allow from 10.0.1.20 to any port 3306  # Another app server

# Custom Fail2Ban for databases
echo '[mysqld-auth]
enabled = true
port = 3306
filter = mysqld-auth
logpath = /var/log/mysql/error.log
maxretry = 5
bantime = 3600' | sudo tee -a /etc/fail2ban/jail.local

sudo systemctl restart fail2ban
```

## High Security Examples

### Financial Services
Maximum security configuration for financial applications.

```bash
# Financial services setup
sudo server-config install \
  --ssh-port 9922 \
  --whitelist-ip 203.0.113.0/24,198.51.100.0/24 \
  --geo-block CN,RU,KP,NP,IR,AF,SY,YE,SS,LR \
  --verbose

# Additional security measures
sudo ufw default deny outgoing
sudo ufw allow out 53    # DNS
sudo ufw allow out 80    # HTTP for updates
sudo ufw allow out 443   # HTTPS
sudo ufw allow out 9418  # Git
sudo ufw deny out from any to any

# Enable audit logging
sudo apt install auditd -y
sudo systemctl enable auditd
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
sudo auditctl -w /etc/shadow -p wa -k shadow_changes
```

### Government/Defense
Ultra-secure configuration for government systems.

```bash
# Government setup with maximum restrictions
sudo server-config install \
  --ssh-port 8822 \
  --whitelist-ip 203.0.113.0/24 \
  --geo-block CN,RU,KP,NP,IR,AF,SY,YE,SS,LR,CU,SD,MM,TM,UZ,BT,NP,MV,KP,LA,KH,VN,BT,MV \
  --verbose

# Enable additional security services
sudo apt install aide rkhunter chkrootkit -y
sudo aide --init
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Daily security scan
echo '0 2 * * * root /usr/bin/aide --check | mail -s "AIDE Security Report" security@example.com' | sudo tee -a /etc/crontab

# System hardening
echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.conf
echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.conf
sysctl -p
```

### Healthcare (HIPAA Compliance)
HIPAA-compliant configuration for healthcare systems.

```bash
# HIPAA-compliant setup
sudo server-config install \
  --ssh-port 7722 \
  --whitelist-ip 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 \
  --geo-block CN,RU,KP,NP,IR,AF \
  --verbose

# Enable comprehensive logging
sudo apt install auditd syslog-ng -y

# Configure audit rules for HIPAA
cat << 'EOF' | sudo tee /etc/audit/rules.d/hipaa.rules
-w /var/log/audit -p wa -k audit_log
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /var/log/auth.log -p wa -k logins
-w /var/log/secure -p wa -k logins
EOF

sudo augenrules
sudo systemctl restart auditd
```

## Multi-Server Deployments

### Load Balanced Web Farm
Configuration for multiple web servers behind a load balancer.

```bash
# Web server node configuration
sudo server-config install \
  --ssh-port 2222 \
  --whitelist-ip 10.0.1.0/24  # Management network
  --verbose

# Allow load balancer health checks
sudo ufw allow from 10.0.2.10 to any port 80
sudo ufw allow from 10.0.2.10 to any port 443

# Synchronize Fail2Ban across servers
echo 'Backend = auto' | sudo tee -a /etc/fail2ban/jail.local
echo 'Action = %(action_mwl)s' | sudo tee -a /etc/fail2ban/jail.local

# Custom fail2ban sync script
cat << 'EOF' | sudo tee /usr/local/bin/sync-fail2ban.sh
#!/bin/bash
# Synchronize Fail2Ban bans across web farm
FAIL2BAN_DB="/var/lib/fail2ban/fail2ban.sqlite3"
MASTER_SERVER="10.0.2.100"

# Export banned IPs
sqlite3 $FAIL2BAN_DB "SELECT ip FROM bips;" > /tmp/banned_ips.txt

# Send to other servers
for server in 10.0.1.11 10.0.1.12 10.0.1.13; do
    scp /tmp/banned_ips.txt root@$server:/tmp/
    ssh root@$server "fail2ban-client set $(fail2ban-client status | grep jails | cut -d: -f2 | xargs) banip $(cat /tmp/banned_ips.txt)"
done
EOF

sudo chmod +x /usr/local/bin/sync-fail2ban.sh
```

### Microservices Architecture
For microservices with inter-service communication.

```bash
# Microservice node configuration
sudo server-config install --ssh-port 2222

# Allow inter-service communication
# Service A (port 3001)
sudo ufw allow from 10.0.3.0/24 to any port 3001

# Service B (port 3002)
sudo ufw allow from 10.0.3.0/24 to any port 3002

# Service C (port 3003)
sudo ufw allow from 10.0.3.0/24 to any port 3003

# Monitoring and logging
sudo ufw allow from 10.0.10.0/24 to any port 9090  # Prometheus
sudo ufw allow from 10.0.10.0/24 to any port 3000  # Grafana
```

### Disaster Recovery Site
Configuration for backup/DR site.

```bash
# DR site configuration
sudo server-config install \
  --ssh-port 6622 \
  --whitelist-ip 10.0.100.0/24  # Primary site network
  --verbose

# Allow replication from primary site
sudo ufw allow from 203.0.113.0/24 to any port 22   # SSH
sudo ufw allow from 203.0.113.0/24 to any port 3306 # MySQL replication
sudo ufw allow from 203.0.113.0/24 to any port 5432 # PostgreSQL replication

# Backup monitoring
sudo ufw allow from 203.0.113.0/24 to any port 8443 # Backup management
```

## Custom Configurations

### Custom SSH Configuration
Advanced SSH hardening beyond defaults.

```bash
# After running server-config, customize SSH
sudo cat << 'EOF' >> /etc/ssh/sshd_config

# Custom security settings
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxStartups 10:30:60
PermitTunnel no
AllowTcpForwarding no
X11Forwarding no
PermitUserEnvironment no
AcceptEnv LANG LC_*

# Restrict to specific users
AllowUsers admin backup deploy
AllowGroups sshusers

# Only allow specific algorithms
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssl.com,aes256-gcm@openssl.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com

# Logging
LogLevel VERBOSE
SyslogFacility AUTHPRIV
EOF

sudo systemctl restart ssh
```

### Custom Fail2Ban Rules
Adding specialized security rules.

```bash
# Create custom WordPress protection
sudo cat << 'EOF' > /etc/fail2ban/filter.d/wordpress.conf
[Definition]
failregex = ^.* apache2: .* "POST .*wp-login\.php.* 401
            ^.* apache2: .* "POST .*xmlrpc\.php.* 401
ignoreregex =

[Init]
# Chain of blocks for WordPress
chain = INPUT
EOF

# Add WordPress jail
sudo cat << 'EOF' >> /etc/fail2ban/jail.local

[wordpress]
enabled  = true
port     = http,https
filter   = wordpress
logpath  = /var/log/apache2/access.log
maxretry = 3
bantime  = 86400
findtime = 300
EOF

sudo systemctl restart fail2ban
```

### Custom Firewall Rules
Advanced networking configurations.

```bash
# Custom network segmentation
sudo ufw allow in on eth0 to any port 80   # Web traffic on eth0
sudo ufw allow in on eth1 to any port 3306 # Database access on eth1

# NAT configuration
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Quality of Service (QoS)
sudo iptables -t mangle -A OUTPUT -p tcp --dport 22 -j TOS --set-tos Minimize-Delay
sudo iptables -t mangle -A OUTPUT -p tcp --dport 80 -j TOS --set-tos Maximize-Throughput

# Save custom rules
sudo iptables-save > /etc/iptables/custom.rules
```

## Troubleshooting Examples

### SSH Access Issues

**Problem**: Cannot connect after changing SSH port

```bash
# Check if SSH is running
sudo systemctl status ssh

# Check current SSH configuration
sudo grep -n "^Port" /etc/ssh/sshd_config

# Test SSH locally
sudo ssh -p 2222 localhost

# Check firewall status
sudo ufw status verbose

# Emergency: Revert to default SSH port
sudo sed -i 's/^Port .*/Port 22/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

### Fail2Ban Problems

**Problem**: Fail2Ban not banning IPs

```bash
# Check Fail2Ban status
sudo fail2ban-client status

# Check specific jail
sudo fail2ban-client status sshd

# Test regex patterns
sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf

# Check if iptables rules exist
sudo iptables -L -n | grep f2b

# Restart Fail2Ban
sudo systemctl restart fail2ban

# Check logs
sudo tail -f /var/log/fail2ban.log
```

### Firewall Issues

**Problem**: Services not accessible after firewall configuration

```bash
# Check firewall status
sudo ufw status verbose

# Check if rules are loaded
sudo iptables -L -n

# Test connectivity
sudo netstat -tlnp | grep :80
sudo netstat -tlnp | grep :443

# Temporarily disable firewall for testing
sudo ufw disable

# Test service
curl -I http://localhost

# Re-enable firewall
sudo ufw enable
```

### Performance Issues

**Problem**: High CPU usage from security tools

```bash
# Check Fail2Ban performance
sudo fail2ban-client get sshd bantime
sudo fail2ban-client get sshd maxretry

# Optimize for high-traffic sites
sudo sed -i 's/findtime = 600/findtime = 60/' /etc/fail2ban/jail.local
sudo sed -i 's/maxretry = 3/maxretry = 10/' /etc/fail2ban/jail.local

# Check system resources
htop
iotop

# Optimize Fail2Ban database
sudo systemctl stop fail2ban
sudo sqlite3 /var/lib/fail2ban/fail2ban.sqlite3 "VACUUM;"
sudo systemctl start fail2ban
```

## Automation Examples

### Ansible Integration
```yaml
---
- name: Secure server configuration
  hosts: webservers
  become: yes
  tasks:
    - name: Download and install server-config
      get_url:
        url: https://github.com/your-org/server-config/releases/latest/download/server-config-linux-amd64
        dest: /usr/local/bin/server-config
        mode: '0755'
    
    - name: Run server security configuration
      command: server-config install --ssh-port 2222 --verbose
      register: security_config
```

### Docker Integration
```dockerfile
FROM ubuntu:20.04

# Install and configure security
COPY server-config /usr/local/bin/
RUN chmod +x /usr/local/bin/server-config
RUN server-config install --ssh-port 2222

# Your application code here
COPY . /app
WORKDIR /app
CMD ["/app/start.sh"]
```

### Cron Jobs for Maintenance
```bash
# Daily security validation
0 3 * * * root /usr/local/bin/server-config validate >> /var/log/security-validation.log 2>&1

# Weekly backup of configurations
0 2 * * 0 root /usr/local/bin/server-config backup >> /var/log/security-backup.log 2>&1

# Monthly security report
0 1 1 * * root /usr/local/bin/security-report.sh | mail -s "Monthly Security Report" security@example.com
```

These examples should help you configure server-config for various scenarios and environments. Adjust the values based on your specific requirements and network topology.
