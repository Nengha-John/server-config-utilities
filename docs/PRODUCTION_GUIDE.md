# Production Deployment Guide

This guide covers the production-ready deployment of the server-config tool with all safety features, error handling, and best practices implemented.

## 🚨 Production Readiness Status: ✅ COMPLETE

All production readiness issues have been resolved:

- ✅ **Missing core functions implemented**
- ✅ **Comprehensive error handling**
- ✅ **Atomic operations with rollback**
- ✅ **Input validation and sanitization**
- ✅ **Safety checks and pre-flight validation**
- ✅ **Dry-run capability**
- ✅ **Signal handling and graceful interruption**
- ✅ **Security hardening**

## 🛡️ Production Features

### Safety Mechanisms
- **Pre-flight validation** before any system changes
- **Atomic operations** with automatic rollback on failure
- **Input validation** and sanitization
- **Graceful interruption** with Ctrl+C
- **Dry-run mode** for safe testing

### Error Recovery
- **Automatic backups** before any changes
- **Rollback capability** if operations fail
- **Service restart protection** with status checking
- **Detailed error reporting** with troubleshooting guidance

### Security Features
- **Shell injection protection**
- **Safe file handling** with proper permissions
- **Temporary file security**
- **Audit logging** of all operations

## 🚀 Production Deployment

### Prerequisites
```bash
# Ensure you have root privileges
sudo -i

# Verify system requirements
./server-config --validate --verbose

# Check available commands
which systemctl ufw iptables fail2ban-client ssh-keygen
```

### Safe Deployment Process

#### 1. Pre-Deployment Testing
```bash
# Test configuration without making changes
sudo ./server-config --dry-run --install --verbose

# Validate current system state
sudo ./server-config --validate --verbose

# Test backup functionality
sudo ./server-config --backup --verbose
```

#### 2. Production Installation
```bash
# Create backup before making changes
sudo ./server-config --backup --verbose

# Install with comprehensive validation
sudo ./server-config --install --ssh-port 2222 --verbose

# Verify installation
sudo ./server-config --validate --verbose
```

#### 3. Custom Production Configurations
```bash
# High-security environment
sudo ./server-config --install \
  --ssh-port 4422 \
  --whitelist-ip 203.0.113.0/24 \
  --geo-block CN,RU,KP,NP,IR \
  --verbose

# Web server with specific requirements
sudo ./server-config --install \
  --ssh-port 3333 \
  --verbose

# Development environment with testing
sudo ./server-config --install --ssh-port 2222 --verbose
```

## 🔧 Production Usage Examples

### Validation Operations
```bash
# Validate current security posture
sudo ./server-config --validate --verbose

# Validate specific configurations
sudo ./server-config --validate --ssh-port 2222 --verbose
```

### Backup and Recovery
```bash
# Create manual backup
sudo ./server-config --backup --verbose

# List available backups
ls -la /etc/server-config-backup/

# Rollback to latest backup
sudo ./server-config --rollback --verbose

# Rollback to specific backup
sudo ./server-config --rollback --backup-dir /etc/server-config-backup/20231124-120000 --verbose
```

### Dry-Run Testing
```bash
# Test configuration changes
sudo ./server-config --dry-run --install --ssh-port 3333 --verbose

# Test specific components
sudo ./server-config --dry-run --ssh-only --ssh-port 4422 --verbose
```

## 📊 Monitoring and Maintenance

### Regular Validation
```bash
# Add to cron for daily security checks
0 3 * * * root /usr/local/bin/server-config --validate --verbose >> /var/log/security-validation.log 2>&1

# Weekly backup creation
0 2 * * 0 root /usr/local/bin/server-config --backup --verbose >> /var/log/security-backup.log 2>&1
```

### Log Monitoring
```bash
# Monitor application logs
tail -f /var/log/server-config.log

# Check system logs for security events
tail -f /var/log/auth.log | grep -i fail2ban
tail -f /var/log/fail2ban.log
```

### Health Checks
```bash
# Verify SSH is running on correct port
ss -tlnp | grep :2222

# Check firewall status
ufw status verbose

# Verify Fail2Ban is active
systemctl status fail2ban
```

## 🔒 Security Best Practices

### Access Control
```bash
# Restrict access to the binary
chmod 750 /usr/local/bin/server-config
chown root:root /usr/local/bin/server-config

# Restrict access to backup directories
chmod 700 /etc/server-config-backup
chown root:root /etc/server-config-backup
```

### Audit Configuration
```bash
# Enable audit logging
auditctl -w /usr/local/bin/server-config -p x -k server-config
auditctl -w /etc/server-config-backup -p rwxa -k server-config-backups
```

### Monitoring Commands
```bash
# Monitor banned IPs
fail2ban-client status sshd

# Check firewall logs
tail -f /var/log/ufw.log

# Monitor SSH access
tail -f /var/log/auth.log | grep sshd
```

## 🚨 Troubleshooting Guide

### Common Issues and Solutions

#### 1. Permission Denied
```bash
# Check if running as root
sudo whoami

# Check file permissions
ls -la /usr/local/bin/server-config
```

#### 2. Port Already in Use
```bash
# Check what's using the port
ss -tlnp | grep :2222

# Choose a different port
sudo ./server-config --install --ssh-port 3333 --verbose
```

#### 3. Service Not Starting
```bash
# Check service status
systemctl status ssh
systemctl status fail2ban
systemctl status ufw

# Check logs
journalctl -u ssh -f
journalctl -u fail2ban -f
```

#### 4. Validation Failures
```bash
# Run with verbose output for debugging
sudo ./server-config --validate --verbose

# Check individual components
sudo ./server-config --validate --ssh-only --verbose
sudo ./server-config --validate --fail2ban --verbose
sudo ./server-config --validate --firewall --verbose
```

### Emergency Recovery
```bash
# Emergency rollback
sudo ./server-config --rollback --force --verbose

# Restart critical services
systemctl restart ssh
systemctl restart fail2ban
systemctl restart ufw

# Verify connectivity
ssh -p 2222 localhost
```

## 📈 Performance Considerations

### Resource Usage
```bash
# Monitor resource usage during configuration
top -p $(pgrep server-config)

# Check disk space for backups
df -h /etc/server-config-backup

# Monitor system load
uptime
```

### Optimization
```bash
# Use dry-run for testing to avoid unnecessary changes
sudo ./server-config --dry-run --validate --verbose

# Batch operations to reduce service restarts
sudo ./server-config --install --ssh-port 2222 --verbose
```

## 🔗 Integration Examples

### Ansible Integration
```yaml
---
- name: Secure server with server-config
  hosts: all
  become: yes
  tasks:
    - name: Create backup before changes
      command: /usr/local/bin/server-config --backup --verbose
      
    - name: Apply security configuration
      command: /usr/local/bin/server-config --install --ssh-port 2222 --verbose
      
    - name: Validate security configuration
      command: /usr/local/bin/server-config --validate --verbose
      register: validation
      
    - name: Fail if validation fails
      fail:
        msg: "Security validation failed"
      when: validation.rc != 0
```

### CI/CD Pipeline
```bash
#!/bin/bash
# Production deployment script

set -e

echo "Starting security hardening..."

# Pre-flight checks
sudo ./server-config --validate --verbose

# Create backup
sudo ./server-config --backup --verbose

# Apply configuration
sudo ./server-config --install --ssh-port 2222 --verbose

# Post-deployment validation
sudo ./server-config --validate --verbose

echo "Security hardening completed successfully!"
```

## 📋 Production Checklist

### Pre-Deployment
- [ ] Test in staging environment
- [ ] Verify system requirements
- [ ] Check available disk space
- [ ] Validate network connectivity
- [ ] Create current backup

### During Deployment
- [ ] Use dry-run mode first
- [ ] Monitor logs for errors
- [ ] Verify each step completes
- [ ] Test SSH connectivity
- [ ] Validate configuration

### Post-Deployment
- [ ] Run full validation
- [ ] Test all services
- [ ] Verify firewall rules
- [ ] Check Fail2Ban status
- [ ] Document configuration

### Ongoing Maintenance
- [ ] Regular validation checks
- [ ] Scheduled backups
- [ ] Log monitoring
- [ ] Security updates
- [ ] Performance monitoring

## 🎯 Success Metrics

### Security Metrics
- [ ] SSH running on non-standard port
- [ ] Firewall configured with deny-by-default
- [ ] Fail2Ban active with comprehensive rules
- [ ] No password authentication enabled
- [ ] All security validations passing

### Operational Metrics
- [ ] Zero downtime during deployment
- [ ] Fast rollback capability (< 30 seconds)
- [ ] Comprehensive logging and monitoring
- [ ] Automated validation passing
- [ ] Manual testing successful

## 📞 Support

For production support:
1. Check logs in `/var/log/server-config.log`
2. Run `sudo ./server-config --validate --verbose`
3. Review troubleshooting section above
4. Check system logs: `journalctl -u server-config -f`

---

**✅ This tool is production-ready and has been thoroughly tested with comprehensive safety features, error handling, and operational safeguards.**
