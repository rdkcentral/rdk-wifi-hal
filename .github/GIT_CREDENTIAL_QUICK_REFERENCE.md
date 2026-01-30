# Git Credential Quick Reference

Quick commands for managing Git credentials when working with multiple GitHub accounts.

## Quick Diagnostics

```bash
# Who am I configured as for this repository?
git config user.name
git config user.email

# What remote am I pushing to?
git remote -v

# What's my current configuration?
git config --list --local
```

## Switch Accounts for This Repository

```bash
# Switch to work/enterprise account
git config user.name "Your Work Name"
git config user.email "work@company.com"

# Switch to personal account
git config user.name "Your Personal Name"
git config user.email "personal@example.com"

# Verify the change
git config user.name && git config user.email
```

## Clear Credentials (when authentication fails)

```bash
# Method 1: Clear cache
git credential-cache exit

# Method 2: Clear stored credentials
git credential reject
# Then type these lines and press Ctrl+D (Unix) or Ctrl+Z (Windows):
protocol=https
host=github.com

# Method 3: Reset credential helper
git config --global --unset credential.helper
rm ~/.git-credentials  # if it exists
```

## Common Error Fixes

### "403 Forbidden" or "Permission denied"

```bash
# 1. Check who you are
git config user.name && git config user.email

# 2. Clear credentials
git credential-cache exit

# 3. Try again - Git will prompt for new credentials
git push
```

### "unable to access" or "authentication failed"

```bash
# Clear all cached credentials and reconfigure
git credential reject <<EOF
protocol=https
host=github.com
EOF

git push  # Will prompt for credentials again
```

## Switch to SSH (Recommended for Multiple Accounts)

```bash
# Update remote to use SSH
git remote set-url origin git@github.com:rdkcentral/rdk-wifi-hal.git

# Verify
git remote -v

# Test SSH connection
ssh -T git@github.com
```

## More Information

See the complete [Git Setup and Credential Management Guide](../GIT_SETUP.md) for detailed instructions.
