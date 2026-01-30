# Git Setup and Credential Management

This guide helps you configure Git to work with the rdk-wifi-hal repository, especially when managing multiple GitHub accounts (e.g., personal and enterprise accounts).

## Table of Contents
- [Quick Start](#quick-start)
- [Managing Multiple GitHub Accounts](#managing-multiple-github-accounts)
- [HTTPS Authentication](#https-authentication)
- [SSH Authentication](#ssh-authentication)
- [Troubleshooting](#troubleshooting)

## Quick Start

Before contributing, ensure you have:
1. A GitHub account with access to the rdkcentral organization
2. Signed the [RDK Contributor License Agreement (CLA)](CONTRIBUTING.md)
3. Git installed and configured

## Managing Multiple GitHub Accounts

If you have multiple GitHub accounts (personal and enterprise), you need to configure Git to use the correct credentials for this repository.

### Method 1: Repository-Specific Configuration (Recommended)

Configure Git credentials for just this repository:

```bash
cd /path/to/rdk-wifi-hal

# Set your name and email for this repository only
git config user.name "Your Name"
git config user.email "your.email@company.com"

# Verify the configuration
git config user.name
git config user.email
```

### Method 2: Conditional Configuration by Directory

If you work with multiple repositories from different organizations, you can configure Git to automatically use different credentials based on the directory.

Edit your global Git config (`~/.gitconfig`):

```ini
[user]
    name = Your Personal Name
    email = personal@example.com

# Automatically use work credentials for RDK repositories
[includeIf "gitdir:~/work/rdk*/"]
    path = ~/.gitconfig-work

[includeIf "gitdir:~/work/rdkcentral*/"]
    path = ~/.gitconfig-work
```

Then create `~/.gitconfig-work`:

```ini
[user]
    name = Your Work Name
    email = work@company.com
```

## HTTPS Authentication

### Using Personal Access Tokens (PAT)

GitHub requires Personal Access Tokens (PAT) for HTTPS authentication:

1. **Create a Personal Access Token:**
   - Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
   - Click "Generate new token (classic)"
   - Select scopes: `repo` (full control of private repositories)
   - Generate and copy the token

2. **Configure Git Credential Helper:**

   ```bash
   # Store credentials in memory for 1 hour
   git config --global credential.helper cache

   # Or store credentials permanently (less secure)
   git config --global credential.helper store

   # For macOS, use Keychain
   git config --global credential.helper osxkeychain

   # For Windows, use Credential Manager
   git config --global credential.helper manager
   ```

3. **Set Repository-Specific Remote URL with Token:**

   ```bash
   # Clone with token in URL (will be stored in credential helper)
   git clone https://YOUR_TOKEN@github.com/rdkcentral/rdk-wifi-hal.git

   # Or update existing repository
   cd rdk-wifi-hal
   git remote set-url origin https://YOUR_TOKEN@github.com/rdkcentral/rdk-wifi-hal.git
   ```

### Clearing Cached Credentials

If you need to switch accounts or update credentials:

```bash
# Clear cached credentials
git credential reject
# Then paste:
protocol=https
host=github.com
# Press Ctrl+D (Unix) or Ctrl+Z (Windows)

# Or clear stored credentials
git config --global --unset credential.helper
rm ~/.git-credentials  # If using credential.helper store
```

## SSH Authentication

SSH keys provide a more secure and convenient authentication method.

### Setting Up Multiple SSH Keys

1. **Generate SSH Keys for Each Account:**

   ```bash
   # Personal account key
   ssh-keygen -t ed25519 -C "personal@example.com" -f ~/.ssh/id_ed25519_personal

   # Work/Enterprise account key
   ssh-keygen -t ed25519 -C "work@company.com" -f ~/.ssh/id_ed25519_work
   ```

2. **Add Keys to SSH Agent:**

   ```bash
   eval "$(ssh-agent -s)"
   ssh-add ~/.ssh/id_ed25519_personal
   ssh-add ~/.ssh/id_ed25519_work
   ```

3. **Add Public Keys to GitHub:**
   - Copy public key: `cat ~/.ssh/id_ed25519_work.pub`
   - Go to GitHub Settings → SSH and GPG keys → New SSH key
   - Paste the public key

4. **Configure SSH for Multiple Accounts:**

   Create/edit `~/.ssh/config`:

   ```
   # Personal GitHub account
   Host github.com-personal
       HostName github.com
       User git
       IdentityFile ~/.ssh/id_ed25519_personal

   # Work GitHub account (for RDK repositories)
   Host github.com-work
       HostName github.com
       User git
       IdentityFile ~/.ssh/id_ed25519_work
   ```

5. **Use the Appropriate SSH Host:**

   ```bash
   # Clone using work account
   git clone git@github.com-work:rdkcentral/rdk-wifi-hal.git

   # Or update existing repository
   cd rdk-wifi-hal
   git remote set-url origin git@github.com-work:rdkcentral/rdk-wifi-hal.git
   ```

## Troubleshooting

### Error: "Permission denied" or "403 Forbidden"

This usually means Git is using the wrong credentials.

**Solution:**
```bash
# 1. Check which account Git is using
git config user.name
git config user.email

# 2. Verify remote URL
git remote -v

# 3. Clear cached credentials (for HTTPS)
git credential reject
protocol=https
host=github.com
# Press Ctrl+D

# 4. Try pushing again - Git will prompt for credentials
git push
```

### Error: "fatal: unable to access 'https://github.com/rdkcentral/...': The requested URL returned error: 403"

This error indicates:
- You're using HTTPS with incorrect credentials
- Your Personal Access Token (PAT) has expired or lacks permissions
- Git is using cached credentials from a different account

**Solutions:**

1. **Clear and update credentials:**
   ```bash
   # Clear credential cache
   git credential-cache exit
   
   # Or if using credential store
   git config --global --unset credential.helper
   rm ~/.git-credentials
   
   # Reconfigure and try again
   git config credential.helper cache
   git push
   ```

2. **Generate a new Personal Access Token:**
   - Ensure it has `repo` scope
   - Update the token in your credential helper

3. **Switch to SSH authentication** (recommended for multiple accounts)

### Checking Which Credentials Are Being Used

```bash
# Check local repository configuration
git config --list --local

# Check global configuration
git config --list --global

# Check effective configuration (includes system, global, and local)
git config --list

# Test SSH connection
ssh -T git@github.com
# Should output: "Hi USERNAME! You've successfully authenticated..."

# Test with specific SSH config host
ssh -T git@github.com-work
```

### Switching Between Accounts for a Single Repository

If you need to temporarily use a different account:

```bash
# Method 1: Temporarily override user
GIT_COMMITTER_NAME="Work Name" GIT_COMMITTER_EMAIL="work@company.com" \
GIT_AUTHOR_NAME="Work Name" GIT_AUTHOR_EMAIL="work@company.com" \
git commit -m "Your commit message"

# Method 2: Update repository config
git config user.name "Work Name"
git config user.email "work@company.com"
git commit -m "Your commit message"

# Method 3: Amend the last commit with different author
git commit --amend --author="Work Name <work@company.com>"
```

## Best Practices

1. **Use SSH keys** when working with multiple accounts - it's more secure and convenient
2. **Set repository-specific config** rather than global config when working with multiple accounts
3. **Use credential helpers** to avoid repeatedly entering passwords
4. **Never commit tokens or credentials** to the repository
5. **Use Personal Access Tokens (PAT)** instead of passwords for HTTPS authentication
6. **Regularly rotate** your SSH keys and Personal Access Tokens

## Additional Resources

- [GitHub: Managing Multiple Accounts](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-your-personal-account/managing-multiple-accounts)
- [GitHub: Connecting with SSH](https://docs.github.com/en/authentication/connecting-to-github-with-ssh)
- [GitHub: Creating a Personal Access Token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)
- [Git Credential Storage](https://git-scm.com/book/en/v2/Git-Tools-Credential-Storage)

## Getting Help

If you continue to experience authentication issues:
1. Verify you have signed the [RDK Contributor License Agreement (CLA)](CONTRIBUTING.md)
2. Ensure your GitHub account has access to the rdkcentral organization
3. Check the repository's Issues page for similar problems
4. Contact the repository maintainers
