
# Run automated installation script from git-credential-manager 
# Ref https://github.com/git-ecosystem/git-credential-manager/blob/main/docs/install.md
echo "Installing Git-credential-manager"
curl -L https://aka.ms/gcm/linux-install-source.sh | sh
git-credential-manager configure

# Configure default credential helper
echo "Configuring Git to use Git Credential Manager..."
git config --global credential.helper "/usr/local/bin/git-credential-manager"

# Configure GPG as the storage mechanism
echo "Configuring GPG as the storage mechanism..."
git config --global credential.gpgprogram gpg
git config --global gpg.program gpg

echo "Git configuration with Git Credential Manager and GPG is complete!"