#!/bin/bash
set -e

REPO="sahand333/checkspoof"
echo "[+] Fetching latest release download URL for $REPO..."

# Get the latest download URL for the binary from GitHub API
DOWNLOAD_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep "browser_download_url" | cut -d '"' -f 4)

if [ -z "$DOWNLOAD_URL" ]; then
    echo "[-] Error: Could not find latest release binary. Make sure GitHub Actions has finished successfully."
    exit 1
fi

echo "[+] Downloading binary from $DOWNLOAD_URL..."
sudo curl -L -o /usr/local/bin/checkspoof "$DOWNLOAD_URL"
sudo chmod +x /usr/local/bin/checkspoof

echo "[+] Installation complete! You can now run the tool using:"
echo "    sudo checkspoof"
