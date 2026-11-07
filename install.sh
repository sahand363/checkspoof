#!/bin/bash
set -e

REPO="sahand363/checkspoof"
echo "[+] Fetching latest release binary from $REPO..."

DOWNLOAD_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep "browser_download_url" | cut -d '"' -f 4)

if [ -z "$DOWNLOAD_URL" ]; then
    echo "[-] Error: Release binary not found. Ensure GitHub Actions completed successfully."
    exit 1
fi

echo "[+] Downloading binary to /usr/local/bin/checkspoof..."
sudo curl -L -o /usr/local/bin/checkspoof "$DOWNLOAD_URL"
sudo chmod +x /usr/local/bin/checkspoof

echo "[+] Installation successful! You can run CheckSpoof as root using:"
echo "    sudo checkspoof"
