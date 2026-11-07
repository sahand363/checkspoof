#!/bin/bash
set -e

REPO="sahand363/checkspoof"
echo "[+] Fetching latest release binary from $REPO..."

DOWNLOAD_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep "browser_download_url" | cut -d '"' -f 4)

if [ -z "$DOWNLOAD_URL" ]; then
    echo "[-] Error: Release binary not found. Ensure GitHub Actions has finished building."
    exit 1
fi

echo "[+] Downloading CheckSpoof to /usr/local/bin/checkspoof..."
sudo rm -f /usr/local/bin/checkspoof
sudo curl -L -o /usr/local/bin/checkspoof "$DOWNLOAD_URL"
sudo chmod +x /usr/local/bin/checkspoof

echo "[+] Installation complete!"
