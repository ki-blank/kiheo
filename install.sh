#!/usr/bin/env bash
#
# install.sh
# Pemasang sederhana untuk kevps-zivpn dari GitHub.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/ki-blank/kiheo/main/install.sh | sudo bash
#
set -euo pipefail

# Raw URL ke skrip utama di repo Anda
GITHUB_RAW="https://raw.githubusercontent.com/ki-blank/kiheo/main/kevps-zivpn-installer.sh"
TARGET="/usr/local/bin/kevps-zivpn"

echo "Mengunduh kevps-zivpn dari GitHub..."
curl -fsSL "$GITHUB_RAW" -o /tmp/kevps-zivpn-installer.sh || { echo "Gagal mengunduh: $GITHUB_RAW"; exit 1; }
chmod +x /tmp/kevps-zivpn-installer.sh

echo "Menginstall ke $TARGET ..."
mv /tmp/kevps-zivpn-installer.sh "$TARGET"
chmod +x "$TARGET"

echo "Selesai. Jalankan: sudo kevps-zivpn"
echo "Untuk update nanti jalankan: sudo kevps-zivpn update"
