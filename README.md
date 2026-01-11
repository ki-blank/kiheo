# kiheo

```markdown
# kevps-zivpn (Bahasa Indonesia)

Installer & manager lengkap untuk ZIVPN (SSH/Dropbear, BadVPN UDP, XRay VLESS, Nginx + TLS) — versi terjemahan bahasa Indonesia siap pakai untuk repo Anda.

Fitur utama:
- Menu interaktif berwarna dengan tampilan ASCII (mirip screenshot).
- Buat/Hapus/Perpanjang akun SSH.
- Buat/Hapus/Daftar akun VLESS (XRay).
- Menghasilkan file OpenClash (Clash YAML) per user dan vless-<user>.txt.
- TLS otomatis via acme.sh (Let's Encrypt).
- Cron: auto-clean akun kadaluarsa, backup harian, ip-monitor (cek batas IP).
- Suspend cerdas saat melebihi batas IP:
  - Jika IP unik untuk user → hapus client dari config XRay (restart XRay).
  - Jika IP dipakai bersama → blokir IP via iptables (tanpa restart XRay).
- Menu untuk melihat akun yang disuspend dan membuka blokirnya.
- Dapat di-install/update/uninstall dari GitHub raw.

Penting:
- Jalankan hanya di server yang Anda miliki.
- Pastikan DNS A record domain mengarah ke IP VPS sebelum menggunakan opsi issue TLS.
- Review skrip sebelum menjalankan (keamanan).
- Jika server Anda memakai nftables/ufw, aturan iptables mungkin perlu disesuaikan.

Cara men-setup repo & commit:
1. Pastikan repo ini (https://github.com/ki-blank/kiheo) berisi file:
   - `install.sh`
   - `kevps-zivpn-installer.sh`
   - `README.md` (file ini)
2. Edit variabel `GITHUB_RAW` di `install.sh` dan `kevps-zivpn-installer.sh` (sudah diisi untuk repo ini).
   - Contoh: https://raw.githubusercontent.com/ki-blank/kiheo/main/kevps-zivpn-installer.sh
3. Commit & push:
```bash
git add install.sh kevps-zivpn-installer.sh README.md
git commit -m "Menambahkan installer ZIVPN (versi bahasa Indonesia)"
git push origin main
```

Cara install di VPS:
1. Jalankan perintah (di VPS):
```bash
curl -sSL https://raw.githubusercontent.com/ki-blank/kiheo/main/install.sh | sudo bash
```
2. Jalankan manager:
```bash
sudo kevps-zivpn
```

Perintah manajemen:
- `sudo kevps-zivpn` → jalankan menu interaktif
- `sudo kevps-zivpn install` → install/update dari raw GitHub ke /usr/local/bin/kevps-zivpn
- `sudo kevps-zivpn update` → update dari GitHub raw
- `sudo kevps-zivpn uninstall` → hapus installer dari /usr/local/bin

Rekomendasi:
- Untuk produksi, gunakan GitHub Releases dan verifikasi checksum sebelum `curl | bash`.
- Jika Anda ingin saya tambahkan GitHub Actions untuk membuat release otomatis, beri tahu saya.

Jika ingin bantuan deploy langsung (langkah per langkah) atau penambahan fitur (VMess/Trojan/gRPC, panel web, control API XRay), beri tahu saya fitur mana yang diinginkan.
```
