#!/usr/bin/env bash
#
# kevps-zivpn-installer.sh
# Installer & manager lengkap untuk ZIVPN (SSH/Dropbear, Badvpn, XRay VLESS, Nginx + TLS)
# Versi bahasa Indonesia, siap dipublikasikan di repo: ki-blank/kiheo
#
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ===== Konfigurasi =====
GITHUB_RAW="https://raw.githubusercontent.com/ki-blank/kiheo/main/kevps-zivpn-installer.sh"
SYSTEM_BIN="/usr/local/bin/kevps-zivpn"

DB_DIR="/etc/zivpn"
DB_FILE="${DB_DIR}/users.db"      # Format CSV: username,type,expiry_unix,quota_gb,ip_limit,uuid
SUSPENDED="${DB_DIR}/suspended.db"
BACKUP_DIR="/root/zivpn-backup"
XRAY_CONFIG="/etc/xray/config.json"
DOMAIN_FILE="${DB_DIR}/domain"
LOG="/var/log/zivpn-installer.log"
XRAY_BIN="/usr/local/bin/xray"
ACME_HOME="/root/.acme.sh"

# Warna
RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; BLUE="\e[34m"; MAG="\e[35m"; CYAN="\e[36m"; RESET="\e[0m"

log() { echo -e "$(date '+%F %T') - $*" | tee -a "$LOG"; }
die() { echo -e "${RED}ERROR:${RESET} $*"; exit 1; }
ensure_root() { [ "$(id -u)" -eq 0 ] || die "Jalankan sebagai root"; }

# ===== Persiapan =====
prepare_dirs() {
  mkdir -p "$DB_DIR" "$BACKUP_DIR" /var/www/html /etc/xray /var/log
  touch "$DB_FILE" "$SUSPENDED" "$LOG"
}

apt_install() {
  log "Memperbarui apt dan menginstall paket dasar..."
  apt update -y
  apt install -y curl wget gnupg2 ca-certificates lsb-release jq unzip nginx openssh-server dropbear iptables iproute2 \
    net-tools cron socat openssl bc software-properties-common || true
}

# ===== XRay =====
install_xray() {
  if command -v xray >/dev/null 2>&1 || [ -f "$XRAY_BIN" ]; then
    log "Xray sudah terpasang - lewati pemasangan."
    return
  fi
  log "Mengunduh dan memasang Xray-core terbaru..."
  tag="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)"
  tmpd="$(mktemp -d)"
  url="https://github.com/XTLS/Xray-core/releases/download/${tag}/Xray-linux-64.zip"
  wget -qO "${tmpd}/xray.zip" "$url"
  unzip -o "${tmpd}/xray.zip" -d "$tmpd"
  install -m 755 "${tmpd}/xray" "$XRAY_BIN"
  rm -rf "$tmpd"
  cat >/etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=XRay Service
After=network.target nss-lookup.target
[Service]
User=root
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now xray || true
  log "Xray terpasang."
}

write_xray_template() {
  if [ -f "$XRAY_CONFIG" ]; then
    log "Konfigurasi xray sudah ada. Backup lalu lewati penulisan template."
    cp -f "$XRAY_CONFIG" "${XRAY_CONFIG}.bak-$(date +%F-%H%M)" || true
    return
  fi
  cat >"$XRAY_CONFIG" <<'JSON'
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": { "clients": [] },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "wsSettings": { "path": "/vless" }
      }
    },
    {
      "port": 80,
      "listen": "127.0.0.1",
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "settings": {} },
    { "protocol": "blackhole", "tag": "blocked" }
  ],
  "routing": { "domainStrategy": "AsIs" }
}
JSON
  systemctl restart xray || true
  log "Template xray ditulis."
}

# ===== acme.sh dan nginx =====
install_acme() {
  if [ -d "$ACME_HOME" ]; then
    log "acme.sh sudah ada."
    return
  fi
  log "Memasang acme.sh untuk sertifikat Let's Encrypt..."
  curl -sSfLo /root/acme_install.sh https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh
  bash /root/acme_install.sh --install --nocron
  export PATH="$HOME/.acme.sh:$PATH"
}

issue_cert() {
  domain="$1"
  [ -n "$domain" ] || die "Domain dibutuhkan"
  log "Menerbitkan sertifikat untuk $domain (mode standalone)..."
  systemctl stop nginx || true
  "$ACME_HOME"/acme.sh --issue -d "$domain" --standalone --keylength ec-256 || die "Gagal issue acme"
  "$ACME_HOME"/acme.sh --install-cert -d "$domain" \
    --fullchain-file "/etc/ssl/private/${domain}.crt" \
    --key-file "/etc/ssl/private/${domain}.key" --ecc || die "Gagal install sertifikat"
  chmod 600 /etc/ssl/private/"${domain}.key"
  systemctl start nginx || true
  log "Sertifikat terpasang di /etc/ssl/private/${domain}.{crt,key}"
}

nginx_setup() {
  domain="$1"
  cert="/etc/ssl/private/${domain}.crt"
  key="/etc/ssl/private/${domain}.key"
  mkdir -p /var/www/html
  cat >/etc/nginx/sites-available/zivpn.conf <<NGCFG
server {
  listen 80;
  server_name ${domain};
  root /var/www/html;
  location /.well-known/acme-challenge/ { allow all; root /var/www/html; }
  location / { try_files \$uri \$uri/ =404; }
}
server {
  listen 443 ssl http2;
  server_name ${domain};
  ssl_certificate ${cert};
  ssl_certificate_key ${key};
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers HIGH:!aNULL:!MD5;
  root /var/www/html;
  location /vless {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:80;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
  }
  location / { try_files \$uri \$uri/ =404; }
}
NGCFG
  ln -sf /etc/nginx/sites-available/zivpn.conf /etc/nginx/sites-enabled/zivpn.conf
  nginx -t && systemctl reload nginx || true
  log "Nginx dikonfigurasi untuk domain $domain"
}

# ===== DB helpers =====
add_db_record() {
  user="$1"; type="$2"; expiry="$3"; quota="$4"; iplimit="$5"; uuid="${6:-}"
  echo "${user},${type},${expiry},${quota},${iplimit},${uuid}" >>"$DB_FILE"
}
remove_db_record() {
  user="$1"
  grep -v "^${user}," "$DB_FILE" > "${DB_FILE}.tmp" && mv "${DB_FILE}.tmp" "$DB_FILE"
}
get_domain() { [ -f "$DOMAIN_FILE" ] && cat "$DOMAIN_FILE" || echo "your.domain.tld"; }

# ===== SSH account =====
create_ssh_user() {
  read -rp "Username: " user
  read -rp "Password (kosong=acak): " pass
  read -rp "Expired (hari): " days
  read -rp "Kuota GB (0=tanpa batas): " quota
  read -rp "Batas IP (jumlah IP unik): " iplimit
  [ -n "$user" ] || { echo "Username kosong"; return; }
  if [ -z "$pass" ]; then pass="$(openssl rand -base64 12)"; fi
  useradd -M -s /bin/false "$user" >/dev/null 2>&1 || die "Gagal useradd (mungkin sudah ada)"
  echo "${user}:${pass}" | chpasswd
  expiry_unix=$(date -d "+${days} days" +%s)
  chage -E "$(date -d "@$expiry_unix" +%Y-%m-%d)" "$user" || true
  add_db_record "$user" "ssh" "$expiry_unix" "$quota" "$iplimit" ""
  echo -e "${GREEN}SSH dibuat:${RESET} $user | pass:$pass | expire:$(date -d "@$expiry_unix" +%F)"
}

delete_ssh_user() {
  read -rp "Username yang akan dihapus: " user
  id "$user" >/dev/null 2>&1 && userdel -r "$user" || log "User tidak ditemukan"
  remove_db_record "$user"
  echo "Selesai menghapus $user"
}

extend_account() {
  read -rp "Username yang akan diperpanjang: " user
  read -rp "Tambahan hari: " days
  rec="$(grep "^${user}," "$DB_FILE" || true)"
  [ -n "$rec" ] || { echo "Tidak ditemukan"; return; }
  IFS=, read -r u t expiry quota iplim uuid <<<"$rec"
  newexpiry=$((expiry + days*24*3600))
  grep -v "^${user}," "$DB_FILE" > "${DB_FILE}.tmp" && mv "${DB_FILE}.tmp" "$DB_FILE"
  add_db_record "$user" "$t" "$newexpiry" "$quota" "$iplim" "$uuid"
  [ "$t" = "ssh" ] && id "$user" >/dev/null 2>&1 && chage -E "$(date -d "@$newexpiry" +%Y-%m-%d)" "$user" || true
  echo "Perpanjangan selesai. Berakhir pada $(date -d "@$newexpiry" +%F)"
}

# ===== VLESS + OpenClash =====
create_vless_user() {
  read -rp "Remarks/username: " user
  read -rp "Expired (hari): " days
  read -rp "Kuota GB (0=tanpa batas): " quota
  read -rp "Batas IP (jumlah IP unik): " iplimit
  [ -n "$user" ] || { echo "Username kosong"; return; }
  domain="$(get_domain)"
  uuid="$(cat /proc/sys/kernel/random/uuid)"
  expiry_unix=$(date -d "+${days} days" +%s)

  tmp="$(mktemp)"
  jq --arg id "$uuid" --arg email "$user" '.inbounds[0].settings.clients += [{"id":$id,"email":$email}]' "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
  systemctl restart xray || true

  add_db_record "$user" "vless" "$expiry_unix" "$quota" "$iplimit" "$uuid"

  TLS_PORT=443; NTLS_PORT=80; path="/vless"; sni="$domain"
  link_tls="vless://${uuid}@${domain}:${TLS_PORT}?path=${path}&security=tls&encryption=none&type=ws&sni=${sni}#${user}"
  link_ntls="vless://${uuid}@${domain}:${NTLS_PORT}?path=${path}&security=none&encryption=none&type=ws#${user}"
  link_grpc="vless://${uuid}@${domain}:${TLS_PORT}?mode=gun&security=tls&serviceName=vless-grpc#${user}"

  mkdir -p /var/www/html
  yaml_file="/var/www/html/openclash-${user}.yaml"
  cat > "$yaml_file" <<YAML
proxies:
  - name: ${user}-vless-tls
    type: vless
    server: ${domain}
    port: ${TLS_PORT}
    uuid: ${uuid}
    cipher: auto
    tls: true
    network: ws
    ws-path: ${path}
    ws-headers:
      Host: ${domain}
  - name: ${user}-vless-ntls
    type: vless
    server: ${domain}
    port: ${NTLS_PORT}
    uuid: ${uuid}
    cipher: auto
    tls: false
    network: ws
    ws-path: ${path}
    ws-headers:
      Host: ${domain}
proxy-groups:
  - name: "Auto"
    type: select
    proxies:
      - ${user}-vless-tls
      - ${user}-vless-ntls
rules:
  - MATCH,Auto
YAML

  txt_file="/var/www/html/vless-${user}.txt"
  cat > "$txt_file" <<EOF
Link TLS=${link_tls}
Link NTLS=${link_ntls}
Link GRPC=${link_grpc}
OpenClash YAML: https://${domain}/openclash-${user}.yaml
EOF

  systemctl reload nginx || true

  echo -e "${GREEN}VLESS dibuat:${RESET} ${user}"
  printf "UUID: %s\nTLS Link: %s\nNTLS Link: %s\nGRPC Link: %s\nOpenClash: https://%s/openclash-%s.yaml\nDibuat: %s\nKadaluwarsa: %s\n" \
    "$uuid" "$link_tls" "$link_ntls" "$link_grpc" "$domain" "$user" "$(date '+%F')" "$(date -d "@$expiry_unix" +%F)"
}

delete_vless_user() {
  read -rp "VLESS username yang akan dihapus: " user
  rec="$(grep "^${user}," "$DB_FILE" || true)"
  [ -n "$rec" ] || { echo "Tidak ditemukan"; return; }
  IFS=, read -r u t e q iplim uuid <<<"$rec"
  tmpcfg="$(mktemp)"
  jq --arg id "$uuid" '(.inbounds[0].settings.clients) |= map(select(.id != $id))' "$XRAY_CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$XRAY_CONFIG"
  systemctl restart xray || true
  remove_db_record "$user"
  rm -f /var/www/html/openclash-"$user".yaml /var/www/html/vless-"$user".txt
  echo "Selesai menghapus vless user $user"
}

# ===== List & Info =====
list_users() {
  printf "%-15s %-6s %-12s %-6s %-6s %s\n" "USERNAME" "TYPE" "EXPIRES" "QUOTA" "IP_LIM" "UUID"
  while IFS=, read -r u t e q iplim uuid; do
    [ -z "$u" ] && continue
    printf "%-15s %-6s %-12s %-6s %-6s %s\n" "$u" "$t" "$(date -d "@$e" +%F)" "$q" "$iplim" "$uuid"
  done < "$DB_FILE"
  read -rp "Tekan enter untuk kembali..."
}

info_ports() {
  echo -e "${BLUE}=== INFORMASI PORT SERVICE ===${RESET}"
  ss -tulpn | sed -n '1,200p'
  echo -e "${BLUE}==============================${RESET}"
  read -rp "Tekan enter..."
}

# ===== Suspend / Unblock =====
suspend_user() {
  user="$1"; method="$2"; uuid="$3"; ips_csv="$4"; orig_rec="$5"
  ts=$(date +%s)
  echo "${user},${method},${orig_rec},${ips_csv},${ts}" >> "$SUSPENDED"
  if [ "$method" = "iptables" ]; then
    IFS=',' read -ra IPS <<<"$ips_csv"
    for ip in "${IPS[@]}"; do
      ip_trim="$(echo "$ip" | xargs)"
      [ -z "$ip_trim" ] && continue
      iptables -I INPUT -s "$ip_trim" -m comment --comment "zivpn-${user}" -j DROP || true
    done
    log "User $user disuspend dengan memblokir IP: $ips_csv"
  elif [ "$method" = "remove" ]; then
    tmpcfg="$(mktemp)"
    jq --arg id "$uuid" '(.inbounds[0].settings.clients) |= map(select(.id != $id))' "$XRAY_CONFIG" > "$tmpcfg" && mv "$tmpcfg" "$XRAY_CONFIG"
    systemctl restart xray || true
    log "User $user disuspend dengan menghapus client dari xray (restart dilakukan)."
  fi
  grep -v "^${user}," "$DB_FILE" > "${DB_FILE}.tmp" && mv "${DB_FILE}.tmp" "$DB_FILE"
}

unblock_user() {
  read -rp "Username yang akan dibuka blokirnya: " user
  rec="$(grep -a "^${user}," "$SUSPENDED" || true)"
  [ -n "$rec" ] || { echo "Tidak ada record suspend untuk $user"; return; }
  line="$(echo "$rec" | head -n1)"
  method="$(echo "$line" | awk -F',' '{print $2}')"
  ts="$(echo "$line" | awk -F',' '{print $NF}')"
  ips_csv="$(echo "$line" | awk -F',' '{print $(NF-1)}')"
  orig_rec="$(echo "$line" | awk -F',' '{for(i=3;i<=NF-2;i++){printf $i; if(i<NF-2) printf ","}}')"
  IFS=',' read -r u t e q iplim uuid <<<"$orig_rec"
  if [ "$method" = "iptables" ]; then
    IFS=',' read -ra IPS <<<"$ips_csv"
    for ip in "${IPS[@]}"; do
      ip_trim="$(echo "$ip" | xargs)"
      [ -z "$ip_trim" ] && continue
      while iptables -C INPUT -s "$ip_trim" -m comment --comment "zivpn-${user}" -j DROP >/dev/null 2>&1; do
        iptables -D INPUT -s "$ip_trim" -m comment --comment "zivpn-${user}" -j DROP || true
      done
    done
    echo "${u},${t},${e},${q},${iplim},${uuid}" >> "$DB_FILE"
    log "Menghapus pemblokiran iptables untuk $user: $ips_csv"
  elif [ "$method" = "remove" ]; then
    tmp="$(mktemp)"
    jq --arg id "$uuid" --arg email "$u" '.inbounds[0].settings.clients += [{"id":$id,"email":$email}]' "$XRAY_CONFIG" > "$tmp" && mv "$tmp" "$XRAY_CONFIG"
    systemctl restart xray || true
    echo "${u},${t},${e},${q},${iplim},${uuid}" >> "$DB_FILE"
    log "Mengembalikan user $user ke xray config dan menambahkan kembali ke DB."
  fi
  grep -v "^${user}," "$SUSPENDED" > "${SUSPENDED}.tmp" && mv "${SUSPENDED}.tmp" "$SUSPENDED"
  echo "Selesai membuka blokir $user"
}

get_ips_for_uuid() {
  uuid="$1"
  logfile="/var/log/xray/access.log"
  [ -f "$logfile" ] || { echo ""; return; }
  ips="$(grep -a "$uuid" "$logfile" 2>/dev/null | awk '{print $1}' | sed '/^$/d' | sort -u | paste -sd',' -)"
  echo "$ips"
}

ips_shared_with_others() {
  uuid="$1"
  ips_csv="$2"
  logfile="/var/log/xray/access.log"
  [ -f "$logfile" ] || { return 1; }
  IFS=',' read -ra IPS <<<"$ips_csv"
  for ip in "${IPS[@]}"; do
    ip_trim="$(echo "$ip" | xargs)"
    [ -z "$ip_trim" ] && continue
    uuids_seen="$(grep -a "$ip_trim" "$logfile" | grep -oE '[0-9a-fA-F\-]{36}' | sort -u | wc -l || true)"
    if [ -z "$uuids_seen" ]; then uuids_seen=0; fi
    if [ "$uuids_seen" -gt 1 ]; then
      return 1
    fi
  done
  return 0
}

# ===== IP monitor cron =====
ip_limit_monitor() {
  logfile="/var/log/xray/access.log"
  [ -f "$logfile" ] || { log "Tidak ada xray access.log, lewati ip monitor"; return; }
  while IFS=, read -r user type expiry quota iplimit uuid; do
    [ -z "$user" ] && continue
    [ "$type" != "vless" ] && continue
    [ -z "$uuid" ] && continue
    if [ "$iplimit" -gt 0 ]; then
      ips="$(get_ips_for_uuid "$uuid")"
      if [ -z "$ips" ]; then continue; fi
      cnt="$(echo "$ips" | sed 's/,/\n/g' | sed '/^$/d' | wc -l | tr -d ' ')"
      if [ "$cnt" -gt "$iplimit" ]; then
        log "Batas IP terlampaui untuk $user ($cnt > $iplimit). Menentukan aksi..."
        if ips_shared_with_others "$uuid" "$ips"; then
          method="remove"
        else
          method="iptables"
        fi
        orig_rec="${user},${type},${expiry},${quota},${iplimit},${uuid}"
        suspend_user "$user" "$method" "$uuid" "$ips" "$orig_rec"
      fi
    fi
  done < "$DB_FILE"
}

# ===== Backup & restore =====
backup_now() {
  ts="$(date +%F-%H%M)"
  mkdir -p "$BACKUP_DIR"
  tar czf "${BACKUP_DIR}/zivpn-backup-${ts}.tgz" /etc/xray /etc/nginx /etc/zivpn /var/www/html --warning=no-file-changed || true
  log "Backup dibuat: ${BACKUP_DIR}/zivpn-backup-${ts}.tgz"
}
restore_menu() {
  echo "Daftar backup tersedia:"
  ls -1 "$BACKUP_DIR" || echo "Tidak ada backup"
  read -rp "Masukkan nama file backup untuk restore: " f
  if [ -f "${BACKUP_DIR}/${f}" ]; then
    tar xzf "${BACKUP_DIR}/${f}" -C / || die "Restore gagal"
    systemctl restart nginx xray || true
    echo "Restore selesai."
  else
    echo "File tidak ditemukan."
  fi
}

# ===== Cron setup =====
setup_cronjobs() {
  log "Menambahkan cron jobs (auto-clean, backup, ip-monitor)..."
  (crontab -l 2>/dev/null | grep -v zivpn) > /tmp/crontab.$$ || true
  echo "10 3 * * * /usr/local/bin/kevps-zivpn auto-clean >/dev/null 2>&1" >> /tmp/crontab.$$
  echo "30 2 * * * /usr/local/bin/kevps-zivpn auto-backup >/dev/null 2>&1" >> /tmp/crontab.$$
  echo "*/5 * * * * /usr/local/bin/kevps-zivpn ip-monitor >/dev/null 2>&1" >> /tmp/crontab.$$
  crontab /tmp/crontab.$$
  rm -f /tmp/crontab.$$

  cat >/usr/local/bin/kevps-zivpn-run <<'BASH'
#!/usr/bin/env bash
if [ -x /usr/local/bin/kevps-zivpn ]; then
  /usr/local/bin/kevps-zivpn "$@"
fi
BASH
  chmod +x /usr/local/bin/kevps-zivpn-run

  cat >/etc/zivpn/auto-clean.sh <<'BASH'
#!/usr/bin/env bash
/usr/local/bin/kevps-zivpn auto-clean
BASH
  chmod +x /etc/zivpn/auto-clean.sh

  cat >/etc/zivpn/auto-backup.sh <<'BASH'
#!/usr/bin/env bash
/usr/local/bin/kevps-zivpn auto-backup
BASH
  chmod +x /etc/zivpn/auto-backup.sh

  cat >/etc/zivpn/ip-monitor.sh <<'BASH'
#!/usr/bin/env bash
/usr/local/bin/kevps-zivpn ip-monitor
BASH
  chmod +x /etc/zivpn/ip-monitor.sh

  log "Cron dan wrapper terpasang."
}

restart_all() {
  systemctl restart nginx xray ssh dropbear || true
  log "Semua service direstart."
}

# ===== Tampilan ASCII =====
draw_header() {
  clear
  domain="$(get_domain)"
  cat <<EOF
${CYAN}╔════════════════════════════════════════════════════════════════╗${RESET}
${CYAN}║${RESET} ${MAG}SELAMAT DATANG DI SCRIPT KEVPS ZIVPN (Bahasa Indonesia)${RESET} ${CYAN}║${RESET}
${CYAN}╚════════════════════════════════════════════════════════════════╝${RESET}
Sistem: ${YELLOW}Ubuntu 22.04 LTS${RESET}   Domain: ${YELLOW}${domain}${RESET}
EOF
  echo
}

show_suspended() {
  printf "%-15s %-10s %-20s %-8s %s\n" "USERNAME" "METODE" "IPS" "TS" "ORIG_REC"
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    user="$(echo "$line" | awk -F',' '{print $1}')"
    method="$(echo "$line" | awk -F',' '{print $2}')"
    ts="$(echo "$line" | awk -F',' '{print $NF}')"
    ips="$(echo "$line" | awk -F',' '{print $(NF-1)}')"
    orig_rec="$(echo "$line" | awk -F',' '{for(i=3;i<=NF-2;i++){printf $i; if(i<NF-2) printf ","}}')"
    printf "%-15s %-10s %-20s %-8s %s\n" "$user" "$method" "$ips" "$ts" "$orig_rec"
  done < "$SUSPENDED"
  read -rp "Tekan enter..."
}

# ===== Menu utama =====
main_menu() {
  while true; do
    draw_header
    echo "1) Install dasar (deps, xray, template nginx)"
    echo "2) Ganti domain & terbitkan TLS"
    echo "3) Buat akun SSH"
    echo "4) Menu SSH (trial/hapus/perpanjang)"
    echo "5) Buat akun VLESS (xray)"
    echo "6) Menu VLESS (hapus/daftar)"
    echo "7) Daftar pengguna"
    echo "8) Info port"
    echo "9) Pasang cron (auto-clean, backup, ip-monitor)"
    echo "10) Backup / Restore"
    echo "11) Suspended (lihat / buka blokir)"
    echo "12) Restart semua service"
    echo "0) Keluar"
    read -rp "Pilih [0-12]: " opt
    case "$opt" in
      1) ensure_root; prepare_dirs; apt_install; install_xray; write_xray_template; echo "Install dasar selesai."; read -rp "Tekan enter..." ;; 
      2) change_domain_and_issue; read -rp "Tekan enter..." ;;
      3) create_ssh_user; read -rp "Tekan enter..." ;;
      4)
         echo "a) buat trial  b) hapus  c) perpanjang"
         read -rp "Pilih: " s
         case "$s" in
           a) 
             read -rp "Username trial: " tu
             read -rp "Durasi (hari): " tdays
             read -rp "Kuota GB: " tquota
             read -rp "Batas IP: " tipl
             pass="$(openssl rand -base64 10)"
             useradd -M -s /bin/false "$tu" || true
             echo "${tu}:${pass}" | chpasswd
             expiry_unix=$(date -d "+${tdays} days" +%s)
             chage -E "$(date -d "@$expiry_unix" +%Y-%m-%d)" "$tu" || true
             add_db_record "$tu" "ssh" "$expiry_unix" "$tquota" "$tipl" ""
             echo "Trial dibuat: $tu | pass:$pass | expire:$(date -d "@$expiry_unix" +%F)"
             ;;
           b) delete_ssh_user ;;
           c) extend_account ;;
         esac
         read -rp "Tekan enter..." ;;
      5) create_vless_user; read -rp "Tekan enter..." ;;
      6)
         echo "a) hapus vless  b) daftar pengguna"
         read -rp "Pilih: " x
         case "$x" in
           a) delete_vless_user ;;
           b) list_users ;;
         esac
         read -rp "Tekan enter..." ;;
      7) list_users ;;
      8) info_ports ;;
      9) setup_cronjobs; read -rp "Tekan enter..." ;;
      10)
         echo "a) backup sekarang  b) restore"
         read -rp "Pilih: " b
         case "$b" in
           a) backup_now ;;
           b) restore_menu ;;
         esac
         read -rp "Tekan enter..." ;;
      11)
         echo "a) lihat suspended  b) buka blokir user"
         read -rp "Pilih: " s
         case "$s" in
           a) show_suspended ;;
           b) unblock_user ;;
         esac
         read -rp "Tekan enter..." ;;
      12) restart_all; read -rp "Tekan enter..." ;;
      0) exit 0 ;;
      *) echo "Pilihan tidak valid"; read -rp "Tekan enter..." ;;
    esac
  done
}

# ===== Domain helper =====
change_domain_and_issue() {
  read -rp "Masukkan domain (A record -> IP VPS): " domain
  [ -n "$domain" ] || { echo "Domain wajib diisi"; return; }
  echo "$domain" > "$DOMAIN_FILE"
  install_acme
  issue_cert "$domain"
  nginx_setup "$domain"
  echo "Domain diset dan TLS diterbitkan."
}

# ===== Install / update / uninstall dari GitHub raw =====
install_to_system() {
  ensure_root
  prepare_dirs
  if [ -n "$GITHUB_RAW" ]; then
    log "Mengunduh skrip terbaru dari $GITHUB_RAW ..."
    curl -fsSL "$GITHUB_RAW" -o "$SYSTEM_BIN.new" || die "Gagal mengunduh $GITHUB_RAW"
    chmod +x "$SYSTEM_BIN.new"
    mv "$SYSTEM_BIN.new" "$SYSTEM_BIN"
    chmod +x "$SYSTEM_BIN"
    echo "Terinstall ke $SYSTEM_BIN"
    exit 0
  else
    die "GITHUB_RAW belum diatur; edit skrip dan set ke URL raw repo Anda"
  fi
}

self_update() {
  ensure_root
  prepare_dirs
  [ -n "$GITHUB_RAW" ] || die "GITHUB_RAW belum dikonfigurasi"
  log "Melakukan update dari $GITHUB_RAW ..."
  curl -fsSL "$GITHUB_RAW" -o "${SYSTEM_BIN}.new" || die "Gagal mengunduh update"
  chmod +x "${SYSTEM_BIN}.new"
  mv "${SYSTEM_BIN}.new" "$SYSTEM_BIN"
  log "Update selesai: $SYSTEM_BIN"
  exit 0
}

self_uninstall() {
  ensure_root
  rm -f "$SYSTEM_BIN"
  echo "Uninstall selesai: $SYSTEM_BIN dihapus"
  exit 0
}

# ===== Entrypoint =====
case "${1:-}" in
  install) install_to_system ;;
  update) self_update ;;
  uninstall) self_uninstall ;;
  auto-clean) prepare_dirs; /etc/zivpn/auto-clean.sh || true; exit 0 ;;
  auto-backup) prepare_dirs; /etc/zivpn/auto-backup.sh || true; exit 0 ;;
  ip-monitor) prepare_dirs; ip_limit_monitor; exit 0 ;;
  help|-h|--help)
    echo "kevps-zivpn manager (Bahasa Indonesia)"
    echo "sudo kevps-zivpn            # jalankan menu interaktif"
    echo "sudo kevps-zivpn install    # install/update dari GITHUB_RAW ke /usr/local/bin/kevps-zivpn"
    echo "sudo kevps-zivpn update     # update dari GITHUB_RAW"
    echo "sudo kevps-zivpn uninstall  # uninstall"
    exit 0
    ;;
  *)
    ensure_root
    prepare_dirs
    main_menu
    ;;
esac

# Akhir skrip
