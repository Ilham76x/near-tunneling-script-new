#!/bin/bash
# near-tunnel.sh - v0.1-tes
# Script tunneling sederhana, dibuat dari nol untuk tes di VPS trial.
# Bukan salinan script lain. Fokus: Xray WS polos di localhost,
# tanpa TLS / domain / systemd. Port publik mudah diubah di SETTINGS.
# Cara pakai:  bash near-tunnel.sh install   (sekali, sebagai root)
#              near-tunnel                  (menu interaktif)
#              near-tunnel add-vless user 30
set -u

VERSION="0.1-tes"
NT_DIR="/etc/near-tunnel"
DB_DIR="$NT_DIR/db"
SETTINGS="$NT_DIR/settings.conf"
XRAY_BIN="/usr/local/bin/xray"
XRAY_CONF="/etc/xray/config.json"
XRAY_LOG="/var/log/xray-near-tunnel.log"
XRAY_PID="/var/run/near-tunnel-xray.pid"

# ---- nilai default, bisa diubah lewat menu 19 / file settings ----
DOMAIN_OR_IP="127.0.0.1"
PORT="443"
VMESS_PORT="10086"
VLESS_PORT="10087"
TROJAN_PORT="10088"
SS_PORT="10089"
SSH_PORT="22"

load_settings() {
  if [ -f "$SETTINGS" ]; then
    # shellcheck disable=SC1090
    . "$SETTINGS"
  fi
}

save_settings() {
  mkdir -p "$NT_DIR"
  cat > "$SETTINGS" <<EOF
DOMAIN_OR_IP="$DOMAIN_OR_IP"
PORT="$PORT"
VMESS_PORT="$VMESS_PORT"
VLESS_PORT="$VLESS_PORT"
TROJAN_PORT="$TROJAN_PORT"
SS_PORT="$SS_PORT"
SSH_PORT="$SSH_PORT"
EOF
  chmod 600 "$SETTINGS"
}

need_root() {
  if [ "$(id -u)" != "0" ]; then echo "Harus jalan sebagai root."; exit 1; fi
}

pub_ip() {
  local ip=""
  ip=$(curl -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)
  if [ -z "$ip" ]; then ip=$(hostname -I 2>/dev/null | awk '{print $1}'); fi
  echo "${ip:-127.0.0.1}"
}

new_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then uuidgen
  elif [ -r /proc/sys/kernel/random/uuid ]; then cat /proc/sys/kernel/random/uuid
  else python3 -c 'import uuid; print(uuid.uuid4())'; fi
}

rand_pass() {
  tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 12; echo
}

now_epoch() { date +%s; }

expiry_for_days() {
  # $1 = jumlah hari (boleh 0 = hari ini)
  date -d "+$1 days" +%F
}

epoch_for_date() { date -d "$1" +%s 2>/dev/null || echo 0; }

db_get() { # db_get <file> <key>
  grep -E "^$2=" "$1" 2>/dev/null | head -1 | cut -d= -f2-
}

db_set() { # db_set <file> <key> <value>
  local f="$1" k="$2" v="$3"
  if grep -qE "^$k=" "$f" 2>/dev/null; then
    sed -i "s|^$k=.*|$k=$v|" "$f"
  else
    echo "$k=$v" >> "$f"
  fi
}

find_db() { # find_db <user> -> path pertama yang cocok
  local u="$1" f
  for f in "$DB_DIR"/*/"$u"; do [ -f "$f" ] && { echo "$f"; return 0; }; done
  return 1
}

# ---------- Xray config: dibangun ulang dari DB ----------
build_xray_config() {
  mkdir -p /etc/xray "$DB_DIR"
  python3 - "$DB_DIR" "$XRAY_CONF" "$VMESS_PORT" "$VLESS_PORT" "$TROJAN_PORT" "$SS_PORT" <<'PYEOF'
import json, os, sys, time
db, out, vmess_p, vless_p, trojan_p, ss_p = sys.argv[1:7]
now = int(time.time())
def read_db(proto):
    users = []
    d = os.path.join(db, proto)
    if not os.path.isdir(d):
        return users
    for name in sorted(os.listdir(d)):
        p = os.path.join(d, name)
        if not os.path.isfile(p):
            continue
        kv = {}
        with open(p, errors="ignore") as fh:
            for line in fh:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    kv[k.strip()] = v.strip()
        try:
            exp = int(kv.get("expires_epoch", "0") or 0)
        except ValueError:
            exp = 0
        if exp and exp < now:
            continue
        users.append(kv)
    return users
vmess = read_db("vmess") + read_db("trial")
vless = read_db("vless") + read_db("trial")
trojan = read_db("trojan") + read_db("trial")
ss = read_db("shadowsocks")
def ws_inbound(port, proto, path, settings):
    return {"listen": "127.0.0.1", "port": int(port), "protocol": proto,
            "settings": settings,
            "streamSettings": {"network": "ws", "security": "none",
                               "wsSettings": {"path": path}}}
cfg = {
  "log": {"loglevel": "warning"},
  "inbounds": [
    ws_inbound(vmess_p, "vmess", "/vmess",
               {"clients": [{"id": u.get("uuid", ""), "alterId": 0} for u in vmess if u.get("uuid")]}),
    ws_inbound(vless_p, "vless", "/vless",
               {"decryption": "none",
                "clients": [{"id": u.get("uuid", ""), "flow": ""} for u in vless if u.get("uuid")]}),
    ws_inbound(trojan_p, "trojan", "/trojan",
               {"clients": [{"password": u.get("uuid", "")} for u in trojan if u.get("uuid")]}),
    {"listen": "127.0.0.1", "port": int(ss_p), "protocol": "shadowsocks",
     "settings": {"method": "aes-256-gcm",
                  "users": [{"password": u.get("password", ""), "method": "aes-256-gcm",
                             "email": u.get("user", "")} for u in ss if u.get("password")]},
     "streamSettings": {"network": "tcp"}}
  ],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w") as fh:
    json.dump(cfg, fh, indent=2)
print("config ditulis: vmess=%d vless=%d trojan=%d ss=%d" % (len(vmess), len(vless), len(trojan), len(ss)))
PYEOF
}

xray_running() {
  if [ -f "$XRAY_PID" ]; then
    local pid; pid=$(cat "$XRAY_PID" 2>/dev/null || echo "")
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && return 0
  fi
  pgrep -x xray >/dev/null 2>&1
}

start_xray() {
  if xray_running; then echo "Xray sudah jalan."; return 0; fi
  build_xray_config
  mkdir -p "$(dirname "$XRAY_LOG")"
  setsid "$XRAY_BIN" run -c "$XRAY_CONF" >>"$XRAY_LOG" 2>&1 < /dev/null &
  echo $! > "$XRAY_PID"
  sleep 2
  if xray_running; then echo "Xray jalan (PID $(cat "$XRAY_PID"))."; return 0
  else echo "Xray GAGAL jalan. Lihat log: $XRAY_LOG"; tail -20 "$XRAY_LOG" 2>/dev/null; return 1; fi
}

stop_xray() {
  if [ -f "$XRAY_PID" ]; then kill "$(cat "$XRAY_PID")" 2>/dev/null || true; rm -f "$XRAY_PID"; fi
  pkill -x xray 2>/dev/null || true
  sleep 1
}

restart_xray() {
  echo "Restart Xray..."
  stop_xray
  start_xray
}

# ---------- akun ----------
add_account() { # add_account <proto> <user> <hari> [trial: 1=ya]
  local proto="$1" user="$2" days="$3" is_trial="${4:-0}"
  local exp_date exp_epoch uuid pw f
  case "$proto" in
    ssh|vmess|vless|trojan|shadowsocks|trial) ;;
    *) echo "Protokol tidak dikenal: $proto"; return 1 ;;
  esac
  if [ -z "$user" ] || ! echo "$user" | grep -qE '^[A-Za-z0-9_-]+$'; then
    echo "Nama user tidak valid (huruf/angka/_/- saja)."; return 1
  fi
  if find_db "$user" >/dev/null 2>&1; then echo "User $user sudah ada."; return 1; fi
  if [ "$is_trial" = "1" ]; then
    exp_date=$(date -d "+1 hour" +"%F %H:%M")
    exp_epoch=$(( $(now_epoch) + 3600 ))
  else
    exp_date=$(expiry_for_days "$days")
    exp_epoch=$(epoch_for_date "$exp_date")
  fi
  uuid=$(new_uuid); pw=$(rand_pass)
  mkdir -p "$DB_DIR/$proto"
  f="$DB_DIR/$proto/$user"
  {
    echo "user=$user"; echo "proto=$proto"; echo "uuid=$uuid"; echo "password=$pw"
    echo "created=$(date +%F)"; echo "expires=$exp_date"; echo "expires_epoch=$exp_epoch"
    echo "limit_ip=0"; echo "bandwidth=0"
  } > "$f"
  chmod 600 "$f"
  if [ "$proto" = "ssh" ]; then
    if id "$user" >/dev/null 2>&1; then userdel "$user" 2>/dev/null || true; fi
    useradd -M -s /usr/sbin/nologin -e "$exp_date" "$user" 2>/dev/null || useradd -M -s /bin/false -e "$exp_date" "$user"
    echo "$user:$pw" | chpasswd 2>/dev/null || true
  fi
  if [ "$proto" != "ssh" ]; then build_xray_config; restart_xray >/dev/null 2>&1 || start_xray >/dev/null 2>&1 || true; fi
  echo "OK: $proto / $user sampai $exp_date"
  print_link "$proto" "$user"
}

print_link() { # print_link <proto> <user>
  local proto="$1" user="$2" f uuid pw b64
  f=$(find_db "$user") || { echo "User $user tidak ditemukan."; return 1; }
  uuid=$(db_get "$f" uuid); pw=$(db_get "$f" password)
  case "$proto" in
    vmess)
      b64=$(printf '{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","net":"ws","type":"none","host":"%s","path":"/vmess","tls":""}' "$user" "$DOMAIN_OR_IP" "$PORT" "$uuid" "$DOMAIN_OR_IP" | base64 -w0)
      echo "vmess://$b64" ;;
    vless)
      echo "vless://$uuid@$DOMAIN_OR_IP:$PORT?encryption=none&security=none&type=ws&host=$DOMAIN_OR_IP&path=%2Fvless#$user" ;;
    trojan)
      echo "trojan://$uuid@$DOMAIN_OR_IP:$PORT?security=none&type=ws&host=$DOMAIN_OR_IP&path=%2Ftrojan#$user" ;;
    shadowsocks)
      b64=$(printf 'aes-256-gcm:%s@%s:%s' "$pw" "$DOMAIN_OR_IP" "$PORT" | base64 -w0)
      echo "ss://$b64#$user" ;;
    trial)
      echo "Trial (1 jam) - VMess/VLess/Trojan pakai UUID yang sama:"
      print_link vmess "$user"; print_link vless "$user"; print_link trojan "$user" ;;
    ssh)
      echo "SSH: $user@$DOMAIN_OR_IP:$SSH_PORT  (password tersimpan di DB, tampil sekali saat buat)" ;;
  esac
  echo "Catatan tes: link di atas memakai PORT=$PORT. Di VPS trial, Xray WS polos listen di 127.0.0.1:$VMESS_PORT/$VLESS_PORT/$TROJAN_PORT/$SS_PORT tanpa TLS/domain."
}

list_accounts() {
  local f proto user exp now days_left n=0
  now=$(now_epoch)
  echo -e "${PKI}  DAFTAR AKUN TERSIMPAN${NC}"
  echo -e "${PK}┌─────┬──────────────┬────────────┬──────────────┐${NC}"
  printf "%b│%b %b%-3s%b %b│%b %b%-12s%b %b│%b %b%-10s%b %b│%b %b%-12s%b %b│%b\n" "$PK" "$NC" "$PK" "#" "$NC" "$PK" "$NC" "$PK" "User" "$NC" "$PK" "$NC" "$PK" "Protokol" "$NC" "$PK" "$NC" "$PK" "Berakhir" "$NC" "$PK" "$NC"
  echo -e "${PK}├─────┼──────────────┼────────────┼──────────────┤${NC}"
  for f in "$DB_DIR"/*/*; do
    [ -f "$f" ] || continue
    proto=$(basename "$(dirname "$f")"); user=$(db_get "$f" user)
    exp=$(db_get "$f" expires); ep=$(db_get "$f" expires_epoch)
    if [ -n "$ep" ] && [ "$ep" -gt 0 ]; then
      if [ "$ep" -lt "$now" ]; then days_left="KEDALUWARSA"
      elif [ "$(( (ep - now) / 3600 ))" -lt 24 ]; then days_left="$(( (ep - now) / 3600 )) jam"
      else days_left="$(( (ep - now) / 86400 )) hari"; fi
    else days_left="-"; fi
    n=$((n+1))
    printf "%b│%b %b%3s%b %b│%b %b%-12s%b %b│%b %b%-10s%b %b│%b %b%-12s%b %b│%b\n" "$PK" "$NC" "$CYN" "$n" "$NC" "$PK" "$NC" "$WH" "${user:0:12}" "$NC" "$PK" "$NC" "$YEL" "${proto:0:10}" "$NC" "$PK" "$NC" "$WH" "${exp:0:12}" "$NC" "$PK" "$NC"
  done
  if [ "$n" -eq 0 ]; then
    printf "%b│%b %-46s %b│%b\n" "$PK" "$NC" "  (belum ada akun)" "$PK" "$NC"
  fi
  echo -e "${PK}└─────┴──────────────┴────────────┴──────────────┘${NC}"
}

count_proto() { # count_proto <proto>
  local n=0 f
  for f in "$DB_DIR/$1"/*; do [ -f "$f" ] && n=$((n+1)); done
  echo "$n"
}

delete_account() { # delete_account <user> [proto]
  local user="$1" proto="${2:-}" f p
  if [ -n "$proto" ]; then f="$DB_DIR/$proto/$user"; else f=$(find_db "$user") || { echo "User $user tidak ditemukan."; return 1; }; fi
  [ -f "$f" ] || { echo "User $user tidak ditemukan."; return 1; }
  p=$(db_get "$f" proto)
  rm -f "$f"
  if [ "$p" = "ssh" ]; then userdel "$user" 2>/dev/null || true; fi
  if [ "$p" != "ssh" ]; then build_xray_config; restart_xray >/dev/null 2>&1 || true; fi
  echo "OK: $user ($p) dihapus."
}

extend_account() { # extend_account <user> <hari-tambahan>
  local user="$1" add="$2" f ep new_ep new_date p
  f=$(find_db "$user") || { echo "User $user tidak ditemukan."; return 1; }
  ep=$(db_get "$f" expires_epoch); now=$(now_epoch)
  [ "$ep" -gt "$now" ] 2>/dev/null || ep=$now
  new_ep=$(( ep + add * 86400 )); new_date=$(date -d "@$new_ep" +%F)
  db_set "$f" expires "$new_date"; db_set "$f" expires_epoch "$new_ep"
  p=$(db_get "$f" proto)
  if [ "$p" = "ssh" ]; then chage -E "$new_date" "$user" 2>/dev/null || true; fi
  if [ "$p" != "ssh" ]; then build_xray_config; restart_xray >/dev/null 2>&1 || true; fi
  echo "OK: $user diperpanjang sampai $new_date"
}

edit_account() { # edit_account <user> <limit_ip> <bandwidth>
  local user="$1" lip="$2" bw="$3" f
  f=$(find_db "$user") || { echo "User $user tidak ditemukan."; return 1; }
  db_set "$f" limit_ip "$lip"; db_set "$f" bandwidth "$bw"
  echo "OK: $user -> limit_ip=$lip bandwidth=$bw (tersimpan; penegakan otomatis belum aktif di v0.1-tes)"
}

# ---------- instalasi ----------
do_install() {
  need_root
  echo "== near-tunnel $VERSION : instalasi tes =="
  mkdir -p "$NT_DIR" "$DB_DIR" /etc/xray
  if [ ! -f "$SETTINGS" ]; then
    DOMAIN_OR_IP=$(pub_ip); PORT="443"; save_settings
    echo "Domain/IP default diisi IP publik VPS: $DOMAIN_OR_IP"
  else
    load_settings
  fi
  echo "-> apt update + paket dasar (curl jq uuid-runtime unzip iproute2)..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq curl jq uuid-runtime unzip iproute2 procps passwd >/tmp/near-tunnel-apt.log 2>&1 || { echo "apt gagal, lihat /tmp/near-tunnel-apt.log"; tail -20 /tmp/near-tunnel-apt.log; exit 1; }
  if [ ! -x "$XRAY_BIN" ]; then
    echo "-> unduh Xray Core resmi (XTLS/Xray-core, linux-64)..."
    cd /tmp || exit 1
    rm -rf Xray-linux-64.zip xray-geoip.dat xray-geosite.dat xray
    curl -fsSL -o Xray-linux-64.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip || { echo "Unduh Xray gagal."; exit 1; }
    unzip -o -q Xray-linux-64.zip xray geoip.dat geosite.dat
    install -m 755 xray "$XRAY_BIN"
    [ -f geoip.dat ] && install -m 644 geoip.dat /usr/local/bin/geoip.dat
    [ -f geosite.dat ] && install -m 644 geosite.dat /usr/local/bin/geosite.dat
    rm -f Xray-linux-64.zip xray geoip.dat geosite.dat
  fi
  "$XRAY_BIN" version | head -3
  cp "$0" /usr/local/sbin/near-tunnel 2>/dev/null || true
  chmod +x /usr/local/sbin/near-tunnel "$XRAY_BIN" 2>/dev/null || true
  # Perintah singkat "menu" (seperti st-pusat) + menu otomatis saat login root
  cat > /usr/local/sbin/menu <<'EOF'
#!/bin/bash
exec /usr/local/sbin/near-tunnel "$@"
EOF
  chmod +x /usr/local/sbin/menu
  if ! grep -q 'NEAR-TUNNEL-AUTOMENU' /root/.bashrc 2>/dev/null; then
    cat >> /root/.bashrc <<'BRC'

# >>> NEAR-TUNNEL-AUTOMENU >>>
if [[ $- == *i* ]]; then
  near-tunnel
fi
# <<< NEAR-TUNNEL-AUTOMENU <<<
BRC
  fi
  echo "Menu otomatis aktif: ketik 'menu' atau 'near-tunnel', atau tampil sendiri setiap login root."
  build_xray_config
  restart_xray
  echo "== instalasi selesai. Jalankan: near-tunnel =="
}

# ---------- menu (gaya screenshot: sambutan teal/kuning, tabel hijau, daftar pink) ----------
TEAL='\033[0;36m'; YEL='\033[1;33m'; GRN='\033[1;32m'; GRNI='\033[3;32m'
PK='\033[1;95m'; PKI='\033[3;95m'; CYN='\033[0;36m'; WH='\033[1;37m'; GRY='\033[0;90m'; NC='\033[0m'
PU="$PK"
box_row() { # box_row <warna-garis> <teks>
  printf "%b║%b %-48s %b║%b\n" "$1" "$NC" "$2" "$1" "$NC"
}

show_header() {
  load_settings
  local os up mem disk xst
  os=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"'); os=${os:0:32}
  up=$(uptime -p 2>/dev/null || uptime); up=${up:0:36}
  mem=$(free -h 2>/dev/null | awk '/Mem:/{print $3"/"$2}')
  disk=$(df -h / 2>/dev/null | awk 'NR==2{print $3"/"$2}')
  if xray_running; then xst="JALAN"; else xst="MATI"; fi
  clear
  echo -e "${TEAL}╔══════════════════════════════════════════════════╗${NC}"
  printf "%b║%b %b%-48s%b %b║%b\n" "$TEAL" "$NC" "$YEL" "                ✦  WELCOME  ✦" "$NC" "$TEAL" "$NC"
  printf "%b║%b %b%-48s%b %b║%b\n" "$TEAL" "$NC" "$GRY" "            Supported By Near Cloud" "$NC" "$TEAL" "$NC"
  echo -e "${TEAL}╠══════════════════════════════════════════════════╣${NC}"
  box_row "$TEAL" "  Host    : $(hostname)"
  box_row "$TEAL" "  IP      : $(pub_ip)"
  box_row "$TEAL" "  OS      : $os"
  box_row "$TEAL" "  Uptime  : $up"
  box_row "$TEAL" "  RAM     : $mem   Disk: $disk"
  box_row "$TEAL" "  Xray    : $xst (WS $VMESS_PORT/$VLESS_PORT/$TROJAN_PORT/$SS_PORT)"
  box_row "$TEAL" "  Akun    : SSH $(count_proto ssh) | VMess $(count_proto vmess)"
  box_row "$TEAL" "            VLess $(count_proto vless) | Trojan $(count_proto trojan)"
  box_row "$TEAL" "            SS $(count_proto shadowsocks) | Trial $(count_proto trial)"
  box_row "$TEAL" "  Domain  : $DOMAIN_OR_IP   Port link: $PORT"
  echo -e "${TEAL}╚══════════════════════════════════════════════════╝${NC}"
}

pause() { echo; read -r -p "Tekan Enter untuk kembali ke menu..." _x; }

ask_create() { # ask_create <proto> <label>
  local proto="$1" label="$2" user days
  read -r -p "Nama user: " user
  read -r -p "Masa aktif (hari): " days
  days=${days:-30}
  add_account "$proto" "$user" "$days"
  pause
}

menu_loop() {
  need_root
  mkdir -p "$DB_DIR"
  while true; do
    show_header
    echo -e "${GRNI}  MENU UTAMA${NC}"
    echo -e "${GRN}┌──────┬──────────────────────────────────────────────┐${NC}"
    printf "%b│%b %b%4s%b %b│%b %b%-42s%b %b│%b\n" "$GRN" "$NC" "$GRN" "Key" "$NC" "$GRN" "$NC" "$GRN" "Aksi" "$NC" "$GRN" "$NC"
    echo -e "${GRN}├──────┼──────────────────────────────────────────────┤${NC}"
    local keys=(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 0)
    local acts=(
      "Buat Akun SSH" "Buat Akun VMess" "Buat Akun VLess" "Buat Akun Trojan"
      "Buat Akun Shadowsocks" "Buat Akun Trial (1 jam)" "Daftar Semua Akun"
      "Hapus Akun" "Perpanjang Akun" "Edit Akun (limit IP / bandwidth)"
      "Cek Akun Aktif / Cek Masa Aktif" "Restart Xray" "Restart Semua Layanan"
      "Cek Status Service" "Cek Port Aktif" "Speed Test VPS" "Auto Reboot"
      "Setup Notifikasi Telegram" "Ganti Domain" "Update Script" "Backup Akun" "Keluar"
    )
    local i
    for i in "${!keys[@]}"; do
      printf "%b│%b %b%4s%b %b│%b %b%-42s%b %b│%b\n" "$GRN" "$NC" "$CYN" "${keys[$i]}" "$NC" "$GRN" "$NC" "$YEL" "${acts[$i]}" "$NC" "$GRN" "$NC"
    done
    echo -e "${GRN}└──────┴──────────────────────────────────────────────┘${NC}"
    printf "%b➤ Pilih nomor [0-21]: %b" "$CYN" "$NC"
    IFS= read -r pil
    case "$pil" in
      1) ask_create ssh "SSH" ;;
      2) ask_create vmess "VMess" ;;
      3) ask_create vless "VLess" ;;
      4) ask_create trojan "Trojan" ;;
      5) ask_create shadowsocks "Shadowsocks" ;;
      6) read -r -p "Nama user trial: " u; add_account trial "$u" 0 1; pause ;;
      7) list_accounts; pause ;;
      8) read -r -p "Nama user yang dihapus: " u; delete_account "$u"; pause ;;
      9) read -r -p "Nama user: " u; read -r -p "Tambah berapa hari: " d; extend_account "$u" "${d:-7}"; pause ;;
      10) read -r -p "Nama user: " u; read -r -p "Limit IP (0 = tanpa batas): " l; read -r -p "Bandwidth GB (0 = tanpa batas): " b; edit_account "$u" "${l:-0}" "${b:-0}"; pause ;;
      11) list_accounts; pause ;;
      12) restart_xray; pause ;;
      13) echo "Mode tes: tidak ada systemd di VPS trial. SSHD tidak di-restart (dilarang)."; restart_xray; pause ;;
      14) if xray_running; then echo "Xray: JALAN (PID $(cat $XRAY_PID 2>/dev/null))"; else echo "Xray: MATI"; fi; "$XRAY_BIN" version 2>/dev/null | head -2; echo "--- port listen ---"; (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep -E '1008|46824|22' || true; pause ;;
      15) (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) || echo "ss/netstat tidak tersedia"; pause ;;
      16) echo "Speed test (unduh 25MB dari Cloudflare)..."; curl -s -o /dev/null -w "Waktu: %{time_total}s  Kecepatan: %{speed_download} byte/s\n" https://speed.cloudflare.com/__down?bytes=25000000 || echo "Speed test gagal (cek internet VPS)."; pause ;;
      17) echo "Mode tes: Auto Reboot BELUM AKTIF di VPS trial (tanpa systemd). Akan aktif di VPS baru."; pause ;;
      18) read -r -p "Chat ID Telegram: " cid; read -r -s -p "Bot token Telegram (tidak ditampilkan): " tok; echo; printf 'CHAT_ID="%s"\nBOT_TOKEN="%s"\n' "$cid" "$tok" > "$NT_DIR/telegram.conf"; chmod 600 "$NT_DIR/telegram.conf"; unset tok; echo "Tersimpan di $NT_DIR/telegram.conf (600). Token tidak ditampilkan di sini."; pause ;;
      19) read -r -p "Domain / IP baru: " nd; read -r -p "Port link baru [$PORT]: " np; [ -n "$nd" ] && DOMAIN_OR_IP="$nd"; [ -n "$np" ] && PORT="$np"; save_settings; echo "OK: domain=$DOMAIN_OR_IP port=$PORT (Xray tetap WS polos di localhost; TLS/domain dipasang di VPS baru)."; pause ;;
      20) echo "Mode tes: Update Script BELUM AKTIF di VPS trial. Akan aktif di VPS baru (cek rilis baru, lalu ganti file). Versi ini: $VERSION"; pause ;;
      21) mkdir -p /root; tar -czf "/root/near-tunnel-backup-$(date +%Y%m%d-%H%M).tar.gz" -C /etc near-tunnel 2>/dev/null && echo "Backup tersimpan di /root/near-tunnel-backup-*.tar.gz" || echo "Backup gagal."; pause ;;
      0) echo "Keluar. Sampai jumpa."; exit 0 ;;
      *) echo "Pilihan tidak ada."; sleep 1 ;;
    esac
  done
}

# ---------- CLI ----------
load_settings
mkdir -p "$DB_DIR" 2>/dev/null || true
case "${1:-}" in
  install) do_install ;;
  add-vmess) add_account vmess "$2" "${3:-30}" ;;
  add-vless) add_account vless "$2" "${3:-30}" ;;
  add-trojan) add_account trojan "$2" "${3:-30}" ;;
  add-ssh) add_account ssh "$2" "${3:-30}" ;;
  add-ss) add_account shadowsocks "$2" "${3:-30}" ;;
  add-trial) add_account trial "$2" 0 1 ;;
  list) list_accounts ;;
  delete) delete_account "$2" "${3:-}" ;;
  extend) extend_account "$2" "${3:-7}" ;;
  restart) restart_xray ;;
  status) if xray_running; then echo "Xray JALAN"; else echo "Xray MATI"; fi ;;
  menu|"") menu_loop ;;
  *) echo "Pakai: $0 [install|menu|add-vmess|add-vless|add-trojan|add-ssh|add-ss|add-trial|list|delete|extend|restart|status]"; exit 1 ;;
esac
