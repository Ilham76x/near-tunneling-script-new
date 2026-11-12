#!/bin/bash
# near-tunnel.sh - v0.2-tes
# v0.2: kartu akun TLS/NTLS/GRPC + kuota/IP manual + single-host.
# Dibangun dari v0.1-tes (bukan salinan st-clean/st-pusat).
# Script tunneling sederhana, dibuat dari nol untuk tes di VPS trial.
# Bukan salinan script lain. Fokus: Xray WS polos di localhost,
# tanpa TLS / domain / systemd. Port publik mudah diubah di SETTINGS.
# Cara pakai:  bash near-tunnel.sh install   (sekali, sebagai root)
#              near-tunnel                  (menu interaktif)
#              near-tunnel add-vless user 30
set -u

VERSION="0.2-tes"
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
# v0.2: bug host untuk link TLS/NTLS, single-host (1=pakai DOMAIN apa adanya),
# daftar port yang ditampilkan di kartu, port GRPC Xray, port OpenClash.
BUG_HOST="bug.com"
SINGLE_HOST="1"
TLS_PORTS="443, 8443, 2087, 2096"
NTLS_PORTS="80, 8080, 8880, 2082"
VMESS_GRPC_PORT="10090"
VLESS_GRPC_PORT="10091"
TROJAN_GRPC_PORT="10092"
OC_PORT="81"
OC_DIR="$NT_DIR/openclash"

load_settings() {
  if [ -f "$SETTINGS" ]; then
    # shellcheck disable=SC1090
    . "$SETTINGS"
  fi
  # Default untuk settings lama (v0.1) yang belum punya kunci v0.2.
  BUG_HOST="${BUG_HOST:-bug.com}"
  SINGLE_HOST="${SINGLE_HOST:-1}"
  TLS_PORTS="${TLS_PORTS:-443, 8443, 2087, 2096}"
  NTLS_PORTS="${NTLS_PORTS:-80, 8080, 8880, 2082}"
  VMESS_GRPC_PORT="${VMESS_GRPC_PORT:-10090}"
  VLESS_GRPC_PORT="${VLESS_GRPC_PORT:-10091}"
  TROJAN_GRPC_PORT="${TROJAN_GRPC_PORT:-10092}"
  OC_PORT="${OC_PORT:-81}"
  OC_DIR="${OC_DIR:-$NT_DIR/openclash}"
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
BUG_HOST="$BUG_HOST"
SINGLE_HOST="$SINGLE_HOST"
TLS_PORTS="$TLS_PORTS"
NTLS_PORTS="$NTLS_PORTS"
VMESS_GRPC_PORT="$VMESS_GRPC_PORT"
VLESS_GRPC_PORT="$VLESS_GRPC_PORT"
TROJAN_GRPC_PORT="$TROJAN_GRPC_PORT"
OC_PORT="$OC_PORT"
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
  python3 - "$DB_DIR" "$XRAY_CONF" "$VMESS_PORT" "$VLESS_PORT" "$TROJAN_PORT" "$SS_PORT" "$VMESS_GRPC_PORT" "$VLESS_GRPC_PORT" "$TROJAN_GRPC_PORT" <<'PYEOF'
import json, os, sys, time
db, out, vmess_p, vless_p, trojan_p, ss_p, vmess_g, vless_g, trojan_g = sys.argv[1:10]
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
def grpc_inbound(port, proto, service, settings):
    return {"listen": "127.0.0.1", "port": int(port), "protocol": proto,
            "settings": settings,
            "streamSettings": {"network": "grpc", "security": "none",
                               "grpcSettings": {"serviceName": service}}}
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
    grpc_inbound(vmess_g, "vmess", "vmess-grpc",
               {"clients": [{"id": u.get("uuid", ""), "alterId": 0} for u in vmess if u.get("uuid")]}),
    grpc_inbound(vless_g, "vless", "vless-grpc",
               {"decryption": "none",
                "clients": [{"id": u.get("uuid", ""), "flow": ""} for u in vless if u.get("uuid")]}),
    grpc_inbound(trojan_g, "trojan", "trojan-grpc",
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
add_account() { # add_account <proto> <user> <hari> [trial: 1=ya] [quota_gb] [limit_ip]
  local proto="$1" user="$2" days="$3" is_trial="${4:-0}"
  local quota_gb="${5:-0}" limit_ip="${6:-0}"
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
    echo "quota_gb=$quota_gb"; echo "limit_ip=$limit_ip"; echo "bandwidth=$quota_gb"
  } > "$f"
  chmod 600 "$f"
  if [ "$proto" = "ssh" ]; then
    if id "$user" >/dev/null 2>&1; then userdel "$user" 2>/dev/null || true; fi
    useradd -M -s /usr/sbin/nologin -e "$exp_date" "$user" 2>/dev/null || useradd -M -s /bin/false -e "$exp_date" "$user"
    echo "$user:$pw" | chpasswd 2>/dev/null || true
  fi
  if [ "$proto" != "ssh" ]; then build_xray_config; restart_xray >/dev/null 2>&1 || start_xray >/dev/null 2>&1 || true; fi
  echo "OK: $proto / $user sampai $exp_date"
  case "$proto" in
    vmess|vless|trojan)
      if [ "$is_trial" = "1" ]; then print_account_card "$proto" "$user" "1 Jam"
      else print_account_card "$proto" "$user" "$days Hari"; fi
      write_openclash "$proto" "$user" ;;
    trial)
      for _p in vmess vless trojan; do
        print_account_card "$_p" "$user" "1 Jam"
        write_openclash "$_p" "$user"
      done ;;
    *) print_link "$proto" "$user" ;;
  esac
}

# ---- v0.2: pembangun link (dipakai kartu akun + file OpenClash) ----
# Batas jujur (bukan klaim): link TLS/NTLS/GRPC di sini dibuat dari setting
# (BUG_HOST, DOMAIN, port 443/80). Di VPS trial yang jalurnya Cloudflare
# Tunnel, hanya link WS port 443 yang benar-benar bisa dijangkau; port
# TLS lain (8443/2087/2096), port NTLS lain, dan GRPC lewat hostname
# publik tunnel TIDAK didukung Cloudflare (hanya private subnet routing).
# GRPC baru bisa jalan di VPS dengan port 443 publik + TLS/HTTP2.
# Kuota/IP di kartu hanya tercatat di DB v0.2, penegakan otomatis belum aktif.
fmt_date() { date -d "$1" +"%d %b, %Y" 2>/dev/null || echo "$1"; }

_link_host() { # host untuk link: SINGLE_HOST=1 -> DOMAIN apa adanya
  if [ "${SINGLE_HOST:-1}" = "1" ]; then echo "$DOMAIN_OR_IP"
  else
    case "$DOMAIN_OR_IP" in
      *[!0-9.]*) case "$1" in
        vmess) echo "vmess.$DOMAIN_OR_IP" ;;
        vless) echo "vless.$DOMAIN_OR_IP" ;;
        trojan) echo "trojan.$DOMAIN_OR_IP" ;;
        *) echo "$DOMAIN_OR_IP" ;;
      esac ;;
      *) echo "$DOMAIN_OR_IP" ;;
    esac
  fi
}

tls_link() { # tls_link <proto> <user> <uuid>
  local proto="$1" user="$2" uuid="$3"
  case "$proto" in
    vmess)
      printf 'vmess://%s' "$(printf '{"v":"2","ps":"%s","add":"%s","port":"443","id":"%s","aid":"0","net":"ws","type":"none","host":"%s","path":"/%s","tls":"tls","sni":"%s"}' "$user" "$BUG_HOST" "$uuid" "$DOMAIN_OR_IP" "$proto" "$DOMAIN_OR_IP" | base64 -w0)" ;;
    vless)
      echo "vless://$uuid@$BUG_HOST:443?path=/$proto&security=tls&host=$DOMAIN_OR_IP&encryption=none&type=ws&sni=$DOMAIN_OR_IP#$user" ;;
    trojan)
      echo "trojan://$uuid@$BUG_HOST:443?path=/$proto&security=tls&host=$DOMAIN_OR_IP&type=ws&sni=$DOMAIN_OR_IP#$user" ;;
  esac
}

ntls_link() { # ntls_link <proto> <user> <uuid>
  local proto="$1" user="$2" uuid="$3"
  case "$proto" in
    vmess)
      printf 'vmess://%s' "$(printf '{"v":"2","ps":"%s","add":"%s","port":"80","id":"%s","aid":"0","net":"ws","type":"none","host":"%s","path":"/%s","tls":""}' "$user" "$BUG_HOST" "$uuid" "$DOMAIN_OR_IP" "$proto" | base64 -w0)" ;;
    vless)
      echo "vless://$uuid@$BUG_HOST:80?path=/$proto&encryption=none&type=ws&host=$DOMAIN_OR_IP#$user" ;;
    trojan)
      echo "trojan://$uuid@$BUG_HOST:80?path=/$proto&type=ws&host=$DOMAIN_OR_IP#$user" ;;
  esac
}

grpc_link() { # grpc_link <proto> <user> <uuid>
  local proto="$1" user="$2" uuid="$3"
  case "$proto" in
    vmess)
      printf 'vmess://%s' "$(printf '{"v":"2","ps":"%s","add":"%s","port":"443","id":"%s","aid":"0","net":"grpc","type":"none","host":"%s","path":"","tls":"tls","sni":"%s","serviceName":"%s-grpc"}' "$user" "$DOMAIN_OR_IP" "$uuid" "$DOMAIN_OR_IP" "$BUG_HOST" "$proto" | base64 -w0)" ;;
    vless)
      echo "vless://$uuid@$DOMAIN_OR_IP:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=$proto-grpc&sni=$BUG_HOST#$user" ;;
    trojan)
      echo "trojan://$uuid@$DOMAIN_OR_IP:443?mode=gun&security=tls&type=grpc&serviceName=$proto-grpc&sni=$BUG_HOST#$user" ;;
  esac
}

print_account_card() { # print_account_card <proto> <user> [aktif-label]
  local proto="$1" user="$2" aktif="${3:-}" f uuid quota lip created expires
  f=$(find_db "$user") || { echo "User $user tidak ditemukan."; return 1; }
  uuid=$(db_get "$f" uuid); quota=$(db_get "$f" quota_gb); lip=$(db_get "$f" limit_ip)
  created=$(db_get "$f" created); expires=$(db_get "$f" expires)
  quota=${quota:-0}; lip=${lip:-0}
  [ -z "$aktif" ] && aktif="30 Hari"
  local label; label=$(printf '%s' "$proto" | tr 'a-z' 'A-Z')
  echo "◇━━━━━━━━━━━━━━━━━◇"
  echo " CREATE $label ACCOUNT"
  echo "◇━━━━━━━━━━━━━━━━━◇"
  printf "Remarks     : %s\n" "$user"
  printf "Domain      : %s\n" "$DOMAIN_OR_IP"
  printf "User Quota  : %s GB\n" "$quota"
  printf "User Ip     : %s IP\n" "$lip"
  printf "port TLS    : %s\n" "$TLS_PORTS"
  printf "Port NTLS   : %s\n" "$NTLS_PORTS"
  printf "User ID     : %s\n" "$uuid"
  echo "Encryption  : none"
  printf "Path TLS    : /%s\n" "$proto"
  printf "ServiceName : %s-grpc\n" "$proto"
  echo "◇━━━━━━━━━━━━━━━━━◇"
  printf "Link TLS    : %s\n" "$(tls_link "$proto" "$user" "$uuid")"
  echo "◇━━━━━━━━━━━━━━━━━◇"
  printf "Link NTLS   : %s\n" "$(ntls_link "$proto" "$user" "$uuid")"
  echo "◇━━━━━━━━━━━━━━━━━◇"
  printf "Link GRPC   : %s\n" "$(grpc_link "$proto" "$user" "$uuid")"
  echo "◇━━━━━━━━━━━━━━━━━◇"
  printf "Format OpenClash : https://%s:%s/%s-%s.txt\n" "$DOMAIN_OR_IP" "$OC_PORT" "$proto" "$user"
  echo "◇━━━━━━━━━━━━━━━━━◇"
  printf "Aktif Selama     : %s\n" "$aktif"
  printf "Dibuat Pada      : %s\n" "$(fmt_date "$created")"
  printf "Berakhir Pada    : %s\n" "$(fmt_date "$expires")"
  echo "◇━━━━━━━━━━━━━━━━━◇"
  echo "Catatan: kuota/IP tercatat, penegakan otomatis belum aktif."
}

write_openclash() { # write_openclash <proto> <user>
  local proto="$1" user="$2" f uuid
  f=$(find_db "$user") || return 1
  uuid=$(db_get "$f" uuid)
  mkdir -p "$OC_DIR"
  {
    echo "# Remarks: $user"
    echo "# $proto TLS: $(tls_link "$proto" "$user" "$uuid")"
    echo "# $proto NTLS: $(ntls_link "$proto" "$user" "$uuid")"
    echo "# $proto GRPC: $(grpc_link "$proto" "$user" "$uuid")"
    tls_link "$proto" "$user" "$uuid"
    ntls_link "$proto" "$user" "$uuid"
    grpc_link "$proto" "$user" "$uuid"
  } > "$OC_DIR/$proto-$user.txt"
  chmod 644 "$OC_DIR/$proto-$user.txt"
}

print_link() { # print_link <proto> <user>
  local proto="$1" user="$2" f uuid pw b64 link_host
  f=$(find_db "$user") || { echo "User $user tidak ditemukan."; return 1; }
  uuid=$(db_get "$f" uuid); pw=$(db_get "$f" password)
  # SINGLE_HOST=1 (default v0.2): pakai DOMAIN apa adanya untuk semua
  # protokol, tanpa awalan vmess./vless./trojan. — ini yang melindungi
  # domain utama: satu subdomain saja yang dipakai buat tunnel.
  # SINGLE_HOST=0: kembali ke logika lama per-subdomain.
  link_host=$(_link_host "$proto")
  case "$proto" in
    vmess)
      b64=$(printf '{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","net":"ws","type":"none","host":"%s","path":"/vmess","tls":""}' "$user" "$link_host" "$PORT" "$uuid" "$link_host" | base64 -w0)
      echo "vmess://$b64" ;;
    vless)
      echo "vless://$uuid@$link_host:$PORT?encryption=none&security=none&type=ws&host=$link_host&path=%2Fvless#$user" ;;
    trojan)
      echo "trojan://$uuid@$link_host:$PORT?security=none&type=ws&host=$link_host&path=%2Ftrojan#$user" ;;
    shadowsocks)
      b64=$(printf 'aes-256-gcm:%s@%s:%s' "$pw" "$DOMAIN_OR_IP" "$PORT" | base64 -w0)
      echo "ss://$b64#$user" ;;
    trial)
      echo "Trial (1 jam) - VMess/VLess/Trojan pakai UUID yang sama:"
      for _p in vmess vless trojan; do print_account_card "$_p" "$user" "1 Jam"; done ;;
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
    printf "%b│%b %b%3s%b %b│%b %b%-12s%b %b│%b %b%-10s%b %b│%b %b%-12s%b %b│%b\n" "$PK" "$NC" "$CYN" "$n" "$NC" "$PK" "$NC" "$WH" "${user:0:12}" "$NC" "$PK" "$NC" "$YEL" "${proto:0:10}" "$NC" "$PK" "$NC" "$WH" "${exp:0:10}" "$NC" "$PK" "$NC"
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

edit_account() { # edit_account <user> <limit_ip> <bandwidth> [quota_gb]
  local user="$1" lip="$2" bw="$3" qgb="${4:-}" f
  f=$(find_db "$user") || { echo "User $user tidak ditemukan."; return 1; }
  db_set "$f" limit_ip "$lip"; db_set "$f" bandwidth "$bw"
  if [ -n "$qgb" ]; then db_set "$f" quota_gb "$qgb"; fi
  echo "OK: $user -> limit_ip=$lip bandwidth=$bw quota_gb=${qgb:-$(db_get "$f" quota_gb)} (kuota/IP tercatat, penegakan otomatis belum aktif di v0.2-tes)"
}

# ---------- instalasi ----------
do_install() {
  need_root
  echo "== near-tunnel $VERSION : instalasi tes =="
  mkdir -p "$NT_DIR" "$DB_DIR" /etc/xray "$NT_DIR/openclash"
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

# ---------- menu cyberpunk ----------
# Palet neon cyberpunk
NC='\033[0m'
BOLD='\033[1m'; DIM='\033[2m'; ITAL='\033[3m'
NEON_CYAN='\033[38;5;51m'
NEON_MAG='\033[38;5;201m'
NEON_GRN='\033[38;5;46m'
NEON_YEL='\033[38;5;226m'
NEON_ORG='\033[38;5;208m'
NEON_PNK='\033[38;5;213m'
NEON_BLU='\033[38;5;45m'
NEON_PUR='\033[38;5;141m'
NEON_RED='\033[38;5;196m'
GRY='\033[38;5;240m'
WH='\033[38;5;255m'

# Alias lama agar tidak pecah kalau masih dipakai
TEAL="$NEON_CYAN"; YEL="$NEON_YEL"; GRN="$NEON_GRN"; GRNI="$NEON_GRN"
PK="$NEON_MAG"; PKI="$NEON_PNK"; CYN="$NEON_CYAN"; PU="$NEON_MAG"

# Lebar total box
BOX_W=58

# Garis double-line neon
hr_top()    { local c="$1"; printf "%b╔" "$c"; printf '═%.0s' $(seq 1 $BOX_W); printf "╗%b\n" "$NC"; }
hr_mid()    { local c="$1"; printf "%b╠" "$c"; printf '═%.0s' $(seq 1 $BOX_W); printf "╣%b\n" "$NC"; }
hr_bot()    { local c="$1"; printf "%b╚" "$c"; printf '═%.0s' $(seq 1 $BOX_W); printf "╝%b\n" "$NC"; }

# Hitung lebar kolom teks (tanpa ANSI), tidak tergantung locale:
# di locale POSIX, ${#teks} menghitung byte, padahal simbol seperti ✦/●
# itu 3 byte tapi 1 kolom. vislen menghitung byte lalu mengurangi 2
# untuk tiap karakter UTF-8 3-byte, jadi padding box selalu pas.
vislen() {
  local s="$1" b mb
  b=$(printf '%s' "$s" | wc -c)
  mb=$(printf '%s' "$s" | LC_ALL=C grep -o $'[\xE0-\xEF][\x80-\xBF][\x80-\xBF]' | wc -l)
  echo $(( b - 2 * mb ))
}

# Baris teks di dalam box
# row <warna> <teks>  (teks akan di-pad ke BOX_W-2)
# Perbaikan Zero: format printf diselaraskan — %*s makan 2 argumen
# (lebar + string), jadi argumen warna/teks harus pas, kalau tidak
# angka pad dan kode warna bocor jadi teks dan muncul error "invalid number".
row() {
  local c="$1" t="$2"
  # hitung panjang visual (strip ANSI)
  local plain; plain=$(printf "%b" "$t" | sed -E 's/\x1b\[[0-9;]*m//g')
  local len; len=$(vislen "$plain")
  local pad=$(( BOX_W - 2 - len ))
  [ "$pad" -lt 0 ] && pad=0
  printf "%b║%b %b%*s %b║%b\n" "$c" "$NC" "$t" "$pad" "" "$c" "$NC"
}

# Baris tabel: tbl_row <warna_kiri> <warna_kanan> <kiri> <kanan>
tbl_row() {
  local cl="$1" cr="$2" l="$3" r="$4"
  local pl; pl=$(printf "%b" "$l" | sed -E 's/\x1b\[[0-9;]*m//g')
  local pr; pr=$(printf "%b" "$r" | sed -E 's/\x1b\[[0-9;]*m//g')
  local ll; ll=$(vislen "$pl"); local rl; rl=$(vislen "$pr")
  local lw=6; local rw=$(( BOX_W - 2 - lw - 3 ))
  local lp=$(( lw - ll )); [ $lp -lt 0 ] && lp=0
  local rp=$(( rw - rl )); [ $rp -lt 0 ] && rp=0
  printf "%b║%b %b%*s %b│%b %b%*s %b║%b\n" \
    "$cl" "$NC" "$l" "$lp" "" "$cl" "$NC" "$r" "$rp" "" "$cl" "$NC"
}

# Header tabel dengan judul kolom (lebar kolom disamakan dengan tbl_row: key 6, aksi 47)
tbl_head() {
  local c="$1"
  printf "%b║%b %b%-6s%b %b│%b %b%-47s%b %b║%b\n" \
    "$c" "$NC" "$c" "KEY" "$NC" "$c" "$NC" "$c" "AKSI" "$NC" "$c" "$NC"
}

# Efek glow / typing (opsional, ringan)
glow() { printf "%b%s%b" "$1" "$2" "$NC"; }

show_header() {
  load_settings
  local os up mem disk xst xpid
  os=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"'); os=${os:0:32}
  up=$(uptime -p 2>/dev/null || uptime); up=${up:0:36}
  mem=$(free -h 2>/dev/null | awk '/Mem:/{print $3"/"$2}')
  disk=$(df -h / 2>/dev/null | awk 'NR==2{print $3"/"$2}')
  if xray_running; then xst="${NEON_GRN}● ONLINE${NC}"; xpid=$(cat "$XRAY_PID" 2>/dev/null || echo "-"); else xst="${NEON_RED}● OFFLINE${NC}"; xpid="-"; fi

  clear
  # Banner neon
  printf "%b" "$NEON_MAG"
  cat <<'BANNER'
   ███╗   ██╗███████╗ █████╗ ██████╗
   ████╗  ██║██╔════╝██╔══██╗██╔══██╗
   ██╔██╗ ██║█████╗  ███████║██████╔╝
   ██║╚██╗██║██╔══╝  ██╔══██║██╔══██╗
   ██║ ╚████║███████╗██║  ██║██║  ██║
   ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
BANNER
  printf "%b" "$NC"
  printf "%b              ── T U N N E L ──              %b\n" "$NEON_CYAN" "$NC"
  printf "%b           [ %s | v%s ]%b\n\n" "$NEON_YEL" "NEAR CLOUD" "$VERSION" "$NC"

  # Panel info sistem
  hr_top "$NEON_CYAN"
  row "$NEON_CYAN" "$(glow "$NEON_MAG$BOLD" "  ✦ SYSTEM INFO")"
  hr_mid "$NEON_CYAN"
  row "$NEON_CYAN" "  ${NEON_YEL}Host   ${NC}: ${WH}$(hostname)${NC}"
  row "$NEON_CYAN" "  ${NEON_YEL}IP     ${NC}: ${WH}$(pub_ip)${NC}"
  row "$NEON_CYAN" "  ${NEON_YEL}OS     ${NC}: ${WH}${os}${NC}"
  row "$NEON_CYAN" "  ${NEON_YEL}Uptime ${NC}: ${WH}${up}${NC}"
  row "$NEON_CYAN" "  ${NEON_YEL}RAM    ${NC}: ${WH}${mem}${NC}  ${NEON_YEL}Disk${NC}: ${WH}${disk}${NC}"
  hr_mid "$NEON_CYAN"
  row "$NEON_CYAN" "  ${NEON_YEL}Xray   ${NC}: ${xst}  ${GRY}PID ${xpid}${NC}"
  row "$NEON_CYAN" "  ${NEON_YEL}Ports  ${NC}: ${NEON_BLU}WS ${VMESS_PORT}/${VLESS_PORT}/${TROJAN_PORT}/${SS_PORT}${NC}"
  row "$NEON_CYAN" "  ${NEON_YEL}Domain ${NC}: ${WH}${DOMAIN_OR_IP}${NC}  ${NEON_YEL}Link Port${NC}: ${WH}${PORT}${NC}"
  hr_mid "$NEON_CYAN"
  # Baris jumlah akun (mini-tabel)
  local ssh_n vmess_n vless_n trojan_n ss_n trial_n
  ssh_n=$(count_proto ssh); vmess_n=$(count_proto vmess); vless_n=$(count_proto vless)
  trojan_n=$(count_proto trojan); ss_n=$(count_proto shadowsocks); trial_n=$(count_proto trial)
  row "$NEON_CYAN" "  ${NEON_PNK}SSH ${WH}${ssh_n}${NC}  ${NEON_PNK}VMess ${WH}${vmess_n}${NC}  ${NEON_PNK}VLess ${WH}${vless_n}${NC}  ${NEON_PNK}Trojan ${WH}${trojan_n}${NC}"
  row "$NEON_CYAN" "  ${NEON_PNK}SS ${WH}${ss_n}${NC}   ${NEON_PNK}Trial ${WH}${trial_n}${NC}"
  hr_bot "$NEON_CYAN"
  echo
}

pause() { echo; printf "%b  ⏎  Tekan Enter untuk kembali...%b" "$DIM$NEON_CYAN" "$NC"; read -r _x; }

ask_create() { # ask_create <proto> <label>
  local proto="$1" label="$2" user days quota lip
  echo
  printf "%b╭─ BUAT AKUN %s ─────────────────────────────╮%b\n" "$NEON_GRN" "$label" "$NC"
  printf "%b│%b " "$NEON_GRN" "$NC"; read -r -p "Nama user        : " user
  printf "%b│%b " "$NEON_GRN" "$NC"; read -r -p "Masa aktif (hari): " days
  printf "%b│%b " "$NEON_GRN" "$NC"; read -r -p "Limit kuota GB (0=tak terbatas): " quota
  printf "%b│%b " "$NEON_GRN" "$NC"; read -r -p "Limit IP (0=tak terbatas): " lip
  printf "%b╰────────────────────────────────────────────╯%b\n" "$NEON_GRN" "$NC"
  days=${days:-30}; quota=${quota:-0}; lip=${lip:-0}
  add_account "$proto" "$user" "$days" 0 "$quota" "$lip"
  pause
}

menu_loop() {
  need_root
  mkdir -p "$DB_DIR"
  while true; do
    show_header

    # Panel menu utama
    hr_top "$NEON_MAG"
    row "$NEON_MAG" "$(glow "$NEON_PNK$BOLD" "  ▸ MENU UTAMA")"
    hr_mid "$NEON_MAG"
    tbl_head "$NEON_MAG"
    hr_mid "$NEON_MAG"

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
      local k="${keys[$i]}" a="${acts[$i]}"
      local kc="$NEON_CYAN" ac="$WH"
      # Warna per kategori
      case "$k" in
        0)  kc="$NEON_RED"; ac="$NEON_RED" ;;               # Keluar
        7|11) kc="$NEON_BLU"; ac="$NEON_BLU" ;;             # Daftar/cek
        8)  kc="$NEON_RED"; ac="$NEON_ORG" ;;               # Hapus
        9|10) kc="$NEON_YEL"; ac="$NEON_YEL" ;;             # Extend/edit
        12|13|14|15) kc="$NEON_ORG"; ac="$NEON_ORG" ;;      # Service
        16) kc="$NEON_PUR"; ac="$NEON_PUR" ;;               # Speedtest
        17) kc="$NEON_PUR"; ac="$NEON_PUR" ;;               # Auto reboot
        18|19|20) kc="$NEON_PNK"; ac="$NEON_PNK" ;;         # Setting
        21) kc="$NEON_GRN"; ac="$NEON_GRN" ;;               # Backup
        *)  kc="$NEON_GRN"; ac="$NEON_GRN" ;;               # Buat akun
      esac
      # Format key jadi 2 digit agar rapi
      local kfmt; kfmt=$(printf "%2s" "$k")
      tbl_row "$NEON_MAG" "$NEON_MAG" "$kc$kfmt$NC" "$ac$a$NC"
    done

    hr_bot "$NEON_MAG"
    echo
    printf "%b  ➤ Pilih nomor %b[%b0-21%b]%b : %b" \
      "$NEON_CYAN" "$NC" "$NEON_YEL" "$NC" "$NEON_CYAN" "$NC"
    IFS= read -r pil
    echo

    case "$pil" in
      1) ask_create ssh "SSH" ;;
      2) ask_create vmess "VMess" ;;
      3) ask_create vless "VLess" ;;
      4) ask_create trojan "Trojan" ;;
      5) ask_create shadowsocks "Shadowsocks" ;;
      6) printf "%b  Nama user trial: %b" "$NEON_YEL" "$NC"; read -r u; add_account trial "$u" 0 1; pause ;;
      7) list_accounts; pause ;;
      8) printf "%b  Nama user yang dihapus: %b" "$NEON_RED" "$NC"; read -r u; delete_account "$u"; pause ;;
      9) printf "%b  Nama user: %b" "$NEON_YEL" "$NC"; read -r u; printf "%b  Tambah berapa hari: %b" "$NEON_YEL" "$NC"; read -r d; extend_account "$u" "${d:-7}"; pause ;;
      10) printf "%b  Nama user: %b" "$NEON_YEL" "$NC"; read -r u; printf "%b  Limit IP (0=tak terbatas): %b" "$NEON_YEL" "$NC"; read -r l; printf "%b  Bandwidth GB (0=tak terbatas): %b" "$NEON_YEL" "$NC"; read -r b; edit_account "$u" "${l:-0}" "${b:-0}" "${b:-0}"; pause ;;
      11) list_accounts; pause ;;
      12) restart_xray; pause ;;
      13) echo "Mode tes: tidak ada systemd di VPS trial. SSHD tidak di-restart (dilarang)."; restart_xray; pause ;;
      14) if xray_running; then printf "%bXray: JALAN (PID %s)%b\n" "$NEON_GRN" "$(cat $XRAY_PID 2>/dev/null)" "$NC"; else printf "%bXray: MATI%b\n" "$NEON_RED" "$NC"; fi; "$XRAY_BIN" version 2>/dev/null | head -2; echo "--- port listen ---"; (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep -E '1008|46824|22' || true; pause ;;
      15) (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) || echo "ss/netstat tidak tersedia"; pause ;;
      16) echo "Speed test (unduh 25MB dari Cloudflare)..."; curl -s -o /dev/null -w "Waktu: %{time_total}s  Kecepatan: %{speed_download} byte/s\n" https://speed.cloudflare.com/__down?bytes=25000000 || echo "Speed test gagal (cek internet VPS)."; pause ;;
      17) echo "Mode tes: Auto Reboot BELUM AKTIF di VPS trial (tanpa systemd). Akan aktif di VPS baru."; pause ;;
      18) printf "%b  Chat ID Telegram: %b" "$NEON_PNK" "$NC"; read -r cid; printf "%b  Bot token (hidden): %b" "$NEON_PNK" "$NC"; read -r -s tok; echo; printf 'CHAT_ID="%s"\nBOT_TOKEN="%s"\n' "$cid" "$tok" > "$NT_DIR/telegram.conf"; chmod 600 "$NT_DIR/telegram.conf"; unset tok; echo "Tersimpan di $NT_DIR/telegram.conf (600)."; pause ;;
      19) printf "%b  Domain/IP baru: %b" "$NEON_PNK" "$NC"; read -r nd; printf "%b  Port link baru [%s]: %b" "$NEON_PNK" "$PORT" "$NC"; read -r np; [ -n "$nd" ] && DOMAIN_OR_IP="$nd"; [ -n "$np" ] && PORT="$np"; save_settings; echo "OK: domain=$DOMAIN_OR_IP port=$PORT"; pause ;;
      20) echo "Mode tes: Update Script BELUM AKTIF. Versi: $VERSION"; pause ;;
      21) mkdir -p /root; tar -czf "/root/near-tunnel-backup-$(date +%Y%m%d-%H%M).tar.gz" -C /etc near-tunnel 2>/dev/null && echo "Backup: /root/near-tunnel-backup-*.tar.gz" || echo "Backup gagal."; pause ;;
      0) printf "%b  ⏻  Keluar. Sampai jumpa.%b\n" "$NEON_MAG" "$NC"; exit 0 ;;
      *) printf "%b  ✗ Pilihan tidak ada.%b\n" "$NEON_RED" "$NC"; sleep 1 ;;
    esac
  done
}

# ---------- CLI ----------
load_settings
mkdir -p "$DB_DIR" 2>/dev/null || true
case "${1:-}" in
  install) do_install ;;
  add-vmess) add_account vmess "$2" "${3:-30}" 0 "${4:-0}" "${5:-0}" ;;
  add-vless) add_account vless "$2" "${3:-30}" 0 "${4:-0}" "${5:-0}" ;;
  add-trojan) add_account trojan "$2" "${3:-30}" 0 "${4:-0}" "${5:-0}" ;;
  add-ssh) add_account ssh "$2" "${3:-30}" 0 "${4:-0}" "${5:-0}" ;;
  add-ss) add_account shadowsocks "$2" "${3:-30}" 0 "${4:-0}" "${5:-0}" ;;
  add-trial) add_account trial "$2" 0 1 ;;
  list) list_accounts ;;
  delete) delete_account "$2" "${3:-}" ;;
  extend) extend_account "$2" "${3:-7}" ;;
  restart) restart_xray ;;
  status) if xray_running; then echo "Xray JALAN"; else echo "Xray MATI"; fi ;;
  menu|"") menu_loop ;;
  *) echo "Pakai: $0 [install|menu|add-vmess|add-vless|add-trojan|add-ssh|add-ss|add-trial|list|delete|extend|restart|status]"; exit 1 ;;
esac
