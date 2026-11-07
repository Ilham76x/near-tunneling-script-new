# near-tunnel v0.1-tes — catatan tes

Script tunneling BARU dari nol (bukan salinan script lama), dibuat untuk tes
di VPS trial near. Menu 1-21, header ala st-pusat, tampil simpel pilih nomor.

## File
- `near-tunnel.sh` — script utama (456 baris, `bash -n` OK)
- Terpasang di VPS trial sebagai `/usr/local/sbin/near-tunnel`
  (jalankan `near-tunnel` sebagai root). `/root/.bashrc` TIDAK diubah.

## Cara kerja (tes)
- Xray Core 26.10.31 (resmi XTLS/Xray-core, linux-64) di `/usr/local/bin/xray`
- Config `/etc/xray/config.json`, dibangun ulang dari DB setiap ada perubahan akun
- Inbound WS polos di 127.0.0.1 saja, tanpa TLS/domain:
  VMess 10086 (/vmess), VLess 10087 (/vless), Trojan 10088 (/trojan),
  Shadowsocks 10089 (aes-256-gcm)
- Xray jalan via `setsid` + nohup (tanpa systemd), PID di
  `/var/run/near-tunnel-xray.pid`, log `/var/log/xray-near-tunnel.log`
- Akun di `/etc/near-tunnel/db/<proto>/<user>` (600), settings di
  `/etc/near-tunnel/settings.conf` — DOMAIN_OR_IP dan PORT (default 443)
  bisa diubah di satu tempat / menu 19
- Link memakai DOMAIN_OR_IP:PORT. Di VPS trial ini link belum bisa dipakai
  langsung dari HP karena belum ada TLS terminator / domain / port publik
  (port ditunda sampai VPS baru, sesuai pesan near).

## Hasil tes di VPS trial (2026-11-07, root@66.33.22.232:46824)
- Instalasi OK. Satu perbaikan saat instal: Xray 26.10.31 wajib
  `"decryption":"none"` di settings VLess, kalau tidak Xray gagal start.
  Setelah diperbaiki, Xray JALAN dan 4 port listen (ss -tlnp).
- Akun tes dibuat via CLI (30 hari, sampai 2026-12-07):
  tesvmess (VMess), tesvless (VLess), testrojan (Trojan),
  tesssh (SSH, user sistem dibuat, uid 1000),
  tesss (Shadowsocks), testrial (Trial 1 jam, masuk VMess+VLess+Trojan)
- Config bertambah sesuai jumlah akun (cek: vmess=2 vless=2 trojan=2 ss=1
  saat trial masih ada; setelah hapus SS jadi ss=0).
- Hapus tesss OK (file DB hilang, config ss=0). Perpanjang tesvless +7 hari
  OK (sampai 2026-12-14). Edit tesvless OK (limit_ip=2, bandwidth=10,
  tersimpan; penegakan otomatis belum aktif di v0.1).
- Menu interaktif tampil benar (header + nomor 1-21 + 0), pilih 0 keluar.
  Menu 17 Auto Reboot dan 20 Update Script tampil jelas sebagai
  "mode tes: BELUM AKTIF di VPS trial". Menu 21 Backup OK
  (`/root/near-tunnel-backup-20261107-0823.tar.gz`).
- Akun tes di atas masih ada di VPS trial (kecuali tesss yang dihapus dan
  testrial yang kedaluwarsa 1 jam setelah dibuat).

## Yang BELUM dites (karena port/domain ditunda)
- Koneksi nyata dari HP / DarkTunnel lewat link (butuh TLS terminator +
  domain + port 443/80 publik di VPS baru).
- Menu 13 Restart Semua Layanan (hanya restart Xray di trial; sshd
  sengaja tidak di-restart), 18 Setup Telegram (hanya simpan config,
  belum kirim pesan tes), 16 Speed Test (ada, belum dijalankan),
  14/15 status & port (kode ada, tampil lewat menu; ss sudah terbukti
  di tes CLI), 11 (sama dengan daftar akun).
- Penegakan limit IP / bandwidth otomatis: baru tersimpan, belum ditegakkan.

## Yang perlu disiapkan di VPS baru nanti
- Domain yang diarahkan ke IP VPS + port 80/443 publik (bukan NAT tertutup)
- TLS terminator (HAProxy/nginx) di depan Xray, atau Xray TLS langsung
- systemd (atau tetap nohup seperti di trial) + cron untuk cek kedaluwarsa
- Kalau mau notifikasi Telegram: bot token + chat ID (diisi lewat menu 18,
  tidak lewat chat)
