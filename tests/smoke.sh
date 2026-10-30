#!/usr/bin/env bash
# Smoke test: drives the whole installer flow with --dry-run against stubbed system commands (no root,
# no firewalld, no database), then runs the file-writing functions for real into a scratch tree and
# checks what they produced. Prints the installer output when something fails.
# shellcheck disable=SC2034,SC1090,SC1091
set -uo pipefail
cd "$(dirname "$0")/.."
export MSYS2_ARG_CONV_EXCL='/CN='   # Git Bash: do not rewrite the openssl "/CN=..." subject into a Windows path
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/etc/apache2/sites-available" "$T/etc/firewalld" "$T/srv/www/vhosts" "$T/var/log"

stub() { printf '#!/usr/bin/env bash\n%s\n' "$2" >"$T/bin/$1"; chmod +x "$T/bin/$1"; }
stub id 'echo 0'
stub systemctl 'case "$1" in is-active|is-enabled) exit 1;; list-unit-files) echo "cron.service enabled";; *) exit 0;; esac'
stub ip 'case "$*" in *"route show default"*) echo "default via 203.0.113.1 dev eth0 proto static";; *"link show"*) exit 0;; *"addr show"*) echo "2: eth0    inet 203.0.113.20/24 brd 203.0.113.255 scope global eth0";; *) exit 0;; esac'
stub curl 'case "$*" in *ipify*) echo 203.0.113.20;; *valid8.php*) echo "<title>User Validation</title>";; *) exit 1;; esac'
stub hostname 'echo dialer.example.com'
stub apt-get 'exit 0'
stub firewall-cmd 'case "$*" in --version) echo 1.3.4;; --state) echo running;; *--get-entries*) echo 203.0.113.9;; *--query-entry*) exit 0;; *) echo success;; esac'
stub crontab 'case "$1" in -l) printf "* * * * * /usr/share/astguiclient/ADMIN_keepalive_ALL.pl\n### ViciBox integrated firewall\n@reboot /usr/bin/VB-firewall --voipbl --quiet\n";; -) cat >"$SMOKE_CRON_OUT";; *) exit 0;; esac'
stub mysql 'q=""; while [ $# -gt 0 ]; do [ "$1" = -e ] && q=$2; shift; done
case "$q" in *vicidial_server_carriers*) printf "host=203.0.113.50\nhost=dynamic\ncontact=sip:198.51.100.77:5060\n";; *COUNT*) echo 2;; *pass_hash_enabled*) echo 0;; *) exit 0;; esac'
stub a2enmod 'exit 0'; stub a2ensite 'exit 0'; stub a2dissite 'exit 0'; stub install 'exit 0'; stub ln 'exit 0'
printf 'VARDB_server => localhost\nVARDB_database => asterisk\nVARDB_user => cron\nVARDB_pass => 1234\nVARDB_port => 3306\n' >"$T/etc/astguiclient.conf"
printf 'Listen 80\n<IfModule ssl_module>\n\tListen 443\n</IfModule>\n' >"$T/etc/apache2/sites-available/../ports.conf"

export PATH="$T/bin:$PATH" SMOKE_CRON_OUT="$T/crontab.out" SSH_CONNECTION="203.0.113.9 55555 203.0.113.20 22"
export VF_SOURCE_ONLY=1
. src/installer.sh; set +e

# point every path the installer touches into the scratch tree
ASTGUI_CONF=$T/etc/astguiclient.conf LOG_FILE=$T/var/log/install.log FW_ETC=$T/etc/firewalld FW_LIB=$T/usr/lib/firewalld
CONF_DIR=$T/etc/vicidial-firewall STATE_FILE=$CONF_DIR/state BACKUP_ROOT=$T/var/backups HELPER=$T/usr/local/sbin/vicidial-firewall
F2B_ETC=$T/etc/fail2ban
PORTAL_DIR=$T/srv/www/vhosts/dynportal VBF_DIR=$T/usr/share/vicibox-firewall VBF_BIN=$T/usr/bin/VB-firewall
detect_os() {
	FAMILY=debian PRETTY="Debian 12 (stub)" PKG=apt VICIBOX=0
	APACHE_SVC=apache2 APACHE_USER=www-data APACHE_GROUP=www-data APACHE_CONF_ROOT=$T/etc/apache2 APACHE_LOG=/var/log/apache2
	VHOST_FILE=$T/etc/apache2/sites-available/dynportal-ssl.conf VHOST_HTTP_FILE=$T/etc/apache2/sites-available/dynportal.conf LISTEN_FILE=$T/etc/apache2/ports.conf
}

fail=0
# ---- A: whole flow, dry run --------------------------------------------------------------------------
out=$(main --dry-run --yes --whitelist=198.51.100.0/24 --cluster-ip=192.0.2.5 --payload-dir="$PWD" 2>&1); rc=$?
chk() { if ! grep -q -- "$1" <<<"$out"; then echo "SMOKE A missing: $1"; fail=1; fi; }
[ $rc -eq 0 ] || { echo "SMOKE A: main exited $rc"; fail=1; }
chk "this SSH session comes from 203.0.113.9"
chk "carrier addresses found in ViciDial: 198.51.100.77, 203.0.113.50"
chk "ViciWhite entries ... 203.0.113.9, 198.51.100.0/24, 198.51.100.77, 203.0.113.50"
chk "internal networks ... 192.0.2.5/32"
chk "public zone ......... rtp dhcpv6-client dynportal-ssl on eth0"
chk "Dynamic Portal ...... https://dialer.example.com:446/valid8.php"
chk "(dry-run) SQL: UPDATE system_settings SET allow_ip_lists='1'"
chk "(dry-run) SQL: INSERT INTO vicidial_ip_list_entries (ip_address, ip_list_id) SELECT '198.51.100.0/24','ViciWhite'"
chk "(dry-run) crontab lines: '@reboot $T/usr/bin/VB-firewall --white --dynamic --quiet'"
chk "(dry-run) write $T/etc/firewalld/zones/external.xml"
chk "(dry-run) write $T/srv/www/vhosts/dynportal/inc/defaults.inc.php"
chk "agents zone ......... http https asterisk rtp  for addresses validated through the portal"
chk "(dry-run) write $T/etc/fail2ban/jail.d/vicidial-dynportal.conf"
chk "(dry-run) append 'Listen 446' to $T/etc/apache2/ports.conf"
chk "vicidial-firewall 1.1.1 installed  -  mode: dynamic"
if grep -qE 'unbound variable|command not found|syntax error' <<<"$out"; then echo "SMOKE A: shell error in output"; fail=1; fi
[ $fail -eq 0 ] || printf '%s\n' "$out" | tail -60

# ---- B: real writers into the scratch tree ----------------------------------------------------------
rm -f "$T/bin/install" "$T/bin/ln"; hash -r   # part B needs the real install(1); forget the cached stub paths
PAYLOAD_DIR=$PWD   # part A ran main in a subshell, so parse_args' value did not reach this shell
DRY_RUN=0; MODE=dynamic; PORTAL=1; PORTAL_HTTP=0; PORTAL_PORT=446; PORTAL_FQDN=dialer.example.com; RTP_RANGE=10000-20000; PUBLIC_IFACE=eth0
INTERNAL_NETS=(192.0.2.5/32); WHITELIST=(198.51.100.0/24); CARRIER_IPS=(); SSH_IP=203.0.113.9; TRUSTED_NETS=(); TRUSTED_IFACES=()
detect_os; compute_plan
mkdir -p "$PORTAL_DIR/inc"; cp -a official/dynportal/. "$PORTAL_DIR/"
out=$( { install_firewalld_config; write_portal_defaults; resolve_ssl; write_vhosts; install_cron; write_state; stub fail2ban-client "exit 0"; install_fail2ban; } 2>&1 ); rc=$?
[ $rc -eq 0 ] || { echo "SMOKE B: writers exited $rc"; printf '%s\n' "$out"; fail=1; }
chkf() { if ! grep -q -- "$2" "$1" 2>/dev/null; then echo "SMOKE B: $1 lacks: $2"; fail=1; fi; }
for z in public external internal drop; do [ -s "$FW_ETC/zones/$z.xml" ] || { echo "SMOKE B: zone $z missing"; fail=1; }; done
chkf "$FW_ETC/zones/public.xml"   '<service name="dynportal-ssl"/>'
chkf "$FW_ETC/zones/external.xml" '<source ipset="whitenets"/>'
chkf "$FW_ETC/zones/external.xml" '<service name="dynportal-ssl"/>'
chkf "$FW_ETC/zones/external.xml" '<service name="ssh"/>'
chkf "$FW_ETC/zones/internal.xml" '<source address="192.0.2.5/32"/>'
chkf "$FW_ETC/zones/internal.xml" '<port protocol="tcp" port="5038"/>'
chkf "$FW_ETC/zones/drop.xml"     '<zone target="DROP"'
chkf "$FW_ETC/services/rtp.xml"   'port="10000-20000"'
chkf "$FW_ETC/services/dynportal-ssl.xml" 'port="446"'
[ "$(ls "$FW_ETC"/ipsets/*.xml | wc -l)" -eq 8 ] || { echo "SMOKE B: expected 8 ipset files"; fail=1; }
if ! grep -q '<service name="ssh"/>' "$FW_ETC/zones/public.xml"; then :; else echo "SMOKE B: ssh must not be public in dynamic mode"; fail=1; fi
d=$PORTAL_DIR/inc/defaults.inc.php
chkf "$d" "^\$PORTAL_userlevel=1;"
chkf "$d" "^\$PORTAL_redirecturl='https://dialer.example.com/agc/vicidial.php';"
chkf "$d" "^\$PORTAL_submitlocal=0;"
grep -q "Jzr87Cp8XqJY" "$d" && { echo "SMOKE B: default form field name kept"; fail=1; }
grep -qE "^\\\$PORTAL_useridvar='[A-Za-z][A-Za-z0-9]{11}';" "$d" || { echo "SMOKE B: random useridvar missing"; fail=1; }
uid1=$(sed -n "s/^\$PORTAL_useridvar='\(.*\)';.*/\1/p" "$d"); write_portal_defaults >/dev/null 2>&1; uid2=$(sed -n "s/^\$PORTAL_useridvar='\(.*\)';.*/\1/p" "$d")
[ "$uid1" = "$uid2" ] || { echo "SMOKE B: field names not preserved on re-run"; fail=1; }
[ -s "$CONF_DIR/ssl/dynportal.crt" ] && [ -s "$CONF_DIR/ssl/dynportal.key" ] || { echo "SMOKE B: self-signed cert not generated"; fail=1; }
openssl x509 -in "$CONF_DIR/ssl/dynportal.crt" -noout -subject 2>/dev/null | grep -q dialer.example.com || { echo "SMOKE B: cert CN wrong"; fail=1; }
v=$VHOST_FILE
chkf "$v" '<VirtualHost _default_:446>'
chkf "$v" 'ServerName dialer.example.com'
chkf "$v" "SSLCertificateFile $CONF_DIR/ssl/dynportal.crt"
chkf "$v" "DocumentRoot $PORTAL_DIR"
grep -q '@@' "$v" && { echo "SMOKE B: unreplaced token in vhost"; fail=1; }
chkf "$LISTEN_FILE" '^Listen 446$'
[ "$(grep -c '^Listen 446$' "$LISTEN_FILE")" -eq 1 ] || { echo "SMOKE B: Listen 446 duplicated"; fail=1; }
write_vhosts >/dev/null 2>&1; [ "$(grep -c '^Listen 446$' "$LISTEN_FILE")" -eq 1 ] || { echo "SMOKE B: Listen 446 duplicated on re-run"; fail=1; }
chkf "$SMOKE_CRON_OUT" '^\* \* \* \* \* '"$VBF_BIN"' --white --dynamic --quiet$'
chkf "$SMOKE_CRON_OUT" '^@reboot '"$VBF_BIN"' --white --dynamic --quiet$'
chkf "$SMOKE_CRON_OUT" 'ADMIN_keepalive_ALL.pl'
grep -q -- '--voipbl' "$SMOKE_CRON_OUT" && { echo "SMOKE B: old VB-firewall cron line survived"; fail=1; }
[ "$(grep -c 'VB-firewall' "$SMOKE_CRON_OUT")" -eq 2 ] || { echo "SMOKE B: unexpected VB-firewall line count: $(grep -c VB-firewall "$SMOKE_CRON_OUT")"; fail=1; }
grep -q '^### ViciBox integrated firewall' "$SMOKE_CRON_OUT" || { echo "SMOKE B: cron header missing"; fail=1; }
( set -u; . "$STATE_FILE" && [ "$MODE" = dynamic ] && [ "$PORTAL_FQDN" = dialer.example.com ] ) || { echo "SMOKE B: state file broken"; fail=1; }

# v1.1: split zones, priorities, fail2ban files
[ -s "$FW_ETC/zones/agents.xml" ] || { echo "SMOKE B: agents zone missing"; fail=1; }
chkf "$FW_ETC/zones/agents.xml"   '<source ipset="dynamiclist"/>'
chkf "$FW_ETC/zones/agents.xml"   '<service name="dynportal-ssl"/>'
grep -q '<service name="ssh"/>' "$FW_ETC/zones/agents.xml" && { echo "SMOKE B: agents zone must not include ssh by default"; fail=1; }
grep -q dynamiclist "$FW_ETC/zones/external.xml" && { echo "SMOKE B: external zone must not include dynamiclist"; fail=1; }
chkf "$FW_ETC/zones/external.xml" '<source ipset="whiteips"/>'
chkf "$FW_ETC/zones/external.xml" '<zone priority="-10">'
chkf "$FW_ETC/zones/drop.xml"     '<zone target="DROP" priority="-20">'
chkf "$F2B_ETC/jail.d/vicidial-dynportal.conf" '^port      = 446,81$'
chkf "$F2B_ETC/jail.d/vicidial-dynportal.conf" '^banaction = firewallcmd-rich-rules$'
chkf "$F2B_ETC/jail.d/vicidial-dynportal.conf" '^backend = systemd$'
chkf "$F2B_ETC/filter.d/vicidial-dynportal.conf" '<HOST>'
chkf "$d" "^\$PORTAL_countunsuccessful=1;"
chkf "$d" "^\$PORTAL_unsuccessfullimit=5;"

if [ $fail -eq 0 ]; then echo "smoke: ok"; else echo "smoke: FAILED"; fi
exit $fail
