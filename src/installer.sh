#!/usr/bin/env bash
#
# vicidial-firewall - installer
# =============================
# Installs and configures the official ViciDial / ViciBox firewall stack on a ViciDial server:
#
#   VB-firewall.pl   the official ViciBox script (James Pearson, The ViciDial Group) that keeps the
#                    firewalld IP sets in sync with the ViciDial IP lists (ViciWhite / ViciBlack) and
#                    with the addresses of recent agent logins (vicidial_user_log)
#   Dynamic Portal   the official ViciBox web portal (valid8.php) where remote agents validate their
#                    current, dynamic IP address with their ViciDial user ID and password
#   firewalld        the same zone / IP-set layout as ViciBox: public, external, internal, drop
#
# Usage:  sudo bash install.sh [options]          (--help lists the options)
#         sudo bash src/installer.sh [options]    (from a checkout of the repository)
#
# Copyright (C) 2026 - GNU AGPL v3 or later (see LICENSE). The official components are
# Copyright (C) James Pearson / The ViciDial Group, AGPL. Provenance: official/SOURCES.md.
#
# shellcheck disable=SC2034,SC1090
set -euo pipefail
umask 022

VF_VERSION="1.1.2"

# ------------------------------------------------------------------------------------------------
# Paths: the official ViciBox layout wherever one exists
# ------------------------------------------------------------------------------------------------
VBF_DIR=/usr/share/vicibox-firewall        # where the vicibox-firewall RPM keeps VB-firewall.pl
VBF_BIN=/usr/bin/VB-firewall               # the symlink that RPM creates; the cron job calls this
PORTAL_DIR=/srv/www/vhosts/dynportal       # where the vicibox-dynportal RPM keeps the portal
CONF_DIR=/etc/vicidial-firewall
STATE_FILE=$CONF_DIR/state
BACKUP_ROOT=/var/backups/vicidial-firewall
HELPER=/usr/local/sbin/vicidial-firewall
LOG_FILE=/var/log/vicidial-firewall-install.log
FW_ETC=/etc/firewalld
FW_LIB=/usr/lib/firewalld
ASTGUI_CONF=/etc/astguiclient.conf
SAFETY_UNIT=vicidial-firewall-safety

# ------------------------------------------------------------------------------------------------
# Options and their defaults
# ------------------------------------------------------------------------------------------------
MODE=dynamic                 # dynamic | whitelist | blacklist
PORTAL=1
PORTAL_PORT=446
PORTAL_HTTP=0
PORTAL_HTTP_PORT=81
PORTAL_FQDN=""
PORTAL_USERLEVEL=1
PORTAL_REDIRECT=""           # "" = https://FQDN/agc/vicidial.php, "none" = no redirect
PORTAL_REDIRECT_ADMIN=""
PORTAL_REDIRECT_SECS=60
PORTAL_LOGIN_PASSTHROUGH=1
SSL_CERT=""
SSL_KEY=""
SSL_CHAIN=""
WHITELIST=()
SSH_WHITELIST=1
KEEP_SSH_PUBLIC=0
TRUSTED_IFACES=()
TRUSTED_NETS=()
INTERNAL_NETS=()
PUBLIC_IFACE=""
RTP_RANGE=""
DYNAMIC_AGE=15
ADD_RFC1918=0
AUTO_CARRIERS=1
KEEP_LEGACY_IPTABLES=0
AGENT_SSH=0                  # 1 = validated agents may also reach SSH (stock ViciBox behaviour)
PUBLIC_RTP=1                 # 0 = RTP media closed to unknown addresses too
PORTAL_LOCKOUT=5             # failed portal logins before a user is ignored; 0 = off
FAIL2BAN=1
F2B_ETC=/etc/fail2ban
SAFETY_MIN=10
ASSUME_YES=0
DRY_RUN=0
PAYLOAD_DIR=""
DB_HOST="" DB_USER="" DB_PASS="" DB_NAME="" DB_PORT=""

# ------------------------------------------------------------------------------------------------
# Detected state
# ------------------------------------------------------------------------------------------------
FAMILY="" PRETTY="" VICIBOX=0 PKG=""
APACHE_SVC="" APACHE_USER="" APACHE_GROUP="" APACHE_CONF_ROOT="" VHOST_FILE="" VHOST_HTTP_FILE="" LISTEN_FILE="" APACHE_LOG=""
SSH_IP="" PUBLIC_IP="" EXTERNAL_IP="" MYSQL_BIN=""
FIREWALLD_WAS_ACTIVE=0 FIREWALLD_WAS_ENABLED=0 ORIG_FW_ACTIVE="" ORIG_FW_ENABLED=""
BACKUP_DIR="" ORIGINAL_BACKUP_DIR=""
VBF_ARGS="" CRON_SCHED=""
SELINUX=0 RPM_PORTAL=0 PORTAL_INSTALLED=0 SSL_SELF_SIGNED=0 LISTEN_ADDED=0 LISTEN_HTTP_ADDED=0 PASS_HASH=0
FW_PRIORITY_OK=0 FAIL2BAN_INSTALLED=0
CARRIER_IPS=()
ALLOW_NOW=()

# ------------------------------------------------------------------------------------------------
# Output helpers
# ------------------------------------------------------------------------------------------------
c_red=$'\e[31m' c_grn=$'\e[32m' c_yel=$'\e[33m' c_bld=$'\e[1m' c_off=$'\e[0m'
[ -t 1 ] || { c_red="" c_grn="" c_yel="" c_bld="" c_off=""; }
logonly() { { printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOG_FILE"; } 2>/dev/null || true; }
say()     { logonly "$*"; printf '%s\n' "$*"; }
hdr()     { say ""; say "${c_bld}==> $*${c_off}"; }
info()    { say "    $*"; }
ok()      { say "    ${c_grn}[ok]${c_off} $*"; }
warn()    { say "    ${c_yel}[warning]${c_off} $*"; }
die()     { say "    ${c_red}[fatal]${c_off} $*"; exit 1; }
run()     { logonly "\$ $*"; if ((DRY_RUN)); then info "(dry-run) $*"; return 0; fi; "$@"; }
# write_file PATH [MODE]  - content on stdin, written atomically
write_file() {
	local path=$1 mode=${2:-0644} tmp
	if ((DRY_RUN)); then info "(dry-run) write $path"; cat >/dev/null; return 0; fi
	mkdir -p "$(dirname "$path")"
	tmp=$(mktemp "$path.XXXXXX")
	cat >"$tmp"; chmod "$mode" "$tmp"; mv -f "$tmp" "$path"
	logonly "wrote $path"
}
install_if_changed() { # SRC DST [MODE]
	if [ -f "$2" ] && cmp -s "$1" "$2"; then return 0; fi
	run install -m "${3:-0644}" "$1" "$2"
}

# ------------------------------------------------------------------------------------------------
# Small pure helpers (also exercised by tests/run-tests.sh)
# ------------------------------------------------------------------------------------------------
valid_ipv4() {
	local ip=${1:-} o
	[[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
	for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
	[ "$ip" != 0.0.0.0 ] && [ "$ip" != 255.255.255.255 ]
}
valid_cidr() {
	local net bits
	[[ ${1:-} =~ ^([0-9.]+)/([0-9]{1,2})$ ]] || return 1
	net=${BASH_REMATCH[1]} bits=${BASH_REMATCH[2]}   # copy first: valid_ipv4 overwrites BASH_REMATCH
	valid_ipv4 "$net" && (( 10#$bits >= 1 && 10#$bits <= 32 ))
}
valid_ip_or_cidr() { valid_ipv4 "$1" || valid_cidr "$1"; }
is_private_ipv4() {
	[[ $1 =~ ^10\. ]] || [[ $1 =~ ^192\.168\. ]] || [[ $1 =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] || [[ $1 =~ ^127\. ]]
}
ip2int() { local IFS=. a b c d; read -r a b c d <<<"$1"; echo $(( (10#$a<<24) | (10#$b<<16) | (10#$c<<8) | 10#$d )); }
cidr_contains() { # CIDR IP
	local net=${1%/*} bits=${1#*/} mask
	mask=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
	(( ( $(ip2int "$net") & mask ) == ( $(ip2int "$2") & mask ) ))
}
rand_name() { # 12 alphanumerics starting with a letter (HTML form field names for the portal)
	local pool
	pool=$(head -c 96 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
	printf '%s%s' "$(printf '%s' "$pool" | tr -dc 'A-Za-z' | cut -c1)" "$(printf '%s' "$pool" | cut -c2-12)"
}
cron_strip_vbf() { # stdin -> stdout without any VB-firewall lines / our header, trailing blanks removed
	{ grep -v -E '(^|[[:space:]/])VB-firewall(\.pl)?([[:space:]]|$)' || true; } \
	| { grep -v -E '^### ViciBox integrated firewall' || true; } \
	| sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'
}
render_template() { # FILE  (uses @@TOKENS@@ from TPL_* variables; literal replacement, no regex)
	local t; t=$(<"$1")
	t=${t//@@GENERATED@@/$TPL_GENERATED}; t=${t//@@LISTEN@@/$TPL_LISTEN}; t=${t//@@PORT@@/$TPL_PORT}
	t=${t//@@FQDN@@/$TPL_FQDN}; t=${t//@@DOCROOT@@/$TPL_DOCROOT}; t=${t//@@LOGDIR@@/$TPL_LOGDIR}
	t=${t//@@PHP_INCLUDE@@/$TPL_PHP_INCLUDE}; t=${t//@@CERT@@/$TPL_CERT}; t=${t//@@KEY@@/$TPL_KEY}
	t=${t//@@CHAIN@@/$TPL_CHAIN}
	printf '%s\n' "$t"
}
state_get() { [ -r "$STATE_FILE" ] || return 0; ( set +u; . "$STATE_FILE" 2>/dev/null; printf '%s' "${!1:-}" ); }
fw_version_ge() { # VERSION MIN -> true when major.minor of VERSION >= MIN (e.g. 1.3.4 >= 0.9)
	local v=${1:-} m=$2 vmaj vmin mmaj mmin
	vmaj=${v%%.*}; vmin=${v#*.}; vmin=${vmin%%.*}; mmaj=${m%%.*}; mmin=${m#*.}; mmin=${mmin%%.*}
	[[ $vmaj =~ ^[0-9]+$ && $vmin =~ ^[0-9]+$ ]] || return 1
	(( 10#$vmaj > 10#$mmaj || (10#$vmaj == 10#$mmaj && 10#$vmin >= 10#$mmin) ))
}
detect_fw_priority() { # zone priorities need firewalld 0.9 (2020); older versions would refuse the attribute
	local v; v=$(firewall-cmd --version 2>/dev/null | head -1 | tr -d '[:space:]' || true)
	if fw_version_ge "$v" 0.9; then FW_PRIORITY_OK=1; else FW_PRIORITY_OK=0; fi
}
join_by() { local sep=$1 out="" x; shift; for x in "$@"; do out+="${out:+$sep}$x"; done; printf '%s' "$out"; }

# ------------------------------------------------------------------------------------------------
usage() {
	cat <<EOF
vicidial-firewall installer $VF_VERSION
Installs the official ViciDial / ViciBox firewall (VB-firewall.pl + Dynamic Portal) on this server.

  sudo bash install.sh [options]

Firewall mode
  --mode=dynamic        (default) only the ViciWhite IP list and agents who logged in (ViciDial or the
                        Dynamic Portal) within --dynamic-age days may reach ViciDial; VB-firewall --white --dynamic
  --mode=whitelist      only the ViciWhite IP list; VB-firewall --white
  --mode=blacklist      everything open except the ViciBlack list and the voipbl.org block list (ViciBox default)
  --dynamic-age=DAYS    how long an agent login keeps an IP allowed (default 15, the VB-firewall default)
  --add-rfc1918         also allow 10/8, 172.16/12, 192.168/16 (VB-firewall --addrfc1918; see README caveat)

Who gets in right away
  --whitelist=IP[,IP/CIDR,...]  extra ViciWhite entries: SIP carriers, office, VPN, monitoring
  --no-ssh-whitelist    do not add the IP of this SSH session to ViciWhite (default: it is added)
  --no-auto-carriers    do not add the host= addresses of active ViciDial carriers to ViciWhite
  --keep-ssh-public     keep SSH open to the whole internet in the public zone
  --agent-ssh           let addresses validated through the portal reach SSH too (stock ViciBox behaviour;
                        default: validated agents get web, SIP/WebRTC and audio only)
  --no-public-rtp       close the RTP media range to unknown addresses as well (then EVERY carrier media
                        address must be in ViciWhite, or calls have no audio)
  --trusted-iface=NAME[,NAME]   LAN interfaces that may do anything (firewalld "trusted" zone)
  --trusted-net=CIDR[,CIDR]     LAN networks that may do anything
  --internal-net=CIDR[,CIDR]    cluster peers / networks that also get MySQL, FTP and AMI ("internal" zone)
  --cluster-ip=IP[,IP]          same as --internal-net with /32 entries
  --public-iface=NAME   internet-facing interface (default: the default-route interface)
  --rtp-range=A-B       RTP UDP range kept open to everyone (default: /etc/asterisk/rtp.conf or 10000-20000)
  --keep-legacy-iptables        do not flush pre-existing iptables filter rules after firewalld takes over

Dynamic Portal
  --no-portal           firewall only (cluster servers that do not host the portal)
  --portal-fqdn=HOST    host name agents use (default: hostname -f, else the public IP)
  --portal-port=N       HTTPS port (default 446, the ViciBox default)
  --portal-http         also serve the plain-HTTP portal on port 81 (not recommended)
  --portal-userlevel=N  minimum ViciDial user level allowed to validate (default 1 = agents)
  --portal-redirect=URL page agents are sent to after validating (default https://HOST/agc/vicidial.php)
  --no-portal-redirect  show "Login Validated" only
  --portal-redirect-secs=N      countdown before the redirect (default 60)
  --no-login-passthrough        do not pre-fill the ViciDial login after the redirect
  --portal-lockout=N    failed portal logins after which that user is ignored (default 5; 0 = off;
                        an admin resets it by saving the user in ViciDial Admin > Users)
  --no-fail2ban         do not install the fail2ban jail that bans an address for 1 hour after 5 failed
                        portal logins in 10 minutes
  --ssl-cert=FILE --ssl-key=FILE [--ssl-chain=FILE]   certificate for the portal
                        (default: Let's Encrypt for HOST, else the web server's certificate, else self-signed)

Database (default: read from /etc/astguiclient.conf)
  --db-host=H --db-port=P --db-user=U --db-pass=P --db-name=N

Safety
  --safety-timer=MIN    roll back automatically unless 'vicidial-firewall confirm' is run within MIN minutes
                        (default 10; 0 disables)
  --no-safety-timer     same as --safety-timer=0
  --dry-run             show what would be done; change nothing
  --yes                 do not ask for confirmation
  --uninstall           restore the pre-install firewall and remove everything this installed
  --help                this text
EOF
}

parse_args() {
	local a v _i
	local -a _tmp=()
	while (($#)); do
		a=$1; v=${1#*=}
		case $a in
			--mode=*) MODE=$v ;;
			--dynamic-age=*) DYNAMIC_AGE=$v ;;
			--add-rfc1918) ADD_RFC1918=1 ;;
			--whitelist=*) IFS=, read -r -a _tmp <<<"$v"; WHITELIST+=(${_tmp[@]+"${_tmp[@]}"}) ;;
			--no-ssh-whitelist) SSH_WHITELIST=0 ;;
			--no-auto-carriers) AUTO_CARRIERS=0 ;;
			--keep-ssh-public) KEEP_SSH_PUBLIC=1 ;;
			--trusted-iface=*) IFS=, read -r -a _tmp <<<"$v"; TRUSTED_IFACES+=(${_tmp[@]+"${_tmp[@]}"}) ;;
			--trusted-net=*) IFS=, read -r -a _tmp <<<"$v"; TRUSTED_NETS+=(${_tmp[@]+"${_tmp[@]}"}) ;;
			--internal-net=*) IFS=, read -r -a _tmp <<<"$v"; INTERNAL_NETS+=(${_tmp[@]+"${_tmp[@]}"}) ;;
			--cluster-ip=*) IFS=, read -r -a _tmp <<<"$v"; for _i in ${_tmp[@]+"${_tmp[@]}"}; do INTERNAL_NETS+=("$_i/32"); done ;;
			--public-iface=*) PUBLIC_IFACE=$v ;;
			--rtp-range=*) RTP_RANGE=$v ;;
			--keep-legacy-iptables) KEEP_LEGACY_IPTABLES=1 ;;
			--agent-ssh) AGENT_SSH=1 ;;
			--no-public-rtp) PUBLIC_RTP=0 ;;
			--portal-lockout=*) PORTAL_LOCKOUT=$v ;;
			--no-fail2ban) FAIL2BAN=0 ;;
			--no-portal) PORTAL=0 ;;
			--portal-fqdn=*) PORTAL_FQDN=$v ;;
			--portal-port=*) PORTAL_PORT=$v ;;
			--portal-http) PORTAL_HTTP=1 ;;
			--portal-userlevel=*) PORTAL_USERLEVEL=$v ;;
			--portal-redirect=*) PORTAL_REDIRECT=$v ;;
			--no-portal-redirect) PORTAL_REDIRECT=none ;;
			--portal-redirect-secs=*) PORTAL_REDIRECT_SECS=$v ;;
			--no-login-passthrough) PORTAL_LOGIN_PASSTHROUGH=0 ;;
			--ssl-cert=*) SSL_CERT=$v ;;
			--ssl-key=*) SSL_KEY=$v ;;
			--ssl-chain=*) SSL_CHAIN=$v ;;
			--db-host=*) DB_HOST=$v ;;
			--db-port=*) DB_PORT=$v ;;
			--db-user=*) DB_USER=$v ;;
			--db-pass=*) DB_PASS=$v ;;
			--db-name=*) DB_NAME=$v ;;
			--safety-timer=*) SAFETY_MIN=$v ;;
			--no-safety-timer) SAFETY_MIN=0 ;;
			--dry-run) DRY_RUN=1 ;;
			--yes|-y) ASSUME_YES=1 ;;
			--payload-dir=*) PAYLOAD_DIR=$v ;;
			--uninstall)
				[ -x "$HELPER" ] || die "nothing to uninstall: $HELPER is not installed"
				exec "$HELPER" uninstall ;;
			--version) echo "$VF_VERSION"; exit 0 ;;
			-h|--help) usage; exit 0 ;;
			*) die "unknown option: $a (see --help)" ;;
		esac
		shift
	done
	case $MODE in dynamic|whitelist|blacklist) ;; *) die "--mode must be dynamic, whitelist or blacklist" ;; esac
	[[ $DYNAMIC_AGE =~ ^[0-9]+$ ]] && ((DYNAMIC_AGE >= 1)) || die "--dynamic-age must be a positive number of days"
	[[ $PORTAL_PORT =~ ^[0-9]+$ ]] && ((PORTAL_PORT > 0 && PORTAL_PORT < 65536)) || die "--portal-port is not a port"
	[[ $PORTAL_USERLEVEL =~ ^[0-9]+$ ]] || die "--portal-userlevel must be a number"
	[[ $PORTAL_REDIRECT_SECS =~ ^[0-9]+$ ]] || die "--portal-redirect-secs must be a number"
	[[ $SAFETY_MIN =~ ^[0-9]+$ ]] || die "--safety-timer must be a number of minutes"
	[[ $PORTAL_LOCKOUT =~ ^[0-9]+$ ]] || die "--portal-lockout must be a number"
	local e
	for e in ${WHITELIST[@]+"${WHITELIST[@]}"}; do valid_ip_or_cidr "$e" || die "--whitelist: '$e' is not an IPv4 address or CIDR network"; done
	for e in ${TRUSTED_NETS[@]+"${TRUSTED_NETS[@]}"} ${INTERNAL_NETS[@]+"${INTERNAL_NETS[@]}"}; do valid_cidr "$e" || die "'$e' is not a CIDR network (use a.b.c.d/nn)"; done
	if [ -n "$SSL_CERT$SSL_KEY" ] && { [ -z "$SSL_CERT" ] || [ -z "$SSL_KEY" ]; }; then die "--ssl-cert and --ssl-key go together"; fi
	if [ -z "$PAYLOAD_DIR" ]; then PAYLOAD_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd); fi
	[ -f "$PAYLOAD_DIR/official/VB-firewall.pl" ] || die "payload not found in $PAYLOAD_DIR (official/VB-firewall.pl missing)"
}

# ------------------------------------------------------------------------------------------------
# Preflight
# ------------------------------------------------------------------------------------------------
read_db_config() {
	local conf_val
	conf_val() { sed -n "s/^[[:space:]]*$1[[:space:]]*=>[[:space:]]*//p" "$ASTGUI_CONF" 2>/dev/null | head -1 | sed -e 's/[#;].*$//' -e 's/[[:space:]]*$//'; }
	if [ -r "$ASTGUI_CONF" ]; then
		: "${DB_HOST:=$(conf_val VARDB_server)}" "${DB_USER:=$(conf_val VARDB_user)}" "${DB_PASS:=$(conf_val VARDB_pass)}"
		: "${DB_NAME:=$(conf_val VARDB_database)}" "${DB_PORT:=$(conf_val VARDB_port)}"
	fi
	: "${DB_HOST:=localhost}" "${DB_USER:=cron}" "${DB_PASS:=1234}" "${DB_NAME:=asterisk}" "${DB_PORT:=3306}"
}
db_q() { MYSQL_PWD="$DB_PASS" "$MYSQL_BIN" --batch --raw --skip-column-names --connect-timeout=10 -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" "$DB_NAME" -e "$1"; }
run_sql() { logonly "SQL: $1"; if ((DRY_RUN)); then info "(dry-run) SQL: $1"; else db_q "$1" >/dev/null; fi; }

detect_os() {
	[ -r /etc/os-release ] || die "/etc/os-release not found"
	# shellcheck disable=SC1091
	. /etc/os-release
	PRETTY=${PRETTY_NAME:-${ID:-unknown}}
	case " ${ID:-} ${ID_LIKE:-} " in
		*suse*|*sles*) FAMILY=suse; PKG=zypper ;;
		*debian*|*ubuntu*) FAMILY=debian; PKG=apt ;;
		*rhel*|*fedora*|*centos*|*rocky*|*alma*) FAMILY=rhel; PKG=$(command -v dnf || command -v yum || true) ;;
		*) die "unsupported distribution: $PRETTY (supported: openSUSE/ViciBox, Debian/Ubuntu, RHEL/Rocky/Alma)" ;;
	esac
	if [ "$FAMILY" = suse ] && { rpm -q vicibox-install >/dev/null 2>&1 || [ -d /usr/share/vicibox ]; }; then VICIBOX=1; fi
	case $FAMILY in
		debian) APACHE_SVC=apache2 APACHE_USER=www-data APACHE_GROUP=www-data APACHE_CONF_ROOT=/etc/apache2 APACHE_LOG=/var/log/apache2
			VHOST_FILE=/etc/apache2/sites-available/dynportal-ssl.conf VHOST_HTTP_FILE=/etc/apache2/sites-available/dynportal.conf LISTEN_FILE=/etc/apache2/ports.conf ;;
		rhel)   APACHE_SVC=httpd APACHE_USER=apache APACHE_GROUP=apache APACHE_CONF_ROOT=/etc/httpd APACHE_LOG=/var/log/httpd
			VHOST_FILE=/etc/httpd/conf.d/dynportal-ssl.conf VHOST_HTTP_FILE=/etc/httpd/conf.d/dynportal.conf LISTEN_FILE="" ;;
		suse)   APACHE_SVC=apache2 APACHE_USER=wwwrun APACHE_GROUP=www APACHE_CONF_ROOT=/etc/apache2 APACHE_LOG=/var/log/apache2
			VHOST_FILE=/etc/apache2/vhosts.d/dynportal-ssl.conf VHOST_HTTP_FILE=/etc/apache2/vhosts.d/dynportal.conf LISTEN_FILE=/etc/apache2/listen.conf ;;
	esac
}

detect_network() {
	if [ -z "$PUBLIC_IFACE" ]; then
		PUBLIC_IFACE=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
	fi
	[ -n "$PUBLIC_IFACE" ] || die "could not find the internet-facing interface (no default route); pass --public-iface=NAME"
	ip link show "$PUBLIC_IFACE" >/dev/null 2>&1 || die "interface $PUBLIC_IFACE does not exist"
	PUBLIC_IP=$(ip -4 -o addr show dev "$PUBLIC_IFACE" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
	EXTERNAL_IP=$(curl -4 -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)
	valid_ipv4 "$EXTERNAL_IP" || EXTERNAL_IP=""
	local i
	for i in ${TRUSTED_IFACES[@]+"${TRUSTED_IFACES[@]}"}; do
		ip link show "$i" >/dev/null 2>&1 || die "--trusted-iface: interface $i does not exist"
		[ "$i" != "$PUBLIC_IFACE" ] || die "--trusted-iface: $i is the internet-facing interface"
	done
	if [ -z "$PORTAL_FQDN" ]; then
		local h; h=$(hostname -f 2>/dev/null || true)
		if [[ $h == *.* && $h != *.local && $h != *.localdomain && $h != localhost* ]]; then PORTAL_FQDN=$h; else PORTAL_FQDN=${EXTERNAL_IP:-$PUBLIC_IP}; fi
	fi
	[ -n "$PORTAL_FQDN" ] || die "could not determine a host name or IP for the portal; pass --portal-fqdn"
	if ! valid_ipv4 "$PORTAL_FQDN"; then
		local v6; v6=$(getent ahostsv6 "$PORTAL_FQDN" 2>/dev/null | awk '{print $1}' | grep -v '^::ffff:' | sort -u | head -1 || true)
		if [ -n "$v6" ]; then warn "$PORTAL_FQDN also resolves to IPv6 ($v6). VB-firewall handles IPv4 only, so agents who connect over IPv6 cannot be validated: remove the AAAA record or disable IPv6 on the server"; fi
	fi
	if [ -z "$RTP_RANGE" ] && [ -r /etc/asterisk/rtp.conf ]; then
		local s e
		s=$(sed -n 's/^[[:space:]]*rtpstart[[:space:]]*=[[:space:]]*\([0-9]\+\).*/\1/p' /etc/asterisk/rtp.conf | head -1)
		e=$(sed -n 's/^[[:space:]]*rtpend[[:space:]]*=[[:space:]]*\([0-9]\+\).*/\1/p' /etc/asterisk/rtp.conf | head -1)
		[ -n "$s" ] && [ -n "$e" ] && RTP_RANGE="$s-$e"
	fi
	RTP_RANGE=${RTP_RANGE:-10000-20000}
	[[ $RTP_RANGE =~ ^[0-9]+-[0-9]+$ ]] || die "--rtp-range must look like 10000-20000"
}

detect_ssh_ip() {
	local c="" t
	c=${SSH_CONNECTION:-}; c=${c%% *}
	[ -n "$c" ] || { c=${SSH_CLIENT:-}; c=${c%% *}; }
	if ! valid_ipv4 "$c"; then
		t=$(ps -o tty= -p $$ 2>/dev/null | tr -d ' ')
		if [ -n "$t" ] && [ "$t" != "?" ]; then
			c=$(who 2>/dev/null | awk -v t="$t" '$2==t {print $NF}' | tr -d '()' | head -1)
		fi
	fi
	if valid_ipv4 "$c"; then SSH_IP=$c; fi
}

ssh_covered_by_trusted() {
	[ -n "$SSH_IP" ] || return 1
	local n
	for n in ${TRUSTED_NETS[@]+"${TRUSTED_NETS[@]}"}; do cidr_contains "$n" "$SSH_IP" && return 0; done
	if is_private_ipv4 "$SSH_IP" && ((${#TRUSTED_IFACES[@]} > 0)); then return 0; fi
	return 1
}

preflight() {
	hdr "Preflight"
	[ "$(id -u)" -eq 0 ] || die "run this as root (sudo)"
	mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
	detect_os
	ok "system: $PRETTY (family: $FAMILY$( ((VICIBOX)) && echo ", ViciBox"))"
	command -v systemctl >/dev/null || die "systemd is required"
	if [ ! -r "$ASTGUI_CONF" ] && [ -z "$DB_HOST" ]; then
		die "$ASTGUI_CONF not found: this does not look like a ViciDial server (pass --db-* for a portal-only host)"
	fi
	read_db_config
	ok "ViciDial database: $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
	detect_network
	ok "internet-facing interface: $PUBLIC_IFACE${PUBLIC_IP:+ ($PUBLIC_IP)}${EXTERNAL_IP:+, public address $EXTERNAL_IP}"
	ok "RTP range kept public: $RTP_RANGE/udp"
	detect_ssh_ip
	if [ -n "$SSH_IP" ]; then ok "this SSH session comes from $SSH_IP"; else warn "no SSH client address detected (console session?)"; fi
	if systemctl is-active --quiet firewalld; then FIREWALLD_WAS_ACTIVE=1; fi
	if systemctl is-enabled --quiet firewalld 2>/dev/null; then FIREWALLD_WAS_ENABLED=1; fi
	info "firewalld currently: $( ((FIREWALLD_WAS_ACTIVE)) && echo running || echo "not running")"
	if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" != Disabled ]; then SELINUX=1; info "SELinux is enabled"; fi
	if [ -f "$STATE_FILE" ]; then
		warn "an earlier vicidial-firewall installation exists; its configuration will be re-applied"
		ORIGINAL_BACKUP_DIR=$(state_get ORIGINAL_BACKUP_DIR); ORIG_FW_ACTIVE=$(state_get ORIG_FW_ACTIVE); ORIG_FW_ENABLED=$(state_get ORIG_FW_ENABLED)
	fi
	if [ "$MODE" != blacklist ] && [ -z "$SSH_IP" ] && ((${#WHITELIST[@]} == 0)) && ((${#TRUSTED_NETS[@]} + ${#TRUSTED_IFACES[@]} == 0)) && ((!KEEP_SSH_PUBLIC)); then
		warn "nothing will be whitelisted: after activation only the Dynamic Portal (and RTP) is reachable from outside."
		warn "A portal login gives web and SIP access but not SSH (unless --agent-ssh): pass --whitelist=YOUR.IP or --keep-ssh-public to keep SSH"
	fi
}

# ------------------------------------------------------------------------------------------------
# Packages
# ------------------------------------------------------------------------------------------------
pkg_installed() {
	case $FAMILY in
		debian) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed' ;;
		*)      rpm -q "$1" >/dev/null 2>&1 ;;
	esac
}
pkg_install() { # installs only what is missing (so an end-of-life repository, e.g. ViciBox 10, does not break a run) and never hangs
	local p rc=0 todo=() t=${PKG_TIMEOUT:-600}
	for p in "$@"; do pkg_installed "$p" || todo+=("$p"); done
	((${#todo[@]})) || return 0
	case $FAMILY in
		debian) DEBIAN_FRONTEND=noninteractive run timeout -k 10 "$t" apt-get install -y -qq --no-install-recommends "${todo[@]}" || rc=$? ;;
		rhel)   run timeout -k 10 "$t" "$PKG" -y -q install "${todo[@]}" || rc=$? ;;
		suse)   ZYPP_LOCK_TIMEOUT=60 run timeout -k 10 "$t" zypper -n -q --no-refresh install "${todo[@]}" || rc=$?
		        if [ "$rc" -ge 100 ] && [ "$rc" -le 107 ]; then rc=0; fi ;;   # zypper 100-107 are informational (106 = a repository was skipped)
	esac
	if [ "$rc" -eq 124 ]; then logonly "package installation of ${todo[*]} timed out after ${t}s"; fi
	return "$rc"
}
pkg_required() { PKG_TIMEOUT=900 pkg_install "$@" >/dev/null || die "failed to install required packages: $* (repository unreachable or packages missing)"; }
pkg_optional() { local p; for p in "$@"; do PKG_TIMEOUT=120 pkg_install "$p" >/dev/null 2>&1 || warn "optional package not installed: $p (skipped after at most 120 s)"; done; }
php_has_mysqli() { php -m 2>/dev/null | grep -qi "^mysqli$"; }

install_packages() {
	hdr "Installing packages"
	case $FAMILY in
		debian)
			DEBIAN_FRONTEND=noninteractive run apt-get update -qq >/dev/null || warn "apt-get update failed; using the cached package lists"
			pkg_required firewalld ipset curl openssl ca-certificates perl libdbi-perl libdbd-mysql-perl
			pkg_optional libcrypt-eksblowfish-perl
			php_has_mysqli || pkg_optional php-mysql
			pkg_install mariadb-client >/dev/null 2>&1 || pkg_install default-mysql-client >/dev/null 2>&1 || pkg_optional mysql-client ;;
		rhel)
			[ -n "$PKG" ] || die "neither dnf nor yum found"
			pkg_required firewalld ipset curl openssl perl perl-DBI perl-DBD-MySQL perl-Sys-Syslog
			pkg_optional mariadb mod_ssl policycoreutils-python-utils perl-Crypt-Eksblowfish
			php_has_mysqli || pkg_optional php-mysqlnd ;;
		suse)
			if ((VICIBOX)); then pkg_optional vicibox-firewall vicibox-dynportal; fi
			pkg_required firewalld ipset curl openssl perl perl-DBD-mysql
			pkg_optional mariadb-client perl-Crypt-Eksblowfish
			php_has_mysqli || pkg_optional php8-mysql php7-mysql ;;
	esac
	((DRY_RUN)) && return 0
	perl -MDBI -MDBD::mysql -MSys::Syslog -e1 2>/dev/null || die "Perl modules DBI, DBD::mysql and Sys::Syslog are required by VB-firewall.pl and are missing"
	command -v firewall-cmd >/dev/null || die "firewall-cmd not found even after installing firewalld"
	if [ ! -x /usr/bin/firewall-cmd ]; then run ln -sf "$(command -v firewall-cmd)" /usr/bin/firewall-cmd; fi   # VB-firewall.pl hard-codes this path
	MYSQL_BIN=$(command -v mysql || command -v mariadb || true)
	[ -n "$MYSQL_BIN" ] || die "no mysql/mariadb client found"
	ok "packages present"
}

check_database() {
	hdr "Checking the ViciDial database"
	if ((DRY_RUN)) && [ -z "$MYSQL_BIN" ]; then MYSQL_BIN=$(command -v mysql || command -v mariadb || echo mysql); fi
	local out
	if ! out=$(db_q "SELECT COUNT(*) FROM vicidial_ip_lists" 2>&1); then
		((DRY_RUN)) && { warn "database not reachable in dry-run: $out"; return 0; }
		die "cannot query the ViciDial database as $DB_USER@$DB_HOST: $out"
	fi
	ok "connected; $out IP list(s) defined"
	db_q "SELECT 1 FROM vicidial_ip_list_entries LIMIT 1" >/dev/null 2>&1 || die "table vicidial_ip_list_entries is missing: this ViciDial is too old for the IP Lists feature"
	PASS_HASH=$(db_q "SELECT pass_hash_enabled FROM system_settings LIMIT 1" 2>/dev/null || echo 0)
	if [ "$PASS_HASH" = 1 ] && ! perl -MCrypt::Eksblowfish::Bcrypt -e1 2>/dev/null; then
		warn "ViciDial stores hashed passwords but Perl Crypt::Eksblowfish is missing: the portal cannot verify logins until it is installed"
	fi
}

detect_carriers() {
	((AUTO_CARRIERS)) || return 0
	[ "$MODE" != blacklist ] || return 0
	local raw hosts h ip
	raw=$(db_q "SELECT account_entry FROM vicidial_server_carriers WHERE active='Y'" 2>/dev/null || true)
	[ -n "$raw" ] || return 0
	hosts=$( { printf '%s\n' "$raw" | grep -oiE '(^|[[:space:]])host[[:space:]]*=[[:space:]]*[A-Za-z0-9._-]+' | sed 's/.*=[[:space:]]*//';
	           printf '%s\n' "$raw" | grep -oiE 'sip:[A-Za-z0-9._-]+' | sed 's/^sip://'; } | sort -u | grep -viE '^(dynamic|localhost|127\.0\.0\.1)$' || true)
	for h in $hosts; do
		if valid_ipv4 "$h"; then CARRIER_IPS+=("$h"); continue; fi
		for ip in $(getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}' | sort -u); do valid_ipv4 "$ip" && CARRIER_IPS+=("$ip"); done
	done
	if ((${#CARRIER_IPS[@]})); then
		mapfile -t CARRIER_IPS < <(printf '%s\n' "${CARRIER_IPS[@]}" | awk '!s[$0]++')
		ok "carrier addresses found in ViciDial: $(join_by ', ' "${CARRIER_IPS[@]}")"
	else
		info "no carrier host= addresses found in vicidial_server_carriers"
	fi
}

# ------------------------------------------------------------------------------------------------
# Plan and confirmation
# ------------------------------------------------------------------------------------------------
compute_plan() {
	case $MODE in
		dynamic)   VBF_ARGS="--white --dynamic"; [ "$DYNAMIC_AGE" != 15 ] && VBF_ARGS+=" --dynamicage=$DYNAMIC_AGE"; CRON_SCHED="* * * * *" ;;
		whitelist) VBF_ARGS="--white"; CRON_SCHED="* * * * *" ;;
		blacklist) VBF_ARGS="--voipbl"; CRON_SCHED="0 */6 * * *" ;;
	esac
	((ADD_RFC1918)) && VBF_ARGS+=" --addrfc1918"
	VBF_ARGS+=" --quiet"
	ALLOW_NOW=()
	if [ -n "$SSH_IP" ] && ((SSH_WHITELIST)) && ! ssh_covered_by_trusted; then ALLOW_NOW+=("$SSH_IP"); fi
	ALLOW_NOW+=(${WHITELIST[@]+"${WHITELIST[@]}"} ${CARRIER_IPS[@]+"${CARRIER_IPS[@]}"})
	if ((${#ALLOW_NOW[@]})); then mapfile -t ALLOW_NOW < <(printf '%s\n' "${ALLOW_NOW[@]}" | awk '!s[$0]++'); fi
	return 0
}

public_services() {
	local s=()
	if ((PUBLIC_RTP)) || [ "$MODE" = blacklist ]; then s+=(rtp); fi
	s+=(dhcpv6-client)
	[ "$MODE" = blacklist ] && s+=(ssh http https asterisk)
	((KEEP_SSH_PUBLIC)) && s+=(ssh)
	if ((PORTAL)); then s+=(dynportal-ssl); ((PORTAL_HTTP)) && s+=(dynportal); fi
	printf '%s\n' "${s[@]}" | awk '!x[$0]++'
}

show_plan() {
	hdr "Plan"
	info "mode ................ $MODE  (VB-firewall $VBF_ARGS, cron '$CRON_SCHED')"
	info "public zone ......... $(public_services | tr '\n' ' ')on $PUBLIC_IFACE  (everything else is blocked for unknown addresses)"
	if [ "$MODE" != blacklist ]; then
		info "external zone ....... http https asterisk rtp ssh  for the ViciWhite list (carriers, offices, admins)"
		if [ "$MODE" = dynamic ]; then
			info "agents zone ......... http https asterisk rtp$( ((AGENT_SSH)) && echo " ssh")  for addresses validated through the portal or logged in within $DYNAMIC_AGE days"
		fi
		((PUBLIC_RTP)) || warn "RTP is NOT public: every carrier media address must be in ViciWhite or calls will have no audio"
	fi
	if ((PORTAL)); then
		info "portal protection ... ${PORTAL_LOCKOUT:-0} failed logins ignore the user$( ((FAIL2BAN)) && echo "; fail2ban bans an address for 1 h after 5 failures in 10 min")"
	fi
	((${#TRUSTED_IFACES[@]})) && info "trusted interfaces .. ${TRUSTED_IFACES[*]}"
	((${#TRUSTED_NETS[@]})) && info "trusted networks .... ${TRUSTED_NETS[*]}"
	((${#INTERNAL_NETS[@]})) && info "internal networks ... ${INTERNAL_NETS[*]}  (+ mysql, ftp, AMI 5038)"
	if ((${#ALLOW_NOW[@]})); then info "ViciWhite entries ... $(join_by ', ' "${ALLOW_NOW[@]}")"; else info "ViciWhite entries ... none added"; fi
	if ((PORTAL)); then
		info "Dynamic Portal ...... https://$PORTAL_FQDN:$PORTAL_PORT/valid8.php$( ((PORTAL_HTTP)) && echo "  and http://$PORTAL_FQDN:$PORTAL_HTTP_PORT/valid8.php")"
		info "portal user level ... >= $PORTAL_USERLEVEL;  redirect: ${PORTAL_REDIRECT:-https://$PORTAL_FQDN/agc/vicidial.php}"
	else
		info "Dynamic Portal ...... not installed on this server (--no-portal)"
	fi
	if ((SAFETY_MIN)) && [ "$MODE" != blacklist ]; then
		info "safety timer ........ $SAFETY_MIN min: run '$HELPER confirm' from a new SSH session or the old firewall comes back"
	fi
	((DRY_RUN)) && info "DRY RUN: nothing will be changed"
	say ""
	say "${c_yel}This takes over the host firewall. Carriers, office and VPN addresses that are not in ViciWhite will be${c_off}"
	say "${c_yel}cut off from SIP and the web interface until they are added (ViciDial Admin > IP Lists > ViciWhite).${c_off}"
}

confirm_plan() {
	((ASSUME_YES)) && return 0
	local ans=""
	if [ -t 0 ]; then read -r -p "Proceed? [y/N] " ans
	elif [ -r /dev/tty ]; then read -r -p "Proceed? [y/N] " ans </dev/tty
	else die "no terminal to confirm on: re-run with --yes"; fi
	[[ $ans =~ ^[Yy]([Ee][Ss])?$ ]] || die "aborted"
}

# ------------------------------------------------------------------------------------------------
# Backup
# ------------------------------------------------------------------------------------------------
take_backup() {
	hdr "Backing up the current configuration"
	BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
	[ -n "$ORIGINAL_BACKUP_DIR" ] || ORIGINAL_BACKUP_DIR=$BACKUP_DIR
	[ -n "$ORIG_FW_ACTIVE" ] || ORIG_FW_ACTIVE=$FIREWALLD_WAS_ACTIVE
	[ -n "$ORIG_FW_ENABLED" ] || ORIG_FW_ENABLED=$FIREWALLD_WAS_ENABLED
	((DRY_RUN)) && { info "(dry-run) would back up to $BACKUP_DIR"; return 0; }
	mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_ROOT"
	if [ -d "$FW_ETC" ]; then tar -czf "$BACKUP_DIR/firewalld-etc.tgz" -C / etc/firewalld; else : >"$BACKUP_DIR/firewalld-etc.ABSENT"; fi
	if crontab -l >"$BACKUP_DIR/root-crontab.txt" 2>/dev/null; then :; else rm -f "$BACKUP_DIR/root-crontab.txt"; : >"$BACKUP_DIR/root-crontab.NONE"; fi
	if command -v iptables-save >/dev/null 2>&1; then iptables-save >"$BACKUP_DIR/iptables-save.txt" 2>/dev/null || true; fi
	local f
	for f in "$VHOST_FILE" "$VHOST_HTTP_FILE" "$LISTEN_FILE" "$PORTAL_DIR/inc/defaults.inc.php"; do
		if [ -n "$f" ] && [ -f "$f" ]; then cp -a "$f" "$BACKUP_DIR/$(basename "$f").orig"; fi
	done
	printf 'FIREWALLD_WAS_ACTIVE=%s\nFIREWALLD_WAS_ENABLED=%s\nDATE=%s\nVF_VERSION=%s\n' "$FIREWALLD_WAS_ACTIVE" "$FIREWALLD_WAS_ENABLED" "$(date -Is)" "$VF_VERSION" >"$BACKUP_DIR/pre-install.env"
	ok "saved to $BACKUP_DIR"
}

# ------------------------------------------------------------------------------------------------
# Conflicting firewall managers
# ------------------------------------------------------------------------------------------------
disable_conflicting_firewalls() {
	hdr "Checking for other firewall managers"
	if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
		warn "ufw is active: disabling it, firewalld takes over"; run ufw --force disable >/dev/null
	fi
	local s
	for s in nftables iptables ip6tables netfilter-persistent; do
		if systemctl is-enabled --quiet "$s" 2>/dev/null; then
			warn "$s.service is enabled: disabling it so it does not fight firewalld (rules saved in $BACKUP_DIR/iptables-save.txt)"
			run systemctl disable --now "$s" >/dev/null 2>&1 || true
		fi
	done
	ok "firewalld will be the only firewall manager"
}

# ------------------------------------------------------------------------------------------------
# VB-firewall
# ------------------------------------------------------------------------------------------------
install_vbfirewall() {
	hdr "Installing VB-firewall (official ViciBox firewall script)"
	local existing="$VBF_DIR/VB-firewall.pl"
	if [ -f "$existing" ] && cmp -s "$PAYLOAD_DIR/official/VB-firewall.pl" "$existing"; then
		ok "$existing is already the vendored official release"
	elif [ -f "$existing" ] && grep -q 'Sys::Syslog' "$existing"; then
		ok "keeping the installed $existing (same generation as the vendored copy, from the vicibox-firewall package)"
	else
		if [ -f "$existing" ]; then
			((DRY_RUN)) || cp -a "$existing" "$BACKUP_DIR/VB-firewall.pl.orig" 2>/dev/null || true
			info "the installed VB-firewall.pl is an older release (no syslog, needs /usr/bin/aggregate); replacing it with the current official one (old copy kept in $BACKUP_DIR)"
		fi
		run mkdir -p "$VBF_DIR"
		install_if_changed "$PAYLOAD_DIR/official/VB-firewall.pl" "$existing" 0755
		ok "$existing (official copy, see official/SOURCES.md)"
	fi
	[ -e "$VBF_BIN" ] || run ln -sf "$VBF_DIR/VB-firewall.pl" "$VBF_BIN"
	[ -e /usr/local/bin/VB-firewall.pl ] || run ln -sf "$VBF_DIR/VB-firewall.pl" /usr/local/bin/VB-firewall.pl
	((DRY_RUN)) || "$VBF_BIN" --help >/dev/null 2>&1 || die "$VBF_BIN --help failed (missing Perl modules?)"
	ok "$VBF_BIN works"
}

# ------------------------------------------------------------------------------------------------
# firewalld configuration (ViciBox layout, distribution-neutral service names)
# ------------------------------------------------------------------------------------------------
service_defined_elsewhere() { # a definition that is not ours: from the distribution or from a ViciBox package
	[ -f "$FW_LIB/services/$1.xml" ] && return 0
	[ -f "$FW_ETC/services/$1.xml" ] && ! grep -q 'vicidial-firewall' "$FW_ETC/services/$1.xml"
}

emit_zone() { # NAME SHORT DESCRIPTION TARGET services_array ipsets_array addresses_array ports_array [PRIORITY]
	local name=$1 short=$2 desc=$3 target=$4 prio=${9:-} s attrs=""
	local -n _svc=$5 _ips=$6 _addr=$7 _ports=$8
	[ -n "$target" ] && attrs+=" target=\"$target\""
	if [ -n "$prio" ] && ((FW_PRIORITY_OK)); then attrs+=" priority=\"$prio\""; fi
	{
		printf '<?xml version="1.0" encoding="utf-8"?>\n'
		printf '<!-- managed by vicidial-firewall; ViciBox layout, see official/firewalld/zones/ -->\n'
		printf '<zone%s>\n' "$attrs"
		printf '  <short>%s</short>\n  <description>%s</description>\n' "$short" "$desc"
		for s in ${_svc[@]+"${_svc[@]}"}; do printf '  <service name="%s"/>\n' "$s"; done
		for s in ${_ports[@]+"${_ports[@]}"}; do printf '  <port protocol="%s" port="%s"/>\n' "${s#*/}" "${s%/*}"; done
		for s in ${_ips[@]+"${_ips[@]}"}; do printf '  <source ipset="%s"/>\n' "$s"; done
		for s in ${_addr[@]+"${_addr[@]}"}; do printf '  <source address="%s"/>\n' "$s"; done
		printf '</zone>\n'
	} | write_file "$FW_ETC/zones/$name.xml"
}

emit_service() { # NAME SHORT DESCRIPTION port/proto...
	local name=$1 short=$2 desc=$3 p; shift 3
	{
		printf '<?xml version="1.0" encoding="utf-8"?>\n<!-- managed by vicidial-firewall -->\n<service>\n  <short>%s</short>\n  <description>%s</description>\n' "$short" "$desc"
		for p in "$@"; do printf '  <port protocol="%s" port="%s"/>\n' "${p#*/}" "${p%/*}"; done
		printf '</service>\n'
	} | write_file "$FW_ETC/services/$name.xml"
}

install_firewalld_config() {
	hdr "Installing the firewalld IP sets, services and zones"
	run mkdir -p "$FW_ETC/ipsets" "$FW_ETC/services" "$FW_ETC/zones"
	local f
	for f in "$PAYLOAD_DIR"/official/firewalld/ipsets/*.xml; do install_if_changed "$f" "$FW_ETC/ipsets/$(basename "$f")"; done
	ok "IP sets: whiteips whitenets dynamiclist blackips blacknets voipblip voipblnet geoblock (official definitions)"
	emit_service dynportal-ssl "ViciBox Dynamic Portal SSL" "Allows remote agents to authenticate in a portal to access ViciDial" "$PORTAL_PORT/tcp"
	emit_service dynportal "ViciBox Dynamic Portal" "Allows remote agents to authenticate in a portal to access ViciDial" "$PORTAL_HTTP_PORT/tcp"
	if ! service_defined_elsewhere asterisk; then install_if_changed "$PAYLOAD_DIR/src/firewalld/services/asterisk.xml" "$FW_ETC/services/asterisk.xml"; fi
	if ! service_defined_elsewhere rtp; then
		emit_service rtp "RTP (ViciDial)" "Asterisk RTP media range from /etc/asterisk/rtp.conf" "$RTP_RANGE/udp"
	else
		info "keeping the existing rtp service definition: $(firewall-cmd --info-service=rtp 2>/dev/null | sed -n 's/^[[:space:]]*ports: //p' || true)"
	fi
	ok "services: dynportal-ssl($PORTAL_PORT) dynportal($PORTAL_HTTP_PORT) asterisk rtp($RTP_RANGE)"

	detect_fw_priority
	local none=() pub_svc ext_svc agt_svc int_svc drop_ips ext_ips agt_ips int_ports
	mapfile -t pub_svc < <(public_services)
	ext_svc=(http https asterisk rtp ssh dhcpv6-client)
	agt_svc=(http https asterisk rtp dhcpv6-client)
	((AGENT_SSH)) && agt_svc+=(ssh)
	if ((PORTAL)); then
		ext_svc+=(dynportal-ssl); agt_svc+=(dynportal-ssl)
		if ((PORTAL_HTTP)); then ext_svc+=(dynportal); agt_svc+=(dynportal); fi
	fi
	int_svc=(ssh http https asterisk rtp mysql ftp dhcpv6-client)
	int_ports=(5038/tcp)
	ext_ips=(whiteips whitenets)
	agt_ips=(dynamiclist)
	drop_ips=(blackips blacknets voipblip voipblnet geoblock)
	# priorities (firewalld 0.9+): drop first, then cluster peers, then the whitelist, then validated agents
	emit_zone public "Public" "Internet-facing. Only RTP audio and the Dynamic Portal answer here; everything else needs a ViciWhite entry, a portal validation, or a trusted/internal source (vicidial-firewall)." "" pub_svc none none none
	emit_zone external "External" "Trusted addresses: the ViciWhite IP list (carriers, offices, VPNs, administrators). Full ViciDial access including SSH (vicidial-firewall)." "" ext_svc ext_ips none none -10
	emit_zone agents "Agents" "Addresses validated through the Dynamic Portal or by a ViciDial login within the dynamic age: web, SIP/WebRTC and audio only (vicidial-firewall)." "" agt_svc agt_ips none none 0
	emit_zone internal "Internal" "Cluster peers and private networks named with --internal-net: ViciDial services plus MySQL, FTP and the Asterisk manager port (vicidial-firewall)." "" int_svc none INTERNAL_NETS int_ports -15
	emit_zone drop "Drop" "Blocked addresses: ViciBlack, voipbl.org and geo blocking (vicidial-firewall)." "DROP" none drop_ips none none -20
	ok "zones: public external agents internal drop$( ((FW_PRIORITY_OK)) || echo " (firewalld < 0.9: no zone priorities)")"
}

# ------------------------------------------------------------------------------------------------
# ViciDial database: IP lists feature, ViciWhite / ViciBlack lists, initial entries
# ------------------------------------------------------------------------------------------------
setup_database() {
	hdr "Configuring the ViciDial IP lists"
	run_sql "UPDATE system_settings SET allow_ip_lists='1' WHERE allow_ip_lists='0'"
	run_sql "UPDATE vicidial_users SET modify_ip_lists='1' WHERE user_level='9' AND modify_ip_lists='0'"
	run_sql "INSERT IGNORE INTO vicidial_ip_lists (ip_list_id, ip_list_name, active, user_group) VALUES ('ViciWhite','White List for ViciBox firewall ACL','N','---ALL---'), ('ViciBlack','Black List for ViciBox firewall ACL','N','---ALL---')"
	ok "IP Lists enabled; lists ViciWhite and ViciBlack exist (Admin > IP Lists)"
	local ip
	for ip in ${ALLOW_NOW[@]+"${ALLOW_NOW[@]}"}; do
		run_sql "INSERT INTO vicidial_ip_list_entries (ip_address, ip_list_id) SELECT '$ip','ViciWhite' FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM vicidial_ip_list_entries WHERE ip_list_id='ViciWhite' AND ip_address='$ip')"
	done
	if ((${#ALLOW_NOW[@]})); then ok "ViciWhite now contains: $(join_by ', ' "${ALLOW_NOW[@]}")"; fi
}

# ------------------------------------------------------------------------------------------------
# Dynamic Portal
# ------------------------------------------------------------------------------------------------
write_portal_defaults() {
	local redirect=$PORTAL_REDIRECT admin=$PORTAL_REDIRECT_ADMIN uid pwd old count=0 limit=999
	if ((PORTAL_LOCKOUT > 0)); then count=1 limit=$PORTAL_LOCKOUT; fi
	[ -n "$redirect" ] || redirect="https://$PORTAL_FQDN/agc/vicidial.php"
	[ "$redirect" = none ] && redirect=X
	[ -n "$admin" ] || admin="https://$PORTAL_FQDN/vicidial/admin.php"
	uid=$(rand_name); pwd=$(rand_name)
	if [ -f "$PORTAL_DIR/inc/defaults.inc.php" ]; then   # keep the field names of an earlier run
		old=$(sed -n "s/^\$PORTAL_useridvar='\([A-Za-z0-9]*\)'.*/\1/p" "$PORTAL_DIR/inc/defaults.inc.php" | head -1)
		if [ -n "$old" ] && [ "$old" != Jzr87Cp8XqJY ]; then uid=$old; fi
		old=$(sed -n "s/^\$PORTAL_passwdvar='\([A-Za-z0-9]*\)'.*/\1/p" "$PORTAL_DIR/inc/defaults.inc.php" | head -1)
		if [ -n "$old" ] && [ "$old" != WNK1WOrAvT1I ]; then pwd=$old; fi
	fi
	write_file "$PORTAL_DIR/inc/defaults.inc.php" 0640 <<EOF
<?php
# ViciBox Dynamic Portal settings - written by vicidial-firewall $(date '+%F %T')
# Reference and documentation of every setting: official/dynportal/inc/defaults.inc.php
\$PORTAL_mode=0;                  // 0 production, 1 debug, 2 extended debug (writes passwords to debug.txt - never in production)
\$PORTAL_secure=0;                // the official "forced HTTPS" check is broken on non-443 ports; the HTTP vhost is simply not enabled instead
\$PORTAL_logfile='debug.txt';
\$PORTAL_userlevel=$PORTAL_USERLEVEL;              // minimum ViciDial user level that may validate an IP
\$PORTAL_topbar=1;
\$PORTAL_redirecturl='$redirect';
\$PORTAL_redirectadmin='$admin';
\$PORTAL_redirectsecs=$PORTAL_REDIRECT_SECS;
\$PORTAL_redirectlogin=$PORTAL_LOGIN_PASSTHROUGH;             // 1 = pre-fill the ViciDial login after the redirect
\$PORTAL_adminfield='phone_login'; // users whose phone_login is 'admin' are sent to the admin URL
\$PORTAL_incurdelay=1;             // seconds every submit waits (brute-force counter measure)
\$PORTAL_useridvar='$uid';   // random form field names, regenerated per install
\$PORTAL_passwdvar='$pwd';
\$PORTAL_casesensitive=0;
\$PORTAL_countunsuccessful=$count;      // 1 = a failed portal login raises vicidial_users.failed_login_count
\$PORTAL_unsuccessfullimit=$limit;      // users at or above this count are ignored until an admin saves the user in ViciDial Admin
\$PORTAL_submitlocal=0;            // leave 0: VB-firewall picks the IP up from the database within a minute
\$AST_conffile="$ASTGUI_CONF";
?>
EOF
}

resolve_ssl() {
	local le c k
	if [ -n "$SSL_CERT" ]; then
		[ -r "$SSL_CERT" ] && [ -r "$SSL_KEY" ] || die "--ssl-cert / --ssl-key are not readable"
		ok "certificate: $SSL_CERT"; return 0
	fi
	le="/etc/letsencrypt/live/$PORTAL_FQDN"
	if [ -r "$le/fullchain.pem" ] && [ -r "$le/privkey.pem" ]; then
		SSL_CERT=$le/fullchain.pem SSL_KEY=$le/privkey.pem; ok "certificate: Let's Encrypt for $PORTAL_FQDN"; return 0
	fi
	if ((VICIBOX)); then
		for c in /etc/pki/ssl/vicibox.crt:/etc/pki/ssl/vicibox.key /etc/apache2/ssl.crt/vicibox.crt:/etc/apache2/ssl.key/vicibox.key; do
			if [ -r "${c%%:*}" ] && [ -r "${c##*:}" ]; then SSL_CERT=${c%%:*} SSL_KEY=${c##*:}; break; fi
		done
	fi
	if [ -z "$SSL_CERT" ] && [ -d "$APACHE_CONF_ROOT" ]; then
		c=$(grep -rhsE '^[[:space:]]*SSLCertificateFile[[:space:]]' "$APACHE_CONF_ROOT" 2>/dev/null | grep -vi dynportal | awk '{print $2}' | tr -d '"' | head -1)
		k=$(grep -rhsE '^[[:space:]]*SSLCertificateKeyFile[[:space:]]' "$APACHE_CONF_ROOT" 2>/dev/null | grep -vi dynportal | awk '{print $2}' | tr -d '"' | head -1)
		if [ -n "$c" ] && [ -r "$c" ] && [ -n "$k" ] && [ -r "$k" ]; then SSL_CERT=$c SSL_KEY=$k; fi
	fi
	if [ -n "$SSL_CERT" ]; then
		if [ "$(openssl x509 -in "$SSL_CERT" -noout -issuer 2>/dev/null)" = "$(openssl x509 -in "$SSL_CERT" -noout -subject 2>/dev/null | sed 's/^subject/issuer/')" ]; then SSL_SELF_SIGNED=1; fi
		ok "certificate: reusing the web server's $SSL_CERT$( ((SSL_SELF_SIGNED)) && echo " (self-signed)")"
		return 0
	fi
	SSL_CERT=$CONF_DIR/ssl/dynportal.crt SSL_KEY=$CONF_DIR/ssl/dynportal.key SSL_SELF_SIGNED=1
	if [ ! -s "$SSL_CERT" ] || [ ! -s "$SSL_KEY" ]; then
		local san="DNS:$PORTAL_FQDN"; valid_ipv4 "$PORTAL_FQDN" && san="IP:$PORTAL_FQDN"
		run mkdir -p "$CONF_DIR/ssl"
		run openssl req -x509 -nodes -newkey rsa:2048 -days 3650 -keyout "$SSL_KEY" -out "$SSL_CERT" -subj "/CN=$PORTAL_FQDN" -addext "subjectAltName=$san" >/dev/null 2>&1 \
			|| run openssl req -x509 -nodes -newkey rsa:2048 -days 3650 -keyout "$SSL_KEY" -out "$SSL_CERT" -subj "/CN=$PORTAL_FQDN" >/dev/null 2>&1 || die "openssl could not create a certificate"
		run chmod 600 "$SSL_KEY"
	fi
	warn "no trusted certificate found: a self-signed one is used (browsers show a warning). Get one for $PORTAL_FQDN and re-run with --ssl-cert/--ssl-key, or put it under /etc/letsencrypt/live/$PORTAL_FQDN/"
}

ensure_listen() { # FILE PORT [suffix]  -> appends a Listen line unless one exists; returns 0 if added
	local file=$1 port=$2 suffix=${3:-}
	grep -qsE "^[[:space:]]*Listen[[:space:]]+([0-9.]+:|\[[0-9a-fA-F:]*\]:)?$port([[:space:]]|$)" "$file" && return 1
	if ((DRY_RUN)); then info "(dry-run) append 'Listen $port${suffix:+ $suffix}' to $file"; return 0; fi
	printf '\n# vicidial-firewall: ViciBox Dynamic Portal\nListen %s %s\n' "$port" "$suffix" | sed 's/[[:space:]]*$//' >>"$file"
	return 0
}

write_vhosts() {
	local php_inc="" listen="" chain="" gen
	gen="$(date '+%F %T') (vicidial-firewall $VF_VERSION)"
	[ -n "$SSL_CHAIN" ] && chain=$'\tSSLCertificateChainFile '"$SSL_CHAIN"
	if [ "$FAMILY" = suse ]; then
		php_inc=$'\t<IfModule mod_php7.c>\n\t\tInclude /etc/apache2/conf.d/mod_php7.conf\n\t</IfModule>\n\t<IfModule mod_php8.c>\n\t\tInclude /etc/apache2/conf.d/mod_php8.conf\n\t</IfModule>'
	fi
	case $FAMILY in
		rhel)   listen="Listen $PORTAL_PORT https" ;;
		debian|suse) if ensure_listen "$LISTEN_FILE" "$PORTAL_PORT"; then LISTEN_ADDED=1; fi ;;
	esac
	TPL_GENERATED=$gen TPL_LISTEN=$listen TPL_PORT=$PORTAL_PORT TPL_FQDN=$PORTAL_FQDN TPL_DOCROOT=$PORTAL_DIR TPL_LOGDIR=$APACHE_LOG \
	TPL_PHP_INCLUDE=$php_inc TPL_CERT=$SSL_CERT TPL_KEY=$SSL_KEY TPL_CHAIN=$chain \
		render_template "$PAYLOAD_DIR/src/apache/dynportal-ssl.conf.tpl" | write_file "$VHOST_FILE"
	if ((PORTAL_HTTP)); then
		listen=""
		case $FAMILY in
			rhel) listen="Listen $PORTAL_HTTP_PORT" ;;
			debian|suse) if ensure_listen "$LISTEN_FILE" "$PORTAL_HTTP_PORT"; then LISTEN_HTTP_ADDED=1; fi ;;
		esac
		TPL_GENERATED=$gen TPL_LISTEN=$listen TPL_PORT=$PORTAL_HTTP_PORT TPL_FQDN=$PORTAL_FQDN TPL_DOCROOT=$PORTAL_DIR TPL_LOGDIR=$APACHE_LOG \
		TPL_PHP_INCLUDE=$php_inc TPL_CERT="" TPL_KEY="" TPL_CHAIN="" \
			render_template "$PAYLOAD_DIR/src/apache/dynportal.conf.tpl" | write_file "$VHOST_HTTP_FILE"
	else
		if [ -n "$VHOST_HTTP_FILE" ] && [ -f "$VHOST_HTTP_FILE" ] && grep -q vicidial-firewall "$VHOST_HTTP_FILE"; then run rm -f "$VHOST_HTTP_FILE"; fi
		if [ "$FAMILY" = debian ] && [ -L /etc/apache2/sites-enabled/dynportal.conf ]; then run a2dissite -q dynportal >/dev/null; fi
	fi
	case $FAMILY in
		debian)
			run a2enmod -q ssl headers >/dev/null 2>&1 || warn "a2enmod ssl headers failed"
			run a2ensite -q dynportal-ssl >/dev/null 2>&1 || warn "a2ensite dynportal-ssl failed"
			if ((PORTAL_HTTP)); then run a2ensite -q dynportal >/dev/null 2>&1 || true; fi ;;
		suse)
			run a2enmod ssl >/dev/null 2>&1 || true; run a2enmod headers >/dev/null 2>&1 || true
			if command -v a2enflag >/dev/null 2>&1; then run a2enflag SSL >/dev/null 2>&1 || true; fi ;;
		rhel)
			[ -f /etc/httpd/conf.modules.d/00-ssl.conf ] || warn "mod_ssl does not seem to be installed; the portal vhost will not load" ;;
	esac
	return 0
}

configure_selinux() {
	((SELINUX)) || return 0
	if ! command -v semanage >/dev/null 2>&1; then warn "semanage not found (policycoreutils-python-utils): SELinux may block the portal port"; return 0; fi
	run semanage port -a -t http_port_t -p tcp "$PORTAL_PORT" >/dev/null 2>&1 || run semanage port -m -t http_port_t -p tcp "$PORTAL_PORT" >/dev/null 2>&1 || true
	if ((PORTAL_HTTP)); then run semanage port -a -t http_port_t -p tcp "$PORTAL_HTTP_PORT" >/dev/null 2>&1 || run semanage port -m -t http_port_t -p tcp "$PORTAL_HTTP_PORT" >/dev/null 2>&1 || true; fi
	run semanage fcontext -a -t httpd_sys_content_t "$PORTAL_DIR(/.*)?" >/dev/null 2>&1 || run semanage fcontext -m -t httpd_sys_content_t "$PORTAL_DIR(/.*)?" >/dev/null 2>&1 || true
	run restorecon -R "$PORTAL_DIR" >/dev/null 2>&1 || true
	run setsebool -P httpd_can_network_connect_db on >/dev/null 2>&1 || true
	ok "SELinux: port $PORTAL_PORT labelled http_port_t, $PORTAL_DIR labelled httpd_sys_content_t"
}

apache_apply() {
	local ctl out
	ctl=$(command -v apachectl || command -v apache2ctl || true)
	[ -n "$ctl" ] || { warn "apachectl not found; cannot test the web server configuration"; return 1; }
	((DRY_RUN)) && return 0
	if ! out=$("$ctl" -t 2>&1); then
		warn "the web server configuration does not pass the syntax test after adding the portal:"
		say "$out"
		warn "removing the portal vhost again so the ViciDial web interface keeps working"
		rm -f "$VHOST_FILE"; [ -n "$VHOST_HTTP_FILE" ] && rm -f "$VHOST_HTTP_FILE"
		if [ "$FAMILY" = debian ]; then a2dissite -q dynportal-ssl dynportal >/dev/null 2>&1 || true; fi
		if [ -n "$LISTEN_FILE" ] && ((LISTEN_ADDED)); then sed -i "/^# vicidial-firewall: ViciBox Dynamic Portal$/,+1d" "$LISTEN_FILE"; fi
		return 1
	fi
	systemctl reload "$APACHE_SVC" >/dev/null 2>&1 || systemctl restart "$APACHE_SVC" >/dev/null 2>&1 || { warn "could not reload $APACHE_SVC"; return 1; }
	sleep 1
	if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$PORTAL_PORT$"; then
		systemctl restart "$APACHE_SVC" >/dev/null 2>&1 || true; sleep 1
	fi
	return 0
}

verify_portal() {
	((DRY_RUN)) && return 0
	local body
	body=$(curl -ks --max-time 15 "https://127.0.0.1:$PORTAL_PORT/valid8.php" 2>/dev/null || true)
	if grep -q 'connect ERROR' <<<"$body"; then
		warn "the portal loads but cannot reach the database: $(grep -o 'connect ERROR[^<]*' <<<"$body" | head -1)"; PORTAL_INSTALLED=1
	elif grep -q 'User Validation' <<<"$body"; then
		ok "portal answers: https://$PORTAL_FQDN:$PORTAL_PORT/valid8.php"; PORTAL_INSTALLED=1
	else
		warn "the portal did not answer on https://127.0.0.1:$PORTAL_PORT/valid8.php - check $APACHE_LOG/dynportal-error_log"; PORTAL_INSTALLED=0
	fi
}

install_portal() {
	((PORTAL)) || { info "Dynamic Portal not installed on this server (--no-portal)"; return 0; }
	hdr "Installing the ViciBox Dynamic Portal"
	if ((VICIBOX)) && rpm -q vicibox-dynportal >/dev/null 2>&1 && [ -f "$PORTAL_DIR/valid8.php" ]; then
		RPM_PORTAL=1; ok "vicibox-dynportal RPM is installed; its files are used"
	else
		run mkdir -p "$PORTAL_DIR"
		run cp -a "$PAYLOAD_DIR/official/dynportal/." "$PORTAL_DIR/"
		ok "official portal files copied to $PORTAL_DIR"
	fi
	install_if_changed "$PAYLOAD_DIR/src/dynportal-overlay/inc/functions.inc.php" "$PORTAL_DIR/inc/functions.inc.php"
	install_if_changed "$PAYLOAD_DIR/src/dynportal-overlay/valid8.php" "$PORTAL_DIR/valid8.php"
	ok "security overlay applied (escaped pwcheck.pl arguments, encoded redirect values)"
	write_portal_defaults
	run chown -R "$APACHE_USER:$APACHE_GROUP" "$PORTAL_DIR"
	run chmod 755 "$PORTAL_DIR/inc/pwcheck.pl"
	resolve_ssl
	write_vhosts
	configure_selinux
	if apache_apply; then verify_portal; else PORTAL_INSTALLED=0; fi
}

# ------------------------------------------------------------------------------------------------
# fail2ban: ban an address after repeated failed portal logins (the portal logs every attempt to syslog)
# ------------------------------------------------------------------------------------------------
install_fail2ban() {
	((FAIL2BAN)) && ((PORTAL)) || return 0
	hdr "Installing the fail2ban jail for the Dynamic Portal"
	command -v fail2ban-client >/dev/null 2>&1 || pkg_optional fail2ban
	if ! command -v fail2ban-client >/dev/null 2>&1 && ((!DRY_RUN)); then
		warn "fail2ban is not available: portal brute-force protection is limited to the 1-second delay and the ViciDial lockout"
		FAIL2BAN=0; return 0
	fi
	write_file "$F2B_ETC/filter.d/vicidial-dynportal.conf" <<'EOF'
# vicidial-firewall: failed logins on the ViciBox Dynamic Portal (the portal logs them to syslog as "dynportal")
[Definition]
failregex = ^.*login failed for user .* from <HOST>\s*$
ignoreregex =
EOF
	write_file "$F2B_ETC/jail.d/vicidial-dynportal.conf" <<EOF
# vicidial-firewall: ban an address after repeated failed Dynamic Portal logins.
# backend=systemd here also lets the distribution's default sshd jail work on hosts without /var/log/auth.log.
[DEFAULT]
backend = systemd

[vicidial-dynportal]
enabled   = true
filter    = vicidial-dynportal
journalmatch = SYSLOG_IDENTIFIER=dynportal
port      = $PORTAL_PORT,$PORTAL_HTTP_PORT
banaction = firewallcmd-rich-rules
maxretry  = 5
findtime  = 10m
bantime   = 1h
EOF
	run systemctl enable fail2ban >/dev/null 2>&1 || true
	if ((DRY_RUN)); then info "(dry-run) restart fail2ban"; FAIL2BAN_INSTALLED=1; return 0; fi
	if systemctl restart fail2ban >/dev/null 2>&1; then
		FAIL2BAN_INSTALLED=1; ok "fail2ban jail vicidial-dynportal: 5 failed logins in 10 minutes ban the address for 1 hour"
	else
		warn "fail2ban did not start; check 'journalctl -u fail2ban'. The jail files are in $F2B_ETC"
	fi
}

# ------------------------------------------------------------------------------------------------
# Cron
# ------------------------------------------------------------------------------------------------
install_cron() {
	hdr "Installing the VB-firewall cron job"
	local current merged s
	current=$(crontab -l 2>/dev/null || true)
	merged=$(printf '%s\n' "$current" | cron_strip_vbf)
	merged+=$'\n\n'"### ViciBox integrated firewall (managed by vicidial-firewall; $HELPER status)"$'\n'
	merged+="@reboot $VBF_BIN $VBF_ARGS"$'\n'"$CRON_SCHED $VBF_BIN $VBF_ARGS"$'\n'
	if ((DRY_RUN)); then info "(dry-run) crontab lines: '@reboot $VBF_BIN $VBF_ARGS' and '$CRON_SCHED $VBF_BIN $VBF_ARGS'"
	else printf '%s' "$merged" | sed '1{/^$/d}' | crontab -; fi
	for s in cron crond cronie; do
		if systemctl list-unit-files "$s.service" 2>/dev/null | grep -q "^$s.service"; then
			systemctl is-active --quiet "$s" || run systemctl enable --now "$s" >/dev/null 2>&1 || true
			break
		fi
	done
	ok "root crontab: $CRON_SCHED $VBF_BIN $VBF_ARGS"
}

# ------------------------------------------------------------------------------------------------
# Helper CLI and state
# ------------------------------------------------------------------------------------------------
install_helper() {
	install_if_changed "$PAYLOAD_DIR/src/vicidial-firewall" "$HELPER" 0755
	run mkdir -p "$CONF_DIR"
}

write_state() {
	local kv; kv() { printf '%s=%q\n' "$1" "$2"; }
	{
		printf '# vicidial-firewall state - written by the installer, read by %s. Do not edit.\n' "$HELPER"
		kv VF_VERSION "$VF_VERSION"; kv INSTALLED_AT "$(date -Is)"
		kv FAMILY "$FAMILY"; kv VICIBOX "$VICIBOX"; kv MODE "$MODE"; kv VBF_ARGS "$VBF_ARGS"; kv CRON_SCHED "$CRON_SCHED"; kv DYNAMIC_AGE "$DYNAMIC_AGE"
		kv PORTAL "$PORTAL"; kv PORTAL_INSTALLED "$PORTAL_INSTALLED"; kv RPM_PORTAL "$RPM_PORTAL"; kv PORTAL_PORT "$PORTAL_PORT"; kv PORTAL_HTTP "$PORTAL_HTTP"; kv PORTAL_HTTP_PORT "$PORTAL_HTTP_PORT"
		kv PORTAL_FQDN "$PORTAL_FQDN"; kv PORTAL_DIR "$PORTAL_DIR"; kv VHOST_FILE "$VHOST_FILE"; kv VHOST_HTTP_FILE "$VHOST_HTTP_FILE"; kv LISTEN_FILE "$LISTEN_FILE"
		kv LISTEN_ADDED "$LISTEN_ADDED"; kv LISTEN_HTTP_ADDED "$LISTEN_HTTP_ADDED"; kv APACHE_SVC "$APACHE_SVC"
		kv SSL_CERT "$SSL_CERT"; kv SSL_KEY "$SSL_KEY"; kv SSL_SELF_SIGNED "$SSL_SELF_SIGNED"
		kv PUBLIC_IFACE "$PUBLIC_IFACE"; kv RTP_RANGE "$RTP_RANGE"; kv KEEP_SSH_PUBLIC "$KEEP_SSH_PUBLIC"
		kv AGENT_SSH "$AGENT_SSH"; kv PUBLIC_RTP "$PUBLIC_RTP"; kv PORTAL_LOCKOUT "$PORTAL_LOCKOUT"; kv FAIL2BAN_INSTALLED "$FAIL2BAN_INSTALLED"; kv F2B_ETC "$F2B_ETC"
		kv TRUSTED_IFACES "$(join_by , ${TRUSTED_IFACES[@]+"${TRUSTED_IFACES[@]}"})"; kv TRUSTED_NETS "$(join_by , ${TRUSTED_NETS[@]+"${TRUSTED_NETS[@]}"})"; kv INTERNAL_NETS "$(join_by , ${INTERNAL_NETS[@]+"${INTERNAL_NETS[@]}"})"
		kv BACKUP_DIR "$BACKUP_DIR"; kv ORIGINAL_BACKUP_DIR "$ORIGINAL_BACKUP_DIR"; kv ORIG_FW_ACTIVE "$ORIG_FW_ACTIVE"; kv ORIG_FW_ENABLED "$ORIG_FW_ENABLED"
		kv VBF_DIR "$VBF_DIR"; kv VBF_BIN "$VBF_BIN"; kv SSH_IP "$SSH_IP"
	} | write_file "$STATE_FILE" 0600
}

# ------------------------------------------------------------------------------------------------
# Activation
# ------------------------------------------------------------------------------------------------
fw() { run firewall-cmd "$@" >/dev/null 2>&1 || true; }   # tolerant: ALREADY_ENABLED and friends are fine

flush_legacy_iptables() {
	((KEEP_LEGACY_IPTABLES)) && return 0
	((FIREWALLD_WAS_ACTIVE)) && return 0
	local backend ipt
	backend=$(sed -n 's/^FirewallBackend=//p' "$FW_ETC/firewalld.conf" 2>/dev/null | head -1)
	[ "${backend:-nftables}" = nftables ] || return 0
	for ipt in iptables-legacy iptables; do
		command -v "$ipt" >/dev/null 2>&1 || continue
		if "$ipt" -S 2>/dev/null | grep -vqE '^-P (INPUT|FORWARD|OUTPUT) ACCEPT$'; then
			warn "pre-existing $ipt filter rules found: flushing them so they do not fight firewalld (saved in $BACKUP_DIR/iptables-save.txt; --keep-legacy-iptables keeps them)"
			run "$ipt" -P INPUT ACCEPT; run "$ipt" -P FORWARD ACCEPT; run "$ipt" -P OUTPUT ACCEPT; run "$ipt" -F; run "$ipt" -X
		fi
	done
	return 0
}

activate_firewall() {
	hdr "Activating the firewall"
	run systemctl enable firewalld >/dev/null 2>&1 || true
	if systemctl is-active --quiet firewalld; then
		local loaded; loaded=$(firewall-cmd --ipset=voipblip --get-entries 2>/dev/null | grep -c . || true)
		if [ "${loaded:-0}" -gt 5000 ]; then
			# a reload removes the entries one by one and can take minutes with the voipbl.org list (ViciBox default);
			# a restart drops the whole rule set at once. The firewall is open for the second or two in between.
			info "restarting firewalld: $loaded voipbl.org entries are loaded and a reload would take minutes"
			run systemctl restart firewalld || die "firewalld did not restart; check 'journalctl -u firewalld'"
		else
			info "reloading firewalld"
			run firewall-cmd --reload >/dev/null || die "firewall-cmd --reload failed; check 'journalctl -u firewalld'"
		fi
	else
		run systemctl start firewalld || die "firewalld did not start; check 'journalctl -u firewalld'"
	fi
	((DRY_RUN)) && { info "(dry-run) would bind $PUBLIC_IFACE to public, seed the IP sets and run $VBF_BIN"; return 0; }
	local i
	for i in $(seq 1 30); do firewall-cmd --state >/dev/null 2>&1 && break; sleep 1; done
	firewall-cmd --state >/dev/null 2>&1 || die "firewalld is not running"
	fw --set-default-zone=public
	fw --permanent --zone=public --change-interface="$PUBLIC_IFACE"; fw --zone=public --change-interface="$PUBLIC_IFACE"
	for i in ${TRUSTED_IFACES[@]+"${TRUSTED_IFACES[@]}"}; do fw --permanent --zone=trusted --change-interface="$i"; fw --zone=trusted --change-interface="$i"; done
	for i in ${TRUSTED_NETS[@]+"${TRUSTED_NETS[@]}"}; do fw --permanent --zone=trusted --add-source="$i"; fw --zone=trusted --add-source="$i"; done
	if ((FW_PRIORITY_OK)) && ((${#TRUSTED_NETS[@]})); then fw --permanent --zone=trusted --set-priority=-30; fw --reload; fi   # a trusted LAN wins over its whitelist entry
	if [ "$MODE" != blacklist ]; then
		# seed the allow sets right away so this session (and the carriers) are not cut off while cron catches up
		for i in ${ALLOW_NOW[@]+"${ALLOW_NOW[@]}"}; do
			if valid_cidr "$i"; then fw --ipset=whitenets --add-entry="$i"; else fw --ipset=whiteips --add-entry="$i"; fi
		done
	fi
	info "first synchronisation from the ViciDial database:"
	# shellcheck disable=SC2086
	"$VBF_BIN" ${VBF_ARGS/--quiet/} --verbose 2>&1 | sed 's/^/      /' || warn "VB-firewall reported a problem (see above)"
	flush_legacy_iptables
	ok "firewalld active; default zone public on $PUBLIC_IFACE"
}

verify_access() {
	((DRY_RUN)) && return 0
	[ "$MODE" = blacklist ] && return 0
	[ -n "$SSH_IP" ] || return 0
	local good=0 e
	if ssh_covered_by_trusted; then good=1
	elif firewall-cmd --ipset=whiteips --query-entry="$SSH_IP" >/dev/null 2>&1; then good=1
	else
		for e in $(firewall-cmd --ipset=whitenets --get-entries 2>/dev/null); do
			if valid_cidr "$e" && cidr_contains "$e" "$SSH_IP"; then good=1; break; fi
		done
	fi
	if ((good)); then ok "your address $SSH_IP is allowed in (external zone)"
	else warn "your SSH address $SSH_IP is NOT in the allow sets. Keep this session open and run: $HELPER whitelist add $SSH_IP"; fi
}

arm_safety_timer() {
	((SAFETY_MIN > 0)) || { info "safety timer disabled"; return 0; }
	[ "$MODE" != blacklist ] || return 0
	((DRY_RUN)) && { info "(dry-run) would arm a $SAFETY_MIN minute rollback timer"; return 0; }
	command -v systemd-run >/dev/null 2>&1 || { warn "systemd-run not found: no safety timer"; return 0; }
	rm -f "$CONF_DIR/confirmed"
	systemctl stop "$SAFETY_UNIT.timer" >/dev/null 2>&1 || true
	systemctl reset-failed "$SAFETY_UNIT.service" >/dev/null 2>&1 || true
	if systemd-run --quiet --on-active="${SAFETY_MIN}min" --unit="$SAFETY_UNIT" --description="vicidial-firewall: restore the previous firewall unless confirmed" "$HELPER" rollback-if-unconfirmed >/dev/null 2>&1; then
		ok "safety timer armed for $SAFETY_MIN minutes"
	else
		warn "could not arm the safety timer (systemd-run failed)"
	fi
}

final_report() {
	local line n=1; line=$(printf '=%.0s' $(seq 1 92))
	say ""; say "$line"
	say "${c_bld} vicidial-firewall $VF_VERSION installed  -  mode: $MODE${c_off}"
	say "$line"
	if ((PORTAL)); then
		say " Dynamic Portal ...... https://$PORTAL_FQDN:$PORTAL_PORT/valid8.php$( ((PORTAL_INSTALLED)) || echo "   (NOT answering - see warnings above)")"
		if ((PORTAL_HTTP)); then say "                       http://$PORTAL_FQDN:$PORTAL_HTTP_PORT/valid8.php  (plain HTTP)"; fi
		if ((SSL_SELF_SIGNED)); then say "                       certificate is self-signed: agents will see a browser warning"; fi
	fi
	say " Public zone ......... $(public_services | tr '\n' ' ') on $PUBLIC_IFACE"
	if [ "$MODE" != blacklist ]; then
		say " ViciWhite list ...... http https asterisk rtp ssh   (carriers, offices, VPNs, administrators)"
		if [ "$MODE" = dynamic ]; then say " Validated agents .... http https asterisk rtp$( ((AGENT_SSH)) && echo " ssh")   for $DYNAMIC_AGE days after their last login"; fi
		if ((${#ALLOW_NOW[@]})); then say " ViciWhite entries ... $(join_by ', ' "${ALLOW_NOW[@]}")"; fi
	fi
	if ((PORTAL)); then
		say " Portal protection ... $( ((PORTAL_LOCKOUT)) && echo "user ignored after $PORTAL_LOCKOUT failed logins; " )$( ((FAIL2BAN_INSTALLED)) && echo "fail2ban bans an address for 1 h after 5 failures" || echo "no fail2ban")"
	fi
	say " Cron ................ $CRON_SCHED $VBF_BIN $VBF_ARGS"
	say " Backup .............. $BACKUP_DIR"
	say " Log ................. $LOG_FILE"
	say ""
	say "${c_bld} NEXT STEPS${c_off}"
	if ((SAFETY_MIN > 0)) && [ "$MODE" != blacklist ] && ((!DRY_RUN)); then
		say "  $n. Open a NEW SSH session now and run:   ${c_bld}$HELPER confirm${c_off}"
		say "     Without it the previous firewall configuration is restored in $SAFETY_MIN minutes."; n=$((n+1))
	fi
	if [ "$MODE" != blacklist ]; then
		say "  $n. Add every SIP carrier, office and VPN address that is missing: ViciDial Admin > IP Lists > ViciWhite"
		say "     (one IP or CIDR per line; VB-firewall applies it within a minute)  or:  $HELPER whitelist add IP"; n=$((n+1))
	fi
	if ((PORTAL)); then
		say "  $n. Tell agents to open the portal URL, log in with their ViciDial user ID and password, wait up to"
		say "     a minute, then use ViciDial as usual. Their address stays allowed $DYNAMIC_AGE days after the last login."; n=$((n+1))
	fi
	say "  $n. $HELPER status   |   whitelist list|add|remove   |   dynamic list   |   sync   |   emergency-open   |   uninstall"
	say "$line"
}

# ------------------------------------------------------------------------------------------------
main() {
	parse_args "$@"
	say "vicidial-firewall installer $VF_VERSION  -  official ViciDial/ViciBox firewall: VB-firewall.pl + Dynamic Portal"
	preflight
	install_packages
	check_database
	detect_carriers
	compute_plan
	show_plan
	confirm_plan
	take_backup
	disable_conflicting_firewalls
	install_vbfirewall
	install_firewalld_config
	setup_database
	install_portal
	install_fail2ban
	install_cron
	install_helper
	write_state
	activate_firewall
	verify_access
	arm_safety_timer
	final_report
}

if [ "${VF_SOURCE_ONLY:-0}" != 1 ]; then main "$@"; fi
