#!/usr/bin/env bash
# Unit tests for the pure helper functions of src/installer.sh and for the build payload.
# Runs anywhere bash 4.4+ is available (Linux, Git Bash, WSL); no root, no firewalld needed.
# shellcheck disable=SC2034
set -uo pipefail
cd "$(dirname "$0")/.."
pass=0 fail=0
t() { local name=$1; shift; if "$@" >/dev/null 2>&1; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $name"; fi; }
tn() { local name=$1; shift; if "$@" >/dev/null 2>&1; then fail=$((fail+1)); echo "FAIL (expected failure): $name"; else pass=$((pass+1)); fi; }
eq() { [ "$1" = "$2" ] || { echo "   got:      $1"; echo "   expected: $2"; return 1; }; }

export VF_SOURCE_ONLY=1
# shellcheck disable=SC1091
set +e; . src/installer.sh; set +e +o errexit
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# --- IP helpers -------------------------------------------------------------------------------
t  "ipv4 plain"            valid_ipv4 203.0.113.9
t  "ipv4 leading zero"     valid_ipv4 010.1.1.1
tn "ipv4 octet > 255"      valid_ipv4 256.1.1.1
tn "ipv4 0.0.0.0"          valid_ipv4 0.0.0.0
tn "ipv4 empty"            valid_ipv4 ""
tn "ipv4 garbage"          valid_ipv4 "1.2.3.4; rm -rf /"
t  "cidr /24"              valid_cidr 198.51.100.0/24
t  "cidr /32"              valid_cidr 198.51.100.7/32
tn "cidr /0"               valid_cidr 198.51.100.0/0
tn "cidr /33"              valid_cidr 198.51.100.0/33
tn "cidr no mask"          valid_cidr 198.51.100.0
t  "private 10/8"          is_private_ipv4 10.9.8.7
t  "private 172.31"        is_private_ipv4 172.31.0.1
tn "not private 172.32"    is_private_ipv4 172.32.0.1
t  "cidr contains"         cidr_contains 10.0.0.0/8 10.200.3.4
tn "cidr not contains"     cidr_contains 10.0.0.0/8 11.0.0.1
t  "cidr /31 contains"     cidr_contains 1.2.3.4/31 1.2.3.5
tn "cidr /31 excludes"     cidr_contains 1.2.3.4/31 1.2.3.6

# --- rand_name ------------------------------------------------------------------------------------
n=$(rand_name); t "rand_name shape" bash -c '[[ "$1" =~ ^[A-Za-z][A-Za-z0-9]{11}$ ]]' _ "$n"
t "rand_name differs" bash -c '[ "$1" != "$2" ]' _ "$(rand_name)" "$(rand_name)"

# --- cron merge -----------------------------------------------------------------------------------
cron_in=$'* * * * * /usr/share/astguiclient/ADMIN_keepalive_ALL.pl\n### ViciBox integrated firewall\n@reboot /usr/bin/VB-firewall --voipbl --quiet\n0 */6 * * * /usr/bin/VB-firewall --voipbl --quiet\n* * * * * /usr/local/bin/VB-firewall.pl --white\n\n\n'
cron_out=$(printf '%s' "$cron_in" | cron_strip_vbf)
t "cron strip keeps other jobs"  eq "$cron_out" '* * * * * /usr/share/astguiclient/ADMIN_keepalive_ALL.pl'
t "cron strip on empty input"    eq "$(printf '' | cron_strip_vbf)" ''
t "cron strip keeps unrelated"   eq "$(printf '1 2 * * * /bin/myVB-firewall-tool\n' | cron_strip_vbf)" '1 2 * * * /bin/myVB-firewall-tool'

# --- template rendering ---------------------------------------------------------------------------
out=$(TPL_GENERATED=now TPL_LISTEN="Listen 446 https" TPL_PORT=446 TPL_FQDN=dialer.example.com TPL_DOCROOT=/srv/www/vhosts/dynportal \
      TPL_LOGDIR=/var/log/httpd TPL_PHP_INCLUDE="" TPL_CERT=/c.pem TPL_KEY=/k.pem TPL_CHAIN="" render_template src/apache/dynportal-ssl.conf.tpl)
t "tpl port"        grep -q '^<VirtualHost _default_:446>' <<<"$out"
t "tpl listen"      grep -q '^Listen 446 https$' <<<"$out"
t "tpl serveradmin" grep -q 'ServerAdmin admin@dialer.example.com' <<<"$out"
t "tpl servername"  grep -q 'ServerName dialer.example.com' <<<"$out"
t "tpl cert"        grep -q 'SSLCertificateFile /c.pem' <<<"$out"
t "tpl no tokens"   bash -c '! grep -q "@@" <<<"$1"' _ "$out"
t "tpl no HSTS"     bash -c '! grep -qi "Strict-Transport" <<<"$1"' _ "$out"

# --- zone / service XML generation -------------------------------------------------------------
FW_ETC=$tmp/firewalld; DRY_RUN=0; MODE=dynamic; PORTAL=1; PORTAL_HTTP=0; KEEP_SSH_PUBLIC=0
mapfile -t svc < <(public_services); t "public services dynamic" eq "${svc[*]}" "rtp dhcpv6-client dynportal-ssl"
MODE=blacklist; mapfile -t svc < <(public_services); t "public services blacklist" eq "${svc[*]}" "rtp dhcpv6-client ssh http https asterisk dynportal-ssl"
MODE=dynamic; KEEP_SSH_PUBLIC=1; PORTAL_HTTP=1; mapfile -t svc < <(public_services); t "public services ssh+http" eq "${svc[*]}" "rtp dhcpv6-client ssh dynportal-ssl dynportal"
KEEP_SSH_PUBLIC=0; PORTAL_HTTP=0
a=(http https) b=(whiteips whitenets dynamiclist) c=(10.1.0.0/16) d=(5038/tcp) none=()
emit_zone external "External" "desc" "" a b c d
emit_zone drop "Drop" "desc" "DROP" none b none none
t "zone file written"       test -f "$tmp/firewalld/zones/external.xml"
t "zone service"            grep -q '<service name="https"/>' "$tmp/firewalld/zones/external.xml"
t "zone ipset"              grep -q '<source ipset="dynamiclist"/>' "$tmp/firewalld/zones/external.xml"
t "zone address"            grep -q '<source address="10.1.0.0/16"/>' "$tmp/firewalld/zones/external.xml"
t "zone port"               grep -q '<port protocol="tcp" port="5038"/>' "$tmp/firewalld/zones/external.xml"
t "zone target"             grep -q '<zone target="DROP">' "$tmp/firewalld/zones/drop.xml"
t "zone xml well-formed"    bash -c 'command -v xmllint >/dev/null && xmllint --noout "$1" || grep -q "</zone>" "$1"' _ "$tmp/firewalld/zones/external.xml"
emit_service rtp "RTP" "desc" 10000-20000/udp
t "service port range"      grep -q '<port protocol="udp" port="10000-20000"/>' "$tmp/firewalld/services/rtp.xml"

# --- v1.1: public RTP off, zone priorities, firewalld version compare -----------------------------------
MODE=dynamic; PORTAL=1; PORTAL_HTTP=0; KEEP_SSH_PUBLIC=0; PUBLIC_RTP=0
mapfile -t svc < <(public_services); t "public services no rtp" eq "${svc[*]}" "dhcpv6-client dynportal-ssl"
MODE=blacklist; mapfile -t svc < <(public_services); t "blacklist keeps rtp public" eq "${svc[*]}" "rtp dhcpv6-client ssh http https asterisk dynportal-ssl"
MODE=dynamic; PUBLIC_RTP=1
t  "fw_version_ge 2.1.0 >= 2.0" fw_version_ge 2.1.0 2.0
t  "fw_version_ge 2.0.3 >= 2.0" fw_version_ge 2.0.3 2.0
tn "fw_version_ge 0.9.3 >= 2.0 (ViciBox 10)" fw_version_ge 0.9.3 2.0
tn "fw_version_ge 1.3.4 >= 2.0" fw_version_ge 1.3.4 2.0
tn "fw_version_ge garbage"      fw_version_ge "" 2.0
t  "agent zone sorts after external and internal" bash -c '[[ "$1" > external && "$1" > internal && "$1" > trusted ]]' _ "$AGENT_ZONE"
FW_PRIORITY_OK=1; emit_zone agents "Agents" "d" "" a b none none -10
t "zone priority attr"      grep -q '<zone priority="-10">' "$tmp/firewalld/zones/agents.xml"
FW_PRIORITY_OK=0; emit_zone agents "Agents" "d" "" a b none none -10
t "zone priority omitted"   bash -c '! grep -q priority "$1"' _ "$tmp/firewalld/zones/agents.xml"

# --- compute_plan / VBF args ----------------------------------------------------------------------
SSH_IP=203.0.113.9; WHITELIST=(198.51.100.0/24 203.0.113.9); CARRIER_IPS=(192.0.2.10); TRUSTED_NETS=(); TRUSTED_IFACES=(); SSH_WHITELIST=1; ADD_RFC1918=0; DYNAMIC_AGE=15
MODE=dynamic; compute_plan
t "vbf args dynamic"   eq "$VBF_ARGS" "--white --dynamic --quiet"
t "cron sched dynamic" eq "$CRON_SCHED" "* * * * *"
t "allow_now dedup"    eq "${ALLOW_NOW[*]}" "203.0.113.9 198.51.100.0/24 192.0.2.10"
DYNAMIC_AGE=7; compute_plan; t "vbf args dynamicage" eq "$VBF_ARGS" "--white --dynamic --dynamicage=7 --quiet"
MODE=blacklist; compute_plan; t "vbf args blacklist" eq "$VBF_ARGS" "--voipbl --quiet"; t "cron sched blacklist" eq "$CRON_SCHED" "0 */6 * * *"
MODE=whitelist; ADD_RFC1918=1; compute_plan; t "vbf args whitelist rfc1918" eq "$VBF_ARGS" "--white --addrfc1918 --quiet"
SSH_IP=10.0.0.5; TRUSTED_NETS=(10.0.0.0/8); SSH_WHITELIST=1; WHITELIST=(); CARRIER_IPS=(); compute_plan
t "ssh in trusted net not whitelisted" eq "${ALLOW_NOW[*]-}" ""

# --- trusted/internal overlap is not whitelisted -----------------------------------------------------
mkdir -p "$tmp/firewalld/zones"; printf '<zone target="ACCEPT">
  <source address="135.181.56.155"/>
  <source address="10.9.0.0/16"/>
</zone>
' > "$tmp/firewalld/zones/trusted.xml"
FW_ETC=$tmp/firewalld; MODE=dynamic; SSH_IP=59.103.120.47; SSH_WHITELIST=1; TRUSTED_NETS=(); TRUSTED_IFACES=(); INTERNAL_NETS=(192.0.2.5/32)
WHITELIST=(203.81.238.197 10.9.4.4); CARRIER_IPS=(135.181.56.155 143.244.163.152 192.0.2.5); compute_plan
t "overlap: allow list"   eq "${ALLOW_NOW[*]}" "59.103.120.47 203.81.238.197 143.244.163.152"
t "overlap: skipped"      eq "${SKIPPED_LAN[*]}" "10.9.4.4 135.181.56.155 192.0.2.5"
INTERNAL_NETS=()

# --- state file round trip ------------------------------------------------------------------------
STATE_FILE=$tmp/state; VBF_ARGS="--white --dynamic --quiet"; PORTAL_FQDN="d.example.com"; ORIGINAL_BACKUP_DIR="/var/backups/x y"; BACKUP_DIR=/b
MODE=dynamic; CRON_SCHED="* * * * *"; write_state
t "state readable"   test -f "$tmp/state"
t "state_get quoted" eq "$(state_get ORIGINAL_BACKUP_DIR)" "/var/backups/x y"
t "state_get args"   eq "$(state_get VBF_ARGS)" "--white --dynamic --quiet"
t "helper sources state" bash -c 'set -u; . "$1" && [ "$VBF_ARGS" = "--white --dynamic --quiet" ]' _ "$tmp/state"

# --- parse_args validation (subshells; die exits 1) -----------------------------------------------
PAYLOAD_DIR=$PWD
t  "args ok"              bash -c 'VF_SOURCE_ONLY=1; . src/installer.sh; parse_args --mode=whitelist --whitelist=1.2.3.4,10.0.0.0/8 --cluster-ip=192.0.2.5 --portal-port=8443 && [ "${INTERNAL_NETS[0]}" = 192.0.2.5/32 ] && [ "$PORTAL_PORT" = 8443 ]'
tn "args bad mode"        bash -c 'VF_SOURCE_ONLY=1; . src/installer.sh; parse_args --mode=open'
tn "args bad whitelist"   bash -c 'VF_SOURCE_ONLY=1; . src/installer.sh; parse_args --whitelist=1.2.3'
tn "args bad cidr"        bash -c 'VF_SOURCE_ONLY=1; . src/installer.sh; parse_args --trusted-net=10.0.0.1'
tn "args cert w/o key"    bash -c 'VF_SOURCE_ONLY=1; . src/installer.sh; parse_args --ssl-cert=/x'
tn "args unknown"         bash -c 'VF_SOURCE_ONLY=1; . src/installer.sh; parse_args --bogus'
t  "help exits 0"         bash -c 'VF_SOURCE_ONLY=0 bash src/installer.sh --help | grep -q "vicidial-firewall installer"'

# --- build payload round trip ---------------------------------------------------------------------
if [ -f install.sh ]; then
	mkdir -p "$tmp/x"
	t "payload extracts" bash -c 'sed -n "/^VF_PAYLOAD_B64=\$(cat <<.__VF_PAYLOAD_END__.$/,/^__VF_PAYLOAD_END__$/p" install.sh | sed "1d;\$d" | base64 -d | tar -xzf - -C "$1"' _ "$tmp/x"
	t "payload has installer" test -f "$tmp/x/src/installer.sh"
	t "payload has VB-firewall" cmp -s "$tmp/x/official/VB-firewall.pl" official/VB-firewall.pl
	t "payload has portal"    cmp -s "$tmp/x/official/dynportal/valid8.php" official/dynportal/valid8.php
	t "payload has overlay"   cmp -s "$tmp/x/src/dynportal-overlay/valid8.php" src/dynportal-overlay/valid8.php
	t "payload installer same" cmp -s "$tmp/x/src/installer.sh" src/installer.sh
	t "install.sh syntax"     bash -n install.sh
	t "install.sh --help via payload" bash -c 'VF_SOURCE_ONLY=0 bash install.sh --help | grep -q "vicidial-firewall installer"'
	t "install.sh cleans its temp dir" bash -c 'before=$(ls -d "${TMPDIR:-/tmp}"/vicidial-firewall.* 2>/dev/null | wc -l); VF_SOURCE_ONLY=0 bash install.sh --version >/dev/null; after=$(ls -d "${TMPDIR:-/tmp}"/vicidial-firewall.* 2>/dev/null | wc -l); [ "$before" = "$after" ]'
fi

# --- stubbed end-to-end smoke test ----------------------------------------------------------------
t "smoke test (stubbed dry run + real file writers)" bash tests/smoke.sh

echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
