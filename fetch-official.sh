#!/usr/bin/env bash
# Refreshes official/ from the ViciBox packages on the openSUSE Build Service (home:vicidial:vicibox) and
# verifies every download against the md5 published in the OBS source listing. Run it, review "git diff",
# re-apply/adjust src/dynportal-overlay if the portal changed, then ./build.sh.
set -euo pipefail
cd "$(dirname "$0")"
OBS=https://api.opensuse.org/public/source/home:vicidial:vicibox
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

listing_md5() { sed -n "s/.*name=\"$2\" md5=\"\([0-9a-f]*\)\".*/\1/p" "$work/$1.xml" | head -1; }
fetch() { # pkg file
	local pkg=$1 f=$2 want have
	curl -fsSL -o "$work/$f" "$OBS/$pkg/$f"
	want=$(listing_md5 "$pkg" "$f"); have=$(md5sum "$work/$f" | cut -d' ' -f1)
	[ -n "$want" ] && [ "$want" = "$have" ] || { echo "md5 mismatch for $pkg/$f (listing $want, got $have)" >&2; exit 1; }
	printf '  %-40s %s\n' "$pkg/$f" "$have"
}
for pkg in vicibox-firewall vicibox-dynportal; do curl -fsSL -o "$work/$pkg.xml" "$OBS/$pkg"; done
fw_rev=$(sed -n 's/.*<directory[^>]* rev="\([0-9]*\)".*/\1/p' "$work/vicibox-firewall.xml" | head -1)
dp_rev=$(sed -n 's/.*<directory[^>]* rev="\([0-9]*\)".*/\1/p' "$work/vicibox-dynportal.xml" | head -1)
fw_tar=$(sed -n 's/.*name="\(vicibox-firewall-[0-9.]*\.tar\.xz\)".*/\1/p' "$work/vicibox-firewall.xml" | head -1)
dp_tar=$(sed -n 's/.*name="\(vicibox-dynportal-[0-9.]*\.tar\.xz\)".*/\1/p' "$work/vicibox-dynportal.xml" | head -1)
echo "vicibox-firewall rev $fw_rev, vicibox-dynportal rev $dp_rev"
fetch vicibox-firewall VB-firewall.pl
fetch vicibox-firewall "$fw_tar"
fetch vicibox-firewall vicibox-firewall.changes
for f in "$dp_tar" dynportal.conf dynportal-ssl.conf dynportal.xml dynportal-ssl.xml mod_cband.conf mod_cband.portal vicibox-dynportal.changes; do fetch vicibox-dynportal "$f"; done

rm -rf official/dynportal official/firewalld/ipsets official/firewalld/zones
mkdir -p official/firewalld/services official/apache
install -m 0755 "$work/VB-firewall.pl" official/VB-firewall.pl
tar -xJf "$work/$fw_tar" -C "$work"; cp -r "$work/vicibox-firewall/firewalld/ipsets" "$work/vicibox-firewall/firewalld/zones" official/firewalld/
tar -xJf "$work/$dp_tar" -C "$work"; cp -r "$work/dynportal" official/dynportal
cp "$work/dynportal.xml" "$work/dynportal-ssl.xml" official/firewalld/services/
cp "$work/dynportal.conf" "$work/dynportal-ssl.conf" "$work/mod_cband.conf" "$work/mod_cband.portal" official/apache/
{
	echo "# Provenance of official/"
	echo
	echo "Fetched $(date -u +%F) with fetch-official.sh from the ViciBox packages on the openSUSE Build Service,"
	echo "project home:vicidial:vicibox (https://build.opensuse.org/project/show/home:vicidial:vicibox), maintained by"
	echo "James Pearson (ViciDial Group). Every file was verified against the md5 in the OBS source listing."
	echo
	echo "| package | rev | file | md5 |"; echo "|---|---|---|---|"
	for f in VB-firewall.pl "$fw_tar" vicibox-firewall.changes; do echo "| vicibox-firewall | $fw_rev | $f | $(md5sum "$work/$f" | cut -d' ' -f1) |"; done
	for f in "$dp_tar" dynportal.conf dynportal-ssl.conf dynportal.xml dynportal-ssl.xml mod_cband.conf mod_cband.portal vicibox-dynportal.changes; do echo "| vicibox-dynportal | $dp_rev | $f | $(md5sum "$work/$f" | cut -d' ' -f1) |"; done
	echo
	echo "Layout: VB-firewall.pl (script), firewalld/ipsets and firewalld/zones (from $fw_tar), firewalld/services and"
	echo "apache/ (vicibox-dynportal package files), dynportal/ (from $dp_tar). Nothing in official/ is modified;"
	echo "the installer's changes live in src/ (see README, 'Differences from stock ViciBox')."
	echo
	echo "Upstream change logs (first entries):"; echo
	echo '```'; head -12 "$work/vicibox-firewall.changes"; echo '```'; echo '```'; head -8 "$work/vicibox-dynportal.changes"; echo '```'
} >official/SOURCES.md
echo "official/ refreshed; now check: git diff official/  and  diff -u official/dynportal/inc/functions.inc.php src/dynportal-overlay/inc/functions.inc.php"
