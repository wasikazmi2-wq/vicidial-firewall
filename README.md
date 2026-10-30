# vicidial-firewall

One-command installation of the **official ViciDial / ViciBox firewall** on any ViciDial server:
dynamic IP validation for work-from-home agents, a whitelist for carriers and offices, and
everything else closed.

It does not invent a new firewall. It installs and wires up the pieces the ViciDial Group ships
with ViciBox, unmodified and verified against the upstream package checksums:

| Component | What it is | Upstream |
|---|---|---|
| **VB-firewall.pl** | The ViciBox firewall script. Every minute it reads the `ViciWhite` IP list from the ViciDial database plus the addresses of recent agent logins, and syncs them into firewalld IP sets. | openSUSE Build Service `home:vicidial:vicibox/vicibox-firewall` |
| **Dynamic Portal** | `valid8.php`: a small page on port 446 where an agent enters their ViciDial user ID and password. A good login writes a `VICIBOX` event with the agent's IP into `vicidial_user_log`; VB-firewall opens the firewall for that IP within a minute, on every server of the cluster. | `home:vicidial:vicibox/vicibox-dynportal` |
| **firewalld layout** | The ViciBox zones: `public` (RTP + portal only), `external` (the ViciWhite list), `agents` (addresses validated through the portal: web, SIP/WebRTC, audio, no SSH), `internal` (cluster peers), `drop` (block lists), fed by the IP sets `whiteips`, `whitenets`, `dynamiclist`, ... | same packages |

Provenance and checksums of every official file: [official/SOURCES.md](official/SOURCES.md).
Official documentation of the mechanism: [ViciBox docs, Firewall](https://docs.vicibox.com/en/latest/networking/firewall.html)
(White List, Dynamic Portal, Zones).

## How it works after installation

```
 agent at home (dynamic IP)                       ViciDial server(s)
 ───────────────────────────                      ──────────────────────────────────────────────
 1. opens https://dialer.example.com:446/valid8.php   public zone: only RTP + the portal answer
 2. enters ViciDial user ID + password  ───────────►  portal checks vicidial_users, inserts
                                                      VICIBOX login event with the agent's IP
  3. waits up to 60 s, is redirected to              cron (every minute): VB-firewall --white --dynamic
    https://dialer.example.com/agc/vicidial.php        -> IP goes into the "dynamiclist" IP set
 4. works normally: web, SIP/WebRTC, audio            agents zone: http https asterisk rtp (no SSH)
                                                      IP stays allowed 15 days after the last login
 carriers / office / VPN / admins ────────────────►  ViciWhite IP list (Admin > IP Lists) -> whiteips/whitenets
                                                      external zone: http https asterisk rtp ssh
 everyone else            ───────────────────────►  dropped (except RTP media and the portal page)
 5 failed portal logins   ───────────────────────►  user ignored (ViciDial lockout) + address banned 1 h (fail2ban)
```

## Install

Run on the ViciDial server, **from an SSH session** (its address is whitelisted automatically):

```bash
curl -fsSL https://raw.githubusercontent.com/wasikazmi2-wq/vicidial-firewall/main/install.sh -o install.sh
sudo bash install.sh
```

or straight from the pipe (options after `--`):

```bash
curl -fsSL https://raw.githubusercontent.com/wasikazmi2-wq/vicidial-firewall/main/install.sh | sudo bash -s -- --portal-fqdn=dialer.example.com
```

`install.sh` is one self-contained file (bootstrap + embedded archive) built by `./build.sh` from
`src/` and `official/`. From a clone of this repository you can also run `sudo bash src/installer.sh`.
Replace `wasikazmi2-wq` with the GitHub account you push this repository to, or copy `install.sh` to the
server with `scp`.

The installer shows a plan and asks for confirmation. A typical run on a single server:

```bash
sudo bash install.sh \
  --portal-fqdn=dialer.example.com \
  --whitelist=203.0.113.10,198.51.100.0/24      # SIP carrier, office network
```

Then, **from a new SSH session**, within 10 minutes:

```bash
sudo vicidial-firewall confirm
```

If that command is not run, the installer's safety timer restores the previous firewall
configuration and crontab automatically, so a mistake cannot lock you out for good.

### Before you run it

- **Carriers.** In the default mode only whitelisted and validated addresses may send SIP. Active
  carriers from ViciDial's `vicidial_server_carriers` (their `host=` lines) are added to `ViciWhite`
  automatically; pass anything else with `--whitelist=`. Carriers that register *to* you from
  changing addresses need a whitelist entry per address or a CIDR.
- **Your own access.** The address of the SSH session running the installer goes into `ViciWhite`.
  Office or VPN addresses go in `--whitelist=`. A LAN interface can be fully trusted with
  `--trusted-iface=eth1` (see the RFC1918 caveat below).
- **Clusters.** Run the installer on every server. The lists live in the shared database, so one
  portal serves the whole cluster: use `--no-portal` on all servers but the one agents should open,
  and `--cluster-ip=` / `--internal-net=` for the addresses the servers use to talk to each other
  (MySQL, FTP, AMI 5038 are only open in the `internal` zone).
- **Certificate.** The portal is HTTPS. The installer uses, in this order: `--ssl-cert/--ssl-key`,
  a Let's Encrypt certificate under `/etc/letsencrypt/live/HOST/`, the certificate of the existing
  ViciDial web server, or a generated self-signed one (browser warning for agents).
- **Supported systems.** Debian/Ubuntu, RHEL/Rocky/Alma, openSUSE and ViciBox, with systemd.
  firewalld is required by VB-firewall.pl itself; the installer installs it and disables ufw,
  `nftables.service` and similar managers so only one firewall is in charge.

### Modes

| `--mode=` | Who may reach ViciDial | VB-firewall cron |
|---|---|---|
| `dynamic` (default) | `ViciWhite` entries (web, SIP, WebRTC, SSH) + addresses with a ViciDial or portal login in the last `--dynamic-age` days (web, SIP, WebRTC, audio; SSH only with `--agent-ssh`) | `--white --dynamic` every minute |
| `whitelist` | `ViciWhite` entries only | `--white` every minute |
| `blacklist` | everyone except `ViciBlack` and the voipbl.org block list (what a fresh ViciBox does) | `--voipbl` every 6 hours |

### What stays reachable from the internet, and why

No firewall makes a server "100% secure"; what this one does is reduce the internet-facing surface
to two things, both deliberate:

| Reachable by anyone | Why | How to close it further |
|---|---|---|
| The portal page, `446/tcp` | Agents with changing addresses must be able to validate before anything else is open. It asks for ViciDial credentials, waits 1 second per attempt, ignores a user after 5 failed logins (`--portal-lockout`), and fail2ban bans the address for an hour after 5 failures in 10 minutes. Every attempt is logged (`journalctl -t dynportal`). | `--portal-port=N` moves it off 446; VPN-only shops can use `--no-portal --mode=whitelist`. |
| The RTP media range, `10000-20000/udp` by default | Carriers often send audio from addresses other than their SIP signalling address, so ViciBox keeps RTP public. RTP carries no signalling and no logins. | `--no-public-rtp`, once every carrier media address is in `ViciWhite`. |

Everything else (web interface, SIP, IAX, WebRTC, SSH, MySQL, FTP, AMI) is unreachable from an unknown
address. Validated agents get only what an agent needs; SSH, MySQL and the manager port are never
opened by a portal login. Two reminders: close unused ports at the cloud provider too, and keep
ViciDial and PHP updated, because a firewall does not fix web application bugs for addresses that are
allowed in (the ViciBox documentation itself warns about critical PHP vulnerabilities on older builds).

### All options

`sudo bash install.sh --help` prints them. The important ones:

```
--mode=dynamic|whitelist|blacklist   --dynamic-age=DAYS   --add-rfc1918
--whitelist=IP[,CIDR,...]  --no-ssh-whitelist  --no-auto-carriers  --keep-ssh-public  --agent-ssh
--trusted-iface=NAME  --trusted-net=CIDR  --internal-net=CIDR  --cluster-ip=IP
--public-iface=NAME  --rtp-range=A-B  --no-public-rtp  --keep-legacy-iptables
--no-portal  --portal-fqdn=HOST  --portal-port=446  --portal-http  --portal-userlevel=1
--portal-redirect=URL | --no-portal-redirect  --portal-redirect-secs=60  --no-login-passthrough
--portal-lockout=5  --no-fail2ban
--ssl-cert=FILE --ssl-key=FILE [--ssl-chain=FILE]
--db-host= --db-port= --db-user= --db-pass= --db-name=      (default: /etc/astguiclient.conf)
--safety-timer=MIN | --no-safety-timer   --dry-run   --yes   --uninstall
```

## What agents do

1. Open `https://dialer.example.com:446/valid8.php` (give them this link; it is the only web page
   reachable before validation).
2. Enter their ViciDial **user ID and password** (the same ones they use to log in to the agent screen).
3. Wait for the countdown (60 seconds by default); they are redirected to the agent login with their
   login pre-filled, or they can open ViciDial themselves after a minute.
4. Nothing else for 15 days, as long as they keep logging in. A changed home IP means validating again.

An agent needs ViciDial user level 1 or higher by default (`--portal-userlevel`), must be active,
and must not be over the failed-login limit. After 5 wrong passwords (`--portal-lockout`) the portal
ignores that user until an administrator opens the user in ViciDial Admin > Users and clicks Submit,
which resets the counter. Administrators can validate the same way; a user whose `phone_login` is
`admin` is redirected to the admin page instead. A portal login never opens SSH (see `--agent-ssh`).

## Managing it afterwards

Everything is in the ViciDial database, so the normal way to manage access is
**ViciDial Admin > IP Lists > ViciWhite** (one IP or CIDR per line). VB-firewall applies changes
within a minute on every server. The installer enables the IP Lists feature in System Settings and
gives every level-9 user the *Modify IP Lists* permission.

The helper `vicidial-firewall` (installed in `/usr/local/sbin`) covers the rest:

```
vicidial-firewall status                      zones, IP set sizes, cron, portal, safety timer
vicidial-firewall whitelist list|add X|remove X
vicidial-firewall dynamic list|remove IP      who is in because of a login
vicidial-firewall sync                        run VB-firewall now
vicidial-firewall confirm                     cancel the post-install safety rollback
vicidial-firewall emergency-open              runtime-only: ssh/http/https open to all (and emergency-close)
vicidial-firewall logs                        journalctl -t VB-firewall
vicidial-firewall rollback                    restore the pre-install firewall + crontab
vicidial-firewall uninstall                   remove everything, restore the backup
```

Run the installer again at any time to change options; it re-applies the configuration, keeps the
original backup for `uninstall`, and keeps the portal's random form field names.

## If you get locked out

- The safety timer: do nothing for 10 minutes and the previous firewall configuration is back.
- From the console or a whitelisted address: `vicidial-firewall emergency-open` opens SSH and the web
  interface to everyone until the next reload, or `vicidial-firewall rollback`.
- A portal login opens the web interface and SIP, not SSH, unless you installed with `--agent-ssh`.
  Keep at least one static address (office, VPN) in `ViciWhite` for administration.
- Manual: `firewall-cmd --zone=public --add-service=ssh` (runtime only).

## What the installer changes on the server

| Where | What |
|---|---|
| `/usr/share/vicibox-firewall/VB-firewall.pl`, `/usr/bin/VB-firewall` | official script + symlink (ViciBox RPM layout); an older copy from the vicibox-firewall package (ViciBox 10, 11) is replaced by the current release, the old one kept in the backup |
| `/etc/firewalld/ipsets/*.xml` | the 8 official IP set definitions |
| `/etc/firewalld/services/` | `dynportal`, `dynportal-ssl`, `asterisk` (SIP 5060/5061, IAX 4569, 8088/8089), `rtp` (your RTP range), only where the distribution lacks them |
| `/etc/firewalld/zones/{public,external,agents,internal,drop}.xml` | the ViciBox zone layout with distribution-neutral service names, plus a separate `agents` zone for validated addresses; zone priorities on firewalld 0.9+ |
| `/etc/fail2ban/{jail.d,filter.d}/vicidial-dynportal.conf` | fail2ban jail for the portal (5 failures in 10 min, 1 h ban via firewalld rich rules) |
| root crontab | `@reboot` and `* * * * * /usr/bin/VB-firewall --white --dynamic --quiet` (the same lines the ViciBox manager writes) |
| ViciDial DB | `system_settings.allow_ip_lists=1`, `modify_ip_lists=1` for level-9 users, lists `ViciWhite`/`ViciBlack`, initial `ViciWhite` entries |
| `/srv/www/vhosts/dynportal/` | the official portal + security overlay + generated `inc/defaults.inc.php` |
| Apache | `dynportal-ssl.conf` vhost on port 446 (`sites-available` / `conf.d` / `vhosts.d`), a `Listen 446` line, SELinux port and file labels on RHEL |
| `/usr/local/sbin/vicidial-firewall`, `/etc/vicidial-firewall/` | helper and state |
| `/var/backups/vicidial-firewall/<timestamp>/` | `/etc/firewalld`, root crontab, `iptables-save`, touched Apache files |

Pre-existing `iptables` filter rules on a host where firewalld was not running are flushed after
firewalld takes over (they would otherwise keep blocking validated agents); `--keep-legacy-iptables`
leaves them alone. They are saved in the backup directory either way.

## Differences from stock ViciBox

Everything that is official is used as-is. What this project adds or changes, and why:

- **Portable zones and services.** ViciBox's zone files use openSUSE service names (`apache2`,
  `apache2-ssl`); the installer writes the same zones with `http`/`https` and ships `asterisk`/`rtp`
  service definitions for distributions that do not have them.
- **Portal also reachable from the `external` zone.** Upstream opens the portal in `public` only,
  so an already-validated or whitelisted agent gets "connection refused" when opening the portal
  again (a known forum issue). The portal is harmless to expose to known addresses.
- **Security fixes in the portal** (`src/dynportal-overlay/`, each file lists its changes): with
  hashed ViciDial passwords (`pass_hash_enabled=1`) the official `functions.inc.php` passes the
  submitted password unescaped to a shell command (`pwcheck.pl`), a pre-authentication command
  injection; the overlay uses `escapeshellarg()`. It also replaces the deprecated
  `FILTER_SANITIZE_STRING`, fixes a broken `UPDATE` statement, and URL-encodes/escapes the values
  placed in the post-login redirect.
- **Validated agents are not whitelisted hosts.** ViciBox puts the dynamic list into the same zone as
  the whitelist, so every validated agent also gets SSH. Here the dynamic list feeds its own `agents`
  zone with web, SIP/WebRTC and audio only; `--agent-ssh` restores the stock behaviour.
- **Brute-force protection on the portal**: failed attempts raise ViciDial's own `failed_login_count`
  (stock default off), every attempt is written to syslog, and a fail2ban jail bans the address.
- **Random form field names** are generated per installation instead of the published defaults.
- **No HSTS header** on the portal vhost: HSTS is per host name, and upstream's header would force
  HTTPS on the ViciDial site too, breaking plain-HTTP installations. The CSP allows the inline
  countdown script that upstream's own CSP blocked.
- **Defaults chosen for agents:** portal user level 1 (upstream 5, which rejects normal agents),
  redirect to the agent login enabled (upstream off).
- **Safety timer, carrier auto-whitelisting, SSH auto-whitelisting, backups, uninstall** are the
  installer's own.

## Known limitations

- `--add-rfc1918` puts whole private ranges into the *whitelist*, which (as the ViciBox author
  explains) routes LAN traffic through the `external` zone and breaks cluster MySQL/FTP. Prefer
  `--trusted-iface` / `--trusted-net` for LANs and `--internal-net` for cluster peers.
- VB-firewall handles IPv4 only; IPv6 traffic is simply left to the zone defaults (closed except RTP/portal).
- An address validated through the portal is allowed for all users of ViciDial from that address;
  that is the design of the official dynamic list. Behind a shared NAT (an office, a cafe) that means
  everyone behind it reaches the ViciDial login page, which still asks for credentials.
- Stolen agent credentials validate like the agent would. The portal lockout and fail2ban slow
  guessing down; they do not replace strong passwords and ViciDial's own two-factor options.
- With hashed passwords, `pwcheck.pl` receives the password as a command-line argument (official
  behaviour), briefly visible in the process list of the web server host.
- `firewall-cmd --reload` drops the runtime IP set entries until the next VB-firewall run (one minute),
  which is why the ViciBox docs warn against reloading on a busy telephony server.

## Repository layout and maintenance

```
install.sh              built single-file installer (bootstrap + embedded tar.gz)  ← what users run
build.sh                rebuilds install.sh from src/ and official/
fetch-official.sh       re-downloads official/ from the openSUSE Build Service, verifies md5s, rewrites SOURCES.md
src/installer.sh        the installer
src/vicidial-firewall   the management helper
src/firewalld/          asterisk service definition (zones are generated)
src/apache/             portal vhost templates
src/dynportal-overlay/  two portal files with the security fixes
official/               unmodified upstream files (VB-firewall.pl, IP sets, zones, portal, Apache configs)
tests/run-tests.sh      unit tests for the pure functions and the payload round trip
```

To pick up a new upstream release: `./fetch-official.sh`, review `git diff official/`, re-check the
overlay against the new `functions.inc.php` / `valid8.php`, run `tests/run-tests.sh`, then `./build.sh`.

## Credits and license

VB-firewall.pl, the Dynamic Portal and the firewalld layout are the work of James Pearson and
The ViciDial Group (ViciBox project), AGPL. This installer and its documentation are AGPL-3.0-or-later;
see [LICENSE](LICENSE). Not affiliated with the ViciDial Group.
