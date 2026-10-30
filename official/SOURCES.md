# Provenance of official/

Fetched 2026-10-23 from the ViciBox packages on the openSUSE Build Service, project
home:vicidial:vicibox (https://build.opensuse.org/project/show/home:vicidial:vicibox), maintained by
James Pearson (ViciDial Group). Every file was verified against the md5 published in the OBS source
listing (https://api.opensuse.org/public/source/home:vicidial:vicibox/PACKAGE).
Re-fetch with `./fetch-official.sh`.

| package | rev | file | md5 |
|---|---|---|---|
| vicibox-firewall | 36 | VB-firewall.pl (mtime 2026-06-25) | 4f3e076408ff34461e84e2d47465b9d2 |
| vicibox-firewall | 36 | vicibox-firewall-1.3.tar.xz | 63a5bfe931996738ebec9fa47ff4b351 |
| vicibox-dynportal | 41 | vicibox-dynportal-1.3.tar.xz | f1a786f4f2b5648f3c7b16909c143bd8 |
| vicibox-dynportal | 41 | dynportal.conf | 69e3b4462d134cc651d88eb0e1e4f60d |
| vicibox-dynportal | 41 | dynportal-ssl.conf | 1b3537966fa841f4021c1918afb5052e |
| vicibox-dynportal | 41 | dynportal.xml | 9e56215e42e3436d46cc04e67945e43c |
| vicibox-dynportal | 41 | dynportal-ssl.xml | 8779daea07d6c9ff7bc0e4d16eaf511a |
| vicibox-dynportal | 41 | mod_cband.conf | 79f881e8070c962c4cf2fba1d0cfd9e1 |
| vicibox-dynportal | 41 | mod_cband.portal | 15a438e8750d5bc84429dfdc98320ea0 |

Layout:

- `VB-firewall.pl` - the firewall script (version string inside still says 1.00; the package is 1.3.2).
  Installed by the RPM as `/usr/share/vicibox-firewall/VB-firewall.pl` with the symlink `/usr/bin/VB-firewall`.
- `firewalld/ipsets/*.xml`, `firewalld/zones/*.xml` - from `vicibox-firewall-1.3.tar.xz`
  (the RPM installs them under `/etc/firewalld/`). The zones use openSUSE service names
  (`apache2`, `apache2-ssl`); the installer ships distribution-neutral equivalents in `src/`.
- `firewalld/services/dynportal*.xml`, `apache/*.conf`, `apache/mod_cband.*` - vicibox-dynportal package files.
- `apache/install-dynportal.sh.legacy` - the 2018 ViciBox 8.1 add-on installer from
  http://download.vicidial.com/vicibox/ (SuSEfirewall2 era), kept for reference only.
- `dynportal/` - the Dynamic Portal 1.3 (`valid8.php`, `inc/`, `css/`, `images/`) from `vicibox-dynportal-1.3.tar.xz`.

Nothing in `official/` is modified. The installer's own changes live in `src/`
(see README, "Differences from stock ViciBox").

Other official references used while building the installer:

- ViciBox 13 documentation, firewall section: https://docs.vicibox.com/en/latest/networking/firewall.html
  (white list, dynamic portal, zones, black list, VoIPBL pages)
- ViciBox manager source (`vicibox-manager-1.3.tar.xz`, `tasks/firewall.py`, `tasks/dynportal.py`) for the
  exact cron lines and firewalld service handling
- ViciDial trunk schema (`extras/MySQL_AST_CREATE_tables.sql`, 2025-10-17 snapshot) for
  `vicidial_ip_lists`, `vicidial_ip_list_entries`, `vicidial_user_log`, `system_settings.allow_ip_lists`
