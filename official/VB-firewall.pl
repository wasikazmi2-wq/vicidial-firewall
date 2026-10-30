#!/usr/bin/perl
#
# VB-firewall.pl - version 1.00
#
# Copyright (C) 2018  James Pearson  <jamesp@vicidial.com>    LICENSE: AGPLv2
#
# Takes the IP lists defined in viciwhite, viciblack, and vicidynamic and inserts
# them into the appropriate IPSet tables for the firewall.
#
# Should run from the crontab as follows:
# * * * * * /usr/local/bin/VB-firewall.pl
#
# CHANGES
# 210421-1806 - Updated ipset-voipbl and ipset-geoip locations to include new RPM packaging paths
# 210318-1350 - Updated CLI argument sub so that it accepts characters down to 1 character long
# 191010-2037 - corrected wrong white list ipset defaults and an ipset create bug

# All my lovely little modules
use warnings;
use DBI;
use File::Basename;
use Sys::Syslog qw(:standard :macros);

# Globals
$DEBUG=0;
$DEBUGX=0;
$VERBOSE=0; # quiet by default; use --verbose or --debug for output
$TEST=0;
$LOADRFC=0; # Load RFC1918 IPs into whitelist and dynamic list by default
@RFC1918=('192.168.0.0/16','10.0.0.0/8','172.16.0.0/12','127.0.0.1'); # RFC1918 private ranges + loopback
$PATHCONF = "/etc/astguiclient.conf";
$DBUSER='cron';
$DBPASS='1234';
$DBPORT=3306;
$DBNAME='asterisk';
$DBHOST='localhost';
$FIREWALLD_BIN="/usr/bin/firewall-cmd";
$AGGREGATE=1; # By default, aggregate our networks into larger scopes where possible
$IPWHITE='whiteips'; # IPSet whitelist
$IPWHITENET='whitenets'; # IPSet whitelist for networks
$LISTWHITE='ViciWhite'; # Vici whitelist
$IPDYNAMIC='dynamiclist'; # Dynamic IPSet rule
$IPBLACK='blackips'; # IPSet blacklist IPs
$IPBLACKNET='blacknets'; # IPSet blacklist nets
$LISTBLACK='viciblack'; # Vici blacklist
$VOIPBL=0; # Whether to call the VoIP black list processor script
$VOIPBLURL="https://www.voipbl.org/update/";
$IPVOIPBL="voipblip"; # Where VoIPBL.org IPs are stored
$IPVOIPBLNET="voipblnet"; # Where VoIPBL.org nets are stored
$GEOBLOCK=0; # Whether to call the GeoBlock processor
$GEOBLOCKSCRIPT="/usr/share/vicibox-firewall/ipset-geoblock";
$WHITE=0; # Do not run white list by default
$DYNAMIC=0; # Do not run dynamic list by default
$BLACK=1; # Run black list by default
$DYNAMICAGE=14; # Number of days for dynamic IPs
$TMPDIR='/tmp/'; # Where to write temporary files

# You likely to not need to edit anything below this line!
my $clidbpass=0;
my $clidbuser=0;
my $clidbhost=0;
my $clidbport=0;
my $clidbname=0;
my $cliipwhite=0;
my $cliipdynamic=0;
my $cliipblackip=0;
my $cliipblacknet=0;
my $clilistwhite=0;
my $clidynamicage=0;
my $clilistblack=0;
my $cliipwhitenets=0;

# subs and functions
sub debugoutput {
	# I got tired of repeating this code snippet, so this gives debug output, with optional critical die
	my $debugline = '';
	my $debugdie = 0;
	if ( @_ && length($_[0])>3 ) { $debugline = shift; }
	if ( @_ && $_[0] == 1 ) { $debugdie = shift; }
	if ($DEBUG==1 and $debugdie==0) {
		# We are just giving output, nothing more
		print "$debugline\n";
		} elsif ($DEBUG==1 and $debugdie==1) {
			# Evidently it was a critical error, so we die on output
			die("$debugline\n");
	}
}

sub debugxoutput {
	# I got tired of repeating this code snippet, so this gives debugx output, with optional critical die
	my $debugline = '';
	my $debugdie = 0;
	if ( @_ && length($_[0])>3 ) { $debugline = shift; }
	if ( @_ && $_[0] == 1 ) { $debugdie = shift; }
	if ($DEBUGX==1 and $debugdie==0) {
		# We are just giving output, nothing more
		print "$debugline\n";
		} elsif ($DEBUGX==1 and $debugdie==1) {
			# Evidently it was a critical error, so we die on output
			die("$debugline\n");
	}
}

sub verboseoutput {
	# Print if verbose; always die on critical errors regardless of verbosity
	my $verboseline = '';
	my $verbosedie = 0;
	if ( @_ && length($_[0])>3 ) { $verboseline = shift; }
	if ( @_ && $_[0] == 1 ) { $verbosedie = shift; }
	if ( $verbosedie == 1 ) { die($verboseline . "\n"); }
	if ( $VERBOSE==1 ) { print $verboseline . "\n"; }
}

sub trim($) {
	# Perl trim function to remove whitespace from the start and end of the string, stolen from google cause i'm lazy
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

sub sanitizeipset {
	# Strip anything that isn't alphanumeric, hyphen, or underscore to prevent shell injection
	my $name = shift || '';
	$name =~ s/[^a-zA-Z0-9_-]//g;
	return $name;
}

sub ip_to_int {
	# Convert a dotted-quad IPv4 string to a 32-bit unsigned integer
	return unpack('N', pack('C4', split(/\./, $_[0])));
}

sub int_to_ip {
	# Convert a 32-bit unsigned integer back to a dotted-quad IPv4 string
	return join('.', unpack('C4', pack('N', $_[0])));
}

sub logsummary {
	# Write a one-line summary to the system journal (visible via journalctl -t VB-firewall).
	# Accepts the list's pretty name and the hashref returned by doipnetslist.
	my ($prettyname, $res) = @_;
	return unless ref($res) eq 'HASH';
	my $prefix = $TEST ? '[TEST] ' : '';
	my $msg;
	if ( $res->{ips_added} == 0 && $res->{ips_removed} == 0
	  && $res->{nets_added} == 0 && $res->{nets_removed} == 0 ) {
		$msg = "${prefix}${prettyname}: no changes";
	} else {
		my @parts;
		push @parts, "+$res->{ips_added} IPs"     if $res->{ips_added};
		push @parts, "-$res->{ips_removed} IPs"   if $res->{ips_removed};
		push @parts, "+$res->{nets_added} nets"   if $res->{nets_added};
		push @parts, "-$res->{nets_removed} nets" if $res->{nets_removed};
		$msg = "${prefix}${prettyname}: " . join(', ', @parts);
		$msg .= ' (errors)' unless $res->{ok};
	}
	openlog('VB-firewall', 'pid,nofatal', LOG_DAEMON);
	syslog(LOG_INFO, '%s', $msg);
	closelog();
	debugxoutput("   Journal: $msg");
}

sub getcliarg {
	debugxoutput("--- SUB getcliarg BEGIN ---");
	# Get a specific CLI argument
	my $ARGvalue='X';
	my $CLIarg='';
	if ( @_ ) {
		$CLIarg=shift;
		my $i=0;
		my $args='';
		while ($#ARGV >= $i) {
			$args = "$args $ARGV[$i]";
			$i++;
		}
		my @CLIargARY = split(/$CLIarg/,$args);
		my @CLIargARX = split(/ /,$CLIargARY[1]);
		if (length($CLIargARX[0])>=1) {
			$ARGvalue = $CLIargARX[0];
			$ARGvalue =~ s/\/$| |\r|\n|\t//gi;
		}
	} else {
		debugxoutput("   No CLI argument passed to find");
	}
	debugxoutput("--- SUB getcliarg END ---");
	return $ARGvalue;
}

sub checkipv4 {
	debugxoutput("--- SUB checkipv4 BEGIN ---");
	my $ipaddr = '';
	my $netmask = 32; # Default unless given a value later
	if ( @_ ) { $ipaddr = shift; };
	my $ipcheck=1; # Boolean true result
	# If we have a netmask, split it from the IP
	if ($ipaddr =~ /\//i) { ($ipaddr, $netmask) = split('\/', $ipaddr); }
	# Make sure we like the format
	if( length($ipaddr)>6 && $ipaddr =~ m/^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$/ && $ipaddr ne "0.0.0.0" && $ipaddr ne "255.255.255.255") {
		# Make sure we like the octets too
		if($1 <= 255 && $2 <= 255 && $3 <= 255 && $4 <= 255 ) {
			debugxoutput("   Valid IP: $ipaddr");
		} else {
			debugxoutput("   Invalid Octets: $ipaddr");
			$ipcheck = 0;
		}
	} else {
		debugxoutput("   Invalid Format: $ipaddr");
		$ipcheck = 0;
	}
	if ( $netmask >= 1 && $netmask <= 32 ) {
		debugxoutput("   Valid Netmask: $netmask");
	} else {
		debugxoutput("   Invalid Netmask: $netmask");
		$ipcheck=0;
	}
	debugxoutput("--- SUB checkipv4 END ---");
	return $ipcheck;
}

sub getiplist {
	debugxoutput("--- SUB getiplist BEGIN ---");
	my $iplistid='';
	my $netmasktype=0; # 0 = validate netmask, 1 = reject any netmasks
	my @iplist=(); # Initialize an empty array so we return something
	if ( @_ && length($_[0])>3 ) {
		$iplistid = shift;
		if ( @_ && $_[0] == 1 ) { $netmasktype = shift; }
		debugxoutput("   IP List ID: $iplistid");
		$stmtIPLIST = "select ip_address from vicidial_ip_list_entries where ip_list_id=?";
		$sthIPLIST = $dbhVD->prepare($stmtIPLIST) or verboseoutput("  Preparing stmtIPLIST: " . $dbhVD->errstr, 1);
		$sthIPLIST->execute($iplistid) or verboseoutput("  Executing sthIPLIST: " . $dbhVD->errstr, 1);
		if ($sthIPLIST->rows >= 1) {
			while (@IPLISTrow = $sthIPLIST-> fetchrow_array) {
				my $testip = trim($IPLISTrow[0]); # Trim whitespace cause users
				$testip =~ s/\.0*(\d+)/sprintf('.%d',$1)/ge; # strip leading zeros from octets (e.g. .024 -> .24)
				if ( checkipv4($testip) ) {
					if ($testip =~ /\//i ) {
						(my $tmpipaddr, my $netmask) = split('\/', $testip);
						$netmask = trim($netmask);
						$tmpipaddr = trim($tmpipaddr);
						# Figure out how to validate the netmask
						if ($netmask == 32) {
							# /32 is superfluous and specifies a single IP, so just remove netmask and continue on without validation
							push @iplist, $tmpipaddr;
							debugxoutput("    Added IP $tmpipaddr");
						} elsif ($netmasktype == 0 && $netmask >= 1 && $netmask < 32) {
							push @iplist, $testip;
							debugxoutput("    Added IP $testip");
						} elsif ($netmasktype == 1 )  {
							debugoutput("    Rejected Netmask $testip");
						}
					} else {
						push @iplist, $testip;
						debugxoutput("    Added IP $testip");
					}
				} else {
					debugoutput("    Bad IP $testip");
				}
			}
		}
	}
	debugxoutput("--- SUB getiplist END ---");
	return @iplist;
}

sub aggregateips {
	debugxoutput("--- SUB aggregateips START ---");
	my @iplist = ();
	if ( @_ && ref($_[0]) eq 'ARRAY' ) { @iplist = @{$_[0]}; }

	unless ( $AGGREGATE == 1 && scalar(@iplist) > 0 ) {
		debugxoutput("--- SUB aggregateips END ---");
		return @iplist;
	}

	# --- Step 1: parse each entry into [network_int, prefix_len] ---
	my @cidrs;
	for my $entry (@iplist) {
		my ($ip_str, $plen);
		if ($entry =~ m|^(.+)/(\d+)$|) {
			($ip_str, $plen) = ($1, int($2));
		} else {
			($ip_str, $plen) = ($entry, 32);
		}
		my $net = ip_to_int($ip_str);
		# Normalize: zero out host bits so e.g. 10.0.1.5/24 becomes 10.0.1.0
		if ($plen < 32) {
			my $block = 2 ** (32 - $plen);
			$net = int($net / $block) * $block;
		}
		push @cidrs, [$net, $plen];
	}

	# --- Step 2: sort by network address, then prefix length ascending (broader first) ---
	@cidrs = sort { $a->[0] <=> $b->[0] || $a->[1] <=> $b->[1] } @cidrs;

	# --- Step 3: remove duplicates and prefixes contained within a broader block ---
	my @filtered;
	my ($cover_net, $cover_plen) = (0, 33); # 33 = sentinel meaning no active cover
	for my $cidr (@cidrs) {
		my ($net, $plen) = @$cidr;
		if ($cover_plen <= 32) {
			my $cover_size = 2 ** (32 - $cover_plen);
			# Skip if this block's start address falls inside the current cover block
			next if $net >= $cover_net && $net < $cover_net + $cover_size && $plen >= $cover_plen;
		}
		push @filtered, $cidr;
		($cover_net, $cover_plen) = ($net, $plen);
	}
	@cidrs = @filtered;

	# --- Step 4: repeatedly merge adjacent same-length pairs into one shorter prefix ---
	# Two /N blocks merge into /(N-1) when they are adjacent and the first
	# sits on a /(N-1) boundary (i.e. its block index is even at that size).
	my $changed = 1;
	while ($changed) {
		$changed = 0;
		my @merged;
		my $i = 0;
		while ($i <= $#cidrs) {
			if ($i < $#cidrs) {
				my ($net1, $plen1) = @{$cidrs[$i]};
				my ($net2, $plen2) = @{$cidrs[$i + 1]};
				my $block = 2 ** (32 - $plen1);
				if ( $plen1 == $plen2 && $plen1 > 0
				  && $net2 == $net1 + $block
				  && int($net1 / $block) % 2 == 0 ) {
					push @merged, [$net1, $plen1 - 1];
					$i += 2;
					$changed = 1;
					next;
				}
			}
			push @merged, $cidrs[$i++];
		}
		@cidrs = @merged;
	}

	# --- Step 5: convert back to strings; /32 becomes a plain IP ---
	my @aggresult;
	for my $cidr (@cidrs) {
		my ($net, $plen) = @$cidr;
		push @aggresult, $plen == 32 ? int_to_ip($net) : int_to_ip($net) . "/$plen";
	}

	verboseoutput("   Aggregated " . scalar(@iplist) . " IPs into " . scalar(@aggresult) . " entries (IPs + subnets)");
	debugxoutput("--- SUB aggregateips END ---");
	return @aggresult;
}

sub getfirewallipset {
	debugxoutput("--- SUB getfirewallipset START ---");
	my @theresults=();
	if ( @_ && length($_[0])>=1 ) {
		my $ipset=shift;
		debugxoutput("   IPSet: $ipset");
		my @rawresults = `$FIREWALLD_BIN --ipset=$ipset --get-entries`;
		debugxoutput("   Found " . @rawresults . " raw results");
		foreach (@rawresults) {
			my $result=trim($_);
			if ( checkipv4($result) ) { push @theresults, $result; }
		}
	}
	debugxoutput("   Found " . @theresults . " entries");
	debugxoutput("--- SUB getfirewallipset END ---");
	return @theresults;
}

sub array2hash {
	debugxoutput("--- SUB array2hash START ---");
	# This just creates a search hash, nothing else
	my %theresults;
	if ( @_ && ref($_[0]) eq 'ARRAY' ) {
		my @inputarray=@{$_[0]};
		foreach(@inputarray) {
			debugxoutput("   Adding $_ to hash");
			$theresults{$_} = 1;
		}
	}
	debugxoutput("--- SUB array2hash END ---");
	return %theresults;
}

sub addremipset {
	# Call like addremipset(\@iparray,$ipset,'<add/remove>')
	debugxoutput("--- SUB addremipset START ---");
	my $ipset='X';
	my $function='X';
	my @list;
	my $dothedeed=0;
	my $returnval=0;

	# Check for proper input cause reasons
	if ( @_ >= 1 && ref($_[0]) eq 'ARRAY' ) { @list=@{$_[0]}; $dothedeed=1; }
	if ( @_ >= 2 && length($_[1]) >= 1 ) { $ipset=$_[1]; $dothedeed=1; }
	if ( @_ >= 3 ) {
		my $tmpfunc=$_[2];
		if ( $tmpfunc eq 'add' || $tmpfunc eq 'remove' ) { $function=$tmpfunc; $dothedeed=1; }
	}

	if ($dothedeed==1) {
		# write out the file
		open (my $OUTPUTFILE, ">", "$TMPDIR/$ipset-$function-tmp") or verboseoutput("    Could not write to $TMPDIR/$ipset-$function-tmp! You got serious problems",1);
		debugxoutput("   Writing $ipset $function to file $TMPDIR/$ipset-$function-tmp");
		foreach (@list) { print $OUTPUTFILE "$_\n"; }
		close ($OUTPUTFILE);
		debugxoutput("   Loading $TMPDIR/$ipset-$function-tmp into firewall");
		if ($TEST == 0) {
			system("$FIREWALLD_BIN --ipset=$ipset --$function-entries-from-file=$TMPDIR/$ipset-$function-tmp > /dev/null 2>&1");
			if ($? != 0) { verboseoutput("\n   Error running $ipset $function entries from $TMPDIR/$ipset-$function-tmp!",1); } else { debugxoutput("      $TMPDIR/$ipset-$function-tmp loaded successfully loaded."); $returnval=1;}
		} else {
			verboseoutput("    Test run enabled, not doing actual firewall changes.");
			$returnval=1;
		}
	}

	debugxoutput("--- SUB addremipset END ---");
	return $returnval;
}

sub doipnetslist {
	debugxoutput("--- SUB doipnetslist START ---");
	# Always require an array of IPs/Networks, IP ipset, option network ipset or X for nothing, and then a pretty name for feedback.
	my @listraw=@{$_[0]};
	my $ips=$_[1];
	my $nets=$_[2];
	my $prettyname=$_[3];
	my $returnval=1;

	# Declare change counters here so they are in scope for the return hashref
	my @ipstoadd    = ();
	my @ipstoremove = ();
	my @netstoadd   = ();
	my @netstoremove= ();

	my $sanitycheck=1; # By default, we're sane
	# Check that our ipsets exists
	if ( $ips ne 'X') {
		system("$FIREWALLD_BIN --info-ipset=$ips > /dev/null  2>&1");
		if ($? != 0 ) { $sanitycheck=0; verboseoutput("  IPSet $ips not found! Skipping...",1); }
	}
	if ( $nets ne 'X') {
		system("$FIREWALLD_BIN --info-ipset=$nets > /dev/null  2>&1");
		if ($? != 0 ) { $sanitycheck=0; verboseoutput("  IPSet $nets not found! Skipping...",1); }
	}

	# If we passed our sanity check, do the thing
	if ($sanitycheck == 1) {
		# Sort raw list into single IPs and Networks
		my @listips;
		my @listnets;
		foreach (@listraw) {
			debugxoutput("      Sorting entry $_");
			if ($_ =~ /\//i) {
				push @listnets, $_;
			} else {
				push @listips, $_;
			}
		}
		my %listnets;
		my %listips = array2hash(\@listips);
		verboseoutput("    Found " . @listips . " IPs for $prettyname");
		if ($DEBUG==1) { foreach (@listips) { print("      $_ \n"); } }
		if ($nets ne 'X') {
			%listnets = array2hash(\@listnets);
			verboseoutput("    Found " . @listnets . " networks for $prettyname");
			if ($DEBUG==1) { foreach (@listnets) { print("       $_ \n"); } }
		}

		verboseoutput("   Getting firewall $prettyname entries...");
		my @firewallip = getfirewallipset($ips);
		my %firewallip = array2hash(\@firewallip);
		verboseoutput("    Total " . @firewallip . " IPs in firewall");
		if ($DEBUG==1) { foreach (@firewallip) { print("      IP $_ \n"); } }
		my @firewallnet;
		my %firewallnet;
		if ($nets ne 'X') {
			@firewallnet = getfirewallipset($nets);
			%firewallnet = array2hash(\@firewallnet);
			verboseoutput("    Total " . @firewallnet . " networks in firewall");
			if ($DEBUG==1) { foreach (@firewallnet) { print("      IP $_ \n"); } }
		}

		verboseoutput("   Comparing $prettyname to find changes...");
		my $letsmakechanges=0; # trigger for later
		# Find IPs to add
		foreach (@listips) {
			if( ! exists($firewallip{$_}) ) { push @ipstoadd, $_; $letsmakechanges=1; }
		}
		verboseoutput("    " . @ipstoadd . " IPs to add to firewall");
		if ($DEBUG==1) { foreach (@ipstoadd) { print("      $_ \n"); } }
		if ($nets ne 'X') {
			foreach (@listnets) {
				if( ! exists($firewallnet{$_}) ) { push @netstoadd, $_; $letsmakechanges=1; }
			}
			verboseoutput("    " . @netstoadd . " networks to add to firewall");
			if ($DEBUG==1) { foreach (@netstoadd) { print("      $_ \n"); } }
		}

		# Find IPs to remove
		foreach (@firewallip) {
			if( ! exists($listips{$_}) ) { push @ipstoremove, $_; $letsmakechanges=1; }
		}
		verboseoutput("    " . @ipstoremove . " IPs to remove from firewall");
		if ($DEBUG==1) { foreach (@ipstoremove) { print("      $_ \n"); } }
		if ($nets ne 'X') {
			foreach (@firewallnet) {
				if( ! exists($listnets{$_}) ) { push @netstoremove, $_; $letsmakechanges=1; }
			}
			verboseoutput("    " . @netstoremove . " networks to remove from firewall");
			if ($DEBUG==1) { foreach (@netstoremove) { print("      $_ \n"); } }
		}

		# Finally make changes
		if ( $letsmakechanges==1 ) {
			verboseoutput("\n   Synchronizing firewall changes (remove then add)");
			if ( @ipstoremove > 0 ) {
				verboseoutput("    Removing IPs from firewall...");
				if ( addremipset(\@ipstoremove,$ips,'remove') == 1) {debugoutput("      IPs successfully removed"); } else { verboseoutput("    IPs not removed from $prettyname!? That's weird."); $returnval=0; }
			}
			if ( $nets ne 'X') {
				if ( @netstoremove > 0 ) {
					verboseoutput("    Removing networks from firewall...");
					if ( addremipset(\@netstoremove,$nets,'remove') == 1) {debugoutput("      Networks successfully removed"); } else { verboseoutput("    Networks not removed from $prettyname!? That's weird."); $returnval=0; }
				}
			}
			if ( @ipstoadd > 0 ) {
				verboseoutput("    Adding IPs to firewall...");
				if ( addremipset(\@ipstoadd,$ips,'add') == 1) {debugoutput("      IPs successfully Added"); } else { verboseoutput("    IPs not added to $prettyname!? That's weird."); $returnval=0; }
			}
			if ($nets ne 'X') {
				if ( @netstoadd > 0 ) {
					verboseoutput("    Adding networks to firewall...");
					if ( addremipset(\@netstoadd,$nets,'add') == 1) {debugoutput("      networks successfully Added"); } else { verboseoutput("    networks not added to $prettyname!? That's weird."); $returnval=0; }
				}
			}
		}
	}
	debugxoutput("--- SUB doipnetslist END ---");
	return {
		ips_added    => scalar(@ipstoadd),
		ips_removed  => scalar(@ipstoremove),
		nets_added   => scalar(@netstoadd),
		nets_removed => scalar(@netstoremove),
		ok           => $returnval,
	};
}

### begin parsing run-time options ###
if ( defined $ARGV[0] && length($ARGV[0])>1 ) {
	my $i=0;
	my $args='';
	while ($#ARGV >= $i) {
		$args = "$args $ARGV[$i]";
		$i++;
	}

	if ($args =~ /--help/i) {
		print "\n---- ViciBox Firewall integration ----\n\n";
		print "allowed run time options:\n";
		print "  [--noblack] Do not process the Black List, On by default\n";
		print "  [--white] Process the white list\n";
		print "  [--dynamic] Process the dynamic list\n";
		print "  [--voipbl] Download and Process the voipbl.org Black List\n";
		print "  [--whitelist=$LISTWHITE] ViciDial IP List for white list\n";
		print "  [--whiteips=$IPWHITE] IPSet name for white list IPs\n";
		print "  [--whitenets=$IPWHITENET] IPSet name for white list networks\n";
		print "  [--dynamicips=$IPDYNAMIC] IPSet name for dynamic list\n";
		print "  [--dynamicage=$DYNAMICAGE] How long in days to look for valid agent logins\n";
		print "  [--blacklist=$LISTBLACK] ViciDial IP List for black list\n";
		print "  [--blackips=$IPBLACK] IPSet name for black list IPs\n";
		print "  [--blacknets=$IPBLACKNET] IPSet name for black list networks\n";
		print "  [--verbose] Enable verbose output (quiet is the default for crontab use)\n";
		print "  [--quiet] Quiet output, now the default (kept for backwards compatibility)\n";
		print "  [--addrfc1918] Add RFC1918 private IP ranges and loopback to the whitelist\n";
		print "  [--test] Test run, show what would change without applying it (implies --verbose)\n\n";
		print "  * The white/dynamic options disable the black/geo/voipbl options. If you are\n";
		print "    only allowing certain IP's to connect in then it doesn't make sense to block\n";
		print "    anything since everything is blocked by default.\n";
		exit;
	} else {
		# Check for debug extended flag
		if ($args =~ /--debugX/i) {
			$DEBUG=1;
			$DEBUGX=1;
			$VERBOSE=1;
			print "---- ViciBox Firewall integration -----\n";
			print "\n        ----- DEBUG Extended Enabled -----\n\n";
		}

		# Check for debug flag
		if ($DEBUG == 0 && $args =~ /--debug/i) {
			$DEBUG=1;
			$VERBOSE=1;
			print "---- ViciBox Firewall integration ----\n";
			print "\n        ----- DEBUG Enabled -----\n\n";
		}

		# Run a test run without commits; implies verbose so you can see what would change
		if ($args =~ /--test/i) {
			$TEST=1;
			$VERBOSE=1;
			print "\n        ----- Test Run Enabled -----\n\n";
		}

		# See if we are processing the VoIP Black List
		if ($args =~ /--voipbl/i) {
			$VOIPBL=1;
		}

		# See if we are processing the GeoBlock list
		if ($args =~ /--geoblock/i) {
			$GEOBLOCK=1;
		}

		# Enable verbose output (overrides quiet default; no-op if --debug is active)
		if ($args =~ /--verbose/i && $DEBUG==0) {
			$VERBOSE=1;
		}

		# --quiet is now the default; kept for backwards compatibility
		if ($args =~ /--quiet/i && $DEBUG==0 ) {
			$VERBOSE=0;
		}

		# Do not load RFC1918 lists into whitelist
		if ($args =~ /--addrfc1918/i) {
			$LOADRFC=1;
		}

		# Run white list processing
		if ($args =~ /--white/i) {
			$WHITE=1;
			$BLACK=0; # No point in having a black list since we only allow IPs on the whitelist in this mode
			$VOIPBL=0;
			$GEOBLOCK=0;
		}

		# Do not run black list processing
		if ($WHITE==0 && $args =~ /--noblack/i) {
			$BLACK=0;
		}

		# Run dynamic list processing
		if ($args =~ /--dynamic/i) {
			$DYNAMIC=1;
			$BLACK=0; # No point in having a black list since we only allow IPs on the dynamic list
			$VOIPBL=0;
			$GEOBLOCK=0;
		}

		# DB Host
		if ($args =~ /--dbhost=/i) {
			my $ARGVALtemp = getcliarg('--dbhost=');
			if ($ARGVALtemp ne 'X') {
				$DBHOST = $ARGVALtemp;
				$clidbhost=1;
			}
		}

		# DB user
		if ($args =~ /--dbuser=/i) {
			my $ARGVALtemp = getcliarg('--dbuser=');
			if ($ARGVALtemp ne 'X') {
				$DBUSER = $ARGVALtemp;
				$clidbuser=1;
			}
		}

		# DB Pass
		if ($args =~ /--dbpass=/i) {
			my $ARGVALtemp = getcliarg('--dbpass=');
			if ($ARGVALtemp ne 'X') {
				$DBPASS = $ARGVALtemp;
				$clidbpass=1;
			}
		}

		# DB port
		if ($args =~ /--dbport=/i) {
			my $ARGVALtemp = getcliarg('--dbport=');
			if ($ARGVALtemp ne 'X') {
				$DBPORT = $ARGVALtemp;
				$clidbport=1;
			}
		}

		# DB name
		if ($args =~ /--dbname=/i) {
			my $ARGVALtemp = getcliarg('--dbname=');
			if ($ARGVALtemp ne 'X') {
				$DBNAME = $ARGVALtemp;
				$clidbname=1;
			}
		}

		# Vici White list
		if ($args =~ /--whitelist=/i) {
			my $ARGVALtemp = getcliarg('--whitelist=');
			if ($ARGVALtemp ne 'X') {
				$LISTWHITE = $ARGVALtemp;
				$clilistwhite=1;
			}
		}

		# Vici Dynamic list
		if ($args =~ /--dynamicage=/i) {
			my $ARGVALtemp = getcliarg('--dynamicage=');
			if ($ARGVALtemp ne 'X') {
				$DYNAMICAGE = $ARGVALtemp;
				$clidynamicage=1;
			}
		}

		# Vici Black list
		if ($args =~ /--blacklist=/i) {
			my $ARGVALtemp = getcliarg('--blacklist=');
			if ($ARGVALtemp ne 'X') {
				$LISTBLACK = $ARGVALtemp;
				$clilistblack=1;
			}
		}

		# IPSet White List IPs
		if ($args =~ /--whiteips=/i) {
			my $ARGVALtemp = getcliarg('--whiteips=');
			if ($ARGVALtemp ne 'X') {
				$IPWHITE = sanitizeipset($ARGVALtemp);
				$cliipwhite=1;
			}
		}

		# IPSet White List Networks
		if ($args =~ /--whitenets=/i) {
			my $ARGVALtemp = getcliarg('--whitenets=');
			if ($ARGVALtemp ne 'X') {
				$IPWHITENET = sanitizeipset($ARGVALtemp);
				$cliipwhitenets=1;
			}
		}

		# IPSet Dynamic list
		if ($args =~ /--dynamicips=/i) {
			my $ARGVALtemp = getcliarg('--dynamicips=');
			if ($ARGVALtemp ne 'X') {
				$IPDYNAMIC = sanitizeipset($ARGVALtemp);
				$cliipdynamic=1;
			}
		}

		# IPSet Black IPs list
		if ($args =~ /--blackips=/i) {
			my $ARGVALtemp = getcliarg('--blackips=');
			if ($ARGVALtemp ne 'X') {
				$IPBLACK = sanitizeipset($ARGVALtemp);
				$cliipblackip=1;
			}
		}

		# IPSet Black Networks list
		if ($args =~ /--blacknets=/i) {
			my $ARGVALtemp = getcliarg('--blacknets=');
			if ($ARGVALtemp ne 'X') {
				$IPBLACKNET = sanitizeipset($ARGVALtemp);
				$cliipblacknet=1;
			}
		}
	}
}

# Parse the config file if it's present, command line args get precedence
if ( -e $PATHCONF ) {
	open(my $CONFIG, "<", $PATHCONF);
	my @config = <$CONFIG>;
	close($CONFIG);
	$i=0;
	foreach(@config)
		{
		my $line = $config[$i];
		$line =~ s/ |>|\n|\r|\t|\#.*|;.*//gi;
		if ( ($line =~ /^VARDB_server/) && ($clidbhost < 1) )
			{$DBHOST = $line;   $DBHOST =~ s/.*=//gi;}
		if ( ($line =~ /^VARDB_user/) && ($clidbuser < 1) )
			{$DBUSER = $line;   $DBUSER =~ s/.*=//gi;}
		if ( ($line =~ /^VARDB_pass/) && ($clidbpass < 1) )
			{$DBPASS = $line;   $DBPASS =~ s/.*=//gi;}
		if ( ($line =~ /^VARDB_port/) && ($clidbport < 1) )
			{$DBPORT = $line;   $DBPORT =~ s/.*=//gi;}
		if ( ($line =~ /^VARDB_database/) && ($clidbname < 1) )
			{$DBNAME = $line;   $DBNAME =~ s/.*=//gi;}
		$i++;
	}
}

# Some verbose output if not in debug mode
if ( $DEBUG == 0 && $VERBOSE == 1 ) { print "---- ViciBox Firewall integration ----\n"; }

# Give summary output
if ( $DEBUG == 1 ) {
	print "\n\n";
	if ($clidbhost == 0) { print "         Database Host :   $DBHOST\n"; } else { print "     CLI Database Host :   $DBHOST\n"; }
	if ($clidbname == 0) { print "         Database Name :   $DBNAME\n"; } else { print "     CLI Database Name :   $DBNAME\n"; }
	if ($clidbuser == 0) { print "         Database User :   $DBUSER\n"; } else { print "     CLI Database User :   $DBUSER\n"; }
	if ($clidbpass == 0) { print "         Database Pass :   $DBPASS\n"; } else { print "     CLI Database Pass :   $DBPASS\n"; }
	if ($clidbport == 0) { print "         Database Port :   $DBPORT\n"; } else { print "     CLI Database Port :   $DBPORT\n"; }
	if ($WHITE == 1) {
		print "            White list :   Enabled\n";
		if ($clilistwhite == 0) { print "       Vici White List :   $LISTWHITE\n"; } else { print "        CLI White List :   $LISTWHITE\n"; }
		if ($cliipwhite == 0) { print "  IPSet White List IPs :   $IPWHITE\n"; } else { print "CLI IPSet White List IP:   $IPWHITE\n"; }
		if ($cliipwhitenets == 0) { print " IPSet White List Nets :   $IPWHITENET\n"; } else { print "CLI IPSet White List Net:   $IPWHITENET\n"; }
		if ($LOADRFC == 1) { print "    RFC1918 White List :   YES\n"; } else { print "    RFC1918 White List :   NO\n"; }
	} else {
		print "            White list :   Disabled\n";
	}
	if ($DYNAMIC == 1) {
		print "          Dynamic list :   Enabled\n";
		if ($clidynamicage == 0) { print "     IPSet Dynamic Age :   $DYNAMICAGE\n"; } else { print " CLI IPSet Dynamic Age :   $DYNAMICAGE\n"; }
		if ($cliipdynamic == 0) { print "    IPSet Dynamic List :   $IPDYNAMIC\n"; } else { print "CLI IPSet Dynamic List :   $IPDYNAMIC\n"; }
	} else {
		print "          Dynamic list :   Disabled\n";
	}
	if ($BLACK == 1) {
		print "            Black list :   Enabled\n";
		if ($clilistblack == 0) { print "       Vici Black List :   $LISTBLACK\n"; } else { print "   CLI Vici Black List :   $LISTBLACK\n"; }
		if ($cliipblackip == 0) { print "       IPSet Black IPs :   $IPBLACK\n"; } else { print "   CLI IPSet Black IPs :   $IPBLACK\n"; }
		if ($cliipblacknet == 0) { print "      IPSet Black Nets :   $IPBLACKNET\n"; } else { print "  CLI IPSet Black nets :   $IPBLACKNET\n"; }
	} else {
		print "            Black list :   Disabled\n";
	}
	if ($VOIPBL == 1) {
		print "       VoIP Black List :   Enabled\n";
	} else {
		print "       VoIP Black List :   Disabled\n";
	}
	if ($GEOBLOCK == 1) {
		print "        Geo Block list :   Enabled\n";
		print " Geo Block List script :   $GEOBLOCKSCRIPT\n";
	} else {
		print "        Geo Block list :   Disabled\n";
	}
	print "\n\n";
}

### concurrency checking so we don't loop ourselves
$RUNNING_FILE=basename($0);
debugxoutput("  Running Agent Script :      $RUNNING_FILE",0);
my $grepout = `/bin/ps ax | grep $RUNNING_FILE | grep -v grep | grep -v /bin/sh`;
my $grepnum=0;
$grepnum++ while ($grepout =~ m/\n/g);
if ($grepnum > 1) { verboseoutput("I am not alone! Another $0 is running! Exiting...",1); }

# Sanity checks and connect to database

if ( ! -x $FIREWALLD_BIN ) { verboseoutput("  Could not find executable $FIREWALLD_BIN! Exiting...",1); }

$dbhVD = DBI->connect("DBI:mysql:$DBNAME:$DBHOST:$DBPORT", "$DBUSER", "$DBPASS") or verboseoutput("  Couldn't connect to database: " . DBI->errstr,1);

# Process white list
if ( $WHITE == 1) {
	verboseoutput("  Processing WhiteList...");
	my @whitelist = getiplist($LISTWHITE);
	if (@whitelist > 0 || ($LOADRFC==1 && @RFC1918>0)) {
		verboseoutput("   WhiteList found " . @whitelist . " entries in ViciDial");
		if ($LOADRFC==1) {
			verboseoutput("   Adding RFC1918 IP space to WhiteList");
			foreach (@RFC1918) { push @whitelist, $_; }
		}
		if ( $AGGREGATE == 1 ) {
			verboseoutput("   Aggregating WhiteList IPs into subnets...");
			@whitelist = aggregateips(\@whitelist);
		}
		logsummary("WhiteList", doipnetslist(\@whitelist, $IPWHITE, $IPWHITENET, "WhiteList"));
	} else { verboseoutput("   No WhiteList entries found in ViciDial"); }
	verboseoutput("  WhiteList done!");
}

# Process blacklist
if ($BLACK == 1) {
	verboseoutput("  Processing BlackList...");
	my @blacklist = getiplist($LISTBLACK);
	if (@blacklist > 0 ) {
		verboseoutput("   BlackList found " . @blacklist . " entries in ViciDial");
		logsummary("BlackList", doipnetslist(\@blacklist, $IPBLACK, $IPBLACKNET, "BlackList"));
	} else { verboseoutput("   No BlackList entries found in ViciDial"); }
	verboseoutput("  BlackList done!");
}

if ( $DYNAMIC == 1) {
	verboseoutput("  Processing DynamicList...");

	my $stmtLOGINIP = "SELECT computer_ip FROM vicidial_user_log WHERE event IN ('LOGIN', 'VICIBOX') and event_date >= DATE_SUB(NOW(), INTERVAL $DYNAMICAGE DAY) group by computer_ip;";
	my $sthLOGINIP = $dbhVD->prepare($stmtLOGINIP) or verboseoutput("  Preparing stmtLOGINIP: " . $dbhVD->errstr, 1);
	$sthLOGINIP->execute or verboseoutput("  Executing sthLOGINIP: " . $dbhVD->errstr, 1);
	my @dynamicips=();
	if ($sthLOGINIP->rows >= 1) {
		while (my @LOGINIProw = $sthLOGINIP-> fetchrow_array) {
			my $tmpip = trim($LOGINIProw[0]);
			$tmpip =~ s/\.0*(\d+)/sprintf('.%d',$1)/ge; # strip leading zeros from octets
			if (checkipv4($tmpip)) {
				push @dynamicips, $tmpip;
			}
		}
	}

	if (@dynamicips > 0 ) {
		verboseoutput("   DynamicList found " . @dynamicips . " entries in ViciDial");
		logsummary("DynamicList", doipnetslist(\@dynamicips, $IPDYNAMIC, "X", "DynamicList"));
	} else { verboseoutput("   No DynamicList entries found in ViciDial"); }
	verboseoutput("  DynamicList done!");
}

if ($VOIPBL == 1) {
	verboseoutput("  Processing VoIPBL.org Black List...");
	verboseoutput("   Downloding from $VOIPBLURL");

	### Their SSL certificate is broken, so we have to do a work-around cause reasons :/
	#my $voipblraw=get($VOIPBLURL);
	#my $voipblraw=`/usr/bin/wget -q -O - stdout --no-check-certificate $VOIPBLURL`;
	my $voipblraw=`/usr/bin/curl -ks $VOIPBLURL`; # Less noise, plus CURL

	die "   Couldn't download VoIPBL.org blacklist from $VOIPBLURL" unless defined $voipblraw;
	# Scrub the VoIPBl list cause it's filthy user submitted data
	my @voipbllistraw=split('\n', $voipblraw);
	my @voipbllist;
	foreach (@voipbllistraw) {
		my $rawip = trim($_);
		if (checkipv4($rawip)) {
			if ($rawip =~ /\//i) {
				my ($ipaddr, $netmask) = split('\/', $rawip);
				if ($netmask=="32") { push @voipbllist, $ipaddr; } else {push @voipbllist, $rawip;}
			} else {push @voipbllist, $rawip;}
		}
	}
	if (@voipbllist > 0 ) {
		verboseoutput("   VoIPBL.org found " . @voipbllist . " entries");
		logsummary("VoIPBL", doipnetslist(\@voipbllist, $IPVOIPBL, $IPVOIPBLNET, "VoIPBL.org"));
	} else { verboseoutput("   No VoIPBL.org entries found in download"); }
	verboseoutput("  VoIPBL.org done!");
}

if ($GEOBLOCK == 1) {
	debugoutput("  Launching $GEOBLOCKSCRIPT...");
	if ($VERBOSE == 1 ) { system("$GEOBLOCKSCRIPT"); } else { system("$GEOBLOCKSCRIPT >/dev/null 2>&1"); }
}

$dbhVD->disconnect if $dbhVD;
