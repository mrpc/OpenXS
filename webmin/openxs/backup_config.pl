#!/usr/bin/perl
# backup_config.pl
# Hooks for Webmin's "Backup Configuration Files" module (backup-config):
# makes OpenXS show up in its module list, so a Webmin config backup
# carries OpenXS's settings too. Settings only - scan state under
# /var/lib/openxs (findings DB, quarantine, stats) is data, not config,
# and /etc/postfix/sasl_blocked is live block state, not a setting.

do 'openxs-lib.pl';

# Everything under /etc/openxs (openxs.conf, ignore, rules, path_settings,
# fim_paths, modsec_*, ...) plus the cron files OpenXS writes from its own
# Settings page (scheduled scan, collector, self-update).
sub backup_config_files
{
my @rv = grep { -f $_ } glob('/etc/openxs/*');
push(@rv, grep { -f $_ } glob('/etc/cron.d/openxs-*'));
return @rv;
}

sub pre_backup { return undef; }
sub post_backup { return undef; }
sub pre_restore { return undef; }

# The restored files are only source lists: the modsec ones are compiled
# into Apache config by their own generators, and the daemons read theirs
# at startup. Regenerate + reload Apache (only if the config still tests
# clean) and restart whichever daemons were already running.
sub post_restore
{
foreach my $script ('openxs_modsec_mode.py', 'openxs_modsec_exclusions.py',
		    'openxs_modsec_rule_exclusions.py') {
	system("python3 $pmf_dir/$script >/dev/null 2>&1") if (-e "$pmf_dir/$script");
	}
if (&openxs_modsecurity_installed()) {
	system("apache2ctl -t >/dev/null 2>&1 && (systemctl reload apache2 >/dev/null 2>&1 || service apache2 reload >/dev/null 2>&1)");
	}
system("systemctl try-restart openxs-scand openxs-watchd >/dev/null 2>&1");
return undef;
}

1;
