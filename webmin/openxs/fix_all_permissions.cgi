#!/usr/bin/perl
# fix_all_permissions.cgi
# Bulk-fixes every currently-unresolved "world-writable directory"
# finding in one click - requested live (2026-10-26) after fixing
# 21,121 of these by hand via SSH on a production account, right after
# doing the exact same thing for 2,629 on a different server days
# earlier. The existing per-row "Fix permissions" button (findings.cgi)
# was never going to be realistic at this scale.

require './openxs-lib.pl';
&ReadParse();

my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db
fixed, total = openxs_db.fix_all_world_writable_findings()
print(f'{fixed}/{total}')
"`;
chomp($out);

&openxs_result_page("Fix all permission findings: $out fixed.", 0, "Back to findings", "findings.cgi?cat=fs");
