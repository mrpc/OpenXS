#!/usr/bin/perl
# bulk_action.cgi
# Quarantine/restore/delete many findings at once from findings.cgi's
# checkboxes - cxs's own "Bulk Actions" menu item, which this module had
# no equivalent for before (only ever one finding at a time).

require './openxs-lib.pl';
&ReadParse();

my @ids = $in{'id'} eq '' ? () : split(/\0/, $in{'id'});
@ids = grep { /^\d+$/ } @ids;

my $action = defined($in{'bulk_quarantine'}) ? "quarantine"
           : defined($in{'bulk_restore'})    ? "restore"
           : defined($in{'bulk_delete'})     ? "delete"
           : "";

if (!@ids) {
	&openxs_result_page("No findings selected.", 1, "Back to findings", "findings.cgi");
	}
if ($action !~ /^(quarantine|restore|delete)$/) {
	&openxs_result_page("Invalid request.", 1, "Back to findings", "findings.cgi");
	}

my $ids_csv = join(",", @ids);
my $out = `python3 -c "
import sys
sys.path.insert(0, '$pmf_dir')
import openxs_db
ids = [$ids_csv]
ok = 0
for fid in ids:
    try:
        if '$action' == 'quarantine':
            result = openxs_db.quarantine_file(fid)
        elif '$action' == 'restore':
            result = openxs_db.restore_file(fid)
        else:
            result = openxs_db.delete_quarantined(fid)
        if result:
            ok += 1
    except Exception as e:
        print(f'# finding {fid}: {e}', file=sys.stderr)
print(f'{ok}/{len(ids)} succeeded')
"`;
chomp($out);

my $qs = "cat=" . &html_escape($in{'cat'}) . "&search=" . &html_escape($in{'search'}) . "&fpage=" . &html_escape($in{'fpage'});
&openxs_result_page("Bulk $action: $out", 0, "Back to findings", "findings.cgi?$qs");
