#!/usr/bin/env python3
"""Adds an 'Open OpenXS' link to CSF's own Webmin module main page, only
shown if the OpenXS module is actually installed. CSF is GPLv3 (unlike
cxs), so patching its Perl source is legally fine."""
f = "/usr/local/csf/lib/ConfigServer/DisplayUI.pm"
content = open(f).read()
marker = 'print "<thead><tr><th colspan=\'2\'>Server Information</th></tr></thead>";'
assert content.count(marker) == 1, "marker not found exactly once - CSF version may have changed"

insert = """
\t\tif (-d '/usr/share/webmin/openxs') {
\t\t\tprint "<tr><td colspan='2'><a href='../openxs/' class='btn btn-default'>Open OpenXS Exploit Scanner module &raquo;</a></td></tr>\\n";
\t\t}
"""
open(f, "w").write(content.replace(marker, marker + insert))
print("Patched:", f)
