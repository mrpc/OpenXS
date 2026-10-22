#!/usr/bin/env python3
"""
Wires up CSF's documented regex.custom.pm extension point so lfd picks up
our mod_security block messages and auto-blocks the offending IP, using
CSF's existing LF_CUSTOMTRIGGER mechanism. Does not touch lfd.pl itself,
and inserts without clobbering any custom rules already in the file.

Used both by install.sh (--with-csf-hook) and the Webmin dashboard's
"Install" button (install_csf_hook.cgi) - single source of truth.
"""
import os
import re
import subprocess
import sys

CSF_CONF = "/etc/csf/csf.conf"
CSF_REGEX = "/etc/csf/regex.custom.pm"


def main():
    if not os.path.exists(CSF_CONF):
        print("CSF was not found on this server - nothing to do.")
        return

    apache_log = "/var/log/apache2/error.log" if os.path.exists("/var/log/apache2/error.log") \
        else "/var/log/httpd/error_log"

    with open(CSF_CONF) as f:
        conf = f.read()
    conf, n = re.subn(r'^CUSTOM1_LOG\s*=.*$', f'CUSTOM1_LOG = "{apache_log}"', conf, flags=re.M)
    with open(CSF_CONF, "w") as f:
        f.write(conf)
    print(f'Set CUSTOM1_LOG = "{apache_log}" in csf.conf ({n} line(s) updated)')

    with open(CSF_REGEX) as f:
        content = f.read()
    if "openxs" in content:
        print("regex.custom.pm already has the OpenXS rule, skipping.")
    else:
        marker = "# Do not edit before this point"
        rule = (
            "\n\tif (($globlogs{CUSTOM1_LOG}{$lgfile}) and ($line =~ "
            '/\\[client (\\S+?)(?::\\d+)?\\] \\[client \\S+\\] ModSecurity: Access denied.*'
            'rejected by the approver script "\\/opt\\/php-malware-finder\\/inspectfile\\.sh"/)) {\n'
            '\t\treturn ("openxs-scan blocked malicious upload from",$1,"openxs","1","80,443","1","0");\n'
            "\t}\n"
        )
        idx = content.find(marker)
        if idx < 0:
            print(f"Could not find the expected marker in {CSF_REGEX} - not modified.")
        else:
            idx += len(marker)
            content = content[:idx] + rule + content[idx:]
            with open(CSF_REGEX, "w") as f:
                f.write(content)
            print(f"Inserted OpenXS rule into {CSF_REGEX}")

    out = subprocess.run(["perl", "-c", CSF_REGEX], capture_output=True, text=True)
    print((out.stdout + out.stderr).strip())
    out = subprocess.run(["csf", "-r"], capture_output=True, text=True)
    print((out.stdout + out.stderr).strip())


if __name__ == "__main__":
    main()
