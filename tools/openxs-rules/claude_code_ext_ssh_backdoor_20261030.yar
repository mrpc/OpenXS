/*
 * Trojanized "anthropic.claude-code" VS Code/Cursor extension (v2.1.313,
 * distributed via Open VSX, reported 2026-10-30 - see
 * https://doublepulsar.com/anthropic-hacked-to-deliver-remote-access-trojan-to-claude-developer-laptops-worldwide-1148a92baae2
 * and corroborating coverage on cybersecuritynews.com / gbhackers.com).
 * A 66-line JS loader prepended to extension.js drops an SSH backdoor
 * (authorized_keys entry commented "svc-telemetry", reverse autossh/ssh
 * tunnel to 134.209.82.225, HTTP beacon on :8099/beacon) and persistence
 * (macOS LaunchAgent com.apple.sysmond.plist, Linux @reboot cron, Windows
 * scheduled task "SysMon"). This targets developer workstations (VS
 * Code/Cursor), not hosted PHP sites - not expected to fire on this
 * fleet's web content. Added speculatively in case a dropped copy of the
 * loader, the embedded key, or a persistence script ever lands in a
 * scanned path. Not promoted to yara_exploit/auto-quarantine pending a
 * clean run against the test corpus - see OpenXS-ops/TIMELINE.md 2026-10-30.
 * No official YARA rule was published by any source found for this
 * incident; all strings below are reconstructed from secondary reporting,
 * not verified against a sample of the actual loader.
 */
rule ClaudeCodeExtensionSSHBackdoor_20261030
{
    meta:
        description = "Trojanized anthropic.claude-code extension (v2.1.313) SSH backdoor loader/persistence"
        reference = "https://doublepulsar.com/anthropic-hacked-to-deliver-remote-access-trojan-to-claude-developer-laptops-worldwide-1148a92baae2"
        added = "2026-10-30"
    strings:
        $c2_ip = "134.209.82.225"
        $beacon_path = "/beacon"
        $ssh_comment = "svc-telemetry"
        $launchagent = "com.apple.sysmond"
        $scheduled_task = "SysMon"
        $tunnel_user = "tunnel@134.209.82.225"
        $key_fingerprint = "0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk"
    condition:
        $c2_ip or $ssh_comment or $tunnel_user or $key_fingerprint
        or ($launchagent and $scheduled_task)
        or (any of ($beacon_path) and $c2_ip)
}
