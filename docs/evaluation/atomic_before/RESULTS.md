# Atomic Red Team replay

Run on 2026-10-19 13:07 on the host orion-lab. Each atomic test ran alone; a detection counts when a library rule returns an event of the host inside the test window.

| Technique | Atomic test | Elastic (Auditbeat, orion-lab) | Wazuh |
|---|---|---|---|
| T1003.008 | Access /etc/passwd (Local) | not detected | not detected |
| T1003.008 | Access /etc/shadow (Local) | detected (2) | detected (2) |
| T1046 | Port Scan | not detected | not detected |
| T1049 | System Network Connections Discovery via ss or lsof (Linux/MacOS) | detected (2) | detected (4) |
| T1053.003 | Cron - Replace crontab with referenced file | detected (2) | detected (2) |
| T1053.003 | Cron - Add script to /etc/cron.d folder | not detected | not detected |
| T1059.004 | Create and Execute Bash Shell Script | not detected | not detected |
| T1059.004 | Command-Line Interface | not detected | not detected |
| T1059.004 | Command line scripts | not detected | not detected |
| T1059.004 | Obfuscated command line scripts | not detected | not detected |
| T1059.004 | Shell Creation using awk command | not detected | not detected |
| T1070.003 | Clear Bash history (rm) | detected (2) | detected (2) |
| T1070.003 | Clear Bash history (echo) | detected (2) | detected (2) |
| T1070.003 | Clear Bash history (cat dev/null) | detected (2) | detected (2) |
| T1070.003 | Clear Bash history (truncate) | not detected | not detected |
| T1070.003 | Clear and Disable Bash History Logging | detected (2) | detected (2) |
| T1082 | List OS Information | detected (2) | detected (2) |
| T1082 | Hostname Discovery | not detected | not detected |
| T1082 | Linux List Kernel Modules | not detected | not detected |
| T1087.001 | Enumerate all accounts (Local) | detected (3) | detected (3) |
| T1087.001 | View accounts with UID 0 | not detected | not detected |
| T1087.001 | Enumerate users and groups | not detected | not detected |
| T1105 | Linux Download File and Run | not detected | not detected |
| T1136.001 | Create a user account on a Linux system | detected (3) | detected (1) |
| T1140 | Base64 decoding with shell utilities | detected (5) | detected (5) |
| T1548.001 | Set a SetUID flag on file | not detected | not detected |
| T1548.001 | Set a SetGID flag on file | not detected | not detected |
| T1548.001 | Do reconnaissance for files that have the setuid bit set | not detected | not detected |

**Elastic (Auditbeat, orion-lab)**: 11 of 28 tests detected.

**Wazuh**: 11 of 28 tests detected.
