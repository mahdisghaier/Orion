# False positives and reduction on background activity

Window 2026-10-19T12:16:00Z to 2026-10-19T14:15:00Z on orion-lab, no scenario running. Whatever a rule returns here is a false positive.

## Elastic (Auditbeat, orion-lab)

Process starts in the window: 321, grouped into 35 behaviours.

| Technique | Rule | Events | Behaviours | Examples |
|---|---|---|---|---|
| T1059.004 | Reverse shell one-liner | 0 | 0 |  |
| T1046 | Network discovery tool executed | 0 | 0 |  |
| T1105 | Download piped to a shell or saved to a temporary folder | 0 | 0 |  |
| T1070.003 | Shell history cleared | 0 | 0 |  |
| T1070.002 | System logs removed or truncated | 0 | 0 |  |
| T1562.001 | Security tooling stopped or disabled | 0 | 0 |  |
| T1136.001 | Local account created | 0 | 0 |  |
| T1053.003 | Cron table edited | 0 | 0 |  |
| T1548.001 | Setuid or setgid bit set | 0 | 0 |  |
| T1003.008 | Shadow password file accessed | 0 | 0 |  |
| T1565.001 | Critical system file changed | 0 | 0 |  |
| T1049 | Network connections listed | 38 | 2 | netstat -tulpn; sh -c -- netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\( |
| T1016 | Network configuration listed | 0 | 0 |  |
| T1082 | System information gathered | 0 | 0 |  |
| T1087 | Accounts enumerated | 0 | 0 |  |
| T1140 | Encoded content decoded on the command line | 0 | 0 |  |
| T1027.010 | Decoded content piped into a shell | 0 | 0 |  |
| T1059.006 | Python used for a socket or terminal spawn | 0 | 0 |  |
| T1074.001 | Archive written to a staging folder | 0 | 0 |  |
| T1090 | Tunnel or proxy set up | 0 | 0 |  |

## Wazuh

Process starts in the window: 321, grouped into 35 behaviours.

| Technique | Rule | Events | Behaviours | Examples |
|---|---|---|---|---|
| T1059.004 | Reverse shell one-liner | 0 | 0 |  |
| T1046 | Network discovery tool executed | 0 | 0 |  |
| T1105 | Download piped to a shell or saved to a temporary folder | 0 | 0 |  |
| T1070.003 | Shell history cleared | 0 | 0 |  |
| T1070.002 | System logs removed or truncated | 0 | 0 |  |
| T1562.001 | Security tooling stopped or disabled | 0 | 0 |  |
| T1136.001 | Local account created | 0 | 0 |  |
| T1053.003 | Cron table edited | 0 | 0 |  |
| T1548.001 | Setuid or setgid bit set | 0 | 0 |  |
| T1003.008 | Shadow password file accessed | 0 | 0 |  |
| T1565.001 | Critical system file changed | 0 | 0 |  |
| T1049 | Network connections listed | 38 | 2 | netstat -tulpn; sh -c -- netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\( |
| T1016 | Network configuration listed | 0 | 0 |  |
| T1082 | System information gathered | 0 | 0 |  |
| T1087 | Accounts enumerated | 0 | 0 |  |
| T1140 | Encoded content decoded on the command line | 0 | 0 |  |
| T1027.010 | Decoded content piped into a shell | 0 | 0 |  |
| T1059.006 | Python used for a socket or terminal spawn | 0 | 0 |  |
| T1074.001 | Archive written to a staging folder | 0 | 0 |  |
| T1090 | Tunnel or proxy set up | 0 | 0 |  |
