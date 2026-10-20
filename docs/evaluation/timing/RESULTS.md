# Timed comparison: three hunts by hand and with ORION

One SOC analyst, same data (everything stored in Elastic and Wazuh), stopwatch from reading the hypothesis to the written list.
The manual run came first for hunts 1 and 3, the ORION run first for hunt 2. Rules: the three `.yml` files in this folder. Manual queries: KQL in Kibana, Lucene in the Wazuh dashboard.

| Hunt | By hand | With ORION | Machine time of the hunt (median of 5) | Ranked behaviours returned |
|---|---|---|---|---|
| 1 Download with curl or wget (T1105) | 19 min | 3 min | 0.98 s | 8 |
| 2 Shell history cleared (T1070.003) | 8 min | 5 min | 2.13 s | 45 |
| 3 Netcat listener (T1046) | 6 min | 4 min | 0.43 s | 31 |
| Total | 33 min | 12 min | | |

Limits: one analyst, three hunts, order of the methods alternated but not evenly, lists not compared line by line (the library rule for hunt 3 also covers nmap and port-scan loops).
Machine times come from `scripts/eval/measure_timed_hunts.py`.
