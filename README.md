# Windows Event Log Detector

Python tool that reads an export of Windows **Security** events and raises L1-SOC-style alerts, mapped to MITRE ATT&CK, as a Markdown triage report.

| Rule | Detects | Event IDs | ATT&CK |
|---|---|---|---|
| WIN-001 | Brute-force logon attempts | 4625 | T1110 |
| WIN-002 | Password spraying (many accounts, one source) | 4625 | T1110.003 |
| WIN-003 | Successful logon after a failure burst (possible compromise, **HIGH**) | 4624 + 4625 | T1078, T1110 |
| WIN-004 | Account lockout | 4740 | T1110 |
| WIN-005 | Admin group membership change, flagged higher if a new account was created minutes earlier | 4720, 4728/4732/4756 | T1136.001, T1098 |
| WIN-006 | Audit log cleared | 1102, 104 | T1070.001 |

Standard library only, Python 3.8+.

## Quick start

```bash
python make_sample_events.py            # writes synthetic events.csv
python detector.py events.csv           # prints the report
python detector.py events.csv -o report.md --threshold 5 --window 5
python -m unittest discover -s tests -v # 11 tests
```

See [`example_report.md`](example_report.md) for output.

## Using your own logs

Export Security events from a Windows machine you are authorised to monitor (run PowerShell as Administrator):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4720,4728,4732,4740,4756,1102} -MaxEvents 5000 |
ForEach-Object {
  $x = [xml]$_.ToXml(); $d = @{}
  $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
  [pscustomobject]@{
    TimeCreated = $_.TimeCreated.ToString('o'); EventID = $_.Id; Computer = $_.MachineName
    TargetUserName = $d['TargetUserName']; SubjectUserName = $d['SubjectUserName']
    IpAddress = $d['IpAddress']; LogonType = $d['LogonType']
  }
} | Export-Csv events.csv -NoTypeInformation -Encoding utf8
```

The script also accepts JSON (array or JSON lines) with the same field names. Matching is case-insensitive.

## How the detections work

- **Failure bursts:** a sliding time window per source IP (or per account when the event has no IP) counts 4625 events.
- **Spray vs brute force:** if the burst touches at least `threshold` different accounts it is a spray, otherwise a brute force.
- **Compromise signal:** a 4624 from the same source after the burst raises a HIGH alert for escalation to L2.
- **Persistence signal:** a group-add to an admin group within 30 minutes of a 4720 on the same host is tagged as likely persistence.

## Limitations

- Developed and tested on **synthetic data** only. The PowerShell export above follows the documented Windows event field names, but I have not run it on a real Windows host, so check the columns on your own export.
- Heuristics with fixed thresholds, not a replacement for a SIEM. Real use needs tuning for noisy sources (VPNs, NAT, vulnerability scanners).
- Timestamps are converted to UTC. Group-add events are matched by group name, not by the added member.
- Event 1102 stores the actor in a different XML section, so the actor may show as unknown on a real export.

## Ideas for extension

- Parse `.evtx` directly, add Sysmon events (1, 3, 11), enrich IPs with the companion IOC tool, export to JSON for a SIEM.

## Author

Arik Abdullah - [github.com/Arik-Abdullah](https://github.com/Arik-Abdullah)
