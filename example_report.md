# Windows Security Event Triage Report

- Source: `events.csv`
- Events analysed: 29 (2026-11-09 01:00 to 2026-11-09 01:55 UTC)
- Alerts: 6 (HIGH 3, MEDIUM 3, LOW 0)

## Alert 1: HIGH - Successful logon (4624) as 'Administrator' after failures from 203.0.113.45

- Rule: WIN-003  |  ATT&CK: T1078, T1110
- Host: SRV-RDP-01
- Evidence: Logon type 10 at 01:31:40 on SRV-RDP-01
- Evidence: Same source had a failed-logon burst just before
- Recommended action: ESCALATE to L2: possible account compromise. Isolate the host if confirmed, reset credentials, review activity after the logon.

## Alert 2: HIGH - Privileged group membership change (Administrators) shortly after a new account was created

- Rule: WIN-005  |  ATT&CK: T1136.001, T1098
- Host: SRV-RDP-01
- Evidence: Event 4732: member added to 'Administrators' by 'Administrator' at 01:53:00 on SRV-RDP-01
- Evidence: Account 'svc_backup2' was created (4720) by 'Administrator' 3 min earlier
- Recommended action: ESCALATE to L2 unless this matches an approved change ticket. Verify with the actor and the asset owner.

## Alert 3: HIGH - Security event log cleared on SRV-RDP-01

- Rule: WIN-006  |  ATT&CK: T1070.001
- Host: SRV-RDP-01
- Evidence: Event 1102 at 01:55:00, actor: Administrator
- Recommended action: ESCALATE to L2: clearing logs is a common anti-forensics step. Preserve remaining logs and review activity just before this time.

## Alert 4: MEDIUM - Brute-force logon attempts from 203.0.113.45

- Rule: WIN-001  |  ATT&CK: T1110
- Host: SRV-RDP-01
- Evidence: 12 failed logons (4625) within 5 min, 01:30:00 - 01:31:06
- Evidence: Accounts targeted (1): Administrator
- Recommended action: Block or monitor the source, review the targeted account, check for later successful logons.

## Alert 5: MEDIUM - Password spraying from 198.51.100.7

- Rule: WIN-002  |  ATT&CK: T1110.003
- Host: SRV-RDP-01
- Evidence: 7 failed logons (4625) within 5 min, 01:40:00 - 01:41:30
- Evidence: Accounts targeted (7): admin, backup, guest, sql, support, svc_web, test
- Recommended action: Block or monitor the source, check whether any targeted account logged on successfully, notify the account owners.

## Alert 6: MEDIUM - Account lockout: nusrat

- Rule: WIN-004  |  ATT&CK: T1110
- Host: DC-01
- Evidence: 1 lockout event(s) (4740), first at 01:43:20
- Recommended action: Check the source of the bad passwords; confirm with the user whether it was them.

