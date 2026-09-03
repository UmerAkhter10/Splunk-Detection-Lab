# Splunk SOC Monitoring Lab

A hands-on home lab simulating SOC (Security Operations Center) monitoring using **Splunk Enterprise** as a SIEM, with Windows event log telemetry, custom detection alerts mapped to **MITRE ATT&CK**, and a real-time monitoring dashboard.

## Project Overview

This lab deploys a Splunk Indexer/Search Head on an Ubuntu Server VM and a Splunk Universal Forwarder on a Windows 10 VM to forward Windows Security, Application, and System event logs (including Sysmon telemetry). The logs are parsed, queried with SPL, and used to build detections for common attacker behaviors, brute-force login attempts, new local user account creation, and suspicious PowerShell execution.

## Architecture

```
┌─────────────────────┐         ┌──────────────────────────┐
│   Windows 10 VM      │  9997   │   Ubuntu Server VM        │
│  (Universal Forwarder)├────────►│  (Splunk Indexer/Search   │
│  - Security logs      │  TCP    │   Head)                   │
│  - Application logs   │         │  - index: windows         │
│  - System logs         │        │  - Web UI: :8000          │         
└─────────────────────┘            └──────────────────────────┘
```

## Components

| Component | Role |
|---|---|
| Splunk Enterprise (trial) | Indexer + Search Head + Web UI, installed on Ubuntu Server |
| Splunk Universal Forwarder | Installed on Windows 10 endpoint, forwards event logs |
| Splunk Add-on for Microsoft Windows (`Splunk_TA_windows`) | Field extraction for `WinEventLog`/`XmlWinEventLog` sourcetypes |



### Splunk Enterprise Installation (Ubuntu Server)


### Universal Forwarder Installation (Windows 10)


## Detection Queries & Alerts

| Detection | Event Code | MITRE ATT&CK | SPL |
|---|---|---|---|
| Password brute-force | 4625 (failed logon) | T1110.001 – Brute Force: Password Guessing (Credential Access) | `index="windows" EventCode=4625 \| bucket _time span=5m \| stats count by user, _time \| where count>3` |
| New local user creation | 4720 | T1136.001 – Create Account: Local Account (Persistence) | `index="windows" EventCode=4720 \| table _time, src_user, user` |
| Suspicious PowerShell execution | 4688 (process creation) | T1059.001 – Command and Scripting Interpreter: PowerShell (Execution) | `index="windows" EventCode=4688 Process_Command_Line=*Encoded* \| table _time, parent_process_name, process_name, Process_Command_Line` |

## SOC Monitoring Dashboard

A classic dashboard was built with 5 panels:
1. **Single value** — total events in the last 24 hours (`windows` index)
2. **Statistics table** — brute-force attack alerts (last 24h)
3. **Statistics table** — new user creation alerts (last 24h)
4. **Statistics table** — suspicious PowerShell execution alerts (last 24h)
5. **Column chart** — successful vs. failed logins by user (last 24h):
   ```
   index="windows" (EventCode=4624 OR EventCode=4625)
   | where Logon_Type IN (2,7,10,11)
   | stats count(eval(EventCode=4624)) as Successful_Logins,
           count(eval(EventCode=4625)) as Failed_Logins by user
   ```

## Skills Demonstrated

- Deployment and configuration of a Splunk Indexer/Search Head and Universal Forwarder
- Windows event log telemetry configuration (`inputs.conf`, group policy)
- Diagnosing and resolving field-extraction issues
- Writing SPL to detect, filter, bucket, and tabularize security-relevant events
- Mapping detections to the MITRE ATT&CK framework
- Building a real-time SOC monitoring dashboard

