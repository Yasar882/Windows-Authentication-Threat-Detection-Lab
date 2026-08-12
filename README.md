# Windows Authentication Threat Detection Lab

## Project Overview

This project demonstrates an end-to-end SOC detection workflow for identifying failed Windows authentication attempts generated from a Kali Linux attacker machine and detecting them in Splunk.
### Lab architecture

```text
Kali Linux (Attacker)        192.168.42.3
        |
        | Authentication attempts
        v
Windows 10 Pro (Victim)      192.168.42.5
        |
        | Windows Security Event 4625
        v
Splunk Universal Forwarder
        |
        | TCP/9997
        v
Physical Windows Host        192.168.42.1
Splunk Enterprise
        |
        v
index=windows
        |
        v
Detection / Alert
```

> All IP addresses are lab-only examples. Replace them when recreating the lab.

## Objectives

- Build an isolated SOC lab with VirtualBox.
- Configure Windows Security event collection.
- Configure Splunk Universal Forwarder.
- Configure Splunk Enterprise to receive TCP/9997.
- Generate controlled failed authentication events.
- Identify Windows Event ID 4625.
- Extract useful fields from XML events.
- Detect repeated failed authentication.
- Create a Splunk alert.
- Document the investigation as a portfolio project.

## Lab Components

| Component | Role | Example |
|---|---|---|
| Kali Linux | Attacker/test source | 192.168.42.3 |
| Windows 10 Pro | Victim/log source | 192.168.42.5 |
| Physical Windows PC | Splunk host | 192.168.42.1 |
| Splunk receiving | UF receiver | TCP/9997 |
| Splunk Web | SIEM interface | TCP/8000 |
| Windows RDP | Authentication service | TCP/3389 |

## Tools

- Kali Linux
- Windows 10 Pro
- Oracle VirtualBox
- Splunk Enterprise
- Splunk Universal Forwarder
- PowerShell
- Windows Security logs
- Netcat
- FreeRDP
- SPL

## Network Verification

From Kali:

```bash
nc -nvz 192.168.42.5 3389
```

Expected:

```text
192.168.42.5 3389 port [ms-wbt-server] open
```

From Windows:

```powershell
Test-NetConnection 192.168.42.1 -Port 9997
```

Expected:

```text
TcpTestSucceeded : True
```

## Splunk Receiving Configuration

Splunk Web:

```text
http://192.168.42.1:8000
```

Receiving port:

```text
TCP/9997
```

Effective receiver configuration:

```ini
[splunktcp://9997]
connection_host = ip
disabled = 0
```

Verify on the Splunk host:

```powershell
Get-NetTCPConnection -LocalPort 9997 -State Listen
```

## Universal Forwarder Configuration

Destination:

```text
192.168.42.1:9997
```

Security input file:

```text
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

```ini
[WinEventLog://Security]
disabled = 0
index = windows
renderXml = true
```

Verify:

```powershell
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" btool inputs list "WinEventLog://Security" --debug
```

Restart:

```powershell
Restart-Service SplunkForwarder
```

## RDP Configuration

Windows 10 Pro was used because it supports incoming RDP.

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

Verify from Kali:

```bash
nc -nvz 192.168.42.5 3389
```

## Generating Event 4625

A controlled failed authentication was generated from Kali:

```bash
xfreerdp /v:192.168.42.5 /u:soclab /p:WrongPassword123!
```

Verify on Windows:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5
```

## Observed Event

The captured event contained:

```text
EventID: 4625
TargetUserName: soclab
WorkstationName: kali
IpAddress: 192.168.42.3
LogonType: 3
AuthenticationPackageName: NTLM
Status: 0xc000006d
SubStatus: 0xc0000064
```

Interpretation:

- `4625` = failed logon
- `soclab` = targeted account
- `192.168.42.3` = source IP
- `kali` = source workstation
- `3` = network logon
- `NTLM` = authentication protocol

> The captured event had LogonType 3, so it should be described as a failed network authentication, not as an RDP-specific LogonType 10 event.

## Splunk Verification

Basic search:

```spl
index=windows "4625"
```

The event was received in Splunk through the Universal Forwarder.

## Field Extraction

```spl
index=windows "4625"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]*)</Data>"
| rex field=_raw "<Data Name='IpAddress'>(?<SourceIP>[^<]*)</Data>"
| rex field=_raw "<Data Name='WorkstationName'>(?<WorkstationName>[^<]*)</Data>"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>\d+)</Data>"
| table _time host EventCode TargetUserName SourceIP WorkstationName LogonType
```

Expected example:

```text
4625 | soclab | 192.168.42.3 | kali | 3
```

## Repeated Authentication Detection

```spl
index=windows "4625"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]*)</Data>"
| rex field=_raw "<Data Name='IpAddress'>(?<SourceIP>[^<]*)</Data>"
| rex field=_raw "<Data Name='WorkstationName'>(?<WorkstationName>[^<]*)</Data>"
| rex field=_raw "<Data Name='LogonType'>(?<LogonType>\d+)</Data>"
| bin _time span=5m
| stats count as FailedAttempts by _time SourceIP TargetUserName WorkstationName LogonType
| where FailedAttempts >= 3
| sort - FailedAttempts
```

Detection logic:

```text
3+ failed authentications
+ same source
+ within 5 minutes
= suspicious repeated authentication activity
```

This is a heuristic, not proof of malicious activity. Analysts should investigate context.

## Alert

Suggested name:

```text
Windows - Repeated Failed Authentication
```

Suggested description:

```text
Detects three or more Windows Event ID 4625 authentication failures from the same source IP against a Windows account within a five-minute window.
```

Suggested schedule:

```text
Every 5 minutes
```

Suggested trigger:

```text
Number of results > 0
```

## SOC Investigation Workflow

1. Identify source IP.
2. Identify targeted account.
3. Identify affected host.
4. Count and timeline the failures.
5. Determine LogonType.
6. Determine authentication protocol.
7. Check whether the source is authorized.
8. Search for successful Event 4624 around the same time.
9. Review other Windows Security events.
10. Escalate or contain if malicious.

## Skills Demonstrated

- SIEM deployment
- Splunk Enterprise
- Splunk Universal Forwarder
- SPL
- Windows Security Event Logs
- Event ID 4625 analysis
- XML parsing
- Regex field extraction
- Authentication monitoring
- Brute-force detection concepts
- Windows Firewall configuration
- VirtualBox networking
- Kali Linux
- RDP
- SOC alert development
- Security event investigation

## Recommended Screenshots

Add sanitized screenshots to `screenshots/`:

1. VirtualBox network
2. Kali IP
3. Windows IP
4. Splunk receiver 9997
5. TCP 9997 test
6. Universal Forwarder configuration
7. `inputs.conf`
8. Windows 4625 event
9. Raw XML event
10. Splunk 4625 search
11. Extracted fields
12. Detection results
13. Alert configuration
14. Triggered alert

Never commit passwords, API keys, tokens, private keys, or other secrets.

## Repository Structure

```text
windows-authentication-threat-detection/
├── README.md
├── configs/
│   ├── inputs.conf
│   └── outputs.conf.example
├── spl/
│   ├── 01_basic_4625_search.spl
│   ├── 02_field_extraction.spl
│   ├── 03_repeated_authentication_detection.spl
│   └── 04_investigation_query.spl
├── screenshots/
├── docs/
│   ├── architecture.md
│   ├── investigation.md
│   └── detection-notes.md
└── LICENSE
```

## Limitations

- Single Windows victim.
- Simple threshold detection.
- Private Host-Only lab.
- Controlled authentication testing.
- Captured example was LogonType 3, not RDP-specific LogonType 10.
- Regex extraction was used for the observed XML format.
- Alerting is intended for lab demonstration, not production deployment.

## Future Improvements

- Add Sysmon.
- Collect process creation events.
- Correlate 4625 with 4624.
- Add multiple-account attack detection.
- Add PowerShell logging.
- Add risk scoring.
- Add dashboards.
- Add MITRE ATT&CK mapping.
- Add allowlists and detection tuning.

## Portfolio Summary

**Windows Authentication Threat Detection Lab Lab**

Built a VirtualBox SOC lab integrating Kali Linux, Windows 10 Pro, Splunk Enterprise, and Splunk Universal Forwarder; collected Windows Security Event ID 4625, parsed XML authentication telemetry, extracted source IP/account fields with SPL, and developed a threshold-based detection for repeated failed authentication attempts.

## Disclaimer

This project was performed in an isolated, authorized lab environment for cybersecurity learning and defensive detection engineering. No unauthorized systems were targeted.
