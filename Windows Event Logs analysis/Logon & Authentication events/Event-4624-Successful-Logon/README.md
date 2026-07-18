# Event 4624 – Successful Logon

## Event Description
Event 4624 is generated every time a user or system **successfully logs into** a Windows machine or server. It records critical details such as the username, logon type (interactive, network, RDP, etc.), source IP address, and time of login.

This is one of the **most frequently seen events** in a SOC environment and is heavily used during incident response to build timelines and detect unauthorized access.

### Logon Type Reference
| Logon Type | Description |
|------------|-------------|
| 2 | Interactive (local login) |
| 3 | Network (shared folder, etc.) |
| 10 | Remote Interactive (RDP) |
| 5 | Service logon |

---

## SOC Relevance
- First indicator that an attacker has **successfully gained access**
- Used to build **login timelines** during incident response
- Helps distinguish **normal user activity** from suspicious logons
- Correlate with **4625 (Failed Logon)** — multiple failures followed by a 4624 = successful brute force

---

## Lab Method 1 – Manual GUI

1. Lock the screen using `Win + L`
2. Log back in with correct username and password (use user `scott`)
3. Event 4624 will be generated on successful login

---

<img width="627" height="435" alt="WhatsApp Image 2026-07-18 at 8 10 47 PM" src="https://github.com/user-attachments/assets/024f2ba4-3b59-4dd1-83a4-4f82d89069ca" />

---
<img width="643" height="395" alt="image" src="https://github.com/user-attachments/assets/43b56ea0-0c7a-4e9f-92ca-1163711469f3" />

---




## Lab Method 2 – PowerShell

```powershell
# Confirm currently logged in user (triggers session activity)
whoami
```

> 💡 For a more realistic trigger: login as `scott`, perform some activity, then log off and check the event log.

---

## Detection Command

Run this on your **Domain Controller or target machine**:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 10 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time      = $_.TimeCreated
        User      = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        LogonType = ($xml.Event.EventData.Data | Where {$_.Name -eq 'LogonType'}).'#text'
        SourceIP  = ($xml.Event.EventData.Data | Where {$_.Name -eq 'IpAddress'}).'#text'
    }
} | Format-Table -AutoSize
```
---

<img width="985" height="512" alt="image" src="https://github.com/user-attachments/assets/84f9c487-7e17-4a26-b680-faa66a38b3ce" />

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/18/2026 8:18:31 AM
Event ID:      4624
Task Category: Logon
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-KAHJ94DKN9V.techcorp.local
Description:
An account was successfully logged on.

Subject:
	Security ID:		NULL SID
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Information:
	Logon Type:		3
	Restricted Admin Mode:	-
	Virtual Account:		No
	Elevated Token:		Yes

Impersonation Level:		Impersonation

New Logon:
	Security ID:		SYSTEM
	Account Name:		WIN-KAHJ94DKN9V$
	Account Domain:		TECHCORP.LOCAL
	Logon ID:		0x35C700
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{1fa593bd-2fc3-336c-df37-28667fff707e}

Process Information:
	Process ID:		0x0
	Process Name:		-

Network Information:
	Workstation Name:	-
	Source Network Address:	::1
	Source Port:		0

Detailed Authentication Information:
	Logon Process:		Kerberos
	Authentication Package:	Kerberos
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon session is created. It is generated on the computer that was accessed.

The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).

The New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.

The network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The impersonation level field indicates the extent to which a process in the logon session can impersonate.

The authentication information fields provide detailed information about this specific logon request.
	- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-18T15:18:31.2974966Z" />
    <EventRecordID>2070</EventRecordID>
    <Correlation />
    <Execution ProcessID="652" ThreadID="880" />
    <Channel>Security</Channel>
    <Computer>WIN-KAHJ94DKN9V.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-0-0</Data>
    <Data Name="SubjectUserName">-</Data>
    <Data Name="SubjectDomainName">-</Data>
    <Data Name="SubjectLogonId">0x0</Data>
    <Data Name="TargetUserSid">S-1-5-18</Data>
    <Data Name="TargetUserName">WIN-KAHJ94DKN9V$</Data>
    <Data Name="TargetDomainName">TECHCORP.LOCAL</Data>
    <Data Name="TargetLogonId">0x35c700</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="LogonProcessName">Kerberos</Data>
    <Data Name="AuthenticationPackageName">Kerberos</Data>
    <Data Name="WorkstationName">-</Data>
    <Data Name="LogonGuid">{1fa593bd-2fc3-336c-df37-28667fff707e}</Data>
    <Data Name="TransmittedServices">-</Data>
    <Data Name="LmPackageName">-</Data>
    <Data Name="KeyLength">0</Data>
    <Data Name="ProcessId">0x0</Data>
    <Data Name="ProcessName">-</Data>
    <Data Name="IpAddress">::1</Data>
    <Data Name="IpPort">0</Data>
    <Data Name="ImpersonationLevel">%%1833</Data>
    <Data Name="RestrictedAdminMode">-</Data>
    <Data Name="TargetOutboundUserName">-</Data>
    <Data Name="TargetOutboundDomainName">-</Data>
    <Data Name="VirtualAccount">%%1843</Data>
    <Data Name="TargetLinkedLogonId">0x0</Data>
    <Data Name="ElevatedToken">%%1842</Data>
  </EventData>
</Event>
```
---

## What to Look For (SOC Analyst Tips)
- Logon **Type 10** (RDP) from unknown external IPs
- Successful logons **after multiple 4625 failures** (brute force success)
- Logons at **unusual hours** (e.g., 3 AM)
- Logons from **new or unexpected machines**
- `SYSTEM` or service account logons from interactive sessions

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Initial Access / Lateral Movement |
| Technique | T1078 – Valid Accounts |
