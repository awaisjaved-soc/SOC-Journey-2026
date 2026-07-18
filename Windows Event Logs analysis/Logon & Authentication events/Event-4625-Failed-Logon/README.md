# Event 4625 – Failed Logon

## Event Description
Event 4625 is generated whenever a **logon attempt fails** due to wrong username, wrong password, or other authentication issues. It contains critical details like the attempted username, source IP, and the reason for failure.

This is one of the **most important events for detecting attacks** like brute force, password spraying, and credential stuffing.

### Common Failure Reason Codes
| Sub Status Code | Meaning |
|-----------------|---------|
| 0xC000006A | Wrong password |
| 0xC0000064 | Username does not exist |
| 0xC0000234 | Account locked out |
| 0xC000006F | Logon outside allowed hours |

---

## SOC Relevance
- Primary indicator of **brute force attacks**
- Multiple 4625s in short time = **password spraying**
- 4625 followed by 4624 = **successful brute force** — critical alert
- Helps identify **targeted accounts** under attack

---

## Lab Method 1 – Manual GUI

1. Go to the login screen of your Windows Server / client
2. Try logging in as `scott` with a **wrong password** multiple times (5-6 times)
3. Each failed attempt generates Event 4625

---

<img width="628" height="443" alt="image" src="https://github.com/user-attachments/assets/669436d0-5cff-4861-a3a2-1944217bf267" />

---

<img width="620" height="123" alt="image" src="https://github.com/user-attachments/assets/34608abe-8cb9-4a1e-948e-499295edf856" />

---

## Lab Method 2 – PowerShell

```powershell
$username = "scott"
$wrongpass = ConvertTo-SecureString "WrongPass123" -AsPlainText -Force

1..6 | ForEach-Object {
    $cred = New-Object System.Management.Automation.PSCredential($username, $wrongpass)
    Start-Process powershell.exe -Credential $cred -NoNewWindow -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 700
}
```

---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time     = $_.TimeCreated
        User     = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        SourceIP = ($xml.Event.EventData.Data | Where {$_.Name -eq 'IpAddress'}).'#text'
    }
} | Format-Table -AutoSize
```
---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/18/2026 8:15:16 AM
Event ID:      4625
Task Category: Logon
Level:         Information
Keywords:      Audit Failure
User:          N/A
Computer:      WIN-KAHJ94DKN9V.techcorp.local
Description:
An account failed to log on.

Subject:
	Security ID:		SYSTEM
	Account Name:		WIN-KAHJ94DKN9V$
	Account Domain:		TECHCORP
	Logon ID:		0x3E7

Logon Type:			7

Account For Which Logon Failed:
	Security ID:		NULL SID
	Account Name:		Administrator
	Account Domain:		TECHCORP

Failure Information:
	Failure Reason:		Unknown user name or bad password.
	Status:			0xC000006D
	Sub Status:		0xC000006A

Process Information:
	Caller Process ID:	0x83c
	Caller Process Name:	C:\Windows\System32\svchost.exe

Network Information:
	Workstation Name:	WIN-KAHJ94DKN9V
	Source Network Address:	127.0.0.1
	Source Port:		0

Detailed Authentication Information:
	Logon Process:		User32 
	Authentication Package:	Negotiate
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon request fails. It is generated on the computer where access was attempted.

The Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).

The Process Information fields indicate which account and process on the system requested the logon.

The Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The authentication information fields provide detailed information about this specific logon request.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4625</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-18T15:15:16.7332622Z" />
    <EventRecordID>1972</EventRecordID>
    <Correlation ActivityID="{860854d8-16c6-0002-3455-0886c616dd01}" />
    <Execution ProcessID="652" ThreadID="880" />
    <Channel>Security</Channel>
    <Computer>WIN-KAHJ94DKN9V.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">WIN-KAHJ94DKN9V$</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x3e7</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">Administrator</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="Status">0xc000006d</Data>
    <Data Name="FailureReason">%%2313</Data>
    <Data Name="SubStatus">0xc000006a</Data>
    <Data Name="LogonType">7</Data>
    <Data Name="LogonProcessName">User32 </Data>
    <Data Name="AuthenticationPackageName">Negotiate</Data>
    <Data Name="WorkstationName">WIN-KAHJ94DKN9V</Data>
    <Data Name="TransmittedServices">-</Data>
    <Data Name="LmPackageName">-</Data>
    <Data Name="KeyLength">0</Data>
    <Data Name="ProcessId">0x83c</Data>
    <Data Name="ProcessName">C:\Windows\System32\svchost.exe</Data>
    <Data Name="IpAddress">127.0.0.1</Data>
    <Data Name="IpPort">0</Data>
  </EventData>
</Event>
```
---

## What to Look For (SOC Analyst Tips)
- **5+ failures in under 1 minute** from same IP = brute force
- Same IP targeting **multiple different usernames** = password spraying
- Failures against **admin or service accounts**
- Failures from **external/unknown IPs**
- 4625 immediately followed by 4624 for same user = **attacker succeeded**

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Technique | T1110 – Brute Force |
