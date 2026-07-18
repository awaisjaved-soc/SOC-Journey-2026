# Event 4648 – Logon with Explicit Credentials

## Event Description
Event 4648 is generated when a user or process **uses alternate credentials** to run something — for example, using the `runas` command or right-clicking "Run as different user." It records both the **account that initiated the action** and the **target account** being used.

This event is critical because it shows someone is **using credentials other than their own** — which is a common attacker technique.

---

## SOC Relevance
- Key indicator of **lateral movement** — attacker using stolen credentials on another machine
- Detects **Pass-the-Hash (PtH)** and **Pass-the-Ticket** attacks
- Shows **privilege escalation attempts** via runas
- Helps identify **credential theft** in progress

---

## Lab Method 1 – Manual GUI

1. Hold **Shift** and **Right-click** on Command Prompt or any application
2. Click **"Run as different user"**
3. Enter `scott`'s credentials
4. Event 4648 will be generated

---

<img width="630" height="436" alt="image" src="https://github.com/user-attachments/assets/0d1edf6f-ef53-4820-a452-824f119cbb80" />

---
<img width="602" height="405" alt="WhatsApp Image 2026-07-18 at 9 54 11 PM" src="https://github.com/user-attachments/assets/128bf6ee-1fb1-4cc9-90aa-f54e78268955" />


## Lab Method 2 – PowerShell

```powershell
Start-Process powershell.exe -Credential (Get-Credential) -ArgumentList "-NoExit"
```
---

<img width="1013" height="720" alt="image" src="https://github.com/user-attachments/assets/e22a5844-3024-41f5-89e3-79cf656b400b" />


---

> A credential popup will appear — enter `scott`'s username and password to trigger the event.

---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time         = $_.TimeCreated
        TargetUser   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        UsingAccount = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
    }
} | Format-Table -AutoSize
```
---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/18/2026 9:10:55 AM
Event ID:      4648
Task Category: Logon
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-KAHJ94DKN9V.techcorp.local
Description:
A logon was attempted using explicit credentials.

Subject:
	Security ID:		TECHCORP\Administrator
	Account Name:		Administrator
	Account Domain:		TECHCORP
	Logon ID:		0xEEDBD
	Logon GUID:		{dc62aeb7-ba94-82e8-e40c-db13522c056d}

Account Whose Credentials Were Used:
	Account Name:		alexrivera
	Account Domain:		TECHCORP
	Logon GUID:		{b6b0966e-2bf4-d731-6a36-20fd2696e2e2}

Target Server:
	Target Server Name:	localhost
	Additional Information:	localhost

Process Information:
	Process ID:		0x23c0
	Process Name:		C:\Windows\System32\svchost.exe

Network Information:
	Network Address:	::1
	Port:			0

This event is generated when a process attempts to log on an account by explicitly specifying that account’s credentials.  This most commonly occurs in batch-type configurations such as scheduled tasks, or when using the RUNAS command.
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4648</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-18T16:10:55.9144142Z" />
    <EventRecordID>3401</EventRecordID>
    <Correlation ActivityID="{423bbde8-16cb-0001-15be-3b42cb16dd01}" />
    <Execution ProcessID="648" ThreadID="4912" />
    <Channel>Security</Channel>
    <Computer>WIN-KAHJ94DKN9V.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-2896402138-2534863141-3184233234-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0xeedbd</Data>
    <Data Name="LogonGuid">{dc62aeb7-ba94-82e8-e40c-db13522c056d}</Data>
    <Data Name="TargetUserName">alexrivera</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetLogonGuid">{b6b0966e-2bf4-d731-6a36-20fd2696e2e2}</Data>
    <Data Name="TargetServerName">localhost</Data>
    <Data Name="TargetInfo">localhost</Data>
    <Data Name="ProcessId">0x23c0</Data>
    <Data Name="ProcessName">C:\Windows\System32\svchost.exe</Data>
    <Data Name="IpAddress">::1</Data>
    <Data Name="IpPort">0</Data>
  </EventData>
</Event>
```

---

## What to Look For (SOC Analyst Tips)
- **Non-admin users** using explicit credentials to run processes as admin
- 4648 seen on **multiple machines** for the same account = lateral movement
- `SubjectUserName` and `TargetUserName` are **completely different accounts** = suspicious
- 4648 combined with **4624 Type 3 (network logon)** = strong lateral movement indicator
- Appearing on **servers or Domain Controllers** from workstation accounts

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Lateral Movement / Privilege Escalation |
| Technique | T1550.002 – Pass the Hash / T1078 – Valid Accounts |
