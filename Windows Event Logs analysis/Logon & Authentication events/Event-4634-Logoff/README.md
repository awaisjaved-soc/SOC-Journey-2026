# Event 4634 – Logoff

## Event Description
Event 4634 is generated when a **user session ends** — either by logging off, session timeout, or system-initiated termination. It records the username and logon ID to link back to the original 4624 logon event.

This event **pairs with Event 4624** to give a complete picture of how long a user was logged in.

---

## SOC Relevance
- Helps calculate **session duration** (4624 login time → 4634 logoff time)
- Detect **suspiciously short sessions** (attacker grabbed what they needed and left fast)
- Detect **sessions that never ended** (persistent access)
- Important for **building user activity timelines** during incident response

---

## Lab Method 1 – Manual GUI

1. Login as `scott`
2. Do some activity for a few minutes
3. Press `Ctrl + Alt + Del` → Click **Sign out**
4. Event 4634 will be generated on logoff

---

<img width="629" height="436" alt="image" src="https://github.com/user-attachments/assets/e6b5e52c-ddfd-4b19-a190-88ba9a2cad9a" />

---

## Lab Method 2 – PowerShell

```powershell
logoff
```

---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4634} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time = $_.TimeCreated
        User = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```
---

<img width="986" height="513" alt="image" src="https://github.com/user-attachments/assets/171e8e82-57cd-44b8-94a0-48c640938727" />

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/18/2026 8:09:44 AM
Event ID:      4634
Task Category: Logoff
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-KAHJ94DKN9V.techcorp.local
Description:
An account was logged off.

Subject:
	Security ID:		TECHCORP\Administrator
	Account Name:		Administrator
	Account Domain:		TECHCORP
	Logon ID:		0x1CDCD9

Logon Type:			7

This event is generated when a logon session is destroyed. It may be positively correlated with a logon event using the Logon ID value. Logon IDs are only unique between reboots on the same computer.
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4634</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12545</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-18T15:09:44.6006661Z" />
    <EventRecordID>1877</EventRecordID>
    <Correlation />
    <Execution ProcessID="652" ThreadID="4404" />
    <Channel>Security</Channel>
    <Computer>WIN-KAHJ94DKN9V.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserSid">S-1-5-21-2896402138-2534863141-3184233234-500</Data>
    <Data Name="TargetUserName">Administrator</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetLogonId">0x1cdcd9</Data>
    <Data Name="LogonType">7</Data>
  </EventData>
</Event>
```

## What to Look For (SOC Analyst Tips)
- Sessions with **very short duration** (login and logoff within seconds)
- Accounts that logged in but **4634 never appeared** (session still active — persistent access?)
- Logoff events from **service or system accounts** at unusual times
- Correlate the **LogonID** in 4634 with the same field in 4624 to match sessions

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Technique | T1078 – Valid Accounts (session tracking) |
