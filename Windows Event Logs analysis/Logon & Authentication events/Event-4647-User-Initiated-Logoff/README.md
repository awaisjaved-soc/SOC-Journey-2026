# Event 4647 – User Initiated Logoff

## Event Description
Event 4647 is generated when a **user manually initiates a logoff** by clicking Sign Out from the Start menu or using `shutdown /l`. It is very similar to Event 4634 but specifically records a **user-initiated** action rather than a system or session timeout.

> 💡 Key difference: **4634** = session ended (any reason) | **4647** = user clicked "Sign out" themselves

---

## SOC Relevance
- Helps **differentiate** between normal user logoff vs system-forced termination
- Useful for understanding **user behavior patterns**
- Can indicate an attacker **cleanly logging off** after completing their objective
- Pairs with 4624 to complete full session timeline

---

## Lab Method 1 – Manual GUI

1. Login as `scott`
2. Click **Start** → **Power button** → **Sign out**
3. Event 4647 will be generated

---

<img width="625" height="439" alt="image" src="https://github.com/user-attachments/assets/1c88ea00-abf0-44a1-83b9-928f22ac8966" />

---

## Lab Method 2 – PowerShell

```powershell
shutdown /l
```

---

## Detection Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4647} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time = $_.TimeCreated
        User = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```
---

<img width="975" height="515" alt="image" src="https://github.com/user-attachments/assets/f660c6fb-03de-474e-b836-31b62426a0e5" />

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/18/2026 9:01:01 AM
Event ID:      4647
Task Category: Logoff
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-KAHJ94DKN9V.techcorp.local
Description:
User initiated logoff:

Subject:
	Security ID:		TECHCORP\alexrivera
	Account Name:		alexrivera
	Account Domain:		TECHCORP
	Logon ID:		0x2DF2A3

This event is generated when a logoff is initiated. No further user-initiated activity can occur. This event can be interpreted as a logoff event.
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4647</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12545</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-18T16:01:01.1218111Z" />
    <EventRecordID>3281</EventRecordID>
    <Correlation ActivityID="{423bbde8-16cb-0001-15be-3b42cb16dd01}" />
    <Execution ProcessID="648" ThreadID="8576" />
    <Channel>Security</Channel>
    <Computer>WIN-KAHJ94DKN9V.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserSid">S-1-5-21-2896402138-2534863141-3184233234-1114</Data>
    <Data Name="TargetUserName">alexrivera</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetLogonId">0x2df2a3</Data>
  </EventData>
</Event>
```

## What to Look For (SOC Analyst Tips)
- 4647 appearing for **admin accounts at odd hours** (attacker signing out after work)
- 4647 without a corresponding **4624** earlier (session anomaly)
- Multiple sign-outs in quick succession across different accounts
- Sign-out on **critical servers** (Domain Controller, file servers) unexpectedly

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Technique | T1070 – Indicator Removal (cleaning up session traces) |
