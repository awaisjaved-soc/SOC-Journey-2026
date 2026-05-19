

---

### **Event 4725 – User Account Disabled**

**What it means:**  
This event logs when an account is disabled.

**SOC Importance:** Medium — Can be normal HR action or attacker disabling accounts to hide.

#### **Method 1: PowerShell**

```powershell
# Disable user account
Disable-ADAccount -Identity "testuser01"
```

**Explanation:**  
`Disable-ADAccount` → Specifically disables the user account.

#### **Method 2: Manual GUI**

1. Open `dsa.msc`
2. Find the user → Right click → **Disable Account**

---
<img width="630" height="442" alt="EVENT 4725" src="https://github.com/user-attachments/assets/72f8eba3-84fb-4fd3-bf13-1ae50bd9cba1" />

---
```
# Detection Command for 4725
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4725
} -MaxEvents 5 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated     = $_.TimeCreated
        EventID         = 4725
        DisabledBy      = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
        DisabledUser    = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
    }

} | Format-Table -AutoSize

```
---
<img width="759" height="529" alt="image" src="https://github.com/user-attachments/assets/a9160a8d-ea1d-46a5-a291-cf3eaa689bf9" />

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          5/19/2026 6:20:47 PM
Event ID:      4725
Task Category: User Account Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-N4LQQSU0MFA.techcorp.local
Description:
A user account was disabled.

Subject:
	Security ID:		TECHCORP\Administrator
	Account Name:		Administrator
	Account Domain:		TECHCORP
	Logon ID:		0x40D32

Target Account:
	Security ID:		TECHCORP\testuser01
	Account Name:		testuser01
	Account Domain:		TECHCORP
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4725</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13824</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-05-20T01:20:47.9856337Z" />
    <EventRecordID>7989</EventRecordID>
    <Correlation />
    <Execution ProcessID="620" ThreadID="2812" />
    <Channel>Security</Channel>
    <Computer>WIN-N4LQQSU0MFA.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserName">testuser01</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-3567083499-616298403-1270708564-1117</Data>
    <Data Name="SubjectUserSid">S-1-5-21-3567083499-616298403-1270708564-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x40d32</Data>
  </EventData>
</Event>
```
---


