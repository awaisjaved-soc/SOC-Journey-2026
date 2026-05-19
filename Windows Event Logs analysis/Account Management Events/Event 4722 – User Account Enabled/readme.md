

### **Event 4722 – User Account Enabled**

**What it means:**  
This event is logged when a previously disabled account is re-enabled.

**SOC Importance:** Medium — Suspicious if done at odd hours or by non-HR staff.

#### **Method 1: PowerShell**

```powershell
# Enable disabled account
Enable-ADAccount -Identity "testuser01"
```

#### **Method 2: Manual GUI**

1. Open `dsa.msc`
2. Right click on disabled user → **Enable Account**

---

<img width="635" height="439" alt="EVENT 4722" src="https://github.com/user-attachments/assets/abd50714-d624-41b6-9e69-2d18a960a249" />



---
### Detection method using CMD
### **. Event 4722 – User Account Enabled**

```powershell
# Detection Command for 4722
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4722
} -MaxEvents 5 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated     = $_.TimeCreated
        EventID         = 4722
        EnabledBy       = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
        EnabledUser     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```

---

<img width="754" height="531" alt="image" src="https://github.com/user-attachments/assets/0e2d1437-16f9-4dde-a461-e08d03bff438" />

```
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          5/19/2026 6:22:36 PM
Event ID:      4722
Task Category: User Account Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-N4LQQSU0MFA.techcorp.local
Description:
A user account was enabled.

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
    <EventID>4722</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13824</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-05-20T01:22:36.9978105Z" />
    <EventRecordID>8032</EventRecordID>
    <Correlation />
    <Execution ProcessID="620" ThreadID="2840" />
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
