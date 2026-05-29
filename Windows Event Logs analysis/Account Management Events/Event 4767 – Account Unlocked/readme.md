


### **5. Event 4767 – Account Unlocked**

**What it means:**  
A locked account was manually unlocked by admin.

**SOC Importance:** Medium – Often comes after 4740.

#### **Manual GUI Method**
1. Open `dsa.msc`
2. Right click on locked user → **Enable Account** (or Properties → Uncheck "Account is locked out")

#### **PowerShell Method**
```powershell
Unlock-ADAccount -Identity "mannual"
```
---
<img width="411" height="533" alt="WhatsApp Image 2026-05-23 at 7 27 43 PM" src="https://github.com/user-attachments/assets/93a19631-8981-4508-ae02-8f718979e06b" />

---
<img width="633" height="434" alt="WhatsApp Image 2026-05-23 at 7 27 49 PM" src="https://github.com/user-attachments/assets/c512312a-aeb0-45ef-825d-5b67ab149154" />

---

#### **Detection Command**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4767} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time          = $_.TimeCreated
        UnlockedBy    = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
        UnlockedUser  = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```
---

<img width="970" height="279" alt="WhatsApp Image 2026-05-23 at 7 33 51 PM" src="https://github.com/user-attachments/assets/5cc98e95-5f10-43f1-845f-dd88b1695de6" />

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          5/22/2026 9:43:35 AM
Event ID:      4767
Task Category: User Account Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-N4LQQSU0MFA.techcorp.local
Description:
A user account was unlocked.

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x62B699

Target Account:
	Security ID:		TECHCORP\mannual
	Account Name:		mannual
	Account Domain:		TECHCORP
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4767</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13824</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-05-22T04:43:35.4048943Z" />
    <EventRecordID>16829</EventRecordID>
    <Correlation />
    <Execution ProcessID="624" ThreadID="2984" />
    <Channel>Security</Channel>
    <Computer>WIN-N4LQQSU0MFA.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserName">mannual</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-3567083499-616298403-1270708564-1122</Data>
    <Data Name="SubjectUserSid">S-1-5-21-3567083499-616298403-1270708564-500</Data>
    <Data Name="SubjectUserName">administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x62b699</Data>
  </EventData>
</Event>
```

---

