
---

### **6. Event 4781 – Account Name Changed**

**What it means:**  
The name (SamAccountName or Display Name) of an account was changed.

**SOC Importance:** High – Attackers use this to camouflage accounts.

#### **Manual GUI Method**
1. Open `dsa.msc`
2. Right click user → **Rename** → Enter new name

#### **PowerShell Method**
```powershell
Rename-ADObject -Identity (Get-ADUser -Identity "mannual").DistinguishedName -NewName "svc-itadmin"
```
---
<img width="378" height="327" alt="WhatsApp Image 2026-05-23 at 7 42 28 PM" src="https://github.com/user-attachments/assets/1bf951fa-2cf1-4c6d-9395-1cede1f45f61" />
---

<img width="630" height="438" alt="WhatsApp Image 2026-05-23 at 7 41 40 PM" src="https://github.com/user-attachments/assets/7c2c54e5-a184-432d-bbaf-f3047624053b" />
---

#### **Detection Command**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4781} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time      = $_.TimeCreated
        OldName   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'OldTargetUserName'}).'#text'
        NewName   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'NewTargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```

<img width="763" height="530" alt="WhatsApp Image 2026-05-23 at 7 42 45 PM" src="https://github.com/user-attachments/assets/28a2123f-6c44-4ff8-9073-716aeeb451b0" />




<img width="977" height="517" alt="WhatsApp Image 2026-05-23 at 7 44 13 PM" src="https://github.com/user-attachments/assets/a6836347-6c95-4eeb-ab59-119908fc5f2e" />





```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          5/22/2026 9:58:01 AM
Event ID:      4781
Task Category: User Account Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-N4LQQSU0MFA.techcorp.local
Description:
The name of an account was changed:

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x62B699

Target Account:
	Security ID:		TECHCORP\suspicioususer
	Account Domain:		TECHCORP
	Old Account Name:	suspicioususer
	New Account Name:	renameuser

Additional Information:
	Privileges:		-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4781</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13824</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-05-22T04:58:01.2258817Z" />
    <EventRecordID>16953</EventRecordID>
    <Correlation />
    <Execution ProcessID="624" ThreadID="2980" />
    <Channel>Security</Channel>
    <Computer>WIN-N4LQQSU0MFA.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="OldTargetUserName">suspicioususer</Data>
    <Data Name="NewTargetUserName">renameuser</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-3567083499-616298403-1270708564-1116</Data>
    <Data Name="SubjectUserSid">S-1-5-21-3567083499-616298403-1270708564-500</Data>
    <Data Name="SubjectUserName">administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x62b699</Data>
    <Data Name="PrivilegeList">-</Data>
  </EventData>
</Event>
```

