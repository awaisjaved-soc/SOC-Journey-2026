

### **4. Event 4740 – Account Locked Out**

**What it means:**  
User account got locked due to too many failed login attempts.

**SOC Importance:** **High** – Strong indicator of **Brute Force Attack**.

#### **Manual GUI Method**
- Just try wrong password 5+ times on the login screen of that user.

#### **PowerShell Method** (To trigger lockout)
```powershell
# Run this multiple times with wrong password
1..6 | ForEach-Object {
    $cred = New-Object System.Management.Automation.PSCredential("mannual", (ConvertTo-SecureString "WrongPass123" -AsPlainText -Force))
    Start-Process powershell -Credential $cred -NoNewWindow -ErrorAction SilentlyContinue
}
```
or
```powershell
$username = "mannual"
$wrongpass = ConvertTo-SecureString "WrongPass123" -AsPlainText -Force

1..7 | ForEach-Object {
    $cred = New-Object System.Management.Automation.PSCredential($username, $wrongpass)
    Start-Process powershell.exe -Credential $cred -NoNewWindow -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 700
}
```
---
```powershell
automation locking the account after multiple failed attempts like 5 attempts 
# Set Account Lockout Policy (Best for Lab)
Set-ADDefaultDomainPasswordPolicy -Identity "techcorp.local" `
    -LockoutThreshold 5 `          # Lock after 5 failed attempts
    -LockoutDuration "00:30:00" `  # Locked for 30 minutes
    -LockoutObservationWindow "00:30:00"  # Reset counter after 30 minutes
```
```powershell
Set-ADDefaultDomainPasswordPolicy -Identity "techcorp.local" `
    -LockoutThreshold 5 `
    -LockoutDuration "00:30:00" `
    -LockoutObservationWindow "00:30:00"
```
---

---
<img width="1008" height="761" alt="WhatsApp Image 2026-05-23 at 7 11 08 PM" src="https://github.com/user-attachments/assets/5cfe4592-4124-41a5-95ec-4749f4a8bce6" />

---

<img width="626" height="439" alt="WhatsApp Image 2026-05-23 at 7 12 28 PM" src="https://github.com/user-attachments/assets/12a9c873-92d3-44dd-90f4-051e199874cc" />



#### **Detection Command**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time          = $_.TimeCreated
        LockedUser    = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
        LockedFrom    = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
    }
} | Format-Table -AutoSize
```
---
<img width="981" height="509" alt="WhatsApp Image 2026-05-23 at 7 13 30 PM" src="https://github.com/user-attachments/assets/15109cca-0870-4094-aaf2-7138fecc920b" />

---
```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          5/22/2026 9:26:10 AM
Event ID:      4740
Task Category: User Account Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-N4LQQSU0MFA.techcorp.local
Description:
A user account was locked out.

Subject:
	Security ID:		SYSTEM
	Account Name:		WIN-N4LQQSU0MFA$
	Account Domain:		TECHCORP
	Logon ID:		0x3E7

Account That Was Locked Out:
	Security ID:		TECHCORP\mannual
	Account Name:		mannual

Additional Information:
	Caller Computer Name:	WIN-N4LQQSU0MFA
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4740</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13824</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-05-22T04:26:10.5169006Z" />
    <EventRecordID>16564</EventRecordID>
    <Correlation />
    <Execution ProcessID="624" ThreadID="3232" />
    <Channel>Security</Channel>
    <Computer>WIN-N4LQQSU0MFA.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserName">mannual</Data>
    <Data Name="TargetDomainName">WIN-N4LQQSU0MFA</Data>
    <Data Name="TargetSid">S-1-5-21-3567083499-616298403-1270708564-1122</Data>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">WIN-N4LQQSU0MFA$</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x3e7</Data>
  </EventData>
</Event>
```
<img width="411" height="533" alt="WhatsApp Image 2026-05-23 at 7 27 43 PM" src="https://github.com/user-attachments/assets/6574fb4d-c26c-4b7c-a274-88f544361312" />



