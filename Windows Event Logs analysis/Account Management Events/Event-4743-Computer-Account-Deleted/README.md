# Event 4743 – Computer Account Deleted

## Event Description
This event is logged when a **computer account is deleted** from the Active Directory domain.  
Legitimate deletions happen during decommissioning of machines, but attackers also delete accounts to **cover their tracks** after use.

## SOC Relevance
After using a rogue computer account for lateral movement or Kerberos attacks, an attacker may delete it to remove evidence. Sudden deletion of computer accounts — especially ones recently created — is a strong red flag.

---

## Lab Method 1 – Manual GUI

1. Open **Active Directory Users and Computers** (`dsa.msc`)
2. Navigate to the **Computers** container
3. Right-click the computer account → **Delete**
4. Confirm deletion

---

<img width="625" height="435" alt="image" src="https://github.com/user-attachments/assets/650b70be-780f-4b6b-a3e1-653d2dc4fcee" />

---



## Lab Method 2 – PowerShell

```powershell
Remove-ADComputer -Identity "ROGUE-PC-01" -Confirm:$false
```
---

<img width="643" height="119" alt="image" src="https://github.com/user-attachments/assets/b7711fcc-0569-4e36-a9af-a32f59abde2c" />

---

## Detection Command

Run this on your **Domain Controller** to detect Event 4743:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4743} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time         = $_.TimeCreated
        DeletedBy    = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
        ComputerName = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
    }
} | Format-Table -AutoSize
```
---

<img width="980" height="521" alt="WhatsApp Image 2026-07-12 at 4 19 42 PM" src="https://github.com/user-attachments/assets/0103a5d1-3efb-4e24-8c99-ebdb97980362" />

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          7/12/2026 3:05:53 PM
Event ID:      4743
Task Category: Computer Account Management
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-G2FL349UD7V.techcorp.local
Description:
A computer account was deleted.

Subject:
	Security ID:		TECHCORP\Administrator
	Account Name:		Administrator
	Account Domain:		TECHCORP
	Logon ID:		0x9745A

Target Computer:
	Security ID:		TECHCORP\TEST-COMPUTER$
	Account Name:		TEST-COMPUTER$
	Account Domain:		TECHCORP

Additional Information:
	Privileges:		-
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4743</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13825</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-12T22:05:53.7134829Z" />
    <EventRecordID>5204</EventRecordID>
    <Correlation />
    <Execution ProcessID="688" ThreadID="2076" />
    <Channel>Security</Channel>
    <Computer>WIN-G2FL349UD7V.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserName">TEST-COMPUTER$</Data>
    <Data Name="TargetDomainName">TECHCORP</Data>
    <Data Name="TargetSid">S-1-5-21-2093721230-1860313452-4243889928-1116</Data>
    <Data Name="SubjectUserSid">S-1-5-21-2093721230-1860313452-4243889928-500</Data>
    <Data Name="SubjectUserName">Administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x9745a</Data>
    <Data Name="PrivilegeList">-</Data>
  </EventData>
</Event>
```

## What to Look For (SOC Analyst Tips)
- Computer account deleted **shortly after it was created** (Event 4741 → 4743 pair)
- Deletion performed by a **non-standard admin** account
- Deletion of accounts that had **recent logon activity**
- Multiple deletions in a short time window (cleanup sweep)

---

## MITRE ATT&CK Mapping
| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Technique | T1070 – Indicator Removal |
