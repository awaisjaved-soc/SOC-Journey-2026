# Event 4698 – Scheduled Task Created

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4698 |
| **Category** | Process & System Events |
| **Log** | Security |
| **Tier** | 🟠 Tier 2 – High Value |
| **SOC Importance** | 🔴 High |

## What Is This Event?

Event 4698 is generated whenever a **new scheduled task is created** on the system. Scheduled tasks are one of the most common persistence techniques used by attackers. Malware and threat actors frequently create scheduled tasks so their payload runs automatically — even after the system reboots or the user logs off.

In a SOC environment, this event should be closely monitored, especially when tasks are created by unusual users, from unexpected locations, or with suspicious command lines pointing to scripts or binaries in temp folders.

---

## Setup – Must Do First

Run this command as **Administrator** before generating or detecting this event:

```powershell
# Enable auditing for Scheduled Task events
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
gpupdate /force
```

### Verify the Policy is Active

```powershell
auditpol /get /subcategory:"Other Object Access Events"
```

Expected output: `Other Object Access Events   Success and Failure`

---

## How to Generate This Event

### Method 1 – GUI (Task Scheduler)
1. Open **Task Scheduler** — press `Win + R` → type `taskschd.msc` → Enter
2. Click **Create Basic Task** in the right panel
3. Name it `TestTask4698`
4. Set trigger to **"When I log on"**
5. Action → **Start a program** → enter `notepad.exe`
6. Click **Finish**

---


<img width="590" height="421" alt="Screenshot_1" src="https://github.com/user-attachments/assets/3345fb63-e46f-4184-923d-f5d69d312036" />

---
<img width="590" height="423" alt="Screenshot_2" src="https://github.com/user-attachments/assets/357e3de7-3513-495c-ab7b-3dbcdd9e9a91" />

---

<img width="586" height="423" alt="Screenshot_3" src="https://github.com/user-attachments/assets/449305f2-bcda-4577-8217-8d5bc3824f84" />

---

<img width="584" height="422" alt="Screenshot_4" src="https://github.com/user-attachments/assets/60b202bf-17a0-44bf-ad41-82dfc8259712" />

---

### Method 2 – PowerShell (Standard)
```powershell
$action = New-ScheduledTaskAction -Execute "notepad.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "TestTask4698" -Action $action -Trigger $trigger -Description "SOC Lab Test Task"
```
---
<img width="588" height="422" alt="Screenshot_5" src="https://github.com/user-attachments/assets/0bb62edd-e39c-468a-a1e3-bc8576bc74ba" />

---

<img width="587" height="422" alt="Screenshot_6" src="https://github.com/user-attachments/assets/f5b702ef-bd68-4b62-af0c-0b15e1a5f3be" />

---


<img width="588" height="425" alt="Screenshot_7" src="https://github.com/user-attachments/assets/5a2a04b5-b15c-4daf-b1b1-f0572c6ebe28" />



### Method 3 – PowerShell (Visible Task – Runs on Screen)
By default, tasks run under the SYSTEM account which has no desktop — so Notepad won't appear on screen. Use this method to create a visible task:

```powershell
$action = New-ScheduledTaskAction -Execute "notepad.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "Administrator" -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName "VisibleNotepadTask" -Action $action -Trigger $trigger -Principal $principal -Description "Visible Task for Lab"
```

Then go to Task Scheduler → Right-click **VisibleNotepadTask** → **Run** — Notepad will open on screen.

---

## Common Issue – Notepad Not Appearing on Screen

If you create a task and run it but Notepad does not open, this is expected behavior. Here is why and how to fix it:

**Why this happens:** Scheduled tasks run under the **SYSTEM** account by default. The SYSTEM account has no desktop session, so GUI programs like Notepad run invisibly in the background.

**Fix via Task Scheduler GUI:**
1. Open Task Scheduler → Find your task → Right-click → **Properties**
2. **General Tab:** Select **"Run only when user is logged on"** and check **"Run with highest privileges"**
3. **Conditions Tab:** Uncheck everything (especially "Start only if on AC power")
4. **Settings Tab:** Check **"Allow task to be run on demand"**
5. Click **OK** → Right-click the task → **Run**

---

<img width="588" height="246" alt="Screenshot_8" src="https://github.com/user-attachments/assets/ad03ec85-c1e2-4401-ac84-7fdb5dfd5530" />

---

<img width="587" height="230" alt="Screenshot_9" src="https://github.com/user-attachments/assets/3edeb8f3-1912-4aab-b2b3-60520da44171" />

---

## Detection Commands

### Basic Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} -MaxEvents 5 |
Select-Object TimeCreated, Id, Message | Format-List
```
<img width="627" height="426" alt="Screenshot_10" src="https://github.com/user-attachments/assets/6597fd41-00f8-4567-a8dd-bc11d1d85e4b" />

---

<img width="678" height="140" alt="Screenshot_12" src="https://github.com/user-attachments/assets/a2ea177d-59db-4a20-938e-241b8b497360" />

---

### Extended Detection with XML Parsing
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} -MaxEvents 5 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time     = $_.TimeCreated
        TaskName = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TaskName'}).'#text'
        User     = ($xml.Event.EventData.Data | Where {$_.Name -eq 'SubjectUserName'}).'#text'
    }
} | Format-Table -AutoSize
```
---
<img width="612" height="163" alt="Screenshot_11" src="https://github.com/user-attachments/assets/285da56a-bac6-4d45-84ce-74db5dd4c1f7" />

---
<img width="633" height="225" alt="Screenshot_13" src="https://github.com/user-attachments/assets/9e2ddeda-6a7b-45cc-8a47-6535a9891dde" />

---

## SOC Analyst Notes

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          9/2/2026 9:24:06 PM
Event ID:      4698
Task Category: Other Object Access Events
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
A scheduled task was created.

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x57D34

Task Information:
	Task Name: 		\test-task
	Task Content: 		<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-09-02T21:24:06.0342725</Date>
    <Author>TECHCORP\administrator</Author>
    <URI>\test-task</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>TECHCORP\administrator</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <RunLevel>LeastPrivilege</RunLevel>
      <UserId>TECHCORP\administrator</UserId>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\notepad.exe</Command>
    </Exec>
  </Actions>
</Task>

Other Information:
	ProcessCreationTime: 		3377699720528669
	ClientProcessId: 			6896
	ParentProcessId: 			5248
	FQDN: 		0
	
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4698</EventID>
    <Version>1</Version>
    <Level>0</Level>
    <Task>12804</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-03T04:24:06.1321067Z" />
    <EventRecordID>10719</EventRecordID>
    <Correlation ActivityID="{6f3f901a-3b49-0002-5b90-3f6f493bdd01}" />
    <Execution ProcessID="676" ThreadID="796" />
    <Channel>Security</Channel>
    <Computer>WIN-LFHCJK09RND.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-2393829360-1893506578-1941953886-500</Data>
    <Data Name="SubjectUserName">administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x57d34</Data>
    <Data Name="TaskName">\test-task</Data>
    <Data Name="TaskContent">&lt;?xml version="1.0" encoding="UTF-16"?&gt;
&lt;Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"&gt;
  &lt;RegistrationInfo&gt;
    &lt;Date&gt;2026-09-02T21:24:06.0342725&lt;/Date&gt;
    &lt;Author&gt;TECHCORP\administrator&lt;/Author&gt;
    &lt;URI&gt;\test-task&lt;/URI&gt;
  &lt;/RegistrationInfo&gt;
  &lt;Triggers&gt;
    &lt;LogonTrigger&gt;
      &lt;Enabled&gt;true&lt;/Enabled&gt;
      &lt;UserId&gt;TECHCORP\administrator&lt;/UserId&gt;
    &lt;/LogonTrigger&gt;
  &lt;/Triggers&gt;
  &lt;Principals&gt;
    &lt;Principal id="Author"&gt;
      &lt;RunLevel&gt;LeastPrivilege&lt;/RunLevel&gt;
      &lt;UserId&gt;TECHCORP\administrator&lt;/UserId&gt;
      &lt;LogonType&gt;InteractiveToken&lt;/LogonType&gt;
    &lt;/Principal&gt;
  &lt;/Principals&gt;
  &lt;Settings&gt;
    &lt;MultipleInstancesPolicy&gt;IgnoreNew&lt;/MultipleInstancesPolicy&gt;
    &lt;DisallowStartIfOnBatteries&gt;true&lt;/DisallowStartIfOnBatteries&gt;
    &lt;StopIfGoingOnBatteries&gt;true&lt;/StopIfGoingOnBatteries&gt;
    &lt;AllowHardTerminate&gt;true&lt;/AllowHardTerminate&gt;
    &lt;StartWhenAvailable&gt;false&lt;/StartWhenAvailable&gt;
    &lt;RunOnlyIfNetworkAvailable&gt;false&lt;/RunOnlyIfNetworkAvailable&gt;
    &lt;IdleSettings&gt;
      &lt;Duration&gt;PT10M&lt;/Duration&gt;
      &lt;WaitTimeout&gt;PT1H&lt;/WaitTimeout&gt;
      &lt;StopOnIdleEnd&gt;true&lt;/StopOnIdleEnd&gt;
      &lt;RestartOnIdle&gt;false&lt;/RestartOnIdle&gt;
    &lt;/IdleSettings&gt;
    &lt;AllowStartOnDemand&gt;true&lt;/AllowStartOnDemand&gt;
    &lt;Enabled&gt;true&lt;/Enabled&gt;
    &lt;Hidden&gt;false&lt;/Hidden&gt;
    &lt;RunOnlyIfIdle&gt;false&lt;/RunOnlyIfIdle&gt;
    &lt;WakeToRun&gt;false&lt;/WakeToRun&gt;
    &lt;ExecutionTimeLimit&gt;P3D&lt;/ExecutionTimeLimit&gt;
    &lt;Priority&gt;7&lt;/Priority&gt;
  &lt;/Settings&gt;
  &lt;Actions Context="Author"&gt;
    &lt;Exec&gt;
      &lt;Command&gt;C:\Windows\notepad.exe&lt;/Command&gt;
    &lt;/Exec&gt;
  &lt;/Actions&gt;
&lt;/Task&gt;</Data>
    <Data Name="ClientProcessStartKey">3377699720528669</Data>
    <Data Name="ClientProcessId">6896</Data>
    <Data Name="ParentProcessId">5248</Data>
    <Data Name="RpcCallClientLocality">0</Data>
    <Data Name="FQDN">WIN-LFHCJK09RND.techcorp.local</Data>
  </EventData>
</Event>
```

### What to Look For

| Indicator | Risk |
|-----------|------|
| Task created by a non-admin user | 🔴 Investigate immediately |
| Task command points to `%TEMP%`, `%APPDATA%`, or `C:\Users\Public` | 🔴 Malware dropper |
| Task created outside business hours | 🟡 Suspicious |
| Task runs `powershell.exe`, `cmd.exe`, or `wscript.exe` with arguments | 🔴 Likely malicious |
| Task name looks like a legitimate Windows task but is slightly different | 🔴 Masquerading |
| Task created right after a failed login or phishing email | 🔴 Compromise in progress |

### Attack Scenario

```
Attacker gets foothold
    → Drops payload to C:\Users\Public\update.exe
    → Creates scheduled task: schtasks /create /tn "WindowsUpdate" /tr "C:\Users\Public\update.exe" /sc onlogon
    → Event 4698 fires
    → Analyst sees task with suspicious path and unusual name
```

### Related Events

| Event ID | Relationship |
|----------|-------------|
| 4699 | Task was deleted (attacker cleaning up) |
| 4700 | Task was enabled |
| 4701 | Task was disabled |
| 4702 | Task was modified |
| 4688 | Process created when the task runs |
