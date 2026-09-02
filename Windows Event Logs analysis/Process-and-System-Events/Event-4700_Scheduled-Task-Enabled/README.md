# Event 4700 – Scheduled Task Enabled

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4700 |
| **Category** | Process & System Events |
| **Log** | Security |
| **Tier** | 🟠 Tier 2 – High Value |
| **SOC Importance** | 🟡 Medium |

## What Is This Event?

Event 4700 is generated when a **previously disabled scheduled task is re-enabled**. Attackers may disable a task temporarily to avoid detection during an investigation, then re-enable it once they believe the threat has passed. This event is most useful when combined with Event 4701 (Task Disabled) to understand the full enable/disable lifecycle of a task.

---

## Setup – Must Do First

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
gpupdate /force
```

---

## How to Generate This Event

### Method 1 – GUI
1. Open **Task Scheduler** (`taskschd.msc`)
2. Find any task (or create `EnableTestTask`)
3. Right-click → **Disable** (this generates Event 4701)
4. Right-click → **Enable** (this generates **Event 4700**)

---

<img width="469" height="334" alt="Screenshot_2" src="https://github.com/user-attachments/assets/8b6bb004-504a-4e9d-98d8-8bc5c722ce2c" />

---

<img width="623" height="288" alt="Screenshot_3" src="https://github.com/user-attachments/assets/8db8c7ab-c465-4553-b7f8-1a5b065bfc0a" />

---


### Method 2 – PowerShell (Full Sequence)
```powershell
# Step 1 – Create a task
$action = New-ScheduledTaskAction -Execute "calc.exe"
Register-ScheduledTask -TaskName "EnableTestTask" -Action $action

# Step 2 – Disable it first (generates 4701)
Disable-ScheduledTask -TaskName "EnableTestTask"

# Step 3 – Enable it (generates 4700)
Enable-ScheduledTask -TaskName "EnableTestTask"
```

---

<img width="808" height="378" alt="Screenshot_4" src="https://github.com/user-attachments/assets/8445071c-b7dc-4a1d-a583-702454bfd0b9" />

---

## Detection Commands

### Basic Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4700} -MaxEvents 5 |
Select-Object TimeCreated, Id, Message | Format-List
```

### See Enable and Disable Together
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4700,4701} -MaxEvents 10 |
Select-Object TimeCreated, Id, Message |
Sort-Object TimeCreated |
Format-Table -AutoSize -Wrap
```
---

<img width="681" height="385" alt="Screenshot_1" src="https://github.com/user-attachments/assets/28c31166-a17c-4913-b2f2-68344171c028" />

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          9/2/2026 9:59:50 PM
Event ID:      4700
Task Category: Other Object Access Events
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
A scheduled task was enabled.

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x2970A4

Task Information:
	Task Name: 		\test-task
	Task Content: 		<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-09-02T21:58:20.9058108</Date>
    <Author>TECHCORP\administrator</Author>
    <URI>\test-task</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-2393829360-1893506578-1941953886-500</UserId>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
  </Settings>
  <Triggers>
    <LogonTrigger>
      <UserId>TECHCORP\Administrator</UserId>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\notepad.exe</Command>
    </Exec>
  </Actions>
</Task>

Other Information:
	ProcessCreationTime: 		3659174697238867
	ClientProcessId: 			3904
	ParentProcessId: 			6476
	FQDN: 		0
	
Event Xml:
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4700</EventID>
    <Version>1</Version>
    <Level>0</Level>
    <Task>12804</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-03T04:59:50.2464545Z" />
    <EventRecordID>12261</EventRecordID>
    <Correlation ActivityID="{243ab529-3b5d-0002-9cb5-3a245d3bdd01}" />
    <Execution ProcessID="684" ThreadID="4792" />
    <Channel>Security</Channel>
    <Computer>WIN-LFHCJK09RND.techcorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-2393829360-1893506578-1941953886-500</Data>
    <Data Name="SubjectUserName">administrator</Data>
    <Data Name="SubjectDomainName">TECHCORP</Data>
    <Data Name="SubjectLogonId">0x2970a4</Data>
    <Data Name="TaskName">\test-task</Data>
    <Data Name="TaskContent">&lt;?xml version="1.0" encoding="UTF-16"?&gt;
&lt;Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"&gt;
  &lt;RegistrationInfo&gt;
    &lt;Date&gt;2026-09-02T21:58:20.9058108&lt;/Date&gt;
    &lt;Author&gt;TECHCORP\administrator&lt;/Author&gt;
    &lt;URI&gt;\test-task&lt;/URI&gt;
  &lt;/RegistrationInfo&gt;
  &lt;Principals&gt;
    &lt;Principal id="Author"&gt;
      &lt;UserId&gt;S-1-5-21-2393829360-1893506578-1941953886-500&lt;/UserId&gt;
      &lt;LogonType&gt;InteractiveToken&lt;/LogonType&gt;
    &lt;/Principal&gt;
  &lt;/Principals&gt;
  &lt;Settings&gt;
    &lt;DisallowStartIfOnBatteries&gt;true&lt;/DisallowStartIfOnBatteries&gt;
    &lt;StopIfGoingOnBatteries&gt;true&lt;/StopIfGoingOnBatteries&gt;
    &lt;MultipleInstancesPolicy&gt;IgnoreNew&lt;/MultipleInstancesPolicy&gt;
    &lt;IdleSettings&gt;
      &lt;Duration&gt;PT10M&lt;/Duration&gt;
      &lt;WaitTimeout&gt;PT1H&lt;/WaitTimeout&gt;
      &lt;StopOnIdleEnd&gt;true&lt;/StopOnIdleEnd&gt;
      &lt;RestartOnIdle&gt;false&lt;/RestartOnIdle&gt;
    &lt;/IdleSettings&gt;
  &lt;/Settings&gt;
  &lt;Triggers&gt;
    &lt;LogonTrigger&gt;
      &lt;UserId&gt;TECHCORP\Administrator&lt;/UserId&gt;
    &lt;/LogonTrigger&gt;
  &lt;/Triggers&gt;
  &lt;Actions Context="Author"&gt;
    &lt;Exec&gt;
      &lt;Command&gt;C:\Windows\notepad.exe&lt;/Command&gt;
    &lt;/Exec&gt;
  &lt;/Actions&gt;
&lt;/Task&gt;</Data>
    <Data Name="ClientProcessStartKey">3659174697238867</Data>
    <Data Name="ClientProcessId">3904</Data>
    <Data Name="ParentProcessId">6476</Data>
    <Data Name="RpcCallClientLocality">0</Data>
    <Data Name="FQDN">WIN-LFHCJK09RND.techcorp.local</Data>
  </EventData>
</Event>
```

---

## SOC Analyst Notes

| Scenario | Risk |
|----------|------|
| Task re-enabled after an incident was investigated | 🔴 Attacker returning |
| Task enabled by a non-admin user | 🔴 Unauthorized change |
| Enable/disable cycling on a task in short time | 🟡 Evasion technique |
| Security or backup task disabled then re-enabled | 🟡 Confirm with admin |

### Related Events

| Event ID | Relationship |
|----------|-------------|
| 4698 | Task originally created |
| 4701 | Task was disabled (pairs with 4700) |
| 4702 | Task was modified |
| 4699 | Task was deleted |
