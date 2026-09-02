# Event 4701 – Scheduled Task Disabled

## Overview

| Field | Details |
|-------|---------|
| **Event ID** | 4701 |
| **Category** | Process & System Events |
| **Log** | Security |
| **Tier** | 🟠 Tier 2 – High Value |
| **SOC Importance** | 🟡 Medium |

## What Is This Event?

Event 4701 is logged when a **scheduled task is disabled**. While this is often a legitimate administrative action, attackers may disable security-related or monitoring tasks to reduce visibility and avoid detection. SOC analysts should investigate when critical system tasks are disabled — especially by non-admin users or during unusual hours.

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
2. Find the task `EnableTestTask` (or any task)
3. Right-click → **Disable**

---

<img width="469" height="332" alt="Screenshot_1" src="https://github.com/user-attachments/assets/fecd7bc4-d814-4dd9-80fd-3c3b68c42d0c" />

---

<img width="818" height="333" alt="Screenshot_2" src="https://github.com/user-attachments/assets/0b12a333-a212-49b1-9cf2-3caed7a653a3" />

---

### Method 2 – PowerShell
```powershell
Disable-ScheduledTask -TaskName "EnableTestTask"
```

### Full Lab Sequence
```powershell
# Create task first
$action = New-ScheduledTaskAction -Execute "calc.exe"
Register-ScheduledTask -TaskName "EnableTestTask" -Action $action

# Disable the task (generates 4701)
Disable-ScheduledTask -TaskName "EnableTestTask"
```

---

## Detection Commands

### Basic Detection
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4701} -MaxEvents 5 |
Select-Object TimeCreated, Id, Message | Format-List
```

---

<img width="677" height="387" alt="Screenshot_3" src="https://github.com/user-attachments/assets/fe3d9993-71bc-4dca-bdf2-ea915f97cf70" />

---

```powershell
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          9/2/2026 9:52:50 PM
Event ID:      4701
Task Category: Other Object Access Events
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      WIN-LFHCJK09RND.techcorp.local
Description:
A scheduled task was disabled.

Subject:
	Security ID:		TECHCORP\administrator
	Account Name:		administrator
	Account Domain:		TECHCORP
	Logon ID:		0x2970A4

Task Information:
	Task Name: 		\test-task
	Task Content: 		<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-09-02T21:24:06.0342725</Date>
    <Author>TECHCORP\administrator</Author>
    <URI>\test-task</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-2393829360-1893506578-1941953886-500</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <Enabled>false</Enabled>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
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
    <EventID>4701</EventID>
    <Version>1</Version>
    <Level>0</Level>
    <Task>12804</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-03T04:52:50.0497140Z" />
    <EventRecordID>12132</EventRecordID>
    <Correlation ActivityID="{243ab529-3b5d-0002-9cb5-3a245d3bdd01}" />
    <Execution ProcessID="684" ThreadID="344" />
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
&lt;Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"&gt;
  &lt;RegistrationInfo&gt;
    &lt;Date&gt;2026-09-02T21:24:06.0342725&lt;/Date&gt;
    &lt;Author&gt;TECHCORP\administrator&lt;/Author&gt;
    &lt;URI&gt;\test-task&lt;/URI&gt;
  &lt;/RegistrationInfo&gt;
  &lt;Principals&gt;
    &lt;Principal id="Author"&gt;
      &lt;UserId&gt;S-1-5-21-2393829360-1893506578-1941953886-500&lt;/UserId&gt;
      &lt;LogonType&gt;InteractiveToken&lt;/LogonType&gt;
      &lt;RunLevel&gt;HighestAvailable&lt;/RunLevel&gt;
    &lt;/Principal&gt;
  &lt;/Principals&gt;
  &lt;Settings&gt;
    &lt;DisallowStartIfOnBatteries&gt;false&lt;/DisallowStartIfOnBatteries&gt;
    &lt;StopIfGoingOnBatteries&gt;true&lt;/StopIfGoingOnBatteries&gt;
    &lt;Enabled&gt;false&lt;/Enabled&gt;
    &lt;MultipleInstancesPolicy&gt;IgnoreNew&lt;/MultipleInstancesPolicy&gt;
    &lt;IdleSettings&gt;
      &lt;StopOnIdleEnd&gt;true&lt;/StopOnIdleEnd&gt;
      &lt;RestartOnIdle&gt;false&lt;/RestartOnIdle&gt;
    &lt;/IdleSettings&gt;
    &lt;UseUnifiedSchedulingEngine&gt;true&lt;/UseUnifiedSchedulingEngine&gt;
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
| Windows Defender or backup task disabled | 🔴 Attacker disabling security |
| Task disabled by a non-admin | 🔴 Unauthorized change |
| Task disabled outside business hours | 🟡 Suspicious |
| Admin disabling a test or temp task | 🟢 Normal — verify with admin |

> **Key question in any investigation:** Which task was disabled, who disabled it, and does that match authorized change management records?
