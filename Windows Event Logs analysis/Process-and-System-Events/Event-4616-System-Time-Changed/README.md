# Event ID 4616 — The System Time Was Changed

**Log:** Security  
**Category:** System  
**Subcategory:** Security State Change  
**Level:** Information  
**Lab Environment:** Windows Server 2019 — TECHCORP / techcorp.local

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 4616 |
| Event Name | The system time was changed |
| Log Location | Windows Logs → Security |
| Audit Category | System |
| Audit Subcategory | Security State Change |
| Default State | Enabled by default on most Windows systems |
| No SACL Required | Yes — this event fires automatically, no object-level auditing needed |

---

## What Is Event 4616?

Event 4616 is fundamentally different from the other four events in this tier. It belongs to the **System** audit category rather than Object Access, which means it does not require any SACL configuration on specific objects. Any change to the system clock — regardless of who makes it or how — automatically generates a 4616 event in the Security log, as long as the Security State Change audit subcategory is enabled.

The event records two pieces of information that make it uniquely valuable: the **Previous Time** (what the clock showed before the change) and the **New Time** (what it was set to). This before-and-after record cannot be erased by the time change itself, because the event is written to the Security log using the system's own logging mechanism, which records the event at the moment the kernel processes the time change call.

---

## The Anti-Forensics Technique This Event Detects

To understand why 4616 matters, you need to understand what attackers are trying to accomplish when they change the system clock.

Every event in the Windows Security log has a timestamp. Every file on the filesystem has created, modified, and accessed timestamps. Every network packet capture has a timestamp. Incident responders rebuild the timeline of an attack by correlating these timestamps across different systems and log sources — placing each attacker action in sequence to understand what happened, in what order, and how long each phase took.

If an attacker changes the system clock, all subsequent log entries are written with the wrong time. A log entry that should say "3:00 AM" might say "11:00 PM yesterday" instead. When the incident responder correlates logs across systems, the tampered machine's logs appear to show a different sequence of events, or appear to show activity happening before or after it actually did.

Specific scenarios where time manipulation causes damage to investigations:

**Log correlation failure** — SIEM platforms correlate events by timestamp. If one system's clock is off by two hours, alerts that should fire based on correlated events across systems will fail because the timestamps do not line up.

**Alibi construction** — If an attacker exfiltrates data at 3 AM and then moves the clock back to 1 AM, the log shows the exfiltration happening at 1 AM — before the attacker's VPN connection was established (which the firewall logs at 2 AM with the correct time). This creates a false appearance that the data was taken before the attacker was even connected.

**File timestamp manipulation** — When attackers create or modify files on the target system with the clock set to a different time, the file metadata shows the wrong creation and modification times. This can place files in a timeframe before the attacker was present.

**Certificate validation bypass** — Some software checks whether a certificate is currently valid. Setting the clock to a date within an expired certificate's validity period can bypass this check.

Event 4616 is the one audit record that directly counters this technique. The event itself contains both the real time it was written (the OS records this before applying the new time) and the new time being set, allowing investigators to reconstruct exactly when the clock was changed and by how much.

---

## The NTP Normal Case

Not every 4616 event is malicious. The Windows Time service (`W32tm`) automatically synchronises the system clock with time servers on a regular schedule. Each sync that results in a clock adjustment generates a 4616 event. This is completely normal and the Security log on any domain-joined system will contain many 4616 events from `svchost.exe` running the Windows Time service.

The distinction between normal and suspicious 4616 events is almost entirely determined by the **Process Name** field:

| Process Name | Verdict |
|---|---|
| `svchost.exe` (hosting W32Time service) | Normal — NTP synchronisation |
| `w32tm.exe` | Normal — manual time sync command |
| `powershell.exe` | **Suspicious — investigate** |
| `cmd.exe` | **Suspicious — investigate** |
| Any other process | **Critical — immediate investigation** |

Additionally, the **magnitude of the time change** matters. NTP adjustments are typically less than a second, sometimes a few seconds. A change of minutes, hours, or days is a clear indicator of deliberate manipulation.

---

## What You Will See on Screen

Unlike the other four events in this tier, 4616 has a visible consequence — **your system clock changes**. If you have the clock visible in the taskbar, you will see it jump to the new time when you run the trigger commands. This makes 4616 the only event in Tier 3 where you can see the trigger effect on screen. After capturing the event, you must restore the correct time immediately to avoid disrupting other lab activities.

---

## Audit Policy Setup

### Check if Already Enabled

```cmd
auditpol /get /subcategory:"Security State Change"
```

On most Windows Server installations, this is already enabled. If the output shows `No Auditing`, enable it with:

### Method 1 — Group Policy (GUI)

1. Open **Group Policy Management** → right-click domain → **Edit**
2. Navigate to: `Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → System`
3. Double-click **Audit Security State Change**
4. Check **Configure the following audit events** → check **Success** → OK
5. Run `gpupdate /force`

### Method 2 — Command Line

```cmd
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
```

Verify:

```cmd
auditpol /get /subcategory:"Security State Change"
```

Expected: `Security State Change    Success and Failure`

> **No SACL required.** Unlike 4656, 4657, 4660, and 4663, Event 4616 fires automatically for any system clock change. There is no per-object auditing configuration needed.

---

## Generating the Event

> ⚠️ **Important:** These commands actually change your system clock. Note the current time before proceeding and restore it immediately after capturing the event.

### Method 1 — PowerShell (Recommended)

Open PowerShell as Administrator:

```powershell
# Record the exact current time before making any changes
$originalTime = Get-Date
Write-Host "Current time before change: $originalTime"
Write-Host "Changing clock forward by 2 hours to simulate attacker manipulation..."

# Change the system clock — this immediately fires Event 4616
Set-Date -Date (Get-Date).AddHours(2)

Write-Host "Clock changed. Check taskbar — time should show +2 hours."
Write-Host "Now go to Event Viewer → Security log → filter for Event ID 4616."
Write-Host ""
Write-Host "Press Enter when you have captured the screenshot..."
Read-Host

# Restore the correct time
Set-Date -Date $originalTime
Write-Host "Clock restored to: $(Get-Date)"
Write-Host "Event 4616 was generated for both the change and the restoration."
```

For a smaller, less disruptive change (still fires 4616):

```powershell
$originalTime = Get-Date
Write-Host "Original time: $originalTime"

# Move clock back by 30 minutes
Set-Date -Date (Get-Date).AddMinutes(-30)
Write-Host "Clock set back 30 minutes. Time is now: $(Get-Date)"

Start-Sleep -Seconds 3

# Restore
Set-Date -Date $originalTime
Write-Host "Clock restored to: $(Get-Date)"
```

### Method 2 — Command Line (CMD)

Open Command Prompt as Administrator:

```cmd
:: Note current time
echo Current time:
time /t

:: Change the time — adjust to something clearly different
time 23:59:00

:: Wait a moment
timeout /t 5

:: Restore manually — type the correct current time
time HH:MM:SS
```

### Method 3 — GUI Trigger

1. Right-click the clock in the taskbar → **Adjust date/time**
2. Turn off **Set time automatically**
3. Click **Change** next to Set the date and time manually
4. Change the hour by 1-2 hours → **Change**
5. This fires 4616 immediately
6. After capturing the screenshot, restore the correct time and re-enable automatic time sync

---

## Detecting the Event

### Method 1 — Event Viewer (GUI)

1. Open **Event Viewer** → **Windows Logs** → **Security**
2. **Filter Current Log** → Event ID: `4616` → OK
3. You will see multiple entries — your triggered change plus previous NTP sync events
4. Look for events with `powershell.exe` in the Process Name to identify your lab trigger
5. Double-click to view full details

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Subject: Account Name | Who changed the time |
| Subject: Logon ID | Links to logon session |
| Previous Time | What the clock showed before |
| New Time | What it was changed to |
| Process Name | **Critical** — `svchost.exe` = NTP normal / `powershell.exe` = suspicious |
| Process ID | Cross-reference with 4688 process creation |

### Method 2 — PowerShell Detection

```powershell
# Find all time change events in the last 24 hours
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4616
    StartTime = (Get-Date).AddDays(-1)
} | Select-Object TimeCreated, Message | Format-List
```

```powershell
# Extract key fields with XML parsing
$filter = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[EventID=4616]]
    </Select>
  </Query>
</QueryList>
"@

Get-WinEvent -FilterXml $filter | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time         = $_.TimeCreated
        AccountName  = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        PreviousTime = ($data | Where-Object { $_.Name -eq 'PreviousTime'    }).'#text'
        NewTime      = ($data | Where-Object { $_.Name -eq 'NewTime'         }).'#text'
        ProcessName  = ($data | Where-Object { $_.Name -eq 'ProcessName'     }).'#text'
    }
} | Format-Table -AutoSize
```

```powershell
# Hunt specifically for suspicious time changes — filter out known NTP processes
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4616
    StartTime = (Get-Date).AddDays(-7)
} | Where-Object {
    # Flag anything that is NOT the normal Windows Time service
    $_.Message -notlike "*svchost*" -and $_.Message -notlike "*w32tm*"
} | ForEach-Object {
    Write-Host "=== SUSPICIOUS TIME CHANGE DETECTED ===" -ForegroundColor Red
    Write-Host "Time of Event: $($_.TimeCreated)"
    Write-Host $_.Message
    Write-Host ""
}
```

```powershell
# Calculate the magnitude of the time change — large deltas are more suspicious
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4616
    StartTime = (Get-Date).AddDays(-1)
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    $prev = ($data | Where-Object { $_.Name -eq 'PreviousTime' }).'#text'
    $new  = ($data | Where-Object { $_.Name -eq 'NewTime'      }).'#text'
    $proc = ($data | Where-Object { $_.Name -eq 'ProcessName'  }).'#text'

    if ($prev -and $new) {
        $delta = [datetime]$new - [datetime]$prev
        $absDelta = [Math]::Abs($delta.TotalMinutes)

        $severity = if ($absDelta -gt 60) { "CRITICAL" }
                    elseif ($absDelta -gt 5) { "HIGH" }
                    elseif ($absDelta -gt 1) { "MEDIUM" }
                    else { "LOW (NTP normal)" }

        [PSCustomObject]@{
            EventTime   = $_.TimeCreated
            ProcessName = $proc
            DeltaMin    = [Math]::Round($absDelta, 2)
            Severity    = $severity
        }
    }
} | Format-Table -AutoSize
```

---

## SOC Analyst Notes

### Assessing Severity of a 4616 Event

A 4616 event should be assessed along three axes:

**1. Process Name** — Is this a known time-keeping process or an unexpected executable?

**2. Delta magnitude** — How large is the time change? NTP corrections are fractions of a second. A 2-hour jump is clearly deliberate.

**3. Frequency** — Is this a one-time event or is the clock being changed repeatedly? Repeated changes suggest ongoing active manipulation.

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | `svchost.exe` or `w32tm.exe`, delta under 5 seconds — normal NTP |
| 🟡 Medium | Administrator using date/time control panel, small delta |
| 🔴 High | `powershell.exe` or `cmd.exe` changing time by minutes or hours |
| 🔴 Critical | Unknown process changing time, large delta, or repeated changes in short period |

### Connecting 4616 to the Broader Investigation

When you find a suspicious 4616 event, the investigation should expand outward:

- What other events occurred from the same account around the same time?
- Are there 4657 (registry modifications) or scheduled task events clustered near this time?
- Check other machines in the environment — did they also have time changes?
- Look at network logs — was there unusual outbound traffic around the time of the clock change?
- Check if any files were created or modified on the system immediately after the time change

A time change that occurs in the middle of an otherwise quiet period, from a non-system process, is a strong indicator that an attacker is trying to cover their tracks before or after a significant action.

### MITRE ATT&CK Reference

- **T1070.006** — Indicator Removal: Timestomp
- **T1562.002** — Impair Defenses: Disable Windows Event Logging (related — attacker is impairing forensic capability)
- **T1027** — Obfuscated Files or Information (time manipulation as obfuscation of attack timeline)
