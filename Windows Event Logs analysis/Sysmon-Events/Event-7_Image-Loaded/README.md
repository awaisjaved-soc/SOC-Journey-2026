# Sysmon Event ID 7 – Image Loaded

## Overview

| Field        | Details                              |
|--------------|--------------------------------------|
| **Event ID** | 7                                    |
| **Category** | Process & System Events              |
| **Name**     | Image Loaded                         |
| **Log**      | Microsoft-Windows-Sysmon/Operational |
| **Importance** | High                               |

---

## What Is Event ID 7?

**Event ID 7 (Image Loaded)** is generated every time a process loads a DLL (Dynamic Link Library) or any other module into its memory.

When any program starts — for example Notepad — it does not run standalone. It loads many supporting DLL files to handle things like the user interface, graphics, file access, and security. Sysmon logs each of these DLL loads individually as a separate Event ID 7 entry. This is why opening a single program like Notepad can generate 20 or more Event ID 7 entries.

This event is extremely useful for SOC analysts because attackers commonly use **DLL Side-Loading** and **DLL Hijacking** — techniques where a malicious DLL is placed so that a legitimate program loads it instead of the real Windows DLL.

This event helps detect:
- DLLs loaded from suspicious locations (Temp, AppData, Public, Downloads, etc.)
- Unsigned or invalidly-signed DLLs
- Malicious DLLs loaded by legitimate processes
- DLL injection and side-loading attacks

---

## Key Fields

| Field              | Meaning                                                            |
|--------------------|--------------------------------------------------------------------|
| `Image`            | The process that loaded the DLL                                    |
| `ImageLoaded`      | Full path of the DLL that was loaded                               |
| `Signed`           | Whether the DLL is digitally signed (`true` or `false`)            |
| `Signature`        | Name of the signing authority (e.g. Microsoft Windows)             |
| `SignatureStatus`  | Whether the signature is valid (`Valid`, `Invalid`, `Unavailable`) |
| `Company`          | Company listed in the DLL's metadata                               |
| `Hashes`           | SHA256 and other hashes of the DLL                                 |
| `User`             | User context of the process that loaded the DLL                    |

---

## Understanding DLL Search Order

This is the most important concept for Event ID 7. When a program needs a DLL, Windows searches for it in this order:

1. **The folder where the `.exe` is located** ← Highest priority — this is what attackers exploit
2. `C:\Windows\System32`
3. `C:\Windows\System` (legacy)
4. `C:\Windows`
5. Current working directory
6. Directories in the system PATH

**What this means for attackers:**
If an attacker places a malicious `version.dll` in the same folder as a legitimate `MyApp.exe`, the program will load the attacker's DLL instead of the real one from System32. The program does not need Admin rights to do this — just write access to that folder.

---

## Q&A from the Lab

**Q: Why do multiple Event ID 7 entries appear when I only open Notepad?**  
Because one program loads many DLLs (ole32.dll, uxtheme.dll, user32.dll, gdi32.dll, etc.). Each DLL load generates a separate Event ID 7.

**Q: How can a normal process load a malicious DLL?**  
Windows uses DLL Search Order. It first looks for the DLL in the same folder where the EXE is located. If an attacker places a malicious DLL with the same name in that folder, the legitimate program loads the attacker's DLL instead of the real one from System32.

**Q: Are DLLs from System32 always legitimate?**  
Mostly yes. DLLs loaded from `C:\Windows\System32` that are signed by Microsoft are generally safe. DLLs loaded from user-writable locations (Temp, AppData, Public, etc.) are more suspicious.

**Q: Why don't attackers just put the DLL in System32?**  
Because writing to System32 requires Administrator privileges and triggers more scrutiny. It's easier and quieter to place the malicious DLL in the same folder as the target EXE or in a user-writable location.

**Q: If the search order starts with the EXE folder, why not just put the malicious DLL in Temp?**  
`Temp` is not automatically in the search path. The attacker places the malicious DLL in the **same folder as the EXE** (which can be Public, Downloads, AppData, or anywhere the attacker wrote the EXE). Some programs also change their working directory to Temp, which can also cause DLLs to be loaded from there.

---

## How to Enable Event ID 7 (If Not Logging)

By default, many Sysmon configurations filter Event ID 7 heavily because it is very noisy. To enable it for the lab:

```powershell
$config = @"
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ImageLoad onmatch="exclude">
    </ImageLoad>
    <ProcessCreate onmatch="exclude">
    </ProcessCreate>
    <NetworkConnect onmatch="exclude">
    </NetworkConnect>
    <FileCreate onmatch="exclude">
    </FileCreate>
  </EventFiltering>
</Sysmon>
"@

$config | Out-File -FilePath "C:\SysmonConfig-Enable7.xml" -Encoding UTF8
```

```powershell
cd "C:\Sysmon"
.\Sysmon64.exe -c C:\SysmonConfig-Enable7.xml
```

---

## How to Generate Event ID 7

### Method 1: GUI

Open any program — Notepad, Calculator, Command Prompt, PowerShell. Each launch generates multiple Event ID 7 entries.

### Method 2: PowerShell

```powershell
Start-Process notepad.exe
Start-Process calc.exe
Start-Process powershell.exe
Start-Process cmd.exe

# Force loading .NET modules (generates additional Event ID 7 entries)
Add-Type -AssemblyName System.Windows.Forms
```

### DLL Search Order Lab (Safe Practical)

This demonstrates how a program loads a DLL from its own folder first.

```powershell
# Step 1: Create a test folder
New-Item -Path "C:\DLLLab" -ItemType Directory -Force

# Step 2: Copy Notepad to the test folder
Copy-Item "C:\Windows\System32\notepad.exe" -Destination "C:\DLLLab\notepad.exe"

# Step 3: Copy a legitimate DLL to the same folder
Copy-Item "C:\Windows\System32\version.dll" -Destination "C:\DLLLab\version.dll"

# Step 4: Run the copied Notepad from the new location
Start-Process "C:\DLLLab\notepad.exe"
```

---

## Detection Commands

### Basic View

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=7]]" -MaxEvents 10 |
Select-Object TimeCreated, Id, Message | Format-List
```

### Detailed View (Recommended)

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=7]]" -MaxEvents 15 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time         = $_.TimeCreated
        Process      = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text'
        DLL_Loaded   = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ImageLoaded'}).'#text'
        Signed       = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Signed'}).'#text'
        Signature    = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Signature'}).'#text'
        Company      = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Company'}).'#text'
    }
} | Format-Table -AutoSize -Wrap
```

### Filter for DLLLab Process Only

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=7]]" -MaxEvents 100 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    $process = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text'
    $dll     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ImageLoaded'}).'#text'

    if ($process -like "*DLLLab*notepad.exe") {
        [PSCustomObject]@{
            DLL = $dll
        }
    }
} | Format-Table -AutoSize
```

### Filter: Show DLL Path, Signed Status, and Signature Together

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=7]]" -MaxEvents 20 |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time       = $_.TimeCreated
        Process    = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text'
        DLL_Loaded = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ImageLoaded'}).'#text'
        Signed     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Signed'}).'#text'
    }
} | Where-Object { $_.Process -like "*DLLLab*" } | Format-Table -AutoSize -Wrap
```

---

## Lab Output Analysis

The following DLLs were observed loading when `C:\DLLLab\notepad.exe` was executed:

| DLL                            | Path                        | Status   |
|--------------------------------|-----------------------------|----------|
| `ntdll.dll`                    | C:\Windows\System32\        | Safe     |
| `kernel32.dll`                 | C:\Windows\System32\        | Safe     |
| `KernelBase.dll`               | C:\Windows\System32\        | Safe     |
| `user32.dll`                   | C:\Windows\System32\        | Safe     |
| `gdi32.dll`, `gdi32full.dll`  | C:\Windows\System32\        | Safe     |
| `ole32.dll`                    | C:\Windows\System32\        | Safe     |
| `combase.dll`                  | C:\Windows\System32\        | Safe     |
| `advapi32.dll`, `sechost.dll` | C:\Windows\System32\        | Safe     |
| `uxtheme.dll`                  | C:\Windows\System32\        | Safe     |
| `comctl32.dll`                 | C:\Windows\WinSxS\          | Safe     |
| `msvcrt.dll`, `ucrtbase.dll`  | C:\Windows\System32\        | Safe     |

**Finding:** All DLLs loaded from `System32` or `WinSxS`. No malicious DLLs detected in this lab run. Note that `C:\DLLLab\notepad.exe` also appears in the DLL list — this is the process itself being counted as an image load, which is normal.

---

## Identifying Legitimate vs Suspicious DLLs

| Indicator          | Legitimate (Safe)                          | Suspicious                                           |
|--------------------|--------------------------------------------|------------------------------------------------------|
| **Path**           | `C:\Windows\System32\` or `\SysWOW64\`   | `C:\Users\`, `Temp`, `AppData`, `Public`, `Downloads`|
| **Signed**         | `true`                                     | `false`                                              |
| **Signature**      | Microsoft Windows                          | Empty, unknown, or invalid                           |
| **SignatureStatus**| Valid                                      | Invalid or Unavailable                               |
| **Company**        | Microsoft Corporation                      | Empty or unfamiliar company name                     |

---

## SOC Analyst Notes

When analyzing Event ID 7:

1. **DLL location is the first thing to check.** If the DLL is not from System32 or SysWOW64, investigate further.
2. **Signature status matters.** A DLL that is unsigned and loaded by a legitimate process is unusual.
3. **Match the process to the DLL.** Ask: should this process ever need this DLL?
4. **Hash lookup.** Take the hash and check VirusTotal. Known malicious DLLs will have detections.

**Attack pattern to watch for:**
```
Image:       C:\Users\Public\LegitApp.exe
ImageLoaded: C:\Users\Public\version.dll   ← Same folder as EXE, not System32
Signed:      false
Signature:   (empty)
```
This is the classic DLL side-loading signature.

> Note: Event ID 7 is disabled or heavily filtered in many Sysmon configs by default because it generates very high volume. In production environments it is usually filtered to only flag specific unsigned DLLs or loads from non-standard paths.

---

## Key Takeaways

- Event ID 7 = A process loaded a DLL
- Multiple events per program launch is completely normal
- DLLs from `System32` + Microsoft signature = generally safe
- DLLs from user-writable locations + unsigned = suspicious
- Attackers exploit DLL Search Order by placing malicious DLLs in the same folder as a legitimate EXE
- Writing to System32 requires Admin rights — that's why attackers prefer user-writable locations

---

*Lab environment: Windows Server 2022 – SOC Journey 2026*
