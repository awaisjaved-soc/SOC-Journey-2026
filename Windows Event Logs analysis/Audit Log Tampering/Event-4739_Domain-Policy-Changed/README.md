# Event ID 4739 — Domain Policy Changed

**Log:** Security  
**Category:** Policy Change  
**Subcategory:** Authentication Policy Change  
**Level:** Information  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local (Domain Controller)  
**Lab Status:** ✅ Successfully Generated — Requires Domain Controller

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 4739 |
| Event Name | Domain Policy was changed |
| Log Location | Windows Logs → Security — **on the Domain Controller** |
| Audit Category | Policy Change |
| Audit Subcategory | Authentication Policy Change |
| Default State | Enabled by default on Domain Controllers |
| SACL Required | No |
| Where It Fires | Domain Controller only — not on member servers |

---

<img width="631" height="360" alt="Screenshot_6" src="https://github.com/user-attachments/assets/408f6360-1c98-4f57-950b-b671d49488b1" />

---


## What Is Event 4739?

Event 4739 fires when the domain-wide security policy is modified in Active Directory. This is different from Event 4719 which covers local audit policy on individual machines. Event 4739 covers changes to policies that apply to every machine and every user account in the entire domain — password policies, account lockout policies, and domain security settings.

The scope of 4739 is what makes it so serious. A change to the local audit policy on one machine affects one machine. A change to the domain policy affects the entire organisation — potentially thousands of users and hundreds of machines simultaneously.

### What an Attacker Can Achieve by Modifying Domain Policy

**Removing account lockout** — The default setting locks an account after a certain number of failed password attempts (typically 5). An attacker who changes the lockout threshold to 0 disables this protection entirely. They can now attempt unlimited password guesses against any account in the domain with no risk of lockout. Brute force and password spraying attacks become far more viable.

**Weakening password requirements** — Reducing minimum password length or removing complexity requirements makes all future password changes weaker and makes current passwords relatively stronger targets by comparison.

**Extending Kerberos tolerances** — Domain policy also affects some Kerberos-related settings. Modifying these can extend the window during which replay attacks are possible.

### Important Note

Event 4739 only fires on the **Domain Controller** where the policy change is processed. If you are looking at a member server's Security log, you will never see 4739 there — you must check the DC's Security log. In an enterprise environment with multiple DCs, check all of them or use a SIEM that collects from all DCs.

---

## Audit Policy Setup

```cmd
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
```

Run this on the Domain Controller.

---


## Generating the Event

> ⚠️ This modifies live domain policy. Revert immediately after capturing the screenshot. Changing lockout threshold to 0 temporarily removes brute force protection for the entire domain.

### GUI Method — Domain Controller Only

1. Log in to the **Domain Controller**
2. Open **Group Policy Management** (`gpmc.msc`)
3. Expand your domain → right-click **Default Domain Policy** → **Edit**
4. Navigate to: `Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Account Lockout Policy`
5. Double-click **Account lockout threshold**
6. Change from `5` to `0` (disabling lockout)
7. Click OK → close the editor
8. Run `gpupdate /force` in an elevated command prompt
9. Check the **Security log on the Domain Controller** for Event 4739
10. **Immediately** restore the setting back to 5

---

<img width="558" height="429" alt="Screenshot_1" src="https://github.com/user-attachments/assets/0ef84791-b97e-4749-b4f6-3e976e79adcb" />

---

<img width="581" height="398" alt="Screenshot_2" src="https://github.com/user-attachments/assets/32083780-2d1e-41c4-a184-2c968ab37e33" />

---

<img width="960" height="482" alt="Screenshot_3" src="https://github.com/user-attachments/assets/553e0456-4bbc-4964-bd4f-4be067f87eb3" />

---

<img width="950" height="470" alt="Screenshot_4" src="https://github.com/user-attachments/assets/20528f86-75c9-47ad-b338-adf8012f3465" />

---

<img width="640" height="85" alt="Screenshot_5" src="https://github.com/user-attachments/assets/47c28239-037e-4d91-a36d-c2c6a5ffcdf7" />

---


### PowerShell Method — Domain Controller Only

```powershell
# View current domain policy
net accounts /domain

# Disable account lockout — generates 4739 on DC
net accounts /lockoutthreshold:0 /domain
Write-Host "Domain lockout disabled — Event 4739 fired on DC." -ForegroundColor Red

Start-Sleep -Seconds 3

# Restore immediately
net accounts /lockoutthreshold:5 /domain
Write-Host "Domain lockout restored to 5 attempts." -ForegroundColor Green

# Verify restoration
net accounts /domain
```

---

<img width="631" height="360" alt="Screenshot_6" src="https://github.com/user-attachments/assets/afe197ee-e189-4345-b90f-c6ec53650886" />

---

<img width="474" height="330" alt="Screenshot_7" src="https://github.com/user-attachments/assets/99861baf-bf22-431b-ba99-e3c5b5d7082a" />

---

## Detecting the Event

### GUI — Event Viewer (on Domain Controller)

1. Log in to the **Domain Controller**
2. Event Viewer → Windows Logs → **Security**
3. Filter → Event ID: `4739` → OK
4. Each entry shows which domain policy was changed

---

<img width="958" height="453" alt="Screenshot_8" src="https://github.com/user-attachments/assets/a2a8402d-8546-42d2-ac23-b81297892e7e" />

---

<img width="468" height="329" alt="Screenshot_9" src="https://github.com/user-attachments/assets/dbc41a47-0acc-49b7-a6ad-e4e4f3cbc9f8" />

---


**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Subject: Account Name | Who changed the domain policy — should be a known domain admin |
| Domain Name | Which domain was affected |
| Min Password Age | If changed — attackers reduce this to allow immediate password changes |
| Max Password Age | If reduced — passwords expire faster (disruption) or never (set to 0) |
| Lockout Threshold | If set to 0 — brute force protection removed |
| Lockout Duration | If set to 0 — lockout never automatically clears |

### PowerShell Detection — Run on Domain Controller

```powershell
# Find domain policy changes
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4739
    StartTime = (Get-Date).AddDays(-30)
} | Select-Object TimeCreated, Message | Format-List
```

```powershell
# Alert on lockout threshold changes — most common attacker modification
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4739
    StartTime = (Get-Date).AddDays(-30)
} | Where-Object {
    $_.Message -like "*LockoutThreshold*" -or $_.Message -like "*lockout*"
} | ForEach-Object {
    Write-Host "=== DOMAIN LOCKOUT POLICY CHANGED ===" -ForegroundColor Red
    Write-Host "Time    : $($_.TimeCreated)"
    Write-Host "Details : $($_.Message)"
}
```

---

<img width="958" height="489" alt="Screenshot_10" src="https://github.com/user-attachments/assets/ee33f159-31e7-44be-a343-6b7fac10ceaf" />

---

<img width="957" height="491" alt="Screenshot_12" src="https://github.com/user-attachments/assets/771863af-ab71-43ec-840e-34f368340392" />

---


## SOC Analyst Notes

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Known admin account, documented change, business hours |
| 🟡 Medium | Policy change outside business hours |
| 🔴 High | Lockout threshold set to 0 — brute force protection removed |
| 🔴 Critical | Policy change immediately before a wave of authentication attempts |

### MITRE ATT&CK Reference

- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1110** — Brute Force (lockout removal enables this)
- **T1484.001** — Domain Policy Modification: Group Policy Modification
