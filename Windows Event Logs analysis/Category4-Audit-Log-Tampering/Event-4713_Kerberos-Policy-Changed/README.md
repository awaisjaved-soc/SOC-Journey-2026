# Event ID 4713 — Kerberos Policy Changed

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
| Event ID | 4713 |
| Event Name | Kerberos policy was changed |
| Log Location | Windows Logs → Security — **on the Domain Controller** |
| Audit Category | Policy Change |
| Audit Subcategory | Authentication Policy Change |
| Default State | Enabled by default on Domain Controllers |
| SACL Required | No |
| Where It Fires | Domain Controller only — not on member servers |

---

## What Is Event 4713?

Event 4713 fires when Kerberos policy settings are changed at the domain level. Kerberos is the authentication protocol used in Active Directory — it issues encrypted tickets that prove a user's identity. These tickets have lifetimes, renewal periods, and tolerance windows that are defined by domain policy.

Attackers with Domain Admin access may modify Kerberos policy to extend ticket lifetimes, making stolen Kerberos tickets valid for much longer periods. In a Pass-the-Ticket attack, an attacker steals a legitimate user's Kerberos ticket and uses it to authenticate as that user. Normally tickets expire within 10 hours. If an attacker extends the maximum ticket lifetime to a very high value (for example 99999 hours), stolen tickets remain valid for an extremely long time.

### Why This Matters

Extending Kerberos ticket lifetime is a classic post-exploitation technique. It allows the attacker to maintain access even after the legitimate user changes their password, because the already-issued ticket remains valid until its (now very long) lifetime expires.

Event 4713 only fires on the **Domain Controller** where the policy change is processed.

---

## Understanding the Event Details

When you open Event 4713, the change is shown in a technical hexadecimal format rather than plain hours:

```
KerMaxT: 0x14762a65a1800 (0x53d1ac1000)
KerMaxR: 0x147ae1641c000 (0x58028e44000)
```

| Field | Meaning |
|---|---|
| KerMaxT | Maximum lifetime for user ticket (the main setting attackers change) |
| KerMaxR | Maximum lifetime for ticket renewal |

These values are stored in 100-nanosecond intervals. In real investigations, the fastest way to understand the current setting is to check the live policy rather than converting the hex every time.

---

## Audit Policy Setup

```cmd
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
```

Run this on the Domain Controller.

---

## Generating the Event

> ⚠️ This modifies live domain Kerberos policy. Revert immediately after capturing the screenshot.

### GUI Method — Domain Controller Only

1. Log in to the **Domain Controller**
2. Open **Group Policy Management** (`gpmc.msc`)
3. Expand your domain → right-click **Default Domain Policy** → **Edit**
4. Navigate to: `Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Kerberos Policy`
5. Double-click **Maximum lifetime for user ticket**
6. Change from `10` hours to a high value (for example `999`)
7. Click OK → close the editor
8. Run `gpupdate /force` in an elevated command prompt
9. Check the **Security log on the Domain Controller** for Event 4713
10. **Immediately** restore the setting back to 10 hours

### PowerShell / Command Note

Kerberos policy changes are best performed through the Group Policy GUI on the Domain Controller. The event fires when the GPO is applied.

```powershell
# After making the change via GPO, force refresh
gpupdate /force

# Verify current settings (run on DC)
net accounts /domain
```

---

## Detecting the Event

### GUI — Event Viewer (on Domain Controller)

1. Log in to the **Domain Controller**
2. Event Viewer → Windows Logs → **Security**
3. Filter → Event ID: `4713` → OK
4. Open the event and examine the KerMaxT / KerMaxR values

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Subject: Account Name | Who changed the Kerberos policy — should be a known domain admin |
| KerMaxT | Maximum user ticket lifetime — large increases are suspicious |
| KerMaxR | Maximum renewal lifetime |
| Date and Time | When the policy was changed |

### PowerShell Detection — Run on Domain Controller

```powershell
# Find Kerberos policy changes
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4713
    StartTime = (Get-Date).AddDays(-30)
} | Select-Object TimeCreated, Message | Format-List
```

```powershell
# Quick way to check current ticket lifetime settings
net accounts /domain
```

---

## SOC Analyst Notes

### Practical Investigation Tip

When you see Event 4713, do not spend time manually converting hex values. Immediately check the current live policy on the Domain Controller with `net accounts /domain` or by opening the Default Domain Policy. This tells you the real current values faster and more reliably.

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Known admin account, documented change, business hours |
| 🟡 Medium | Ticket lifetime increased moderately |
| 🔴 High | Ticket lifetime increased to extremely high values (hundreds or thousands of hours) |
| 🔴 Critical | Policy change followed by suspicious authentication activity or ticket-based attacks |

### MITRE ATT&CK Reference

- **T1558** — Steal or Forge Kerberos Tickets
- **T1550.003** — Use Alternate Authentication Material: Pass the Ticket
- **T1484.001** — Domain Policy Modification: Group Policy Modification
