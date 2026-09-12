# Event ID 4707 — Trust to Domain Removed

**Log:** Security  
**Category:** Policy Change  
**Subcategory:** Authentication Policy Change  
**Level:** Information  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local (Domain Controller)  
**Lab Status:** ⚠️ Could Not Be Fully Generated — Requires Existing Trust (See Lab Note)

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 4707 |
| Event Name | A trust to a domain was removed |
| Log Location | Windows Logs → Security — **on the Domain Controller** |
| Audit Category | Policy Change |
| Audit Subcategory | Authentication Policy Change |
| Default State | Enabled by default on Domain Controllers |
| SACL Required | No |
| Where It Fires | Domain Controller only |

---

## What Is Event 4707?

Event 4707 is the partner to Event 4706. It fires when an existing domain trust is removed.

While removing a trust can be a legitimate administrative action, it can also be used by attackers in two ways:

1. **Covering tracks** — An attacker who previously created a malicious trust (Event 4706) later removes it to hide the backdoor after they no longer need it.
2. **Impact / Disruption** — Removing a legitimate trust can break authentication for users who rely on that trust to access resources in another domain, causing business disruption.

### Relationship with Event 4706

In an attack timeline you may see:

```
4706  →  Malicious trust created (backdoor established)
... attacker uses the trust ...
4707  →  Trust removed (attacker cleaning up)
```

Seeing both events close together, or a 4707 for a trust that was never formally approved, is highly suspicious.

---

## Lab Note — Why This Event Could Not Be Fully Generated

> **Lab Note:** Event 4707 requires an existing trust that can be removed. Because Event 4706 could not be successfully generated in the single-domain lab (no second domain available), there was no trust object to remove. Therefore Event 4707 also could not be generated.
>
> The event is fully documented here for detection and investigation purposes.

---

## Generating the Event

### GUI Method (when a trust exists)

1. On the Domain Controller, open **Active Directory Domains and Trusts**
2. Right-click your domain → **Properties**
3. Click the **Trusts** tab
4. Select the trust you want to remove → **Remove**
5. Confirm the removal
6. Event 4707 fires on the Domain Controller

### PowerShell

```powershell
# View existing trusts first
Get-ADTrust -Filter * | Select-Object Name, TrustType, Direction

# Only remove a trust if you are certain it is safe to do so
# Remove-ADTrust -Identity "target.domain" -Confirm:$false
```

---

## Detecting the Event

### GUI — Event Viewer (on Domain Controller)

1. Event Viewer → Windows Logs → **Security**
2. Filter → Event ID: `4707`
3. Note which domain trust was removed and by which account

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| Domain | Which trust was removed |
| Subject: Account Name | Who removed the trust |
| Date and Time | When the trust was removed — correlate with other activity |

### PowerShell Detection — Run on Domain Controller

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4707
    StartTime = (Get-Date).AddDays(-90)
} | Select-Object TimeCreated, Message | Format-List
```

---

## SOC Analyst Notes

### Investigation Questions

- Was the removed trust a known, approved trust?
- Who removed it, and was there a change ticket?
- Was there a corresponding 4706 earlier for the same domain?
- Did any authentication failures or access issues occur after the removal?

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Documented removal of a known trust by authorised admin |
| 🟡 Medium | Trust removed outside of a change window |
| 🔴 High | Removal of a trust that was only recently created (possible attacker cleanup) |
| 🔴 Critical | Unauthorised removal causing business impact or hiding previous malicious trust |

### MITRE ATT&CK Reference

- **T1484.002** — Domain Trust Modification
- **T1070** — Indicator Removal on Host (when used for cleanup)
