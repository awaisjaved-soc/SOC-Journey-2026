# Event ID 4706 — New Trust Created to Domain

**Log:** Security  
**Category:** Policy Change  
**Subcategory:** Authentication Policy Change  
**Level:** Information  
**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local (Domain Controller)  
**Lab Status:** ⚠️ Could Not Be Fully Generated — Requires Second Domain (See Lab Note)

---

## Event Overview

| Field | Detail |
|---|---|
| Event ID | 4706 |
| Event Name | A new trust was created to a domain |
| Log Location | Windows Logs → Security — **on the Domain Controller** |
| Audit Category | Policy Change |
| Audit Subcategory | Authentication Policy Change |
| Default State | Enabled by default on Domain Controllers |
| SACL Required | No |
| Where It Fires | Domain Controller only |

---

<img width="406" height="387" alt="Screenshot_1" src="https://github.com/user-attachments/assets/3a1aa8e4-1982-4049-a8c6-623fdcf24331" />

---

## What Is Event 4706?

Event 4706 fires when a new trust relationship is established between your domain and another domain. Domain trusts are legitimate features in enterprise environments with multiple domains — they allow users in one domain to access resources in another.

However, trusts are also abused by attackers. An attacker who has obtained Domain Admin privileges can create a trust to an attacker-controlled domain. This creates a persistent backdoor at the domain level. Even if every compromised account is reset and every malicious service is removed, the trust relationship remains and can allow the attacker’s domain to authenticate against the victim domain.

### Why This Is Critical

Creating a malicious domain trust is a high-impact persistence technique. It survives password resets, service removals, and many standard incident response actions. Detecting Event 4706 quickly and verifying the legitimacy of any new trust is essential.

---

## Lab Note — Why This Event Could Not Be Fully Generated

> **Lab Note:** Event 4706 requires a second domain (or at least a reachable external domain) to successfully create a trust. In a single-domain lab environment, attempts to create a trust to a non-existent domain (for example `test.fake`) fail before the trust is actually committed. As a result, no trust object is created and Event 4706 does not fire.
>
> Creating a full second domain just for this event is possible but time-consuming and outside the practical scope of this lab stage. The event is fully documented here so the detection methods and investigation approach are understood even though live generation was not completed.

---

## Generating the Event

### Requirements

- Domain Controller
- A second domain (or a real external domain) that can be contacted

### GUI Method (when a second domain is available)

1. On the Domain Controller, open **Active Directory Domains and Trusts**
2. Right-click your domain → **Properties**
3. Click the **Trusts** tab → **New Trust**
4. Follow the wizard and complete the trust creation
5. Event 4706 fires on the Domain Controller

---

<img width="406" height="387" alt="Screenshot_1" src="https://github.com/user-attachments/assets/0257b842-f812-4031-8fda-c859663c1671" />

---


### PowerShell (view existing trusts)

```powershell
# View current trusts
Get-ADTrust -Filter * | Select-Object Name, TrustType, Direction | Format-List
```

---

<img width="440" height="326" alt="Screenshot_2" src="https://github.com/user-attachments/assets/939653af-ab76-4da0-b1e2-1cb136971e02" />

---


## Detecting the Event

### GUI — Event Viewer (on Domain Controller)

1. Event Viewer → Windows Logs → **Security**
2. Filter → Event ID: `4706`
3. Examine the details of any new trust

**Key fields to examine:**

| Field | What to Look For |
|---|---|
| New Domain | The domain a trust was established with |
| Trust Type | External vs Forest trust |
| Trust Direction | Inbound, Outbound, or Bidirectional |
| Subject: Account Name | Who created the trust — should be a known domain admin |

### PowerShell Detection — Run on Domain Controller

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4706
    StartTime = (Get-Date).AddDays(-90)
} | Select-Object TimeCreated, Message | Format-List
```
---

<img width="475" height="312" alt="Screenshot_3" src="https://github.com/user-attachments/assets/41169697-5f4c-42e7-b040-d199f05154ae" />

---


```powershell
# Also check currently configured trusts
Get-ADTrust -Filter * | Format-List Name, TrustType, Direction, Source, Target
```

---

<img width="711" height="380" alt="Screenshot_7" src="https://github.com/user-attachments/assets/2d010064-b184-400a-968d-33107d09b8c9" />

---

## SOC Analyst Notes

### Investigation Workflow

```
Step 1: Note the domain name that the trust was created with
Step 2: Verify with the domain admin team — is this a known, approved trust?
Step 3: Check the account that created the trust
Step 4: If the trust is unauthorised → treat as high-severity persistence
Step 5: Review any authentication activity involving the new trust
```

### Risk Table

| Risk Level | Indicator |
|---|---|
| 🟢 Low | Known, documented trust created by authorised admin during change window |
| 🔴 Critical | Any unexpected trust creation, especially to an unknown external domain |
| 🔴 Critical | Trust created by an account that should not have Domain Admin rights |

### MITRE ATT&CK Reference

- **T1484.002** — Domain Trust Modification
- **T1134** — Access Token Manipulation (related to trust abuse)
