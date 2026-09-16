# Category 7 — Privilege Use Events

**Lab Environment:** Windows Server 2022 — TECHCORP / techcorp.local  
**Status:** ✅ Completed

---

## What Is This Category?

Privilege Use events track when a process or user **uses** a sensitive privilege that was already assigned to them.

This is different from Account Management events:

- **Account Management** → tracks when privileges are **granted** or **removed**
- **Privilege Use** → tracks when those privileges are actually **used**

In real SOC work, these events are important because legitimate administrators rarely trigger sensitive privileges constantly. When you see a spike in Event 4673 or 4674 — especially from unexpected accounts or at odd hours — it is worth investigating.

Attackers who have compromised an admin account will trigger these events when they try to:
- Debug processes (LSASS dumping)
- Load malicious drivers
- Take ownership of sensitive files
- Manipulate audit logs
- Act as part of the operating system

---

## Events in This Category

| Event ID | Name                              | SOC Importance | Description                                      |
|----------|-----------------------------------|----------------|--------------------------------------------------|
| 4673     | Sensitive Privilege Use Attempted | 🟡 Medium      | A process tried to use a sensitive privilege     |
| 4674     | Operation on Privileged Object    | 🟡 Medium      | An operation was performed on a privileged object|

---

## Key Distinction

- **4673** = Privilege use was **attempted** (may have succeeded or failed)
- **4674** = Operation was performed on a **specific privileged object**

---

## Audit Policy Required

Both events are controlled by the same subcategory:

```powershell
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
gpupdate /force
```

Verify:

```powershell
auditpol /get /subcategory:"Sensitive Privilege Use"
```

---

## Important Privileges Explained

| Privilege                        | Meaning                                      | Why Attackers Want It                          | Risk Level |
|----------------------------------|----------------------------------------------|------------------------------------------------|----------|
| SeDebugPrivilege                 | Debug / inject into other processes          | LSASS dumping, process injection               | Critical |
| SeTcbPrivilege                   | Act as part of the operating system          | Extremely powerful, almost full control        | Critical |
| SeTakeOwnershipPrivilege         | Take ownership of any object                 | Take ownership of sensitive files/registry     | High     |
| SeBackupPrivilege                | Read any file ignoring ACLs                  | Steal SAM, SYSTEM, SECURITY hives              | High     |
| SeRestorePrivilege               | Write any file ignoring ACLs                 | Plant malware in system folders                | High     |
| SeLoadDriverPrivilege            | Load kernel drivers                          | Install rootkits                               | Critical |
| SeSecurityPrivilege              | Manage auditing and security log             | Clear event logs / disable auditing            | High     |
| SeProfileSingleProcessPrivilege  | Profile other processes                       | Reconnaissance                                 | Medium   |

---

## How Attackers Enumerate Privileges

After gaining initial access, attackers check what privileges their current token has.

**Common commands:**

```powershell
whoami /priv
whoami /all
```

They also use tools such as:
- Seatbelt
- SharpUp
- PowerUp
- WinPEAS

Once they find powerful privileges, they abuse them for privilege escalation, credential dumping, or defense evasion.

---

## Lab Goal

In this category you will:

1. Enable the required audit policy
2. Generate Event 4673 using reliable methods
3. Generate Event 4674
4. Understand what each privilege means
5. Learn how attackers discover and abuse these privileges
6. Practice detection queries

Go to the individual event folders for full practical labs.
