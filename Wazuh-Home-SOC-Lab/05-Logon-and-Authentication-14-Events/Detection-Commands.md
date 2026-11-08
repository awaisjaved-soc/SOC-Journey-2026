# Detection Commands — Logon & Authentication

Copy-paste DQL queries, flood filters, and dashboard lessons from the 4624/4625 tuning work. Everything here was used in the lab on Nov 8–9, 2026. Threat Hunting shows the **alerts** index only — if an event fired no rule, it is invisible here; check the archives index or `Get-WinEvent` on the DC instead.

---

## Custom rule alerts

**100113 — high-privilege logons (Administrator, SID -500):**
```
rule.id: 100113
```

**100114 — normal user logons:**
```
rule.id: 100114
```

**100115 — off-hours logons:**
```
rule.id: 100115
```

**100116 — off-hours failed logons:**
```
rule.id: 100116
```

**All four custom logon rules at once:**
```
rule.id: 100113 OR rule.id: 100114 OR rule.id: 100115 OR rule.id: 100116
```

---

## Built-in rule alerts

**60106 — all logon successes (the flood):**
```
rule.id: 60106
```

**60122 — all failed logons (built-in, on-hours):**
```
rule.id: 60122
```

**60115 — account lockouts:**
```
rule.id: 60115
```

**92653 — RDP logons (built-in; shadowed by 100113/100114 since Nov 8, 2026 — last fired 18:08 that day):**
```
rule.id: 92653
```

---

## Event filters (by event ID, any rule)

**All 4624s (successful logons):**
```
data.win.system.eventID: 4624
```

**All 4625s (failed logons):**
```
data.win.system.eventID: 4625
```

**One account, all its logons:**
```
data.win.system.eventID: 4624 AND data.win.eventdata.targetUserName: svc-chain02
```

**One account, all its failed logons:**
```
data.win.system.eventID: 4625 AND data.win.eventdata.targetUserName: svc-chain02
```

**One logon type only (2 = console, 3 = network, 10 = RDP):**
```
data.win.system.eventID: 4624 AND data.win.eventdata.logonType: 10
```

**Failed logons by status code** (`0xC0000234` = account locked out, `0xC000006D` = bad password):
```
data.win.system.eventID: 4625 AND data.win.eventdata.status: 0xC0000234
```

---

## Flood filters — the human-only filter

**Human logons only** (drops computer accounts ending in `$` and SYSTEM noise):
```
data.win.system.eventID: 4624 AND NOT data.win.eventdata.targetUserName: *$ AND NOT data.win.eventdata.targetUserName: SYSTEM
```

**Human logons from my PC** (the 60106 shadowing check — this must return nothing, proving 60106 stays silent on human logons):
```
rule.id: 60106 AND data.win.eventdata.ipAddress: 192.168.100.27
```

**One account, one logon type, the full chain** (the Logon ID ties the logon to everything the session did):
```
data.win.system.eventID: 4624 AND data.win.eventdata.targetUserName: svc-chain02 AND data.win.eventdata.logonType: 10
```

---

## The 60104 flood — and how to exclude it

Built-in rule **60104** ("Windows audit failure event") is a generic bucket: it catches audit failures that have no more specific rule. On Nov 9, 2026 it produced **23,477 hits in 24 hours** — enough to fill the whole Threat Hunting view and hide every other alert. It is not a custom rule and not an attack; it is the catch-all for failures nobody wrote a rule for yet. The underlying event ID behind the flood had not been identified at the time of writing — find it by adding `data.win.system.eventID` as a column on a `rule.id: 60104` query and looking at which event dominates.

**Exclude 60104 from the view** (do NOT delete the events — they are evidence):

```
rule.id: * AND NOT rule.id: 60104
```

**Why the `rule.id: *` prefix matters:** a bare `NOT rule.id: 60104` query returns **zero results** in DQL. A query that starts with `NOT` and has no positive term has nothing to negate from. Always pair the exclusion with a positive term (`rule.id: *` matches every alert that has a rule ID).

**Or use the filter UI instead of DQL:** click **Add filter** → field `rule.id` → operator **is not** → value `60104`. The UI filter always works; the DQL quirk above does not apply to it.

---

## Discover columns — how to add them

Typing a field name in the search bar **does not** create a column. To see names, types, and IPs per row:

1. Click **Columns** (top-left, above the results).
2. Or open the **available fields** panel (the "802 available fields" link) and click **+** next to the field.

The three fields worth adding for logon work:

| Field | What it shows |
|---|---|
| `data.win.eventdata.targetUserName` | Who logged on |
| `data.win.eventdata.logonType` | How (2 console, 3 network, 10 RDP) |
| `data.win.eventdata.ipAddress` | From where |

With those three columns, one row tells the whole story without opening the detail.

---

## Time picker — relative range, never absolute

**Use a relative range** (e.g. **Last 24 hours**) plus **30-second auto-refresh**. A relative range always ends at "now", so new events keep appearing when you refresh.

**Never use an absolute (fixed) date range** for live work. On Nov 9, 2026 the view was set to a fixed date and showed **"No results match your search criteria"** even with an empty query — the data was there, the window had simply stopped moving. The fix was switching back to Last 24 hours.

If the view suddenly shows zero results with an empty query, check the time picker first — it is almost always the time range, not the data and not the query.

---

## The commands behind the rules (Kali / manager)

Deploying a rule file to the manager — the same sequence for every lab:

```bash
docker cp local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

Three things that cost an evening each, learned the hard way:

1. **`chown wazuh:wazuh` after every `docker cp`.** `docker cp` leaves the file owned by uid 1000; the manager's `wazuh` user cannot read it, and `wazuh-db` fails with "Error reading XML file (line 0)". The XML can be perfectly valid and still fail to load on ownership alone.
2. **Validate with `wazuh-analysisd -t` before restarting.** It catches structural errors (e.g. a deleted `<group>` wrapper) while the old rules are still running. Never restart on a failed config test.
3. **Edit single lines with `sed`, not `nano`.** A `nano` edit once deleted the `<group>` wrapper and broke the whole file. `sed -i 's|OLD|NEW|'` changes one line and nothing else. Always back the file up first (`cp local_rules.xml local_rules.xml.bak`).

## The commands behind the events (DC)

**Check the lockout policy** (threshold, duration, observation window):
```powershell
Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold, LockoutDuration, LockoutObservationWindow
```

**Unlock an account** (after a lockout test):
```powershell
Unlock-ADAccount -Identity svc-chain02
Unlock-ADAccount -Identity administrator
```

**Check whether an account is locked:**
```powershell
Get-ADUser -Identity svc-chain02 -Properties LockedOut | Select-Object Name, LockedOut
```

**Check live sessions** (when a type 10 is missing — a reconnecting session generates no new type 10):
```powershell
query session
```

**Log off a session** (so the next RDP creates a fresh type-10 logon):
```powershell
logoff <session-id>
```

**Check the audit subcategory** (a 4624/4625 that never appears usually means the subcategory is off):
```powershell
auditpol /get /subcategory:"Logon"
```

---

*Part of [05-Logon-and-Authentication-14-Events](README.md).*
