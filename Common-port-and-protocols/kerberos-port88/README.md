


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


