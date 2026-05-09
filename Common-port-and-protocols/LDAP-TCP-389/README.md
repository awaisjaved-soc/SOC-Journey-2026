

### **What is LDAP? (Simple Explanation)**

**LDAP** = **Lightweight Directory Access Protocol**

Think of it as a **central phone book + identity database** for a company.

- It stores information about users, groups, computers, emails, permissions, etc.
- Almost every big company uses LDAP (especially through **Active Directory** in Windows).
- Port: **389** (normal) and **636** (secure LDAPS)

- What does it store?

Usernames
Full names
Email addresses
Phone numbers
Which department they belong to
What files/folders they can access
Password hashes (in encrypted form)

**Real Life Example:**
When you login to your office computer, LDAP checks:
- Is this user real?
- What groups is he in?
- What files/folders can he access?

---

### **How LDAP Works**

1. Client says: "I am awais, give me my info"
2. LDAP Server checks the database
3. Server replies with user details (name, email, groups, etc.)

Attackers love LDAP because they can **enumerate** (find) usernames, groups, and computers without logging in sometimes.

---

### **Full LDAP Practical Lab**

**Lab Environment**
- Server (LDAP Server): 192.168.100.91
- Client: 192.168.100.90
- Domain: `lab.local`

---

#### **STEP 1: On LDAP Server (192.168.100.91)**

```bash
# Update system
sudo apt update

# Install OpenLDAP server and tools
sudo apt install slapd ldap-utils -y
```

**During installation:**
- Administrator password → Set `Password123`
- Confirm it

```bash
# Reconfigure if needed
sudo dpkg-reconfigure slapd
```

**Choose these options:**
- Omit OpenLDAP server configuration? → **No**
- DNS domain name → `lab.local`
- Organization name → `Lab`
- Administrator password → `Password123`
- Database backend → MDB
- Remove database when purging? → **No**

```bash
# Restart service
sudo systemctl restart slapd
sudo systemctl status slapd
```

**Purpose:** This installs and starts the LDAP server.

---

#### **STEP 2: Add Sample Users (Create Directory Data)**

```bash
sudo nano /tmp/users.ldif
```

Paste this:

```ldif
dn: ou=people,dc=lab,dc=local
objectClass: organizationalUnit
ou: people

dn: cn=awais,ou=people,dc=lab,dc=local
objectClass: inetOrgPerson
cn: awais
sn: Javed
uid: awais
userPassword: Password123

dn: cn=mian,ou=people,dc=lab,dc=local
objectClass: inetOrgPerson
cn: mian
sn: Awais
uid: mian
userPassword: Password123
```

Save & exit.

```bash
# Add users to LDAP
sudo ldapadd -x -D "cn=admin,dc=lab,dc=local" -W -f /tmp/users.ldif
```

Enter password: `Password123`

**Purpose:** We created two users (awais and mian) in the LDAP directory.

---

#### **STEP 3: Query LDAP from Client (192.168.100.90)**

```bash
sudo apt install ldap-utils -y

# Search all users
ldapsearch -x -H ldap://192.168.100.91 -b "dc=lab,dc=local" "(objectclass=inetOrgPerson)"
```

**Purpose:** This shows how attackers or admins query the directory to find users.

---

### **Nmap Commands for LDAP**

```bash
# Basic scan
nmap -p 389,636 192.168.100.91

# Version detection
nmap -sV -p 389,636 192.168.100.91
```

---

### **Best Wireshark Filters for LDAP**

```bash
# Best general filter
ldap || tcp.port == 389 || tcp.port == 636

# Bind (Login) requests
ldap && ldap.op == 0

# Search requests (enumeration)
ldap && ldap.op == 2
```

**What you will see:**
- Bind Request (authentication)
- Search Request (someone trying to find users)
- Search Result (user data returned — often readable if not using LDAPS)

---
Real world like senerio......




### **Real-Life LDAP Lab – "TechCorp Company"**

**Company Name:** TechCorp  
**Domain:** `techcorp.local`

We will create:
- HR Manager: **Hamza Khan**
- SOC Analyst: **Awais Javed**
- Finance Manager: **Sara Ahmed**

---

### **STEP 1: On LDAP Server (192.168.100.91)**

```bash
# 1. Update and install LDAP server
sudo apt update
sudo apt install slapd ldap-utils -y
```

**During installation:**
- Administrator password → Set `AdminPass123`

```bash
# 2. Reconfigure LDAP
sudo dpkg-reconfigure slapd
```

**Choose these:**
- Omit OpenLDAP server configuration? → **No**
- DNS domain name → `techcorp.local`
- Organization name → `TechCorp`
- Administrator password → `AdminPass123`
- Database backend → MDB
- Remove database when purging? → **No**

```bash
# 3. Restart service
sudo systemctl restart slapd
sudo systemctl status slapd
```

---

### **STEP 2: Create Real-Life Users (Company Data)**

```bash
sudo nano /tmp/company_users.ldif
```

**Paste this real-life data:**

```ldif
# Organizational Unit for People
dn: ou=people,dc=techcorp,dc=local
objectClass: organizationalUnit
ou: people

# HR Manager - Hamza Khan
dn: cn=Hamza Khan,ou=people,dc=techcorp,dc=local
objectClass: inetOrgPerson
cn: Hamza Khan
sn: Khan
givenName: Hamza
uid: hamza
title: HR Manager
mail: hamza@techcorp.local
userPassword: HamzaPass123

# SOC Analyst - Awais Javed
dn: cn=Awais Javed,ou=people,dc=techcorp,dc=local
objectClass: inetOrgPerson
cn: Awais Javed
sn: Javed
givenName: Awais
uid: awais
title: SOC Analyst
mail: awais@techcorp.local
userPassword: AwaisPass123

# Finance Manager - Sara Ahmed
dn: cn=Sara Ahmed,ou=people,dc=techcorp,dc=local
objectClass: inetOrgPerson
cn: Sara Ahmed
sn: Ahmed
givenName: Sara
uid: sara
title: Finance Manager
mail: sara@techcorp.local
userPassword: SaraPass123
```

Save & exit.

```bash
# Add these users to LDAP
sudo ldapadd -x -D "cn=admin,dc=techcorp,dc=local" -W -f /tmp/company_users.ldif
```

Enter password: `AdminPass123`

---

### **STEP 3: Query LDAP (From Client Machine)**

On your **Client** (192.168.100.90):

```bash
sudo apt install ldap-utils -y

# Search all employees
ldapsearch -x -H ldap://192.168.100.91 -b "dc=techcorp,dc=local" "(objectclass=inetOrgPerson)"

# Search only SOC Analyst
ldapsearch -x -H ldap://192.168.100.91 -b "dc=techcorp,dc=local" "(uid=awais)"

# Search by job title
ldapsearch -x -H ldap://192.168.100.91 -b "dc=techcorp,dc=local" "(title=*Manager*)"
```

---

**This is how it looks in real life** — you can see full employee details like name, title, email, etc.

---
or using automated loop

while read user; do
  while read pass; do
    echo "Trying $user : $pass"
    ldapsearch -x -H ldap://192.168.100.91 \
      -D "cn=$user,ou=people,dc=techcorp,dc=local" \
      -w "$pass" \
      -b "dc=techcorp,dc=local" "(uid=$user)" > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
      echo "✅ SUCCESS → Username: $user | Password: $pass"
      # Remove "break 2" to continue testing other users
    fi
  done < /tmp/passwords.txt
done < /tmp/usernames.txt



cat /tmp/usernames.txt
cat /tmp/passwords.txt

cat > /tmp/usernames.txt << EOF
Awais Javed
Hamza Khan
Sara Ahmed
Usman Ali
Fatima Khan
EOF

cat > /tmp/passwords.txt << EOF
Password123
HamzaPass123
sara123
Usman123
FatimaCEO456
EOF
