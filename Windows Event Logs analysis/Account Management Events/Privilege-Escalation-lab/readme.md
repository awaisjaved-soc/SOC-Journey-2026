

---

```markdown
# Privilege Escalation using Security Groups in Active Directory

**SOC Analyst Practical Lab**  
**Author:** Muhammad Awais Javed  
**Domain:** `techcorp.local`  
**Date:** May 2026

---

### **Objective**

To demonstrate a **real-world privilege escalation attack** using Security Groups.

**Scenario:**
- A normal employee cannot access a confidential file.
- After being added to a privileged Security Group, the same user gains access to the restricted file.

---

### **Lab Environment**

- **Domain:** `techcorp.local`
- **Domain Controller:** Windows Server 2022
- **Normal User:** `michaelscott`
- **Security Group:** `EliteOpsTeam`

---

### **Step 1: Create Restricted Confidential Data (Run as Administrator)**

```powershell
# Create folder and secret file
New-Item -Path "C:\ConfidentialData" -ItemType Directory
echo "This is highly confidential company financial report. Only authorized team members can read it." > "C:\ConfidentialData\Financial_Report_2026.txt"

# Reset permissions and give access ONLY to Administrators
icacls "C:\ConfidentialData" /reset /T
icacls "C:\ConfidentialData" /inheritance:r /grant "Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F" /T
```

---

### **Step 2: Create Normal User**

```powershell
New-ADUser -Name "Michael Scott" `
           -SamAccountName "michaelscott" `
           -UserPrincipalName "michaelscott@techcorp.local" `
           -AccountPassword (ConvertTo-SecureString "MichaelPass123" -AsPlainText -Force) `
           -Enabled $true
```

---

### **Step 3: Create Security Group**

```powershell
New-ADGroup -Name "EliteOpsTeam" `
            -GroupScope Global `
            -GroupCategory Security `
            -Description "Elite Operations Team - High Privilege Group"
```

**Event Generated:** `4727` (Security Group Created)

---

### **Step 4: Privilege Escalation – Add User to Group**

```powershell
Add-ADGroupMember -Identity "EliteOpsTeam" -Members "michaelscott"
```

**Event Generated:** `4728` (Member Added to Global Group)

---

### **Step 5: Grant Permissions to the Security Group**

```powershell
icacls "C:\ConfidentialData" /grant "EliteOpsTeam:(OI)(CI)F" /T
icacls "C:\ConfidentialData\Financial_Report_2026.txt" /grant "EliteOpsTeam:F"
```

**Event Generated:** `4670` (Permissions on an object were changed)

---

### **Step 6: Testing**

1. Log off current session.
2. **Log in as `michaelscott`** (Password: `MichaelPass123`)
3. Go to `C:\ConfidentialData`
4. Try to open `Financial_Report_2026.txt`

**Expected Result:**
- Before adding to group → **Access Denied**
- After adding to group + fresh login → **File opens successfully**

---

### **SOC Detection Commands**

```powershell
# Check Privilege Escalation Events
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4727,4728,4670
} -MaxEvents 30 | 
Select TimeCreated, Id, Message | 
Sort-Object TimeCreated -Descending | 
Format-Table -AutoSize -Wrap
```

---

### **SOC Relevance**

- Monitor **4727** (New Group Created)
- Monitor **4728** (User Added to Privileged Group) — Very Critical
- Monitor **4670** (File/Folder Permission Changes)
- Look for suspicious group names and unusual group membership changes

**Real Attack Pattern:**  
Attacker compromises normal user → Adds himself to high-privilege group → Gains domain-wide access.

---



