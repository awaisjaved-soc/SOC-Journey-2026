
```markdown
# Privilege Escalation using Security Groups in Active Directory

**SOC Analyst Practical Lab**  
**Author:** Muhammad Awais Javed  
**Domain:** `techcorp.local`  
**Date:** july 2026

---

### **Objective**

To demonstrate a **real-world privilege escalation attack** using Security Groups in Active Directory.

**Scenario:**
- A normal domain user (`alexrivera`) cannot access a confidential file.
- After being added to a privileged Security Group (`EliteOpsTeam`), the same user gains full access to the restricted file.

This lab generates key SOC events: **4727, 4728, and 4670**.

---

### **Lab Environment**

- **Domain Controller:** Windows Server 2022 (`techcorp.local`)
- **Normal User:** `alexrivera`
- **Security Group:** `EliteOpsTeam`

---

### **Step 1: Create Restricted Confidential Data (Run as Administrator)**

```
 # Create folder and secret file
```powershell
New-Item -Path "C:\ConfidentialData" -ItemType Directory -Force

"This is highly confidential company financial report. Only authorized team members can read it." | Out-File "C:\ConfidentialData\Financial_Report_2026.txt"

```





<img width="834" height="599" alt="image" src="https://github.com/user-attachments/assets/53a13b92-1cb6-4fd1-b494-c05c34f4df17" />

---
<img width="848" height="626" alt="image" src="https://github.com/user-attachments/assets/52788753-e188-4b97-9007-467cbb8b4cc3" />

---

# Reset permissions and give access ONLY to Administrators
```
icacls "C:\ConfidentialData" /reset /T
icacls "C:\ConfidentialData" /inheritance:r /grant "Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F" /T
```
---
<img width="988" height="529" alt="image" src="https://github.com/user-attachments/assets/0ca86920-5261-4aa8-8f45-3f580e15380d" />

---

### **Step 2: Create Normal User**

```powershell
New-ADUser -Name "Alex Rivera" `
           -SamAccountName "alexrivera" `
           -UserPrincipalName "alexrivera@techcorp.local" `
           -AccountPassword (ConvertTo-SecureString "AlexPass123" -AsPlainText -Force) `
           -Enabled $true
```
---
<img width="982" height="515" alt="image" src="https://github.com/user-attachments/assets/5258683c-07a2-4ece-a825-8e48c1ff20b8" />

---

### **Step 3: Create Security Group**

```powershell
New-ADGroup -Name "EliteOpsTeam" `
            -GroupScope Global `
            -GroupCategory Security `
            -Description "Elite Operations Team - High Privilege Group"
```
---
<img width="753" height="538" alt="image" src="https://github.com/user-attachments/assets/1d5b79d1-33e0-4d7a-8d32-620826036add" />
---

**Event Generated:** `4727` (Security Group Created)
---
<img width="645" height="442" alt="image" src="https://github.com/user-attachments/assets/576d2ce0-099a-4dca-ab0a-cfcde56fb062" />

---

### **Step 4: Privilege Escalation – Add User to Group**

```powershell
Add-ADGroupMember -Identity "EliteOpsTeam" -Members "alexrivera"
```

**Event Generated:** `4728` (Member Added to Global Group)
---
<img width="671" height="459" alt="image" src="https://github.com/user-attachments/assets/2a4f9cc4-dbc4-42c3-b6b1-17134c27caaa" />

---

### **Step 5: Grant Permissions to the Security Group**

```powershell
# Give full permission to the group
icacls "C:\ConfidentialData" /grant "EliteOpsTeam:(OI)(CI)F" /T
icacls "C:\ConfidentialData\Financial_Report_2026.txt" /grant "EliteOpsTeam:F"
```
---
<img width="1001" height="538" alt="image" src="https://github.com/user-attachments/assets/4b6f301d-c75c-438e-8cb5-98f336f48e55" />

---

**Event Generated:** 

<img width="608" height="136" alt="image" src="https://github.com/user-attachments/assets/6fe8df02-6587-4cf0-b243-ff04708be8e2" />

---

<img width="647" height="443" alt="image" src="https://github.com/user-attachments/assets/dde4db7f-eab4-4c18-bbf6-ffd5316544fd" />

---

<img width="645" height="442" alt="image" src="https://github.com/user-attachments/assets/606e5518-f7c0-42fd-9e4a-d2a53eab4827" />

---

<img width="652" height="469" alt="image" src="https://github.com/user-attachments/assets/585c8b66-e281-42d4-8fb9-49f6fc9a4f41" />

---

<img width="671" height="459" alt="image" src="https://github.com/user-attachments/assets/87b1986b-697b-4532-8084-ab31b32c84c9" />


---

### **Step 6: Testing the Attack**

1. Completely **Log off** the current session.
2. **Log in as `alexrivera`** (Password: `AlexPass123`)
3. Navigate to `C:\ConfidentialData`
4. Try to open `Financial_Report_2026.txt`

**Expected Result:**
- Before adding to group → **Access Denied**
- <img width="857" height="617" alt="image" src="https://github.com/user-attachments/assets/21a96d28-257e-458e-a5a5-886f8e3d16ff" />

- After adding to group + **fresh login** → File opens successfully
<img width="780" height="544" alt="image" src="https://github.com/user-attachments/assets/1fc35d5e-ba77-403c-8338-9b997ae4af47" />

---

### **Common Issues & Fixes**

**Issue:** User still gets "Access Denied" even after adding to group.  
**Solution:** Always do a **full logoff + login** (new security token is required).

**Issue:** Even Administrator cannot access the folder.  
**Solution:** Run these commands:

```powershell
icacls "C:\ConfidentialData" /setowner "Administrators" /T
icacls "C:\ConfidentialData" /grant "Administrators:(OI)(CI)F" /T
```

**Issue:** User cannot log in (sign-in method not allowed).  
**Solution:**
<img width="772" height="627" alt="image" src="https://github.com/user-attachments/assets/de285eb2-683d-4d0d-85c0-228d93d12eab" />

```powershell
Add-ADGroupMember -Identity "Remote Desktop Users" -Members "alexrivera"
Add-ADGroupMember -Identity "Users" -Members "alexrivera"
```

Then restart the server or gpupdate /force.

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

- **4727** → New security group created (check who created it and group name)
- **4728** → User added to privileged group (**Very Critical**)
- **4670** → File/folder permission changed
- Attackers often use this technique for **lateral movement** and **persistence**

**Real Attack Pattern:**  
Once attackers compromise a normal user, they try to escalate privileges by adding that user to high-privilege groups instead of directly using admin accounts.

---

