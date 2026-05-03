

# SMB Protocol (Port 445) Practical Lab  
**Author:** Muhammad Awais Javed (Mian Awais)  
**Date:** May 2026  
**Part of:** SOC-Journey-2026

### What is SMB?
SMB (Server Message Block) is a protocol used for file and printer sharing in Windows networks. It is also known as CIFS in older versions. Modern SMB runs on **TCP Port 445**.

**SOC Importance:**  
SMB is one of the most attacked protocols. It is heavily used in ransomware, lateral movement, and EternalBlue-style exploits. SOC analysts monitor port 445 very carefully because plaintext SMB can leak file contents, usernames, and folder structures.

### Lab Environment
- Server: Kali VM (192.168.100.91)  
- Client: Laptop Kali VM (192.168.100.90)  
- User: `mianawais` (Linux + SMB user)  
- Password: `mian`  
- Share Name: `AwaisShare`

---

### Full Setup Process (Server Side - 192.168.100.91)

**1. Update and install Samba**
```bash
sudo apt update
sudo apt install samba -y
```
- Updates package list and installs the Samba server software.

**2. Create Linux user**
```bash
sudo adduser mianawais
```
- Creates a Linux user. Set password when asked (we will use `mian` for SMB).

**3. Set Samba password**
```bash
sudo smbpasswd -a mianawais
sudo smbpasswd -e mianawais
```
- Adds the user to Samba database and enables it. Use password `mian`.

**4. Create shared folder**
```bash
sudo mkdir -p /srv/samba/AwaisShare
sudo chown -R mianawais:mianawais /srv/samba/AwaisShare
sudo chmod -R 770 /srv/samba/AwaisShare
```
- Creates the folder and gives ownership + proper permissions to avoid "Permission denied" issues.

**5. Configure smb.conf (main settings)**
```bash
sudo nano /etc/samba/smb.conf
```

Add this at the end:
```ini
[AwaisShare]
   path = /srv/samba/AwaisShare
   browsable = yes
   writable = yes
   guest ok = no
   force user = mianawais
   create mask = 0664
   directory mask = 0775
   force create mode = 0664
   force directory mode = 0775
```

Save (Ctrl+O → Enter → Ctrl+X)

**6. Restart Samba**
```bash
sudo systemctl restart smbd
sudo systemctl status smbd
```

---

### File Upload / Download Process

**Uploading files to SMB Server (from Server PC)**

Method 1 (Direct copy):
```bash
sudo cp ~/Downloads/anyfile.exe /srv/samba/AwaisShare/
```

Method 2 (Using smbclient from client – optional)
```bash
smbclient //192.168.100.91/AwaisShare -U mianawais
```
Inside prompt: `put anyfile.exe`

**Downloading files to Laptop Client**

Method 1 (smbclient):
```bash
smbclient //192.168.100.91/AwaisShare -U mianawais
```
Inside prompt: `get anyfile.exe`

Method 2 (Mount – best for large files like WinRAR.exe):
```bash
sudo mkdir -p /mnt/AwaisShare
sudo mount -t cifs //192.168.100.91/AwaisShare /mnt/AwaisShare -o username=mianawais,password=mian,vers=3.0
cp /mnt/AwaisShare/filename.exe ~/
```

---

### Deleting Files / Share / User

**Delete a file:**
```bash
sudo rm /srv/samba/AwaisShare/filename.exe
```

**Delete the whole share folder:**
```bash
sudo rm -r /srv/samba/AwaisShare
```

**Delete a share from config:**
Edit `smb.conf`, remove the `[AwaisShare]` section, then `sudo systemctl restart smbd`

**Delete user `mianawais`:**
```bash
sudo smbpasswd -x mianawais
sudo userdel -r mianawais
```
**TO fix permissions:**
```bash
sudo chown mianawais:mianawais /srv/samba/AwaisShare/filename.exe
```
**To check ownership**
```
ls -la /srv/samba/AwaisShare/
```
**To go to the share folder**
```
cd /srv/samba/AwaisShare
```
**Fix ownership of ALL files including root-owned ones**
```bash
sudo chown mianawais:mianawais /srv/samba/AwaisShare/Wireshark-4.6.4-x64.exe
sudo chown mianawais:mianawais /srv/samba/AwaisShare/nmap-7.98-setup.exe
```
**Remove the restrictive ACL entries from these files**
```bash
sudo setfacl -b /srv/samba/AwaisShare/Wireshark-4.6.4-x64.exe
sudo setfacl -b /srv/samba/AwaisShare/nmap-7.98-setup.exe
```
**Fix ALL files at once — ownership + remove bad ACLs***
```bash
sudo chown mianawais:mianawais /srv/samba/AwaisShare/*
sudo setfacl -b /srv/samba/AwaisShare/*
```
---

### Wireshark Capture (on Client)

1. Open Wireshark → Select `eth0` → Start capture
2. Perform file upload/download
3. Stop capture → Apply filter: `tcp.port == 445`

**Useful filters:**
- `tcp.port == 445` → All SMB traffic
- `smb` → SMB protocol only
- `ntlmssp` → Authentication packets
- here you can see the traffic flow when you upload or download a file.If the file is large there will be a big flowof packets.
- the encryption is disabled thats why you can see the name of the file you upload or download if the encryption will enalble maybe thats file name is not visible you can only see all the encrypted messages flowing in the wireshark.

**Key packets to observe:**
- Negotiate Protocol
- Session Setup (NTLM)
- Tree Connect
- Create / Read / Write
- ```bash
  nmap -p 445 -sV --script smb-os-discovery,smb-security-mode 192.168.100.91
  nmap -p 445 192.168.100.91
  ```

**SOC Takeaways:** Monitor port 445 for lateral movement and ransomware. Plaintext SMB leaks data.

