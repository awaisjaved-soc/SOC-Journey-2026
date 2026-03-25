
# Commands We Used + Why We Used Them

## Here is every command we ran and its exact purpose:

### `sudo apt update`
→ Updates the list of available programs (like refreshing a shopping list).
### ` sudo apt install vsftpd -y`
→ Installs the FTP server software on your Kali (vsftpd = Very Secure FTP Daemon — ironically not very secure).
### ` sudo nano /etc/vsftpd.conf`
→ Opens the main settings file so we can change rules.
### ` Changed anonymous_enable=YES`
→ Allows anyone to login without password (for our lab demo only — never do this in real life).
### ` sudo systemctl restart vsftpd`
→ Restarts the FTP server so our changes take effect.
### `echo "This is my secret file..." | sudo tee /srv/ftp/test.txt`
→ Creates a test file inside the FTP folder so we have something to download.
### ` ftp 127.0.0.1`
→ Starts the FTP client and connects to your own machine (127.0.0.1 = localhost).
### ` anonymous (as username) + blank password`
→ Logs in without real credentials (this is what we made possible in config).
### ` ls`
→ Lists files on the FTP server (like dir command).
### ` get test.txt`
→ Downloads the file from server to your current folder.
### ` bye`
→ Closes the FTP connection.
### ` Nmap commands (nmap -p 21 127.0.0.1, -sV, --script ftp-anon)`
→ Scans to check if port 21 is open, what software is running, and if anonymous login is allowed.
### ` Wireshark filter ftp + Follow TCP Stream`
→ Captures the conversation and shows every word (username, password, file content) in plain text.
