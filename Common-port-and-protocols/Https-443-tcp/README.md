

### HTTPS Protocol Lab - Encrypted Web Traffic Analysis (Port 443)

**Introduction**  
HTTPS is the secure version of HTTP. It runs on **Port 443** and uses TLS (Transport Layer Security) encryption to protect data between the client and the server. Unlike HTTP (Port 80), where credentials and data are sent in plaintext, HTTPS encrypts all communication. This lab demonstrates how TLS handshake works and what a SOC Analyst can and cannot see in encrypted traffic.

**Objective:** Set up an HTTPS web server with a modern login page, capture and analyze TLS encrypted traffic in Wireshark from both local machine and another device (phone/laptop).

#### 1. Installation & Setup Commands

```bash
sudo apt update
sudo apt install apache2 php libapache2-mod-php openssl -y
```

```bash
sudo a2enmod ssl
sudo a2enmod rewrite
```

```bash
sudo systemctl start apache2
sudo systemctl enable apache2
```

#### 2. Generate Self-Signed Certificate

```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
-keyout /etc/ssl/private/apache-selfsigned.key \
-out /etc/ssl/certs/apache-selfsigned.crt
```

#### 3. Configure HTTPS Virtual Host

```bash
sudo nano /etc/apache2/sites-available/default-ssl.conf
```

#### 4. Enable HTTPS Site & Restart Apache

```bash
sudo a2ensite default-ssl.conf
sudo systemctl restart apache2
```

Check status:
```bash
sudo systemctl status apache2
```

#### 5. Test HTTPS Login Page
Open browser and visit:  
`https://192.168.100.91/login.html`  
(Accept the self-signed certificate warning)

---

#### 6. Wireshark Capture & Analysis

**For Local Machine (Loopback):**
``` 
Filter: tcp.port == 443 || tls
```

**For Another Device (Phone / Laptop):**
Use this filter (replace with actual IP):

```
ip.addr == 192.168.100.61 && (tls || tcp.port == 443)
```

**Important TLS Filters:**

- `tls` → All TLS traffic
- `tls.handshake.type == 1` → Client Hello
- `tls.handshake.extensions_server_name` → SNI (website domain)
- `tls.app_data` → Encrypted data

**Key Observation:**  
After the TLS handshake is complete, all data (including username and password) becomes encrypted. You cannot see the actual credentials in plaintext.

---

**Security Takeaway:**  
HTTPS protects user credentials and sensitive data from being sniffed on the network. However, SOC Analysts can still monitor metadata such as SNI, certificate details, and traffic patterns.



