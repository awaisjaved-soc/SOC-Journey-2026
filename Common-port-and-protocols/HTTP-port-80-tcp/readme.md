
---

### HTTP Protocol Lab - Modern Styled Login Form (Port 80)

**Objective:** Set up a realistic-looking web login page over HTTP, capture credentials in Wireshark, and understand why HTTP is dangerous in a SOC environment.

#### 1. Installation & Setup

```bash
sudo apt update
sudo apt install apache2 php libapache2-mod-php -y

sudo systemctl start apache2
sudo systemctl enable apache2
```

#### 2. Create Stylish Login Page (`login.html`)

```bash
sudo nano /var/www/html/login.html
```

**Paste the following code:**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Access - Enterprise System</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e2937 100%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
        }
        .login-container {
            background: rgba(255, 255, 255, 0.98);
            padding: 45px 40px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            width: 400px;
            text-align: center;
            animation: fadeInScale 0.8s ease forwards;
        }
        @keyframes fadeInScale {
            from { opacity: 0; transform: scale(0.85); }
            to { opacity: 1; transform: scale(1); }
        }
        h2 {
            color: #1e2937;
            margin-bottom: 35px;
            font-size: 28px;
            font-weight: 600;
            position: relative;
        }
        h2::after {
            content: '';
            position: absolute;
            width: 60px;
            height: 3px;
            background: #3b82f6;
            bottom: -10px;
            left: 50%;
            transform: translateX(-50%);
            border-radius: 3px;
        }
        input {
            width: 100%;
            padding: 16px 18px;
            margin: 14px 0;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.4s ease;
        }
        input:focus {
            border-color: #3b82f6;
            box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.15);
            transform: translateY(-2px);
        }
        button {
            width: 100%;
            padding: 16px;
            margin-top: 25px;
            background: linear-gradient(135deg, #3b82f6, #2563eb);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 17px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.4s ease;
            position: relative;
            overflow: hidden;
        }
        button:hover {
            background: linear-gradient(135deg, #2563eb, #1d4ed8);
            transform: translateY(-3px);
            box-shadow: 0 12px 25px rgba(59, 130, 246, 0.4);
        }
        button::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -100%;
            width: 50%;
            height: 200%;
            background: linear-gradient(120deg, rgba(255,255,255,0) 30%, rgba(255,255,255,0.6) 50%, rgba(255,255,255,0) 70%);
            transition: 0.7s;
        }
        button:hover::before {
            left: 200%;
        }
        .footer-text {
            margin-top: 30px;
            font-size: 14px;
            color: #64748b;
        }
        .logo { font-size: 42px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🔒</div>
        <h2>Enterprise Secure Login</h2>
        <form action="/submit.php" method="POST">
            <input type="text" name="username" placeholder="Username or Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In Securely</button>
        </form>
        <p class="footer-text">SOC Lab Environment • All traffic is monitored</p>
    </div>
</body>
</html>
```

#### 3. Create Response Page (`submit.php`)

```bash
sudo nano /var/www/html/submit.php
```

**Paste this code:**

```php
<?php
if($_POST) {
    $username = htmlspecialchars($_POST['username']);
    $password = htmlspecialchars($_POST['password']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login Response</title>
    <style>
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e2937 100%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
        }
        .card {
            background: rgba(255,255,255,0.97);
            color: #1e2937;
            padding: 50px 40px;
            border-radius: 20px;
            box-shadow: 0 20px 50px rgba(0,0,0,0.3);
            width: 440px;
            text-align: center;
            animation: popIn 0.6s ease forwards;
        }
        @keyframes popIn {
            from { opacity: 0; transform: scale(0.7); }
            to { opacity: 1; transform: scale(1); }
        }
        h2 { color: #10b981; margin-bottom: 25px; font-size: 26px; }
        p { font-size: 18px; margin: 18px 0; color: #334155; }
    </style>
</head>
<body>
    <div class="card">
        <h2>✅ Login Captured Successfully</h2>
        <p><strong>Username:</strong> <?php echo $username; ?></p>
        <p><strong>Password:</strong> <?php echo $password; ?></p>
        <p style="margin-top:35px; color:#64748b; font-size:15px;">
            This is a controlled SOC Analyst lab.<br>
            In real environments, sending credentials over HTTP is extremely dangerous.
        </p>
    </div>
</body>
</html>
<?php
} 
?>
```

#### 4. Restart Apache

```bash
sudo systemctl restart apache2
```

#### 5. Wireshark Capture (SOC Analysis)

**Steps:**

1. Open Wireshark → Select `eth0` interface (for real network traffic) or `lo` (loopback).
2. Start capture.
3. Apply filter:
   ```
   tcp.port == 80
   ```
4. Open browser and go to:  
   `http://192.168.100.91/login.html` (from same machine or another VM)
5. Enter username and password → Click **Sign In Securely**

**Important Filters:**

- `http.request.method == POST` → Shows form submission
- `http contains "password"` → Direct credential search
- `tcp.port == 80 && ip.addr == 192.168.100.90` → Traffic from specific victim IP

**Key Observation in TCP Stream:**
- You will clearly see `username=xxx&password=yyy` in plaintext.
- `Referer` header shows which page the user came from.

---

NOTE: So this is my code that i have used for login form and php you can add javascript or customize things make this form simple or like a professional one..

> This lab demonstrates why **HTTP is extremely dangerous**. Anyone on the same network (or performing MITM) can easily capture usernames and passwords in clear text. This is why modern applications must use **HTTPS (Port 443)**.



