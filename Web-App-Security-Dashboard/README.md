# CX Arena SOC Dashboard — Final Year Project

A SOC operations console I built for my own tournament website (CX Arena). I was running the site blind — every time I wanted to see failed logins, admin actions, or money movement, I had to dig through Supabase tables by hand. So I built a single-file dashboard where every user log, alert, and transaction is visible in one place, with live Telegram + Discord alerting.

It is also useful beyond my site: any website with user accounts, logins, and tournament-style activity (deposits, cashouts, prize payouts) faces the same visibility problem.

> **Scope note:** this is a detection and investigation project, not a web-development showcase. The question behind every tab is: *what can I see, what can I catch, and what is missing from the logs?*

---

## Access control

The dashboard sits behind a 6-digit MPIN login (masked boxes, auto-advance, SHA-256 hash only, lockout protections). No username/password to phish or brute-force.

![MPIN login](screenshots/00-mpin-login.png)

---

![MPIN login — desktop app](screenshots/00-mpin-login-desktop.png)

---

## 📊 1. Overview

The first screen after login. Live security posture at a glance.

- **Stat cards (all-time):** Brute Force attempts, Admin Logins, Deposits OK, Cashouts, Rejected deposits, Total Events
- **⚠️ Active Security Alerts** — live alert feed with severity badges and MITRE technique tags (e.g. T1110). Each alert can be acknowledged (✓ Ack) or marked as a false positive (✖ FP) right from the feed
- **Activity Summary (last 24h):** failed logins, admin logins, deposits approved/rejected, cashouts, total audit and security events
- **Hide triaged** toggle to keep the feed focused on unhandled alerts

![Overview](screenshots/01-overview.png)

---

![Overview — alert detail](screenshots/01-overview-alerts-detail.png)

---

## 🔴 2. Failed Logins

Brute-force detection and triage.

- **Stat cards:** Total Failed, Last Hour, Last 24h, Unique Targets, Peak 15-min (1 account)
- **Grouped by account** — raw attempts are collapsed into per-account rows so a 28-attempt burst reads as one line, not 28
- **Filters:** All · 🔴 High Risk (5+) · 🟡 Medium (3+) · ⚡ Last Hour · 🔑 Logins
- **Per-row:** attempt count with visual burst bar, severity, time span, status (e.g. *Lock expired*, *Never locked — review*)
- **Failed Logins per Hour** chart (last 24h)
- One-click **SQL** and **Report** actions per row for deeper digging

![Failed Logins](screenshots/02-failed-logins.png)

---

![Failed Logins — grouped detail](screenshots/02-failed-logins-detail.png)

---

## 🔐 3. Admin Audit

Every privileged action, logged and filterable. This is the tab that answers *"which admin did what, from where?"*

- **114 events** tracked live
- **Filters:** All · 🔑 Logins · Deposit ✅ · Deposit ❌ · Cashout ✅ · Cashout ❌ · 🏠 Rooms · 🔴 Suspicious
- **Columns:** Time · Admin Email · Action · IP Address (with VirusTotal lookup link) · City · Country · Target / Notes
- **Actions tracked:** `DEPOSIT_APPROVED`, `DEPOSIT_REJECTED`, `ADMIN_LOGIN`, room edits/deletions, and more
- GeoIP resolution on every admin IP — an admin logging in from an unexpected city stands out immediately

![Admin Audit](screenshots/03-admin-audit.png)

---

## 💰 4. Transactions

The full money trail — the tab I check most. Deposits, cashouts, coin movements, prizes.

- **Stat cards:** Total Submitted (49) · Approved (32) · Rejected (17) · Cashouts (3) · Total PKR Volume (PKR 33,210)
- **Filters:** All · Submitted · Approved · Rejected · Cashout Req · Cashout OK · 🔄 P2P Shared · 💱 PKR→Coins · 🏆 Prize PKR · 🪙 Prize Coins
- **Columns:** Time · Action · Sender (name + email) · Receiver (name + email) · Amount (unit-aware: coins vs PKR) · Note/Method (e.g. jazzcash) · Ref ID
- **Money-trail actions:** `coins_shared` (P2P), `pkr_converted` (PKR→coins), `prize_pkr_sent`, `prize_coins_sent`, `deposit_submitted/approved/rejected`
- Suspicious deposit/cashout patterns are flagged for review

![Transactions](screenshots/04-transactions.png)

---

## 🕐 5. Timeline

Every security event in chronological order — the raw feed behind all the other tabs.

- **100 events** in the live sample
- **Filters:** All · Admin · Security · 🔴 Alerts Only
- Each row shows the event type badge (`coins_shared`, `user_login`, `login_failed`), actor, email hash, IP, and timestamp
- Free-text search across everything

![Timeline](screenshots/05-timeline.png)

---

## 👤 6. User Activity

Who is joining, who is logging in, and how.

- **Stat cards:** New Signups (20) · Email Logins (10) · Google Logins (118) · Signups Today · Failed Logins (195)
- **Filters:** All · Signups · Email Login · Google Login · Failed · Today
- **Columns:** Time · Event · User ID · Provider (Google / email) · Role (PLAYER) · Detail (IP)
- Failed rows carry the email hash plus SQL/Report shortcuts, linking straight into investigation

![User Activity](screenshots/06-user-activity.png)

---

## 🔑 7. Password Resets

Account-takeover hunting. A reset followed by a quick login from a new IP is a classic signal.

- **Stat cards:** Reset Requested (8) · Reset Completed (0) · Incomplete (8) · Last 24h
- **Filters:** All · Requested · Completed · 🔴 Suspicious
- **Columns:** Time · Event · User ID · Email Hash · Status (PENDING) · Notes
- **Reset → quick-login correlation** flags the takeover pattern automatically

![Password Resets](screenshots/07-password-resets.png)

---

## 🛡️ 8. User Mgmt

Admin actions on users — bans, locks, unlocks, deletions — plus the ability to act.

- **Stat cards:** Bans (3) · Unbans (2) · Locks (2) · Unlocks (1) · Deletions (8) · Total Actions (38)
- **Filters:** All · Ban · Unban · Lock · Unlock · Delete · Rooms · Wallet Adjust
- **Columns:** Time · Action · By Admin · Target User · Details (e.g. room deleted with room ID)
- Lock/unlock and ban/unban are enforced here, closing the loop from detection → response

![User Management](screenshots/08-user-mgmt.png)

---

## 🔍 9. Investigation

Correlation engine — where individual signals become verdicts.

- **Correlation cards:** 🌐 Shared IPs (42 IPs with 2+ accounts) · 🟢 Geo Anomaly (multi-city users) · ⚡ Fail→Lock (rapid brute then lock) · 🔑 Reset→Login (reset then quick login) · 🚫 Banned Retry (banned still trying) · 💰 Deposit Risk (suspicious patterns)
- **Composite Risk per Identity (0–100):** every identity scored from its signals, with a visual risk bar and the exact signals listed (e.g. *Failed-login cluster (15m) · Shared IP — 3+ accounts*)
- **CSV export** of the full risk table

![Investigation](screenshots/09-investigation.png)

---

## 📈 10. Trends

Long-range view — is today normal?

- **Failed Logins per Hour** (last 24h) — spikes visible at a glance
- **Deposits vs Cashouts per Day** (last 14 days)
- **Admin Actions per Day** (last 14 days) — unusual admin activity bursts stand out

![Trends](screenshots/10-trends.png)

---

## 🗺️ 11. Threat Map

Where the failed logins come from.

- **40 IPs plotted**, GeoIP resolved in the browser and cached locally — zero extra load on the database
- **Top Countries** panel (PK: 194 in the sample)
- Red = high volume, orange = low volume; hover any dot for details

![Threat Map](screenshots/11-threat-map.png)

---

## 🎯 12. MITRE ATT&CK

Every detection mapped to its technique. Clicking a card opens the triage playbook.

- **T1110 Brute Force** (Credential Access) — 31 critical alerts in sample
- **T1078 Valid Accounts** (Persistence · Defense Evasion · Privilege Escalation · Initial Access) — 3 high alerts
- **T1657 Financial Theft** (Impact) — playbook ready, not yet observed
- **T1531 Account Access Removal** (Impact) — playbook ready, not yet observed

![MITRE](screenshots/12-mitre.png)

---

## 🧪 13. Custom Detection Rules

A mini detection engine in the browser — evaluated on the live sample, zero database load.

- **Rule builder:** Rule name · Event (e.g. Failed logins) · Group by (Source IP) · Count > N · Window (min) · Severity · MITRE (optional)
- **Active rules list** with enable/disable toggle
- Example: *IF ≥5 × Failed logins grouped by IP in 60 min → HIGH, T1110*

![Custom Rules](screenshots/13-custom-rules.png)

---

## 🔔 Alerting — Telegram + Discord

Critical and high alerts fire in real time to both channels, with per-channel dedup and a retry queue so bursts don't spam.

- **Telegram:** 🔴 HIGH alerts with account, attempt count, and timestamp
- **Discord:** rich embeds in `#soc-alerts` — red/orange by severity, MITRE tag in the footer, plus INFO alerts (admin sign-ins with IP, new user signups)
- **Test TG / Test DC** buttons verify both channels from the dashboard header

![Telegram alerts](screenshots/16-telegram-alerts.png)

---

![Discord notifications](screenshots/16-discord-notifications.png)

---

![Discord — soc-alerts channel](screenshots/16-discord-soc-alerts.png)

---

![Discord — alert detail](screenshots/16-discord-alerts-2.png)

---

![Discord — more alerts](screenshots/16-discord-alerts-3.png)

---

![Discord — info alerts](screenshots/16-discord-info-alerts.png)

---

![Discord — admin sign-in alerts](screenshots/16-discord-admin-alerts.png)

---

![Discord — alert sent confirmation](screenshots/16-discord-alert-sent.png)

---

## ⚡ Brute-force demo (why this exists)

The app locks accounts after 7 failed logins. This is what an attack looks like end-to-end: the login page rate-limits the attacker, the dashboard groups the burst, the alert fires, and the account locks.

![Login — too many attempts](screenshots/15-bruteforce-demo-login.png)

---

![Brute-force burst in timeline](screenshots/15-bruteforce-timeline.png)

---

## 💻 Desktop app (.exe)

The dashboard also ships as a native Windows desktop app (Electron, v3.14.0) — same console, no browser needed.

![Installer — welcome](screenshots/14-installer-welcome.png)

---

![Installer — location](screenshots/14-installer-location.png)

---

## Privacy

All screenshots use test accounts. Real user emails, names, and IP addresses are blacked out. Email hashes shown are one-way — they cannot be reversed to addresses.

---

## What I learned building this

- **Detection is grouping.** 340 raw failed logins are noise; 47 grouped-by-account rows are triage.
- **Correlation beats single signals.** A password reset alone is nothing; a reset followed by a quick login from a new IP is a takeover.
- **Close the loop.** Detect → alert → act (lock/unlock) in one place, or the dashboard is just a TV.
- **Names are fragile, hashes are forever.** The dashboard keys identities on hashes and IDs, never on display names — the same lesson from my Wazuh custom-rule work, applied to web logs.
