# Web App Security Dashboard

A SOC-style monitoring dashboard I built for a tournament website, so I could investigate its security and admin logs the way an analyst would instead of reading raw database rows.

> Not a web development project. The goal was detection and investigation: what can I see, what can I catch, and what is missing from the logs.

---

## The target application

A tournament website with player accounts, email/password login, an admin panel, and a wallet system (deposits, cashouts, coins). It already logs security events and admin actions, and it rate-limits failed logins.

<img width="632" height="415" alt="Screenshot_25" src="https://github.com/user-attachments/assets/5f678013-5621-4111-9a1c-0c49367def94" />

---

## What the dashboard shows

| Tab | What it answers |
|---|---|
| **Overview** | Live alert feed and 24-hour activity summary |
| **Failed Logins** | Which accounts are being attacked, how often, and over what time span |
| **Admin Actions** | Admin logins and actions with source IP |
| **Transactions** | Deposits, cashouts and coin activity with actor and target |
| **Timeline** | Every event in one filterable view, with an "Alerts only" mode |

### Detections

- **Brute force:** failed attempts are grouped per account and flagged by severity (Medium 3+, High 5+, Critical 7+)
- **Lock status:** each account shows whether it is locked now, was locked and has expired, or was never locked
- **Account guessing:** failed logins against emails with no matching profile are flagged separately, which points to someone trying accounts that do not exist
- **Unknown admin IPs:** admin logins from unrecognised IPs raise an alert
- **Hash-to-account matching:** failed-login events only store a SHA-256 hash of the email. I match those hashes against registered users to see which account was actually targeted, without storing plain emails in the log

---

## Screenshots

User names are blurred.

### Failed Logins
<img width="1835" height="897" alt="2-failed-logins-blurred" src="https://github.com/user-attachments/assets/7dc491d6-056d-42cd-82b1-db263c8d58c9" />

### Overview
<img width="1885" height="852" alt="1-overview-blurred" src="https://github.com/user-attachments/assets/9fe4cad5-6ddc-4102-9ec8-c776dfbe8380" />

### Timeline
<img width="1919" height="902" alt="3-timeline-blurred" src="https://github.com/user-attachments/assets/7f4cfb03-4c82-46ee-8a70-5c07b90e347c" />

---

<img width="1906" height="881" alt="05_recent_activity" src="https://github.com/user-attachments/assets/eb73a2c5-3937-4754-a036-4b9922503d00" />

---

<img width="1919" height="783" alt="01_deposit_admin_freq" src="https://github.com/user-attachments/assets/2c971c1d-763d-4a33-ae18-e90463b630e1" />

---

## Test: brute-forcing my own account

To check that detection and prevention both work, I deliberately entered wrong passwords on my own test account.

| Round | Wrong passwords | Result |
|---|---|---|
| 1 | 7 | 15-minute lockout |
| 2 | 7 (after the lock expired) | 15-minute lockout |

- The lockout triggered exactly as designed
- The dashboard grouped all 14 attempts under one account and marked it **Critical**
- After the lock expired, the status changed to **Lock expired**
- Note: the dashboard's early "BLOCK" label was only a display label based on attempt count, not a real lock. I replaced it with real lock data so the status reflects what actually happened

---

## Findings

1. **Low-and-slow attempts slip past the lockout.** One account had 9 failed attempts spread over 46 hours and was never locked. It could be a user forgetting a password, but it is the exact pattern a simple windowed rate limiter misses. The dashboard still caught it because it looks at the full history.
2. **Failed-login events have no source information.** They record only the email hash. No IP address, user agent or location, so I can see which account was targeted but not where the attempts came from. Admin actions do log IP and location, so the data exists in the app, it is just missing from this event type.
3. **No event when a lock is applied.** The lock is stored as a timestamp on the account's rate-limit record, but no security event is written, so a lock never appears in the timeline.

---

## Limitations

- Read-only. It does not block, ban or lock anything
- Data refreshes every 30 seconds by polling
- The dashboard shows the most recent 500 events per source
- Built with AI assistance. What matters here is what it lets me investigate, and the analysis is my own

## Next steps

- [ ] Log IP, user agent and geo on `login_failed` events
- [ ] Write an `account_locked` event when a lock is applied
- [ ] Add a low-and-slow detection rule (many failures over a long window)
- [ ] Forward these logs into a SIEM (Wazuh) for correlation and alerting

---

## Privacy note

The dashboard file is not published in this repository. It contains project-specific configuration for a live site. Screenshots have user names blurred.

---

*Part of [SOC-Journey-2026](https://github.com/awaisjaved-soc/SOC-Journey-2026)*
