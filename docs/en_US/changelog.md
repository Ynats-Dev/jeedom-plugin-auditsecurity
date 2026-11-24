---
layout: default
lang: en_US
---

# Security Audit changelog

# 23/11/2026 - 0.2.0

- New "Internet exposure" category: ports opened on the Internet router by UPnP, exposure seen by Shodan, IP address blacklists, HTTPS certificate of the external access
- Tests using external services (Shodan, blacklists) can be enabled in the configuration, disabled by default
- New checks: dangerous services listening, pending reboot, sensitive folders readable by everyone (with automatic fix), SUID/SGID files
- fail2ban only counts in the score if Jeedom is exposed to the Internet
- New interface: score gauge, verdict, priorities, filterable category scores, expandable cards
- Fix: the interface stayed on "Audit running" after an audit

# 23/11/2026 - 0.1.0

- First version (beta)
- 38 checks in 8 categories: accounts, access, API, Jeedom and plugins, web server, system, network, backups
- Score out of 100 and grade from A to F, weighted by severity; a critical vulnerability caps the grade at D
- One-click fixes for 16 checks, with confirmation and rollback if the system configuration is invalid
- Checks can be ignored (accepted risk) and are then left out of the score
- Daily or weekly automatic audit, Jeedom message when a new issue appears
- Device with the commands Score, Grade, Serious issues, Failed, To improve, Last audit, Summary and Run the audit
- Widget with the grade, the score and the counters
- Interface in French, English, German, Spanish and Italian
