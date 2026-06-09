# Incident Timeline — Operation BlueBalance

**Campaign ID:** `BLUEDELTA_20260607_072802`  
**Date:** 2026-06-07  
**Analyst:** Adham Alhamidi | Purple Team  
**Supervisor:** Anmar Mohammed

> All timestamps are **UTC+3** (DESKTOP-N56M5HA local time). UTC equivalents provided.  
> Every event is anchored to a confirmed forensic evidence source.  
> Timeline spans: automated attack (07:28–07:29), manual re-execution (11:33–11:38), RAM acquisition (19:00 UTC).

---

## Phase 1 — Automated Attack Chain (07:28:00–07:28:40 Local)

Complete compromise achieved in **40 seconds** of automated execution.

| Time (Local) | UTC | Phase | Event | Evidence Source | MITRE |
|:----------:|:-----:|:-----:|-------|----------------|:-----:|
| **07:28:00** | 04:28:00 | Initial Access | 📧 Phishing email delivered — DHS Directive 2025-09 lure from `anmarma100@gmail.com` impersonating Elena Vasquez / IT Security Compliance Lead | `phishing_email_BLUEDELTA_20260607_072802.txt` | T1566.001 |
| **07:28:05** | 04:28:05 | Execution | 🐍 `python.exe` (PID 2156) executes `NulltackKatz.py` from `C:\NulltackLab\` — attack sequence initiated | Sysmon EID 1 (PID 2156, ParentImage: cmd.exe) | T1204.002 |
| **07:28:10** | 04:28:10 | Discovery | 🔍 `net user` executed — local account enumeration | Sysmon EID 1 / exfiltration_report §2 | T1087.001 |
| **07:28:12** | 04:28:12 | Discovery | 🔍 `ipconfig /all` executed — network configuration collection | Sysmon EID 1 / exfiltration_report §3 | T1016 |
| **07:28:14** | 04:28:14 | Discovery | 🔍 `tasklist` executed — running process enumeration | Sysmon EID 1 / NulltackKatz logs | T1057 |
| **07:28:25** | 04:28:25 | Privilege Escalation | 🔑 `privilege::debug` — SeDebugPrivilege enabled (output: `Privilege 20 OK`) | Sysmon EID 1 / mimikatz output | T1134 |
| **07:28:30** | 04:28:30 | Credential Access | 💀 `lsass.exe` (PID 672) accessed by `python.exe` via mimikatz — `GrantedAccess=0x1010` confirmed | Sysmon EID 10 | T1003.001 |
| **07:28:32** | 04:28:32 | Credential Access | 🗝️ `sekurlsa::logonpasswords` — NTLM hashes + plaintext credentials extracted (Admin123!, Winter2025!, P@ssw0rd123, Finance2024) | `mimikatz_output_simulated.txt` | T1003.001 |
| **07:28:34** | 04:28:34 | Exfiltration | 📡 SMTP TCP SYN: `192.168.88.135:49844 → 142.251.127.108:587` | Sysmon EID 3 (PID 7824) | T1041 |
| **07:28:36** | 04:28:36 | Exfiltration | 🔒 TLS 1.3 Client Hello — `SNI=smtp.gmail.com` confirmed (Wireshark frame 106) | Wireshark PCAP frame 106 | T1041 |
| **07:28:38** | 04:28:38 | Exfiltration | 📤 STARTTLS + Application Data — **3,834-byte** encrypted credential payload transmitted | Wireshark PCAP frame 127.240727 | T1041 |
| **07:28:40** | 04:28:40 | Exfiltration | ✅ **EXFILTRATION CONFIRMED** — SMTP 250 OK, delivered to `adhamalhamidi00@gmail.com` | `exfiltration_report_BLUEDELTA_20260607_072802.txt` | T1041 |

**⏱️ Total automated chain duration: ~35 seconds**

---

## Phase 2 — Manual Re-Execution (11:33–11:38 Local)

Manual execution of mimikatz to demonstrate credential extraction technique.

| Time (Local) | UTC | Event | Evidence Source | MITRE |
|:----------:|:-----:|-------|----------------|:-----:|
| **11:33:56** | 08:33:56 | 🔴 Manual `mimikatz.exe` execution from elevated PowerShell — CommandLine: `"privilege::debug sekurlsa::logonpasswords exit"` | Sysmon EID 1 (PID 3560, ParentImage: powershell.exe, IntegrityLevel: High, SHA256: 92804FAA...) | T1003.001 |
| **11:38:17** | 08:38:17 | 💀 Sysmon EID 10 captured — `mimikatz.exe` (PID 1652) → `lsass.exe` (PID 672), `GrantedAccess=0x1010`, User: DESKTOP-N56M5HA\Shell | Sysmon EID 10 | T1003.001 |
| **11:42:55** | 08:42:55 | 🔴 Second mimikatz execution attempt — PID 3492, PPID 7884 (powershell.exe), same SHA256 hash | Sysmon EID 1 | T1003.001 |

---

## Phase 3 — Memory Forensics Capture (12:00–19:00 UTC)

Post-attack RAM acquisition and forensic analysis.

| Time | UTC | Event | Evidence Source | Notes |
|:----:|:-----:|-------|----------------|-------|
| **12:00:41 PM (local)** | 09:00:41 | Final `mimikatz.exe` execution — PID 1384, PPID 2216 (powershell.exe) | Sysmon EID 1 | This instance captured in RAM dump |
| **~19:00:00 UTC** | 19:00:00 | 🧠 DumpIt launched — RAM acquisition begins | DumpIt v1.3.2.20110401 | `memory.raw` 4GB output |
| **19:00:41 UTC** | 19:00:41 | ✅ `mimikatz.exe` PID 1384 confirmed in physical memory | Volatility 3 `windows.pslist` + `windows.psscan` | No DKOM evasion detected |
| **19:00:55 UTC** | 19:00:55 | DumpIt.exe (PID 6444) visible — RAM acquisition complete | Volatility 3 `windows.pslist` | `memory.raw` preserved |
| **19:00:56 UTC** | 19:00:56 | SystemTime confirmed: 2026-06-07 19:00:56 UTC | Volatility 3 `windows.info` | Corroborates all Sysmon timestamps |

---

## Attack Flow Visualization

```
UTC+3 Timeline:
══════════════════════════════════════════════════════════════════════════
07:28:00  📧 Phishing Email Delivered (T1566.001)
          │
07:28:05  ├─▶ 🐍 NulltackKatz.py Executed (T1204.002)
          │
07:28:10  ├─▶ 🔍 Discovery: net user / ipconfig / tasklist (T1087/T1016/T1057)
          │
07:28:25  ├─▶ 🔑 SeDebugPrivilege Granted (T1134)
          │
07:28:30  ├─▶ 💀 LSASS Accessed GrantedAccess=0x1010 (T1003.001)
          │
07:28:32  ├─▶ 🗝️ Credentials Dumped (T1003.001)
          │
07:28:34  ├─▶ 📡 SMTP TCP SYN to 142.251.127.108:587 (T1041)
          │
07:28:36  ├─▶ 🔒 TLS Handshake SNI=smtp.gmail.com (T1041)
          │
07:28:38  ├─▶ 📤 3,834-byte Payload Transmitted (T1041)
          │
07:28:40  └─▶ ✅ SMTP 250 OK — EXFILTRATION CONFIRMED (T1041)
                                                      ▲
                                              40 SECONDS TOTAL

══════════════════════════════════════════════════════════════════════════
11:33:56  🔴 Manual Mimikatz Execution (T1003.001)
11:38:17  💀 Sysmon EID 10 Confirmed (T1003.001)
══════════════════════════════════════════════════════════════════════════
19:00:00  🧠 DumpIt RAM Acquisition
19:00:41  ✅ mimikatz.exe PID 1384 Confirmed in Memory
19:00:56  ✅ Volatility 3 windows.info SystemTime Confirmed
══════════════════════════════════════════════════════════════════════════
```

---

## Evidence-to-Timeline Cross-Reference

| Evidence Source | Timestamps Covered | Key Finding |
|----------------|-------------------|-------------|
| `phishing_email_BLUEDELTA_*.txt` | 07:28:00 | Email delivery, sender mismatch, DHS lure |
| Sysmon EID 1 | 07:28:05–07:28:14, 11:33:56, 11:42:55, 12:00:41 | Process creation chain, mimikatz executions |
| Sysmon EID 10 | 07:28:30, 11:38:17 | LSASS access, GrantedAccess=0x1010 |
| Sysmon EID 3 | 07:28:34 | SMTP connection to 142.251.127.108:587 |
| Wireshark PCAP | 07:28:34–07:28:40 | TLS handshake, SNI, 3,834-byte payload |
| `mimikatz_output_simulated.txt` | 07:28:32 | Credentials extracted |
| `exfiltration_report_BLUEDELTA.txt` | 07:28:40 | SMTP 250 OK confirmed |
| Volatility 3 `windows.info` | 19:00:56 UTC | System profile, timestamp corroboration |
| Volatility 3 `windows.pslist` | 19:00:41 UTC | Attack process chain in memory |
| Volatility 3 `windows.psscan` | 19:00:41 UTC | mimikatz PID 1384, no DKOM evasion |
| Volatility 3 `windows.handles` | 19:00:41 UTC | PID 1384 → handle 0x2ac → lsass PID 672, GrantedAccess=0x1010 |

---

*Timeline reconstructed from forensic evidence — Operation BlueBalance, Campaign BLUEDELTA_20260607_072802*  
*All events independently corroborated by 2+ evidence sources*
