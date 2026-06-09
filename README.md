<div align="center">

# 🐻 APT28 · BlueDelta · Operation BlueBalance
## DFIR Investigation & Purple Team Report

**Campaign ID:** `BLUEDELTA_20260607_072802` &nbsp;|&nbsp; **Date:** `2026-06-07` &nbsp;|&nbsp; **Analyst:** Adham Alhamidi

---

![DFIR](https://img.shields.io/badge/DFIR-Investigation-1B2A4A?style=for-the-badge&logo=shield&logoColor=white)
![Threat Hunting](https://img.shields.io/badge/Threat-Hunting-C0392B?style=for-the-badge&logo=target&logoColor=white)
![Purple Team](https://img.shields.io/badge/Purple-Team-6C3483?style=for-the-badge&logo=shield&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-E67E22?style=for-the-badge&logo=target&logoColor=white)
![Memory Forensics](https://img.shields.io/badge/Memory-Forensics-1E8449?style=for-the-badge&logo=database&logoColor=white)
![Volatility3](https://img.shields.io/badge/Volatility-3-2E75B6?style=for-the-badge&logo=linux&logoColor=white)
![Sysmon](https://img.shields.io/badge/Sysmon-Telemetry-1B2A4A?style=for-the-badge&logo=windows&logoColor=white)
![Wireshark](https://img.shields.io/badge/Wireshark-Network-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)
![Network Forensics](https://img.shields.io/badge/Network-Forensics-2C3E50?style=for-the-badge&logo=cisco&logoColor=white)
![Threat Intelligence](https://img.shields.io/badge/Threat-Intelligence-922B21?style=for-the-badge&logo=intel&logoColor=white)

---

</div>

## 📋 Table of Contents

| Section | Description |
|---------|-------------|
| [Executive Summary](#-executive-summary) | High-level investigation overview |
| [Scenario Overview](#-scenario-overview) | Exercise scope and environment |
| [Threat Actor Profile](#-threat-actor-profile-apt28--bluedelta) | APT28 attribution and TTPs |
| [Attack Flow](#-attack-flow-overview) | End-to-end kill chain walkthrough |
| [Investigation Methodology](#-investigation-methodology) | Detection and forensic approach |
| [Key Findings](#-key-findings) | Five critical analyst conclusions |
| [Incident Timeline](#-incident-timeline) | Forensically-validated event sequence |
| [MITRE ATT&CK Mapping](#-mitre-attck-mapping) | Full technique coverage |
| [Memory Forensics](#-memory-forensics) | Volatility 3 analysis results |
| [Network Forensics](#-network-forensics) | Wireshark / TLS exfiltration evidence |
| [Detection Engineering](#-detection-engineering) | Suricata + Sysmon + Sigma rules |
| [Knowledge Graph](#-knowledge-graph--attack-visualization) | Executive attack visualization |
| [Obsidian Canvas](#-obsidian-dfir-investigation-canvas) | Analyst investigation board |
| [IOC Summary](#-indicators-of-compromise) | Consolidated IOC master table |
| [Incident Response](#-incident-response--remediation) | NIST 800-61r2 playbook |
| [Lessons Learned](#-lessons-learned) | Strategic defensive improvements |
| [References](#-references) | Sources and documentation |

---

## 🎯 Executive Summary

This repository documents **Operation BlueBalance** — a complete end-to-end APT28 (Fancy Bear / BlueDelta) threat emulation exercise conducted on `2026-06-07` in an isolated Windows 10 lab environment. The campaign emulates the exact tradecraft documented against real-world targets including the 2016 DNC breach, WADA credential theft operations, and the 2025 BlueDelta credential harvesting campaign against Turkish energy companies and European think tanks.

| Metric | Value | Metric | Value |
|--------|-------|--------|-------|
| **Target Host** | `DESKTOP-N56M5HA` | **Attacker IP** | `192.168.88.135` |
| **OS** | Windows 10 (10.0.19045) | **Architecture** | AMD64 |
| **Campaign ID** | `BLUEDELTA_20260607_072802` | **Username** | Shell |
| **Credential Dump** | ✅ Confirmed | **Exfiltration** | ✅ Confirmed |
| **Attack Duration** | ~40 seconds (automated) | **Memory Forensics** | ✅ Complete |
| **MITRE Techniques** | 9 confirmed | **Detection Coverage** | 100% |

### Executive Findings Dashboard

| Attack Stage | MITRE ID | Status | Confidence |
|-------------|----------|--------|------------|
| Initial Access — Spearphishing | T1566.001 | ✅ CONFIRMED | HIGH |
| Execution — Malicious File | T1204.002 | ✅ CONFIRMED | HIGH |
| Discovery — Recon Commands | T1087/T1016/T1057 | ✅ CONFIRMED | HIGH |
| Privilege Escalation — SeDebugPrivilege | T1134 | ✅ CONFIRMED | HIGH |
| Credential Access — LSASS Dump | T1003.001 | ✅ CONFIRMED | HIGH |
| Exfiltration — Gmail SMTP TLS | T1041 | ✅ CONFIRMED | HIGH |
| Detection Coverage — All phases | All | ✅ FULL | HIGH |
| Memory Forensics — Volatility 3 | — | ✅ COMPLETE | HIGH |
| Threat Attribution — GRU Unit 26165 | G0007 | ✅ ATTRIBUTED | MEDIUM-HIGH |

---

## 🔬 Scenario Overview

**Operation BlueBalance** simulates APT28's documented credential theft and exfiltration tradecraft — the same techniques used in real operations against political, government, and defense targets globally.

### Environment

```
Hypervisor:   VMware Workstation (Host-Only Network — Isolated)
Guest OS:     Windows 10 Pro Build 19045 (AMD64)
Hostname:     DESKTOP-N56M5HA
User:         Shell (Standard + Admin context for attack)
Network:      Isolated — controlled Gmail exfiltration only
```

### Tool Stack

| Tool | Role | Configuration |
|------|------|---------------|
| **Sysmon 64** | Endpoint Telemetry | SwiftOnSecurity config — EID 1, 3, 7, 10 |
| **Wireshark** | Network Capture | Filter: `tls or smtp or http` — all interfaces |
| **DumpIt** | RAM Acquisition | Output: `C:\NulltackLab\evidence\memory.raw` |
| **Volatility 3** | Memory Forensics | `windows.pslist`, `psscan`, `handles` |
| **NulltackKatz.py** | APT28 Emulation Tool | `C:\NulltackLab\NulltackKatz.py` |
| **Mimikatz** | Credential Dumping | Invoked automatically by NulltackKatz |

### Evidence Directory Structure

```
C:\NulltackLab\
├── NulltackKatz.py               # APT28 emulation payload
├── logs\
│   ├── phishing_email_BLUEDELTA_*.txt
│   ├── mimikatz_output_simulated.txt
│   └── exfiltration_report_BLUEDELTA_*.txt
└── evidence\
    └── memory.raw                # 4GB full RAM capture
```

---

## 🐻 Threat Actor Profile: APT28 / BlueDelta

APT28 (also known as **Fancy Bear**, **BlueDelta**, **Sednit**, **Sofacy**, **STRONTIUM**, and **Forest Blizzard**) is a state-sponsored cyber espionage group attributed to the **Russian General Staff Main Intelligence Directorate (GRU) — Military Unit 26165 (85th GTsSS)**. Active since at least 2007, the group primarily targets government, military, finance, energy, and political organizations.

| Attribute | Details |
|-----------|---------|
| **Known Aliases** | Fancy Bear, BlueDelta, Sednit, Sofacy, STRONTIUM, Pawn Storm, Tsar Team, Forest Blizzard |
| **Attribution** | Russian GRU — Military Unit 26165 (85th GTsSS) |
| **MITRE Group ID** | [G0007](https://attack.mitre.org/groups/G0007/) |
| **Active Since** | 2007 (publicly identified ~2014) |
| **Motivation** | Political espionage, credential theft, intelligence gathering, election interference |
| **Primary Sectors** | Government, Military, Finance, Energy, Media, Political |
| **Related Units** | Sandworm (GRU Unit 74455) — destructive ops; Unit 29155 — sabotage |

### Historical Operations

| Operation | Year | Target | Key Techniques |
|-----------|------|--------|----------------|
| U.S. Election Interference | 2016 | DNC, Clinton Campaign, DCCC | T1566.001, T1078, T1041 |
| WADA / USADA Operations | 2014–2018 | Anti-doping agencies | T1566, T1213, T1078 |
| OPCW / Spiez Lab Attacks | 2018 | Chemical weapons investigators | Spearphishing, T1003, T1041 |
| BlueDelta Credential Harvesting | 2025 | Turkish energy, EU think tanks | T1566.001, T1003.001, OWA abuse |
| Operation Pawn Storm / Sofacy | 2014–2015 | NATO, White House, Bundestag | T1204.001, T1566, T1071 |

> **APT28 vs. Sandworm:** Both operate under GRU but serve different missions. APT28 (Unit 26165) conducts long-term espionage and credential theft. Sandworm (Unit 74455) executes destructive attacks (NotPetya, BlackEnergy, Olympic Destroyer). This scenario emulates APT28's stealthy intelligence-gathering approach.

---

## ⚔️ Attack Flow Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    APT28 BlueDelta Kill Chain                               │
│                    Campaign: BLUEDELTA_20260607_072802                      │
├──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┤
│  Phase 1  │  Phase 2  │  Phase 3  │  Phase 4  │  Phase 5  │  Phase 6  │ Phase 7 │
│           │           │           │           │           │           │         │
│ SPEAR-    │ MALICIOUS │ DISCOVERY │ PRIVILEGE │ CREDENTIAL│ MEMORY    │ EXFIL-  │
│ PHISHING  │ EXECUTION │           │ ESCALATION│ ACCESS    │ FORENSICS │ TRATION │
│           │           │           │           │           │           │         │
│T1566.001  │T1204.002  │T1087.001  │  T1134    │T1003.001  │Volatility │  T1041  │
│           │           │T1016      │           │           │    3      │         │
│           │           │T1057      │           │           │           │         │
├──────────┼──────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│DHS lure  │NulltackKa│net user   │privilege  │Mimikatz   │DumpIt +  │Gmail    │
│Gmail→    │tz.py via │ipconfig   │::debug    │sekurlsa   │memory.raw│SMTP TLS │
│Drive link│python.exe│tasklist   │Priv 20 OK │NTLM+plain │pslist/   │Port 587 │
│          │          │           │           │text creds │psscan    │SNI conf │
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘

INFRASTRUCTURE LAYER:
APT28 → phishing email → DESKTOP-N56M5HA → NulltackKatz.py → LSASS (PID 672)
     → mimikatz (PID 1384) → credentials → smtp.gmail.com:587 → adhamalhamidi00@gmail.com
```

### Phase Details

**Phase 1 — Spearphishing (T1566.001)**
Two-layered lure strategy:
- **Lure 1:** "IT Security" payroll urgency email from `anmar@nulltack.com` (display-name spoofed)
- **Lure 2:** Sophisticated DHS Directive 2025-09 impersonation referencing fake CVE-2025-2847, NIST SP 800-63B, and fabricated certificate thumbprint — sent from `anmarma100@gmail.com` impersonating "Elena Vasquez, IT Security Compliance Lead"

**Phase 2 — Execution (T1204.002)**
Victim executes `NulltackKatz.py` via Python. Parent chain: `email attachment → python.exe (PID 2156)`. The script immediately initiates the discovery and privilege escalation chain.

**Phase 3 — Discovery (T1087.001 / T1016 / T1057)**
Three discovery commands captured in Sysmon EID 1 and exfiltration report:
- `net user` — local account enumeration (T1087.001)
- `ipconfig /all` — network configuration (T1016)
- `tasklist` — running process discovery (T1057)

**Phase 4 — Privilege Escalation (T1134)**
`privilege::debug` grants SeDebugPrivilege (Privilege 20 OK), enabling direct LSASS memory access.

**Phase 5 — Credential Access (T1003.001)**
`sekurlsa::logonpasswords` dumps NTLM hashes and plaintext passwords. Credentials extracted:
- Administrator: `31d6cfe0d16ae931b73c59d7e0c089c0`
- Shell: `8846f7eaee8fb117ad06bdd830b7586c`
- Plaintext: `Admin123!`, `Winter2025!`, `P@ssw0rd123`, `Finance2024`

**Phase 6 — Memory Forensics**
DumpIt captures 4GB RAM image (`memory.raw`). Volatility 3 confirms full attack toolchain in memory — mimikatz PID 1384 holds Process handle `0x2ac` on lsass.exe PID 672 with `GrantedAccess=0x1010`.

**Phase 7 — Exfiltration (T1041)**
Credential report transmitted via Gmail SMTP (port 587, TLS 1.3) to `adhamalhamidi00@gmail.com`. 3,834-byte Application Data payload confirmed in Wireshark. SMTP 250 OK confirms delivery.

---

## 🔍 Investigation Methodology

The investigation followed a structured DFIR approach across five evidence streams:

```
Email Analysis  →  Sysmon Telemetry  →  Process Tree  →  Network PCAP  →  Memory Forensics
    │                    │                    │                │                │
 T1566.001           T1003.001            T1204.002        T1041            T1003.001
 Phishing IoC       EID 10 (0x1010)      EID 1 (PID)      TLS SNI          handles
 Header mismatch    EID 1 (cmdline)      Parent chain     Port 587         psscan/pslist
```

### Evidence Cross-Correlation

| Evidence Source | Key Finding | MITRE Confirmed |
|----------------|-------------|-----------------|
| `phishing_email_BLUEDELTA_*.txt` | Sender mismatch: `nulltack.com` / reply-to `anmarma100@gmail.com` | T1566.001 |
| Sysmon EID 1 | `python.exe` PID 2156 → `mimikatz.exe` CommandLine: `privilege::debug sekurlsa::logonpasswords exit` | T1204.002, T1003.001 |
| Sysmon EID 10 | `GrantedAccess=0x1010` on `lsass.exe` (PID 672) | T1003.001 |
| Sysmon EID 3 | `python.exe` → `142.251.127.108:587` | T1041 |
| Wireshark PCAP | TLS SNI: `smtp.gmail.com` — frames 106 & 137; 3,834-byte App Data | T1041 |
| Volatility `windows.handles` | PID 1384 (mimikatz) → Process handle `0x2ac` on lsass PID 672, `GrantedAccess=0x1010` | T1003.001 |

---

## 🔑 Key Findings

### Finding 1 — Root Cause: Social Engineering Enabled Full Chain
The root cause is a successful spearphishing attack (T1566.001) exploiting two layered social engineering vectors. **No technical vulnerability was exploited** — the attack relied entirely on human factors. Complete credential exposure was achieved in **40 seconds** of automated execution.

> **Root Cause Path:** T1566.001 → T1204.002 → T1003.001 → T1041

### Finding 2 — 40-Second Automated Compromise
The complete attack chain from script execution to exfiltration confirmation completed in ~40 seconds. Detection **must be pre-positioned** — there is zero time for human SOC intervention during the automated phase.

```
00s  Execution starts (NulltackKatz.py)
10s  Discovery commands complete
20s  SeDebugPrivilege acquired
25s  LSASS memory read (GrantedAccess 0x1010)
27s  Credentials extracted
29s  SMTP TCP SYN to 142.251.127.108:587
31s  TLS handshake (SNI=smtp.gmail.com)
35s  Application Data transmitted (3,834 bytes)
40s  SMTP 250 OK — exfiltration CONFIRMED
```

### Finding 3 — Three Forensic Pillars (Independent Corroboration)
Three independent evidence streams confirm every finding — cross-source validation eliminates any false positive:
1. **Sysmon EID 10** — `GrantedAccess=0x1010` on `lsass.exe` (endpoint telemetry)
2. **Wireshark TLS SNI** — `smtp.gmail.com` confirmed in frames 106 and 137 (network forensics)
3. **Volatility 3 `windows.handles`** — PID 1384 → lsass PID 672, `0x1010` (memory forensics)

### Finding 4 — Five Detection Chokepoints Identified
Five pre-positioned controls would independently catch this attack:
1. **Email gateway** — sender domain `nulltack.com` + reply-to mismatch
2. **Sysmon EID 1** — `python.exe` executing `.py` from `C:\NulltackLab\`
3. **Sysmon EID 10** — `GrantedAccess 0x1010` from non-whitelisted process on `lsass.exe` (**CRITICAL**)
4. **Sysmon EID 3** — `python.exe` initiating outbound TCP/587 to external IP
5. **Suricata TLS SNI** — `smtp.gmail.com` in handshake from workstation

### Finding 5 — Critical Defensive Gaps
- **MISSING:** Windows Credential Guard (would prevent T1003.001 entirely)
- **MISSING:** Outbound SMTP blocked from workstations (would stop T1041)
- **MISSING:** Email attachment sandboxing for `.py` files (would stop T1204.002)
- **MISSING:** LSA Protection (`RunAsPPL=1`) not enabled

---

## 📅 Incident Timeline

> All timestamps are UTC+3 (DESKTOP-N56M5HA system time). UTC equivalents provided.

| Time (Local) | UTC | Event | Evidence Source | MITRE |
|-------------|-----|-------|----------------|-------|
| `07:28:00` | `04:28:00` | 📧 Phishing email delivered — DHS Directive 2025-09 lure | `phishing_email_BLUEDELTA_*.txt` | T1566.001 |
| `07:28:05` | `04:28:05` | 🐍 `python.exe` (PID 2156) executes `NulltackKatz.py` | Sysmon EID 1 (PID 2156) | T1204.002 |
| `07:28:15` | `04:28:15` | 🔍 Discovery: `net user`, `ipconfig /all`, `tasklist` | exfiltration_report §2-3 | T1087/T1016/T1057 |
| `07:28:25` | `04:28:25` | 🔑 `privilege::debug` — SeDebugPrivilege enabled (Privilege 20 OK) | Sysmon EID 1 + mimikatz output | T1134 |
| `07:28:30` | `04:28:30` | 💀 LSASS (PID 672) accessed — `GrantedAccess=0x1010` | Sysmon EID 10 | T1003.001 |
| `07:28:32` | `04:28:32` | 🗝️ NTLM hashes + plaintext credentials extracted | `mimikatz_output_simulated.txt` | T1003.001 |
| `07:28:34` | `04:28:34` | 📡 SMTP connection: `192.168.88.135:49844 → 142.251.127.108:587` | Sysmon EID 3 (PID 7824) | T1041 |
| `07:28:36` | `04:28:36` | 🔒 TLS 1.3 Client Hello — `SNI=smtp.gmail.com` (frame 106) | Wireshark PCAP frame 106 | T1041 |
| `07:28:38` | `04:28:38` | 📤 STARTTLS + 3,834-byte Application Data transmitted | Wireshark frame 127.240727 | T1041 |
| `07:28:40` | `04:28:40` | ✅ **Exfiltration confirmed** — SMTP 250 OK to `adhamalhamidi00@gmail.com` | exfiltration_report | T1041 |
| `11:38:17` | `08:38:17` | 🔁 Manual mimikatz execution — EID 10 `GrantedAccess=0x1010` (PID 1652 → lsass 672) | Sysmon EID 10 | T1003.001 |
| `19:00:41 UTC` | `19:00:41` | 🧠 `mimikatz.exe` PID 1384 confirmed in RAM — DumpIt acquisition complete | Volatility 3 `windows.pslist` | Memory Forensics |

📄 Full timeline: [`timeline/Incident_Timeline.md`](timeline/Incident_Timeline.md)

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Detection Method | Status |
|-------------|----------------|--------|------------------|--------|
| **T1566.001** | Spearphishing Attachment | Initial Access | Email gateway, header analysis, domain reputation | ✅ Confirmed |
| **T1204.002** | Malicious File Execution | Execution | Sysmon EID 1 — `python.exe` + NulltackKatz.py | ✅ Confirmed |
| **T1087.001** | Local Account Discovery | Discovery | Sysmon EID 1 — `net user` command | ✅ Confirmed |
| **T1016** | System Network Config Discovery | Discovery | Sysmon EID 1 — `ipconfig /all` | ✅ Confirmed |
| **T1057** | Process Discovery | Discovery | Sysmon EID 1 — `tasklist` | ✅ Confirmed |
| **T1134** | Access Token Manipulation | Privilege Escalation | Sysmon EID 1 — `privilege::debug` | ✅ Confirmed |
| **T1003.001** | OS Credential Dumping: LSASS | Credential Access | Sysmon EID 10 — `GrantedAccess=0x1010` | ✅ Confirmed |
| **T1041** | Exfiltration Over C2 Channel | Exfiltration | Wireshark TLS SNI, Sysmon EID 3 port 587 | ✅ Confirmed |
| **T1021** | Remote Services (Potential) | Lateral Movement | NTLM hashes available for PtH — identified as risk | ⚠️ Risk Identified |

📄 Full mapping: [`mitre/MITRE_Mapping.md`](mitre/MITRE_Mapping.md)

---

## 🧠 Memory Forensics

RAM acquisition was performed immediately after attack execution using **DumpIt** (4GB `memory.raw`). **Volatility 3 Framework 2.28.1** was used for analysis.

### System Profile

```
Plugin: windows.info
─────────────────────────────────────────────────────
Is64Bit:           True
NtMajorVersion:    10 (Windows 10)
SystemTime:        2026-06-07 19:00:56 UTC
NtSystemRoot:      C:\WINDOWS
Kernel Base:       0xf80348a00000
KeNumberProcessors: 2
```

### Attack Process Chain

```python
# Volatility 3 — windows.pslist (attack processes)
PID    PPID   ImageFileName    CreateTime
─────────────────────────────────────────────────────────────────
672    504    lsass.exe        2026-06-07 13:08:45 UTC  ← TARGET
2216   4480   powershell.exe   2026-06-07 18:52:00 UTC  ← ATTACKER SHELL
2112   2064   python.exe       2026-06-07 19:00:35 UTC  ← NulltackKatz
1384   2216   mimikatz.exe     2026-06-07 19:00:41 UTC  ← CREDENTIAL DUMPER
6444   6824   DumpIt.exe       2026-06-07 19:00:55 UTC  ← FORENSIC CAPTURE
```

### Critical Handle Relationship

```
# Volatility 3 — windows.handles (LSASS access confirmation)
PID 1384 (mimikatz.exe) → Process handle 0x2ac → lsass.exe PID 672
GrantedAccess: 0x1010 = PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
                                    ↑
                        Identical to Sysmon EID 10 GrantedAccess value
                        → Memory-level corroboration of T1003.001
```

### psscan Detection (Anti-DKOM)

```
# Volatility 3 — windows.psscan (bypasses userland hiding)
PID=1384  PPID=2216  ImageFileName=mimikatz.exe
Offset=0xae0820b16080  CreateTime=2026-06-07 19:00:41 UTC
Result: No DKOM evasion detected — mimikatz fully visible in physical memory
```

---

## 🌐 Network Forensics

### Wireshark Evidence Chain

**Filter 1 — SMTP Handshake**
```
Filter: smtp
Result: EHLO from DESKTOP-N56M5HA.localdomain (192.168.88.135)
        Server: 220 smtp.gmail.com ESMTP ← Exfiltration channel confirmed
        STARTTLS negotiation visible
```

**Filter 2 — TCP Port 587 Full Session**
```
Filter: tcp.port == 587
Packets 127-129: TCP SYN → SYN-ACK → ACK (three-way handshake)
Packets 134-136: SMTP EHLO/250, STARTTLS upgrade
Packet 137:      TLSv1.3 Client Hello (SNI=smtp.gmail.com)
Packets 138+:    TLS Application Data (encrypted credential payload)
```

**Filter 3 — TLS SNI Confirmation**
```
Filter: tls.handshake.extensions_server_name contains "smtp.gmail.com"
Results: Frame 106 — TLSv1.3 Client Hello (SNI=smtp.gmail.com)
         Frame 137 — TLSv1.3 Client Hello (SNI=smtp.gmail.com)
→ Definitive, non-repudiable network evidence for T1041
```

**Filter 4 — Encrypted Exfiltration Stream**
```
Filter: tls and ip.dst == 142.251.127.0/24
Frame 127.240727: 3,834-byte Application Data
→ Credential payload confirmed in encrypted stream
```

### Network IOC Summary

```
Source:      192.168.88.135 (DESKTOP-N56M5HA)
Destination: 142.251.127.108:587 (Gmail SMTP Primary)
             142.251.127.109:587 (Gmail SMTP Secondary)
Protocol:    SMTP / STARTTLS / TLSv1.3
Payload:     3,834 bytes (encrypted credential report)
Confirmed:   SMTP 250 OK — delivery to adhamalhamidi00@gmail.com
```

---

## 🛡️ Detection Engineering

### Suricata Rules

```yaml
# Rule 1 — SMTP Exfiltration via Gmail (T1041)
alert tcp $HOME_NET any -> $EXTERNAL_NET 587 (
    msg:"APT28 T1041 - Gmail SMTP Credential Exfiltration";
    flow:established,to_server;
    classtype:trojan-activity; sid:9000001; rev:1;)

# Rule 2 — TLS to Gmail SMTP with SNI check (T1041)
alert tls $HOME_NET any -> $EXTERNAL_NET 465 (
    msg:"APT28 T1041 - SMTPS Exfiltration to Gmail";
    tls.sni; content:"smtp.gmail.com";
    classtype:trojan-activity; sid:9000002; rev:1;)

# Rule 3 — DNS query for Gmail SMTP infrastructure
alert dns $HOME_NET any -> any 53 (
    msg:"APT28 T1041 - DNS Lookup smtp.gmail.com";
    dns.query; content:"smtp.gmail.com";
    sid:9000003; rev:1;)
```

📄 Full rules: [`detection/suricata/`](detection/suricata/) | [`detection/sigma/`](detection/sigma/) | [`detection/sysmon/`](detection/sysmon/)

### Sysmon Detection — Critical Event IDs

| Event ID | Rule | Trigger |
|----------|------|---------|
| **EID 1** | Process Create | `mimikatz` / `NulltackKatz` in Image OR `sekurlsa` in CommandLine |
| **EID 10** | Process Access | `TargetImage=lsass.exe` AND `GrantedAccess=0x1010/0x1410/0x143a` |
| **EID 3** | Network Connect | `DestinationPort=587/465` OR hostname contains `gmail.com` |
| **EID 7** | Image Load | `sekurlsa` / `kerberos` in ImageLoaded |

### Three Priority Detection Rules for SOC

| # | Rule | Logic |
|---|------|-------|
| 1 | **LSASS Memory Read** | Alert: any process accessing `lsass.exe` with `GrantedAccess 0x1010/0x1410/0x143a` (Sysmon EID 10) — whitelist only AV/EDR |
| 2 | **Unusual SMTP Outbound** | Alert: any workstation initiating outbound TCP/587 or TCP/465 — finance hosts should NEVER originate SMTP |
| 3 | **Script → Network Exfil Chain** | Correlate: `python.exe` / `wscript.exe` process creation (EID 1) → outbound TCP/587 from same PID within 5 minutes (EID 3) |

---

## 🕸️ Knowledge Graph & Attack Visualization

### 9.1 Executive Attack Knowledge Graph (Figure 49)

> **Purpose:** Executive-level end-to-end attack lifecycle visualization.
> **Answers:** *"How did the attack occur from beginning to end?"*

The Knowledge Graph maps the complete APT28 attack chain across nine analytical dimensions:

| KG Layer | Content | Analytical Value |
|----------|---------|-----------------|
| **Threat Actor** | APT28 / GRU Unit 26165 / Fancy Bear | Attribution + adversary profile |
| **Infrastructure** | APT28 → DESKTOP-N56M5HA → LSASS → smtp.gmail.com → attacker mailbox | C2 communication flow |
| **MITRE ATT&CK** | T1566.001 → T1204.002 → T1087/T1016/T1057 → T1134 → T1003.001 → T1041 | Sequential kill chain |
| **Evidence Layer** | Sysmon EID 1/3/10 → Wireshark PCAP → Volatility 3 pslist/psscan/handles | Forensic anchor points |
| **Outcomes** | NTLM hashes + plaintext credentials exposed; T1021 lateral movement risk | Business risk assessment |

![Figure 49 — APT28 Executive Attack Knowledge Graph](knowledge_graph/Attack_Knowledge_Graph.png)

*Figure 49 — APT28 Executive Attack Knowledge Graph: End-to-end view of Campaign BLUEDELTA_20260607_072802. Infrastructure: APT28 → DESKTOP-N56M5HA → LSASS → smtp.gmail.com → adhamalhamidi00@gmail.com. MITRE chain: T1566.001 → T1204.002 → T1087/T1016/T1057 → T1134 → T1003.001 → T1041.*

---

## 🔭 Obsidian DFIR Investigation Canvas

> **Purpose:** Analyst-level investigation workflow and evidence correlation board.
> **Answers:** *"How was the attack investigated and reconstructed?"*

The Obsidian Canvas complements Figure 49 with analyst-level investigation logic:

**Canvas Node Structure:**
- 🟦 **APT28 Node** — Threat actor profile and attribution (GRU Unit 26165, G0007)
- 🟧 **Attack Phase Nodes** — Each phase (Initial Access through Impact) as an investigation node
- 🟩 **Evidence Nodes** — Sysmon EIDs, Wireshark PCAP, Volatility results as artifact nodes
- 🟥 **IOC Nodes** — Email addresses, IPs, file hashes, process names
- 🟪 **Detection Nodes** — Suricata rules, Sysmon config, Sigma rule references

**Evidence Relationships:**
```
phishing_email → T1566.001 confirmed
        ↓
NulltackKatz.py → python.exe (Sysmon EID 1) → T1204.002
        ↓
mimikatz.exe → lsass.exe handle (EID 10, Volatility handles) → T1003.001
        ↓
SMTP session (EID 3) → Wireshark SNI → smtp.gmail.com → T1041
```

**Timeline Reconstruction in Canvas:**
```
07:28 UTC  ──→  Email delivery (T1566.001)
07:28 UTC  ──→  Script execution (T1204.002)
07:28 UTC  ──→  Discovery + SeDebug (T1087/T1134)
07:28 UTC  ──→  LSASS dump (T1003.001)
07:28 UTC  ──→  Exfiltration confirmed (T1041)
19:00 UTC  ──→  Memory forensics (Volatility 3)
```

![Obsidian DFIR Investigation Canvas](knowledge_graph/Obsidian_Canvas.png)

*Obsidian Canvas — APT28 BlueBalance DFIR Investigation Board: Analyst-level investigation view covering all forensic artifact nodes, MITRE ATT&CK mappings (T1566.001 → T1041), Sysmon/Suricata/Volatility IOC detection rules, infrastructure layer, and attack reconstruction from Initial Access (07:28 UTC) to Exfiltration (07:33 UTC) — Campaign BLUEDELTA_20260607_072802, GRU Unit 26165.*

---

## 🚨 Indicators of Compromise

📄 Full IOC table: [`iocs/IOC_Master_Table.csv`](iocs/IOC_Master_Table.csv) | [`iocs/IOC_Summary.md`](iocs/IOC_Summary.md)

### Network Indicators

| Type | Indicator | Purpose | Confidence |
|------|-----------|---------|------------|
| IP | `142.251.127.108` | Gmail SMTP exfiltration server (primary) | HIGH |
| IP | `142.251.127.109` | Gmail SMTP exfiltration server (secondary) | HIGH |
| IP | `192.168.88.135` | Victim workstation (DESKTOP-N56M5HA) | HIGH |
| Hostname | `smtp.gmail.com` | C2 exfiltration channel (TLS SNI confirmed) | HIGH |
| Port | `TCP/587` | SMTP STARTTLS exfiltration channel | HIGH |
| Protocol | `TLSv1.3` | Encrypted exfiltration transport | HIGH |
| Domain | `nulltack.com` | Phishing sender domain | HIGH |

### Email Indicators

| Type | Indicator | Purpose |
|------|-----------|---------|
| Email | `anmarma100@gmail.com` | Phishing sender (impersonating "Elena Vasquez") |
| Email | `anmar@nulltack.com` | Phishing display address (spoofed IT Security) |
| Email | `adhamalhamidi00@gmail.com` | Attacker mailbox — credential recipient |

### File & Process Indicators

| Type | Indicator | Purpose |
|------|-----------|---------|
| File | `NulltackKatz.py` | APT28 emulation payload (`C:\NulltackLab\`) |
| File | `mimikatz.exe` | Credential dumping binary |
| Hash (SHA256) | `92804FAAAB2175DC501D73E814663058C78C0A042675A8937266357BCFB96C50` | mimikatz.exe — all instances |
| Process | `python.exe` (PID 2156/7824/2112) | NulltackKatz executor |
| Process | `mimikatz.exe` (PID 1384) | Credential dumper — RAM-resident |

### Credential Indicators ⚠️ ACTION REQUIRED

| Type | Value | Action |
|------|-------|--------|
| NTLM | `31d6cfe0d16ae931b73c59d7e0c089c0` (Shell) | **RESET IMMEDIATELY** |
| NTLM | `31d6cfe0d16ae931b73c59d7e0c089c0` (Administrator) | **RESET IMMEDIATELY** |
| Plaintext | `Admin123!`, `Winter2025!`, `P@ssw0rd123`, `Finance2024` | **RESET IMMEDIATELY** |
| Kerberos | `krbtgt ticket — TESTLAB.LOCAL` | **INVALIDATE** |

---

## 🚑 Incident Response & Remediation

Follows **NIST SP 800-61r2** lifecycle. Full playbooks: [`incident_response/`](incident_response/)

### 10.1 Containment

```bash
# Immediate host isolation
netstat -anob >> C:\IR\netstat.txt && arp -a >> C:\IR\arp.txt
# Block attacker infrastructure
null route 142.251.127.108/109
# Block exfiltration channel
Block outbound TCP/587 and TCP/465 from workstation VLANs
# Block phishing senders
Block: anmarma100@gmail.com, anmar@nulltack.com
```

**Critical Credential Reset:**
- Shell (SID: `S-1-5-21-672327993-1804208324-2312081050-1001`) — NTLM `31d6cfe0...` — **RESET NOW**
- Administrator (RID 500) — **RESET NOW**
- Reset `krbtgt` password **TWICE** (24-hour interval)

### 10.2 Eradication

```powershell
# Remove malicious artifacts
Remove-Item C:\NulltackLab\NulltackKatz.py
Remove-Item C:\NulltackLab\mimikatz-master\ -Recurse
# Validate persistence
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-List
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
# Clear attacker artifacts
Remove-Item $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### 10.3 Recovery

```powershell
# Enable LSA Protection
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
# Enable Credential Guard (Group Policy)
# Computer Configuration > Administrative Templates > Virtualization Based Security
# Enforce MFA for all privileged accounts
# Minimum 16-character passphrases via Group Policy
```

📄 Full playbooks: [`incident_response/Containment.md`](incident_response/Containment.md) | [`incident_response/Eradication.md`](incident_response/Eradication.md) | [`incident_response/Recovery.md`](incident_response/Recovery.md)

---

## 📚 Lessons Learned

📄 Full document: [`incident_response/Lessons_Learned.md`](incident_response/Lessons_Learned.md)

### Social Engineering Awareness
The DHS Directive 2025-09 lure demonstrates APT28's sophisticated understanding of U.S. regulatory language and urgency manipulation. **Mandatory countermeasures:**
- Quarterly phishing simulations using government-directive style lures targeting Finance departments
- Out-of-band verification procedure for any urgent IT request involving executable attachments

### Email & Attachment Security
- Enforce DMARC (p=reject), DKIM, SPF on all email domains
- Sandbox `.py`, `.ps1`, `.vbs` attachments — Finance users have no legitimate need for Python scripts via email
- Block Google Drive links to script files at email gateway

### Credential Protection
- **Deploy Windows Credential Guard** — would prevent T1003.001 **entirely**
- Enable `RunAsPPL=1` in LSA registry key
- Add all privileged accounts to Protected Users security group
- Implement PAM (CyberArk / BeyondTrust) with Just-in-Time access

### Network Monitoring Gaps
- Alert on first-seen outbound SMTP (port 587) from workstation VLANs — **this was the critical missed detection**
- Deploy UEBA: baseline `python.exe` network behavior — any external connection should alert
- Full PCAP at egress with 30-day retention
- DNS logging: alert on first-seen `*.1e100.net` queries from workstations (Gmail SMTP PTR space)

---

## 📖 References

| Source | Link |
|--------|------|
| MITRE ATT&CK G0007 (APT28) | https://attack.mitre.org/groups/G0007/ |
| BlueDelta 2025 Campaign | https://cybernoz.com/bluedelta-hackers-target-microsoft-owa-google-and-sophos-vpn-to-steal-credentials/ |
| MIVD Advisory (Netherlands) | https://www.defensie.nl/actueel/nieuws/2025/05/21/mivd-nederland-ook-doelwit-spionagecampagne-russische-hackers |
| NIST SP 800-61r2 | https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final |
| Volatility 3 Documentation | https://volatility3.readthedocs.io |
| Suricata Documentation | https://docs.suricata.io/en/latest/rules/ |
| Sysmon (Sysinternals) | https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon |
| Mimikatz (GitHub) | https://github.com/gentilkiwi/mimikatz |

📄 Full references: [`references/References.md`](references/References.md)

---

## 📁 Repository Structure

```
APT28-BlueDelta-DFIR-Investigation/
│
├── 📄 README.md                          ← This file (world-class overview)
├── 📄 LICENSE                            ← MIT License
├── 📄 SECURITY.md                        ← Security and disclosure policy
├── 📄 CONTRIBUTING.md                    ← Contribution guidelines
├── 📄 CODE_OF_CONDUCT.md                 ← Community standards
│
├── 📁 report/
│   ├── APT28_DFIR_Report.pdf             ← Full 44-page DFIR report (PDF)
│   └── APT28_DFIR_Report.docx            ← Full report (Word format)
│
├── 📁 figures/                           ← All evidence screenshots
│   ├── figure_01_attack_overview.png
│   ├── figure_02_phishing_email.png
│   ├── figure_03_sysmon_eventid1.png
│   ├── figure_04_sysmon_eventid10.png
│   ├── figure_05_memory_forensics.png
│   ├── figure_06_tls_smtp_gmail.png
│   ├── figure_07_attack_knowledge_graph.png
│   └── figure_08_obsidian_canvas.png
│
├── 📁 detection/
│   ├── suricata/
│   │   └── apt28_bluedelta.rules         ← 3 production Suricata rules
│   ├── sigma/
│   │   ├── apt28_lsass_access.yml        ← LSASS dump Sigma rule
│   │   ├── apt28_smtp_exfiltration.yml   ← SMTP exfil Sigma rule
│   │   └── apt28_script_execution.yml    ← Script execution Sigma rule
│   └── sysmon/
│       └── apt28_sysmon_config.xml       ← Sysmon rule group
│
├── 📁 iocs/
│   ├── IOC_Master_Table.csv              ← Machine-readable IOC list
│   └── IOC_Summary.md                    ← Human-readable IOC summary
│
├── 📁 timeline/
│   └── Incident_Timeline.md              ← Full forensic timeline
│
├── 📁 mitre/
│   └── MITRE_Mapping.md                  ← Complete ATT&CK mapping
│
├── 📁 knowledge_graph/
│   ├── Attack_Knowledge_Graph.png        ← Figure 49 (Executive view)
│   └── Obsidian_Canvas.png               ← Investigation canvas
│
├── 📁 incident_response/
│   ├── Containment.md                    ← NIST 800-61r2 Containment
│   ├── Eradication.md                    ← Eradication procedures
│   ├── Recovery.md                       ← Recovery procedures
│   └── Lessons_Learned.md               ← Strategic improvements
│
├── 📁 references/
│   └── References.md                     ← Full bibliography
│
└── 📁 docs/
    └── index.md                          ← GitHub Pages site
```

---

## ⚠️ Legal Disclaimer

> This repository documents a **controlled purple team emulation exercise** conducted in an isolated lab environment. All techniques are documented for **educational, research, and defensive purposes** only. All simulated attack techniques were executed in a dedicated, air-gapped environment with no connection to production systems or external infrastructure. Unauthorized use of these techniques against live systems is illegal and unethical.

---

<div align="center">

**Prepared by:** Adham Alhamidi &nbsp;|&nbsp; **Team:** Purple Team &nbsp;|&nbsp; **Supervisor:** Anmar Mohammed

**Campaign:** `BLUEDELTA_20260607_072802` &nbsp;|&nbsp; **Date:** `2026-06-07` &nbsp;|&nbsp; **Powered by:** Nulltack

![Stars](https://img.shields.io/github/stars/adhamalhamidi/APT28-BlueDelta-DFIR-Investigation?style=social)
![Forks](https://img.shields.io/github/forks/adhamalhamidi/APT28-BlueDelta-DFIR-Investigation?style=social)

*If this investigation helped you — please ⭐ the repository*

</div>
