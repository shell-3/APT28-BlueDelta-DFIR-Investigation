# IOC Summary — Campaign BLUEDELTA_20260607_072802

**Operation BlueBalance** | APT28 / BlueDelta / GRU Unit 26165  
**Campaign ID:** `BLUEDELTA_20260607_072802` | **Date:** 2026-06-07

> ⚠️ **SIEM ACTION REQUIRED:** All IOCs marked `HIGH` confidence should be ingested into SIEM, EDR, and threat intelligence platforms immediately. Credential indicators require **immediate reset**.

---

## 🌐 Network Indicators

| Type | Indicator | Purpose | Confidence |
|------|-----------|---------|------------|
| IP | `142.251.127.108` | Gmail SMTP exfiltration server (primary) | **HIGH** |
| IP | `142.251.127.109` | Gmail SMTP exfiltration server (secondary) | **HIGH** |
| IP | `192.168.88.135` | Victim workstation (DESKTOP-N56M5HA) | HIGH |
| Hostname | `smtp.gmail.com` | C2 exfiltration channel (TLS SNI confirmed) | **HIGH** |
| Hostname | `lcfrai-in-f108.1e100.net` | Gmail SMTP PTR (primary) | HIGH |
| Hostname | `lcfrai-in-f109.1e100.net` | Gmail SMTP PTR (secondary) | HIGH |
| Domain | `nulltack.com` | Phishing sender domain | **HIGH** |
| Port | `TCP/587` | SMTP STARTTLS exfiltration channel | **HIGH** |
| Protocol | `TLSv1.3` | Encrypted exfiltration transport | HIGH |

**Immediate Actions:**
```
null route 142.251.127.108
null route 142.251.127.109
block outbound TCP/587 from workstation VLANs
block outbound TCP/465 from workstation VLANs
```

---

## 📧 Email Indicators

| Type | Indicator | Purpose | Confidence |
|------|-----------|---------|------------|
| Email | `anmarma100@gmail.com` | Phishing sender (impersonating Elena Vasquez) | **HIGH** |
| Email | `anmar@nulltack.com` | Phishing sender display (impersonating IT Security) | **HIGH** |
| Email | `adhamalhamidi00@gmail.com` | Attacker mailbox — credential recipient | **HIGH** |
| Subject | `URGENT: Payroll System Security Update Required` | Simple urgency lure | HIGH |
| Subject | `[ACTION REQUIRED BY EOD] DHS Directive 2025-09` | Advanced DHS lure | HIGH |
| Persona | `Elena Vasquez / IT Security Compliance Lead` | Impersonation identity | HIGH |
| Fake CVE | `CVE-2025-2847` | Non-existent CVE used as social engineering hook | HIGH |
| Delivery URL | `drive.google.com/file/d/1tpFjOmPWBGw21YLneFRgqN6st8IehZd5` | Payload delivery | HIGH |

**Immediate Actions:**
```
Block at email gateway: anmarma100@gmail.com
Block at email gateway: anmar@nulltack.com
Quarantine all emails with subject containing "DHS Directive 2025-09"
Block Google Drive URL: drive.google.com/file/d/1tpFjOmPWBGw21YLneFRgqN6st8IehZd5
```

---

## 📁 File & Process Indicators

| Type | Indicator | Purpose | Confidence |
|------|-----------|---------|------------|
| File | `NulltackKatz.py` | APT28 emulation payload at `C:\NulltackLab\` | **HIGH** |
| File | `mimikatz.exe` | Credential dumping binary | **HIGH** |
| File | `memory.raw` | 4GB RAM capture artifact | HIGH |
| Hash (SHA256) | `92804FAAAB2175DC501D73E814663058C78C0A042675A8937266357BCFB96C50` | **mimikatz.exe** — all instances | **HIGH** |
| Process | `python.exe` (PID 2156/7824/2112) | NulltackKatz executor | **HIGH** |
| Process | `mimikatz.exe` (PID 1384) | Credential dumper — RAM-resident | **HIGH** |
| Process | `powershell.exe` (PID 2216) | Attacker execution shell | HIGH |
| Path | `C:\NulltackLab\NulltackKatz.py` | Payload path | HIGH |
| Path | `C:\NulltackLab\mimikatz-master\x64\mimikatz.exe` | Tool path | HIGH |

**SHA256 for endpoint blocking:**
```
92804FAAAB2175DC501D73E814663058C78C0A042675A8937266357BCFB96C50
```

---

## 🔐 Credential Indicators ⚠️ IMMEDIATE ACTION REQUIRED

| Type | Value | Account | Action |
|------|-------|---------|--------|
| NTLM Hash | `31d6cfe0d16ae931b73c59d7e0c089c0` | Shell (SID: ...1001) | **RESET NOW** |
| NTLM Hash | `31d6cfe0d16ae931b73c59d7e0c089c0` | Administrator (RID 500) | **RESET NOW** |
| SHA1 | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | Shell credential | **RESET NOW** |
| Plaintext | `Admin123!` | Administrator | **RESET NOW** |
| Plaintext | `Winter2025!` | Compromised account | **RESET NOW** |
| Plaintext | `P@ssw0rd123` | Compromised account | **RESET NOW** |
| Plaintext | `Finance2024` | Finance dept account | **RESET NOW** |
| Kerberos | `krbtgt ticket — TESTLAB.LOCAL` | Domain ticket | **INVALIDATE** |
| SID | `S-1-5-21-672327993-1804208324-2312081050-1001` | Shell user | MONITOR |

> ⚡ **PASS-THE-HASH RISK:** The NTLM hash `31d6cfe0d16ae931b73c59d7e0c089c0` is immediately usable for lateral movement (T1021) without knowing the plaintext password.

---

## 🗺️ MITRE ATT&CK Technique Coverage

| Technique ID | Name | Status |
|-------------|------|--------|
| T1566.001 | Spearphishing Attachment | ✅ Confirmed |
| T1204.002 | Malicious File Execution | ✅ Confirmed |
| T1087.001 | Local Account Discovery | ✅ Confirmed |
| T1016 | System Network Config Discovery | ✅ Confirmed |
| T1057 | Process Discovery | ✅ Confirmed |
| T1134 | Access Token Manipulation | ✅ Confirmed |
| T1003.001 | OS Credential Dumping: LSASS | ✅ Confirmed |
| T1041 | Exfiltration Over C2 Channel | ✅ Confirmed |
| T1021 | Remote Services (Potential) | ⚠️ Risk Identified |

---

## 📥 Machine-Readable Import

Full IOC table available as CSV: [`IOC_Master_Table.csv`](IOC_Master_Table.csv)

Import into threat intelligence platforms:
- **MISP:** Import CSV via MISP module
- **OpenCTI:** Import as structured threat intelligence
- **Splunk ES:** Use `| inputlookup APT28_BlueDelta_IOCs.csv` after uploading lookup
- **Microsoft Sentinel:** Import via Threat Intelligence → TAXII connector or manual CSV upload
- **CrowdStrike Falcon:** Upload as custom IOCs via API or UI

---

*Generated from Operation BlueBalance forensic analysis | Campaign BLUEDELTA_20260607_072802*  
*Analyst: Adham Alhamidi | Purple Team | Supervisor: Anmar Mohammed*
