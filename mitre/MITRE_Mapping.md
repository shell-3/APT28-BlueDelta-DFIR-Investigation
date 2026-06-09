# MITRE ATT&CK Mapping — Campaign BLUEDELTA_20260607_072802

**Operation BlueBalance** | APT28 / BlueDelta / GRU Unit 26165  
**Framework:** MITRE ATT&CK Enterprise v14  
**Group Reference:** [G0007 — APT28](https://attack.mitre.org/groups/G0007/)

---

## Full Technique Mapping

| Technique ID | Technique Name | Tactic | Detection Method | Evidence Confirmed | MITRE Link |
|:----------:|----------------|:------:|------------------|-------------------|:----------:|
| **T1566.001** | Spearphishing Attachment | Initial Access | Email gateway / DMARC enforcement / header analysis | `phishing_email_BLUEDELTA.txt` — sender mismatch, DHS lure | [Link](https://attack.mitre.org/techniques/T1566/001/) |
| **T1204.002** | User Execution: Malicious File | Execution | Sysmon EID 1 — process creation (`python.exe` + NulltackKatz.py) | Sysmon EID 1 (PID 2156) / NulltackKatz execution logs | [Link](https://attack.mitre.org/techniques/T1204/002/) |
| **T1087.001** | Account Discovery: Local Account | Discovery | Sysmon EID 1 — `net user` command-line detection | exfiltration_report §2 / Sysmon EID 1 | [Link](https://attack.mitre.org/techniques/T1087/001/) |
| **T1016** | System Network Configuration Discovery | Discovery | Sysmon EID 1 — `ipconfig /all` execution | exfiltration_report §3 / Sysmon EID 1 | [Link](https://attack.mitre.org/techniques/T1016/) |
| **T1057** | Process Discovery | Discovery | Sysmon EID 1 — `tasklist` execution | NulltackKatz execution logs | [Link](https://attack.mitre.org/techniques/T1057/) |
| **T1134** | Access Token Manipulation | Privilege Escalation | Sysmon EID 1 — `privilege::debug` (Privilege 20 OK) | mimikatz output / Sysmon EID 1 | [Link](https://attack.mitre.org/techniques/T1134/) |
| **T1003.001** | OS Credential Dumping: LSASS Memory | Credential Access | Sysmon EID 10 — `GrantedAccess=0x1010` on `lsass.exe` | Sysmon EID 10 + Volatility `windows.handles` | [Link](https://attack.mitre.org/techniques/T1003/001/) |
| **T1041** | Exfiltration Over C2 Channel | Exfiltration | Sysmon EID 3 port 587 / Suricata TLS SNI / Wireshark PCAP | Wireshark PCAP + Sysmon EID 3 | [Link](https://attack.mitre.org/techniques/T1041/) |
| **T1021** | Remote Services (Potential) | Lateral Movement | EDR / Network monitoring (next phase — risk identified) | exfiltration_report (T1021 mentioned — NTLM hashes for PtH) | [Link](https://attack.mitre.org/techniques/T1021/) |

---

## Kill Chain Visualization

```
MITRE ATT&CK Kill Chain — Campaign BLUEDELTA_20260607_072802

┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│  INITIAL ACCESS  │   │    EXECUTION     │   │   DISCOVERY     │
│                 │   │                 │   │                 │
│  T1566.001      │──▶│  T1204.002      │──▶│  T1087.001      │
│  Spearphishing  │   │  Malicious File │   │  T1016          │
│  Attachment     │   │  Execution      │   │  T1057          │
│                 │   │  NulltackKatz   │   │  (net user,     │
│  DHS Directive  │   │  .py via Python │   │  ipconfig,      │
│  2025-09 lure   │   │                 │   │  tasklist)      │
└─────────────────┘   └─────────────────┘   └─────────────────┘
                                                     │
                                                     ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│   EXFILTRATION  │   │ CREDENTIAL ACC. │   │ PRIV ESCALATION │
│                 │   │                 │   │                 │
│  T1041          │◀──│  T1003.001      │◀──│  T1134          │
│  Gmail SMTP TLS │   │  LSASS Memory   │   │  SeDebugPriv    │
│  Port 587       │   │  Dump via       │   │  Token Manip    │
│  3,834 bytes    │   │  Mimikatz       │   │  Privilege 20OK │
│  SMTP 250 OK ✅ │   │  sekurlsa::...  │   │                 │
└─────────────────┘   └─────────────────┘   └─────────────────┘
        │
        ▼
┌─────────────────┐
│ LATERAL MOVEMENT│
│  (RISK)         │
│  T1021          │
│  Pass-the-Hash  │
│  NTLM hashes    │
│  available      │
└─────────────────┘
```

---

## Technique Detail Cards

### T1566.001 — Spearphishing Attachment

| Field | Value |
|-------|-------|
| **Tactic** | Initial Access |
| **Subtechnique** | .001 — Spearphishing Attachment |
| **APT28 Implementation** | Two-layered lure: (1) payroll urgency from `anmar@nulltack.com`; (2) DHS Directive 2025-09 impersonation from `anmarma100@gmail.com` claiming fake CVE-2025-2847 |
| **Detection** | Email gateway sender mismatch (`anmar@nulltack.com` vs reply-to `anmarma100@gmail.com`); DMARC enforcement; attachment sandbox |
| **Evidence** | `phishing_email_BLUEDELTA_20260607_072802.txt` |
| **Timestamp** | 07:28:00 Local / 04:28:00 UTC |

### T1204.002 — User Execution: Malicious File

| Field | Value |
|-------|-------|
| **Tactic** | Execution |
| **APT28 Implementation** | Python script (`NulltackKatz.py`) disguised as "Payroll Update Tool" — executed by finance analyst from email attachment |
| **Detection** | Sysmon EID 1 — `python.exe` executing `.py` from `C:\NulltackLab\` (non-standard path alert) |
| **Evidence** | Sysmon EID 1 (PID 2156, ParentImage: cmd.exe, SHA256 confirmed) |
| **Timestamp** | 07:28:05 Local / 04:28:05 UTC |

### T1003.001 — OS Credential Dumping: LSASS Memory

| Field | Value |
|-------|-------|
| **Tactic** | Credential Access |
| **APT28 Implementation** | Mimikatz `sekurlsa::logonpasswords` after SeDebugPrivilege — dumps NTLM hashes + plaintext passwords |
| **Detection** | **Sysmon EID 10** — `GrantedAccess=0x1010` on `lsass.exe` from non-whitelisted process = **CRITICAL alert** |
| **Evidence** | Sysmon EID 10 + Volatility 3 `windows.handles` (PID 1384 → lsass PID 672, `GrantedAccess=0x1010`) |
| **Timestamp** | 07:28:30 Local / 04:28:30 UTC (automated); 11:38:17 Local (manual confirmation) |
| **Credentials Extracted** | `Admin123!`, `Winter2025!`, `P@ssw0rd123`, `Finance2024` + NTLM hashes |

### T1041 — Exfiltration Over C2 Channel

| Field | Value |
|-------|-------|
| **Tactic** | Exfiltration |
| **APT28 Implementation** | Gmail SMTP via TLS 1.3 (port 587) — credential report delivered to `adhamalhamidi00@gmail.com` |
| **Detection** | Sysmon EID 3 (port 587); Suricata TLS SNI rule; Wireshark `SNI=smtp.gmail.com` (frames 106/137) |
| **Evidence** | Wireshark PCAP — 3,834-byte Application Data frame at 127.240727s; SMTP 250 OK confirmed |
| **Timestamp** | 07:28:34–07:28:40 Local / 04:28:34–04:28:40 UTC |

### T1134 — Access Token Manipulation

| Field | Value |
|-------|-------|
| **Tactic** | Privilege Escalation |
| **APT28 Implementation** | `privilege::debug` via Mimikatz grants `SeDebugPrivilege` (Privilege 20 OK) — required for LSASS memory read |
| **Detection** | Sysmon EID 1 CommandLine containing `privilege::debug` |
| **Evidence** | Mimikatz output / Sysmon EID 1 |
| **Timestamp** | 07:28:25 Local / 04:28:25 UTC |

---

## ATT&CK Navigator Layer

Export the following JSON to [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize this campaign:

```json
{
  "name": "APT28 BlueDelta - Campaign BLUEDELTA_20260607_072802",
  "versions": { "attack": "14", "navigator": "4.9.1", "layer": "4.5" },
  "domain": "enterprise-attack",
  "description": "Operation BlueBalance - APT28 threat emulation exercise. All techniques confirmed via Sysmon, Wireshark, Volatility 3.",
  "filters": { "platforms": ["windows"] },
  "techniques": [
    { "techniqueID": "T1566.001", "color": "#ff6666", "comment": "CONFIRMED - DHS Directive 2025-09 lure", "score": 100 },
    { "techniqueID": "T1204.002", "color": "#ff6666", "comment": "CONFIRMED - NulltackKatz.py execution", "score": 100 },
    { "techniqueID": "T1087.001", "color": "#ff9900", "comment": "CONFIRMED - net user", "score": 100 },
    { "techniqueID": "T1016",     "color": "#ff9900", "comment": "CONFIRMED - ipconfig /all", "score": 100 },
    { "techniqueID": "T1057",     "color": "#ff9900", "comment": "CONFIRMED - tasklist", "score": 100 },
    { "techniqueID": "T1134",     "color": "#cc0000", "comment": "CONFIRMED - SeDebugPrivilege", "score": 100 },
    { "techniqueID": "T1003.001", "color": "#cc0000", "comment": "CONFIRMED - Mimikatz LSASS dump GrantedAccess=0x1010", "score": 100 },
    { "techniqueID": "T1041",     "color": "#cc0000", "comment": "CONFIRMED - Gmail SMTP TLS port 587 3834 bytes", "score": 100 },
    { "techniqueID": "T1021",     "color": "#ffcc00", "comment": "RISK IDENTIFIED - NTLM hashes for PtH", "score": 50 }
  ]
}
```

---

## Detection Opportunity Matrix

| Technique | Detection Window | Tool | Alert Level |
|-----------|-----------------|------|:-----------:|
| T1566.001 | Before execution — during email delivery | Email gateway | 🟡 HIGH |
| T1204.002 | At execution — python.exe launch | Sysmon EID 1 | 🟡 HIGH |
| T1087/T1016/T1057 | During execution — child process spawns | Sysmon EID 1 | 🟡 HIGH |
| T1134 | During execution — privilege::debug call | Sysmon EID 1 | 🔴 CRITICAL |
| T1003.001 | **At LSASS access — 0x1010 GrantedAccess** | **Sysmon EID 10** | 🔴 **CRITICAL** |
| T1041 | During network connection — port 587 | Sysmon EID 3 + Suricata | 🔴 CRITICAL |
| T1021 | Post-exfiltration — PtH attempts | EDR + Network | 🟠 MONITOR |

---

*MITRE ATT&CK® is a registered trademark of The MITRE Corporation.*  
*Framework version: Enterprise v14 | Reference: https://attack.mitre.org*
