---
layout: default
title: APT28 BlueDelta DFIR Investigation
description: Operation BlueBalance — APT28 threat emulation DFIR case study. Campaign BLUEDELTA_20260607_072802.
---

# 🐻 Operation BlueBalance — APT28 DFIR Investigation

**Campaign:** `BLUEDELTA_20260607_072802` | **Date:** 2026-06-07 | **Analyst:** Adham Alhamidi

> A complete APT28 / Fancy Bear / BlueDelta threat emulation exercise — from spearphishing delivery through credential dumping to confirmed Gmail SMTP exfiltration. Full DFIR investigation with memory forensics, network analysis, and enterprise incident response.

---

## 🗺️ Site Navigation

### 📋 Investigation Documentation
- [**Full DFIR Report (PDF)**](report/APT28_DFIR_Report.pdf) — Complete 44-page investigation report
- [**Incident Timeline**](timeline/Incident_Timeline) — Forensically-validated 12-event timeline
- [**MITRE ATT&CK Mapping**](mitre/MITRE_Mapping) — 9 confirmed techniques + ATT&CK Navigator layer
- [**Key Findings Summary**](../README#-key-findings) — 5 analyst findings

### 🛡️ Detection Engineering
- [**Suricata Rules**](detection/suricata/apt28_bluedelta.rules) — 5 production network detection rules
- [**Sysmon Configuration**](detection/sysmon/apt28_sysmon_config.xml) — APT28-hardened XML rule set
- [**Sigma: LSASS Access**](detection/sigma/apt28_lsass_access.yml) — T1003.001 detection rule
- [**Sigma: SMTP Exfiltration**](detection/sigma/apt28_smtp_exfiltration.yml) — T1041 detection rule
- [**Sigma: Script Execution**](detection/sigma/apt28_script_execution.yml) — T1204.002 detection rule

### 🚨 Indicators of Compromise
- [**IOC Master Table (CSV)**](iocs/IOC_Master_Table.csv) — Machine-readable, SIEM-importable
- [**IOC Summary**](iocs/IOC_Summary) — Human-readable IOC documentation

### 🚑 Incident Response
- [**Containment**](incident_response/Containment) — NIST 800-61r2 containment playbook
- [**Eradication**](incident_response/Eradication) — Artifact removal and persistence validation
- [**Recovery**](incident_response/Recovery) — Hardened restoration procedures
- [**Lessons Learned**](incident_response/Lessons_Learned) — Strategic improvements and gap analysis

### 📚 References
- [**References**](references/References) — Full bibliography and tool documentation

---

## ⚡ Quick Stats

| Metric | Value |
|--------|-------|
| Attack Duration | ~40 seconds (automated chain) |
| MITRE Techniques | 9 confirmed (T1566.001 → T1041) |
| Evidence Sources | 5 independent streams |
| Detection Coverage | 100% of attack phases |
| Credentials Compromised | 4 accounts |
| Exfiltration Payload | 3,834 bytes via Gmail SMTP TLS |

---

## 🔑 Critical Finding

> **Windows Credential Guard was not deployed.** Had it been enabled, T1003.001 (LSASS credential dumping) would have been completely prevented — stopping the attack chain before any credentials could be extracted or exfiltrated.
>
> A single PowerShell command + reboot would have made this attack fail entirely.

---

## ⚠️ Disclaimer

This investigation documents a **controlled purple team exercise** in an isolated lab environment. All techniques are documented for **defensive and educational purposes only**. No production systems were affected.

---

*Prepared by Adham Alhamidi | Purple Team | Supervisor: Anmar Mohammed*  
*[View on GitHub](https://github.com/adhamalhamidi/APT28-BlueDelta-DFIR-Investigation)*
