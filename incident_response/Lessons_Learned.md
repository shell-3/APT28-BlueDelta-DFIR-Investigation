# Lessons Learned — Operation BlueBalance

**Campaign ID:** `BLUEDELTA_20260607_072802`  
**Date:** 2026-06-07  
**Analyst:** Adham Alhamidi | Purple Team | Supervisor: Anmar Mohammed  
**Framework:** NIST SP 800-61r2 Section 3.4 — Post-Incident Activity

---

## Executive Summary of Gaps

Campaign BLUEDELTA_20260607_072802 exposed five critical security gaps that enabled complete credential compromise and exfiltration in **40 seconds** from initial script execution. None required technical exploitation — all gaps were defensive control failures.

| Gap | Impact | Priority |
|-----|--------|----------|
| No Windows Credential Guard | T1003.001 entirely preventable | 🔴 CRITICAL |
| No SMTP egress filtering | T1041 entirely preventable | 🔴 CRITICAL |
| No email attachment sandboxing | T1204.002 preventable | 🔴 CRITICAL |
| Insufficient social engineering training | T1566.001 enabled full chain | 🟠 HIGH |
| Insufficient network monitoring | Zero real-time detection | 🟠 HIGH |

---

## 10.4.1 Social Engineering Awareness

### Root Cause Analysis

The DHS Directive 2025-09 lure was highly sophisticated — it referenced:
- A fabricated but plausible CVE number (CVE-2025-2847)
- Real compliance frameworks (NIST SP 800-63B, CFR Title 5)
- Technical language ("Kerberos token cache", "CPAPI")
- A fake certificate thumbprint for "authenticity verification"
- Severe consequences: "network suspension" and "in-person verification"

**This lure would fool many experienced users.** This is documented APT28 tradecraft used in real operations (2016 DNC, 2025 BlueDelta campaign).

### Mandatory Improvements

**Quarterly Phishing Simulation Program:**
```
Simulation 1: Government-directive impersonation (DHS/CISA style)
Simulation 2: IT Security urgency lure (payroll system style)  
Simulation 3: CEO/executive impersonation
Simulation 4: Vendor invoice/attachment lure
Frequency: Quarterly minimum; monthly for Finance Department
Metric: < 5% click rate target after 2 training cycles
```

**Finance Department Training Requirements:**
- [ ] Mandatory 2-hour social engineering awareness training
- [ ] Specific module: Identifying government-directive phishing
- [ ] Establish out-of-band verification procedure: **Any urgent IT request requiring .py/.exe execution must be confirmed by phone with IT Security before action**
- [ ] "No legitimate IT request will ever ask you to run a script by EOD deadline" — institutionalize this message

**Technical Controls:**
- Implement email banner warnings for external senders
- Add [EXTERNAL] prefix to all emails not originating internally
- Implement reply-to mismatch warnings in email client UI

---

## 10.4.2 Email & Attachment Security

### Gap: No Attachment Sandboxing

The payload `NulltackKatz.py` was delivered via email and executed without any sandbox analysis. A Python script attached to a payroll urgency email should never reach a Finance analyst's inbox unchecked.

### Required Improvements

**Email Security Gateway Hardening:**
```yaml
# Required email gateway policy (Proofpoint/Mimecast/Defender for O365):
attachment_sandbox:
  enabled: true
  file_types:
    - "*.py"      # Python scripts — BLOCK by default
    - "*.ps1"     # PowerShell — BLOCK by default  
    - "*.vbs"     # VBScript — BLOCK by default
    - "*.js"      # JavaScript — SANDBOX + ALERT
    - "*.hta"     # HTML Application — BLOCK
    - "*.jar"     # Java — SANDBOX
  action_on_threat: QUARANTINE_AND_ALERT

dmarc_enforcement:
  policy: reject          # Hard reject — no softfail
  subdomain_policy: reject
  alignment: strict

dkim:
  required: true
  
spf:
  hard_fail: true
  
display_name_impersonation:
  enabled: true
  internal_names_check: true  # "IT Security" from external = BLOCK
```

**URL Defense:**
- Deploy URL sandboxing for all links — including Google Drive links
- Block `drive.google.com` links pointing to executable file types

**Implementation Timeline:**
- Week 1: Deploy DMARC/DKIM/SPF enforcement (p=reject)
- Week 2: Enable attachment sandboxing for .py/.ps1/.vbs
- Week 3: Enable display name impersonation detection
- Month 2: Enable URL defense for all links

---

## 10.4.3 Credential Protection

### Gap: Windows Credential Guard Not Deployed

The single most critical finding: **Windows Credential Guard was not enabled.** With Credential Guard active, LSASS credentials are stored in a hardware-isolated VBS (Virtualization Based Security) enclave that Mimikatz cannot read — even with SeDebugPrivilege and administrator rights.

**If Credential Guard had been deployed, T1003.001 would have completely failed.**

### Required Improvements

**Immediate Deployment (All Windows 10/11 Workstations):**
```powershell
# Enable Credential Guard via Group Policy
# Computer Configuration > Administrative Templates > System > Device Guard
# "Turn On Virtualization Based Security" = Enabled
# "Credential Guard Configuration" = Enabled with UEFI lock

# Enable LSA Protection
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f

# Verify deployment:
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object SecurityServicesRunning, SecurityServicesConfigured
```

**Privileged Access Management (PAM):**
- Deploy CyberArk or BeyondTrust for all admin credentials
- Implement Just-in-Time (JIT) access — zero standing admin rights
- Add Shell and Administrator to Protected Users security group
- Monitor: Any process with SeDebugPrivilege should generate SIEM alert

**Multi-Factor Authentication:**
- Enforce MFA for all accounts (minimum: Microsoft Authenticator)
- Preferred: FIDO2 hardware keys for privileged accounts
- Finance Department: Mandatory MFA within 30 days

---

## 10.4.4 Network Monitoring Gaps

### Gap: No Egress SMTP Filtering

**The most operationally preventable failure:** A single firewall ACL rule blocking outbound TCP/587 from workstation VLANs would have **completely stopped the exfiltration**. This is a free, immediate control that should be default in any security-conscious environment.

**Finance workstations have absolutely no legitimate reason to originate direct SMTP connections.**

### Gap: No PCAP at Egress

The exfiltration was only confirmed through Wireshark analysis after the fact. Real-time PCAP at the egress point would have enabled immediate detection and alerting during the attack window (07:28:34–07:28:40).

### Required Improvements

**Immediate Network Controls:**
```
Priority 1 — Block outbound SMTP from workstation VLANs:
  firewall rule: block TCP from [workstation_subnet] to any port 587
  firewall rule: block TCP from [workstation_subnet] to any port 465
  firewall rule: block TCP from [workstation_subnet] to any port 25
  Exception: Only mail relay servers should originate SMTP

Priority 2 — Deploy detection:
  Alert: First-seen outbound SMTP from any workstation (SIEM rule)
  Alert: python.exe/script process making network connection to port 587
  Alert: TLS SNI=smtp.gmail.com from workstation host
```

**Network Monitoring Program:**
```yaml
full_pcap_egress:
  enabled: true
  retention: 30_days
  alert_on:
    - "outbound SMTP from workstation VLAN"
    - "python.exe initiating network connection"
    - "TLS SNI = smtp.gmail.com from workstation"

ueba_baselines:
  python_exe:
    network_connections: ALERT_ANY_EXTERNAL
    ports_allowed: []  # python.exe should not have external network access
  
dns_logging:
  enabled: true
  alert_on:
    - "*.1e100.net queries from workstations"  # Gmail SMTP PTR space
    - "smtp.gmail.com queries from workstations"
```

**Detection Engineering (Deploy Immediately):**
1. Deploy `detection/suricata/apt28_bluedelta.rules` — all 5 rules
2. Deploy `detection/sysmon/apt28_sysmon_config.xml` — update SwiftOnSecurity base
3. Deploy `detection/sigma/apt28_lsass_access.yml` to SIEM
4. Deploy `detection/sigma/apt28_smtp_exfiltration.yml` to SIEM
5. Deploy `detection/sigma/apt28_script_execution.yml` to SIEM

---

## Metrics & Success Criteria

| Control | Current State | Target State | Measure By |
|---------|--------------|--------------|------------|
| Credential Guard | ❌ Disabled | ✅ Enabled (all workstations) | 30 days |
| Outbound SMTP blocked | ❌ Open | ✅ Blocked from workstations | Immediate |
| Email sandbox | ❌ None | ✅ .py/.ps1/.vbs sandboxed | 14 days |
| DMARC enforcement | Unknown | ✅ p=reject on all domains | 30 days |
| Phishing training | Insufficient | ✅ Quarterly + < 5% click rate | 90 days |
| PCAP at egress | ❌ None | ✅ 30-day retention | 60 days |
| Sysmon APT28 rules | ❌ Not deployed | ✅ Deployed and alerting | Immediate |
| MFA for all accounts | Unknown | ✅ 100% coverage | 30 days |
| PAM solution | ❌ None | ✅ CyberArk/BeyondTrust | 90 days |

---

## Acknowledgments

This exercise was conducted by the Purple Team under controlled conditions. The findings and recommendations in this document represent the most critical defensive improvements identified during Campaign BLUEDELTA_20260607_072802.

---

*Lessons Learned follows NIST SP 800-61r2 Section 3.4 — Post-Incident Activity*  
*Reference: `report/APT28_DFIR_Report.pdf` Section 10.4*
