# Containment Playbook — Campaign BLUEDELTA_20260607_072802

**Operation BlueBalance** | NIST SP 800-61r2 — Phase 2: Containment  
**Analyst:** Adham Alhamidi | Purple Team  
**Priority Scale:** 🔴 CRITICAL (Immediate) → 🟠 HIGH (< 1 hour) → 🟡 MEDIUM (< 24 hours)

---

## Containment Overview

Containment objectives for Campaign BLUEDELTA_20260607_072802:

1. **Stop active exfiltration** — Block Gmail SMTP channel
2. **Isolate compromised host** — Quarantine DESKTOP-N56M5HA
3. **Prevent lateral movement** — Reset compromised credentials immediately
4. **Preserve evidence** — Do not power off; memory already captured

---

## 10.1.1 Host Isolation 🔴 CRITICAL — IMMEDIATE

```powershell
# Step 1: Capture live network state BEFORE isolation
netstat -anob >> C:\IR\netstat_pre_isolation.txt
arp -a >> C:\IR\arp_pre_isolation.txt
ipconfig /all >> C:\IR\ipconfig_pre_isolation.txt

# Step 2: Document all active connections
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | 
    Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
    Out-File C:\IR\active_connections.txt

# Step 3: Map connections to processes
Get-NetTCPConnection | Select LocalAddress, LocalPort, RemoteAddress, RemotePort, 
    @{n="Process";e={(Get-Process -Id $_.OwningProcess).Name}} |
    Out-File C:\IR\connection_process_map.txt
```

**Network Isolation Actions:**
- [ ] Block `192.168.88.135` at internal switch port (802.1X port disable)
- [ ] Create perimeter firewall quarantine rule for host
- [ ] Identify all hosts that communicated with `DESKTOP-N56M5HA` in prior 48 hours
- [ ] **DO NOT power off** — RAM evidence already captured in `memory.raw`
- [ ] Verify `C:\NulltackLab\evidence\memory.raw` is accessible and intact

---

## 10.1.2 Credential Reset 🔴 CRITICAL — IMMEDIATE

**Compromised accounts confirmed by mimikatz output and Volatility analysis:**

```powershell
# Reset Shell account — NTLM 31d6cfe0... FULLY COMPROMISED
# SID: S-1-5-21-672327993-1804208324-2312081050-1001
net user Shell [NewSecurePassword16Chars!] /domain

# Reset Administrator account — same NTLM hash = same password
net user Administrator [NewSecurePassword16Chars!]

# Purge all Kerberos tickets if domain-joined
klist purge

# If TESTLAB.LOCAL domain is in scope — reset krbtgt TWICE
# (24-hour interval required for all DCs to replicate)
# Round 1:
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "[RandomPassword1]" -Force)
# Wait 24 hours, then Round 2:
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "[RandomPassword2]" -Force)

# Revoke OAuth tokens for Shell if cloud services in scope
# (Microsoft 365, Google Workspace, etc.)
```

**Credential Reset Checklist:**
- [ ] Shell (SID: ...1001) — NTLM `31d6cfe0...` — **RESET NOW**
- [ ] Administrator (RID 500) — NTLM `31d6cfe0...` — **RESET NOW**
- [ ] `krbtgt` password reset (Round 1) — **RESET NOW**
- [ ] `krbtgt` password reset (Round 2) — 24 hours later
- [ ] Revoke all OAuth/SAML tokens for Shell
- [ ] Notify all users with compromised plaintext passwords: `Admin123!`, `Winter2025!`, `P@ssw0rd123`, `Finance2024`

> ⚡ **Pass-the-Hash Risk:** NTLM hash `31d6cfe0d16ae931b73c59d7e0c089c0` is immediately usable for lateral movement **without the plaintext password**. Reset is the only effective mitigation.

---

## 10.1.3 Email Blocking 🔴 CRITICAL — IMMEDIATE

```
# Block at email gateway (Proofpoint / Mimecast / Defender for O365):
Block sender: anmarma100@gmail.com
Block sender: anmar@nulltack.com
Block domain: nulltack.com

# Quarantine all emails containing:
Subject: "URGENT: Payroll System Security Update Required"
Subject: "DHS Directive 2025-09"
Attachment filename: NulltackKatz*
Attachment type: .py

# Block delivery URL:
drive.google.com/file/d/1tpFjOmPWBGw21YLneFRgqN6st8IehZd5
```

**Email Containment Checklist:**
- [ ] Block `anmarma100@gmail.com` and `anmar@nulltack.com` at gateway
- [ ] Block domain `nulltack.com` (all subdomains)
- [ ] Quarantine and scan all received emails containing `NulltackKatz` attachment
- [ ] Search gateway logs for all recipients of DHS Directive 2025-09 subject line
- [ ] Notify all identified recipients — check if any others executed the payload
- [ ] Block Google Drive payload URL

---

## 10.1.4 Network Egress Blocking 🔴 CRITICAL — IMMEDIATE

```bash
# Firewall rules (pf/iptables/Windows Firewall syntax varies by platform)
# Block Gmail SMTP exfiltration channels:
block outbound TCP from workstation_vlan to any port 587
block outbound TCP from workstation_vlan to any port 465
block outbound TCP from workstation_vlan to any port 25

# Null route confirmed exfiltration IPs:
route add 142.251.127.108/32 blackhole
route add 142.251.127.109/32 blackhole

# Windows Firewall (on isolated host):
netsh advfirewall firewall add rule name="Block SMTP 587" protocol=TCP dir=out remoteport=587 action=block
netsh advfirewall firewall add rule name="Block SMTPS 465" protocol=TCP dir=out remoteport=465 action=block

# Restrict PowerShell execution:
Set-ExecutionPolicy RemoteSigned -Scope MachinePolicy -Force
```

**IDS/IPS Rules to Deploy:**
```
# Suricata — deploy apt28_bluedelta.rules immediately
# See: detection/suricata/apt28_bluedelta.rules
alert tcp $HOME_NET any -> $EXTERNAL_NET 587 (msg:"APT28 SMTP Exfil Block"; sid:9000001;)
alert tls $HOME_NET any -> $EXTERNAL_NET 465 (tls.sni; content:"smtp.gmail.com"; sid:9000002;)
```

**Network Blocking Checklist:**
- [ ] Block outbound TCP/587 from all workstation VLANs
- [ ] Block outbound TCP/465 from all workstation VLANs
- [ ] Null route `142.251.127.108` and `142.251.127.109`
- [ ] Deploy Suricata rules from `detection/suricata/apt28_bluedelta.rules`
- [ ] Alert on any outbound SMTP from workstation segments

---

## Containment Verification

After completing all containment steps, verify:

```powershell
# Verify host isolation — no active external connections
netstat -anob | Select-String "142.251"  # Should return empty
netstat -anob | Select-String ":587"     # Should return empty

# Verify credential changes took effect
net user Shell | Select-String "Password last set"
net user Administrator | Select-String "Password last set"

# Verify firewall rules are active
netsh advfirewall firewall show rule name="Block SMTP 587"
```

---

*Containment follows NIST SP 800-61r2 Section 3.3.1 — Choosing a Containment Strategy*  
*Reference: `report/APT28_DFIR_Report.pdf` Section 10.1*
