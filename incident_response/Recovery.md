# Recovery Playbook — Campaign BLUEDELTA_20260607_072802

**Operation BlueBalance** | NIST SP 800-61r2 — Phase 4: Recovery  
**Analyst:** Adham Alhamidi | Purple Team  
**Prerequisite:** Eradication complete — artifacts removed, persistence validated

---

## Recovery Overview

Recovery objectives:
1. Restore DESKTOP-N56M5HA to a known-good, hardened state
2. Implement architectural improvements to prevent T1003.001 recurrence
3. Validate all detection rules fire correctly before restoring to production
4. Rebuild organizational trust in credential security

---

## 10.3.1 Host Restoration

### Option A: Restore from Backup (Preferred)

```powershell
# Restore DESKTOP-N56M5HA from backup predating 2026-06-07
# Verify backup integrity before restoring

# 1. Verify backup date and integrity
Get-WBBackupSet | Sort-Object BackupTime | Select-Object -Last 5

# 2. Restore (adjust for your backup solution — Veeam/Windows Backup/Acronis)
# Windows Server Backup:
# wbadmin start recovery -version:[BACKUP_VERSION] -itemtype:Volume -volumes:C: -overwrite

# 3. Confirm restore point predates attack (before 07:28:00 on 2026-06-07)
```

### Option B: Reimage from Golden Image

```powershell
# If no clean backup available — reimage from approved golden image
# 1. Apply all pending Windows security patches BEFORE restoring to network
# 2. Document all patches applied

# Verify Windows is fully patched
Get-HotFix | Sort-Object InstalledOn | Select-Object -Last 20 | Out-File C:\IR\patch_status.txt

# Run Windows Defender full scan
Start-MpScan -ScanType FullScan
Get-MpThreatDetection | Out-File C:\IR\defender_scan_results.txt
```

### Post-Restoration Sysmon Reinstall

```powershell
# Reinstall Sysmon with APT28-hardened configuration
# Include Rule Group for NulltackKatz.py detection patterns

# Deploy Sysmon with updated config:
.\Sysmon64.exe -u  # Uninstall old config
.\Sysmon64.exe -i apt28_sysmon_config.xml -accepteula

# Verify Sysmon is running:
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

---

## 10.3.2 Credential Rotation + Hardening

### Enable Windows Credential Guard

```powershell
# Enable Virtualization Based Security (VBS) + Credential Guard
# This PREVENTS T1003.001 entirely on modern hardware

# Method 1: Group Policy (recommended for enterprise)
# Computer Configuration > Administrative Templates >
# System > Device Guard > Turn On Virtualization Based Security
# Enable: Virtualization Based Protection of Code Integrity
# Enable: Credential Guard Configuration = Enabled with UEFI lock

# Method 2: Registry (immediate, requires reboot)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 1 /f

# Verify Credential Guard status after reboot:
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

### Enable LSA Protected Process Light (PPL)

```powershell
# Enable LSA Protection — prevents mimikatz from accessing LSASS
# without a PPL-signed kernel driver bypass (significantly harder for attacker)

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f

# After reboot, verify:
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RunAsPPL
# Expected: RunAsPPL = 1
```

### Protected Users Security Group

```powershell
# Add all privileged accounts to Protected Users group
# This prevents NTLM authentication (forces Kerberos) and disables credential caching

Add-ADGroupMember -Identity "Protected Users" -Members "Shell", "Administrator"

# Verify:
Get-ADGroupMember -Identity "Protected Users" | Select-Object Name, SamAccountName
```

### New Credential Policy Enforcement

```powershell
# Enforce minimum 16-character passphrases via Group Policy
# Computer Configuration > Windows Settings > Security Settings >
# Account Policies > Password Policy:
# Minimum password length: 16
# Password complexity: Enabled
# Maximum password age: 90 days

# Enable MFA for all accounts (Microsoft Authenticator / FIDO2 key)
# Priority: Shell, Administrator, all service accounts

# Issue new credentials for all compromised accounts:
$accounts = @("Shell", "Administrator")
foreach ($account in $accounts) {
    $newPwd = [System.Web.Security.Membership]::GeneratePassword(20, 4)
    net user $account $newPwd
    Write-Output "Password reset for $account — provide securely to user"
}
```

---

## 10.3.3 Security Validation

### Purple Team Validation Run

```powershell
# After all hardening steps — re-run BlueBalance scenario
# Confirm detection rules now fire as expected

# Test 1: Sysmon EID 10 — LSASS Access Alert
# Attempt mimikatz against hardened system (should fail with Credential Guard)
# Expected: Credential Guard blocks LSASS access; Sysmon EID 10 still fires for audit

# Test 2: Suricata Rule Validation
# Simulate SMTP connection to port 587
# Expected: Rules 1 and 4 from apt28_bluedelta.rules should fire
Test-NetConnection -ComputerName smtp.gmail.com -Port 587

# Test 3: Sysmon Network Detection
# Verify Sysmon EID 3 captures port 587 connections from workstations
# Expected: Alert fires, process chain visible in Sysmon logs

# Test 4: Email Gateway Blocks
# Send test email from blocked domain nulltack.com
# Expected: Blocked at gateway, not delivered to mailbox
```

### Detection Rule Verification

```powershell
# Verify all Sysmon EID 10 alerts fire for LSASS access attempts
# (Even with PPL, attempts should generate EID 10)

# Query recent Sysmon EID 10 events:
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object {$_.Id -eq 10} |
    Select-Object TimeCreated, Message |
    Format-List

# Confirm Suricata rules loaded:
suricata -T -c /etc/suricata/suricata.yaml -S /path/to/apt28_bluedelta.rules
```

### SOC Tabletop Exercise

Conduct 1-hour tabletop with SOC team using this incident as scenario input:

**Scenario:** APT28 spearphishing targeting Finance Department  
**Injects:** 
1. Email gateway alert fires at 07:28:01
2. Sysmon EID 1 fires at 07:28:05
3. Sysmon EID 10 fires at 07:28:30
4. Suricata SMTP alert fires at 07:28:34

**Questions:**
1. What is the SOC triage procedure for each alert?
2. Who is the decision-maker for host isolation?
3. What is the escalation path for credential compromise?
4. How do we notify affected users?

---

## Recovery Verification Checklist

- [ ] Host restored from clean backup or golden image
- [ ] All Windows patches applied (verify via `Get-HotFix`)
- [ ] Windows Credential Guard enabled (verify: `Win32_DeviceGuard`)
- [ ] LSA Protection enabled (`RunAsPPL=1`)
- [ ] All compromised credentials reset with 16+ char passphrases
- [ ] MFA enabled for Shell, Administrator, service accounts
- [ ] Protected Users group updated
- [ ] Sysmon reinstalled with APT28 config (`apt28_sysmon_config.xml`)
- [ ] Suricata rules deployed (`apt28_bluedelta.rules`)
- [ ] Purple team validation run completed
- [ ] SOC tabletop exercise conducted
- [ ] Host returned to network only after all checks pass

---

*Recovery follows NIST SP 800-61r2 Section 3.3.5 — Recovery*  
*Reference: `report/APT28_DFIR_Report.pdf` Section 10.3*
