# Eradication Playbook — Campaign BLUEDELTA_20260607_072802

**Operation BlueBalance** | NIST SP 800-61r2 — Phase 3: Eradication  
**Analyst:** Adham Alhamidi | Purple Team  
**Prerequisite:** Containment phase complete — host isolated, credentials reset

---

## Eradication Overview

Goal: Remove all attacker artifacts, validate no persistence mechanisms remain, and confirm system integrity before initiating recovery.

**Evidence preservation rule:** Before removing ANY artifact — **hash it** and **archive a forensic copy** to `C:\IR\evidence_archive\`.

---

## 10.2.1 Malware Removal

### Pre-Removal: Hash and Archive All Artifacts

```powershell
# Create IR evidence archive directory
New-Item -Path "C:\IR\evidence_archive" -ItemType Directory -Force

# Hash all artifacts before removal
$artifacts = @(
    "C:\NulltackLab\NulltackKatz.py",
    "C:\NulltackLab\mimikatz-master\x64\mimikatz.exe",
    "C:\NulltackLab\logs\phishing_email_BLUEDELTA_*.txt",
    "C:\NulltackLab\logs\mimikatz_output_BLUEDELTA_*.txt",
    "C:\NulltackLab\logs\exfiltration_report_BLUEDELTA_*.txt"
)

foreach ($artifact in $artifacts) {
    if (Test-Path $artifact) {
        $hash = Get-FileHash $artifact -Algorithm SHA256
        Write-Output "$($hash.Hash) | $artifact" >> C:\IR\artifact_hashes.txt
        Copy-Item $artifact "C:\IR\evidence_archive\" -ErrorAction SilentlyContinue
    }
}

# Archive entire NulltackLab directory (preserve evidence)
Compress-Archive -Path "C:\NulltackLab\*" -DestinationPath "C:\IR\NulltackLab_archive.zip"
```

### Remove Malicious Files

```powershell
# Remove NulltackKatz.py emulation payload
Remove-Item "C:\NulltackLab\NulltackKatz.py" -Force -Confirm:$false
Write-Output "[$(Get-Date)] Removed: C:\NulltackLab\NulltackKatz.py" >> C:\IR\removal_log.txt

# Remove Mimikatz installation
# SHA256: 92804FAAAB2175DC501D73E814663058C78C0A042675A8937266357BCFB96C50
Remove-Item "C:\NulltackLab\mimikatz-master\" -Recurse -Force -Confirm:$false
Write-Output "[$(Get-Date)] Removed: C:\NulltackLab\mimikatz-master\" >> C:\IR\removal_log.txt

# Move evidence directory to IR storage (preserve for legal hold)
Move-Item "C:\NulltackLab\evidence\" "C:\IR\NulltackLab_evidence_backup\"

# Verify removal
$remaining = Get-ChildItem "C:\NulltackLab\" -Recurse -ErrorAction SilentlyContinue
if ($remaining) {
    Write-Warning "Files still present in NulltackLab — review: $($remaining.FullName)"
} else {
    Write-Output "[$(Get-Date)] NulltackLab directory cleaned" >> C:\IR\removal_log.txt
}
```

### YARA Scan — Enterprise-Wide

```bash
# Deploy YARA rule across all endpoints for NulltackKatz behavioral patterns
# Install YARA: https://github.com/VirusTotal/yara

# NulltackKatz YARA rule
cat > /tmp/nulltackkatz.yar << 'EOF'
rule APT28_NulltackKatz {
    meta:
        description = "Detects NulltackKatz APT28 emulation tool"
        author = "Adham Alhamidi - Operation BlueBalance"
        campaign = "BLUEDELTA_20260607_072802"
        mitre = "T1204.002, T1003.001"
    strings:
        $s1 = "NulltackKatz" ascii
        $s2 = "BLUEDELTA" ascii
        $s3 = "sekurlsa::logonpasswords" ascii
        $s4 = "privilege::debug" ascii
        $h1 = { 92 80 4F AA AB 21 75 DC }  // mimikatz SHA256 prefix
    condition:
        any of ($s*) or $h1
}
EOF

# Run scan across all endpoints
yara -r nulltackkatz.yar C:\Users\ C:\Temp\ C:\ProgramData\
```

---

## 10.2.2 Artifact Cleanup & Persistence Validation

### Registry Persistence Check

```powershell
# Check all run keys for NulltackKatz or mimikatz entries
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($key in $runKeys) {
    Write-Output "=== Checking: $key ===" >> C:\IR\registry_audit.txt
    Get-ItemProperty -Path $key 2>$null | Out-File -Append C:\IR\registry_audit.txt
}

# Flag any suspicious entries
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | 
    Select-String -Pattern "NulltackKatz|mimikatz|python|powershell" |
    ForEach-Object { Write-Warning "SUSPICIOUS REGISTRY ENTRY: $_" }
```

### Scheduled Task Audit

```powershell
# Enumerate ALL scheduled tasks and flag suspicious entries
Get-ScheduledTask | 
    Where-Object {$_.State -ne "Disabled"} | 
    Select-Object TaskName, TaskPath, State, 
        @{n="Execute";e={$_.Actions.Execute}},
        @{n="Arguments";e={$_.Actions.Arguments}} |
    Where-Object {$_.Execute -match "python|mimikatz|NulltackKatz|powershell" -or
                  $_.Arguments -match "sekurlsa|lsadump|NulltackLab"} |
    Format-List | Out-File C:\IR\suspicious_scheduled_tasks.txt

Write-Output "Scheduled task audit complete" >> C:\IR\removal_log.txt
```

### PowerShell History Cleanup

```powershell
# Remove attacker PowerShell history
$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $historyPath) {
    Copy-Item $historyPath "C:\IR\evidence_archive\ps_history_backup.txt"
    Remove-Item $historyPath -Force
    Write-Output "[$(Get-Date)] PowerShell history removed and archived" >> C:\IR\removal_log.txt
}

# Also clear for all users
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\" |
    Copy-Item -Destination "C:\IR\evidence_archive\" -ErrorAction SilentlyContinue
```

### Service Validation

```powershell
# Validate all services against approved baseline
# Flag any unknown services
$approvedServices = @("Sysmon64", "WinDefend", "EventLog", "wuauserv")
# Compare with actual running services
Get-Service | Where-Object {$_.Status -eq "Running"} | 
    Select-Object Name, DisplayName, Status |
    Export-Csv "C:\IR\running_services_audit.csv" -NoTypeInformation

Write-Output "Service audit complete — review C:\IR\running_services_audit.csv" >> C:\IR\removal_log.txt
```

### WMI Persistence Check

```powershell
# Check for WMI event subscriptions (common APT persistence mechanism)
Get-WMIObject -Namespace "root\subscription" -Class __EventFilter | 
    Format-List Name, Query | Out-File C:\IR\wmi_filters.txt
Get-WMIObject -Namespace "root\subscription" -Class __EventConsumer |
    Format-List Name, CommandLineTemplate | Out-File -Append C:\IR\wmi_filters.txt
Get-WMIObject -Namespace "root\subscription" -Class __FilterToConsumerBinding |
    Format-List | Out-File -Append C:\IR\wmi_filters.txt

if ((Get-Content C:\IR\wmi_filters.txt | Measure-Object -Line).Lines -gt 3) {
    Write-Warning "WMI subscriptions found — review C:\IR\wmi_filters.txt"
}
```

---

## Eradication Verification Checklist

```powershell
# Final verification — all artifacts removed
$checks = @{
    "NulltackKatz.py removed" = !(Test-Path "C:\NulltackLab\NulltackKatz.py")
    "mimikatz-master removed"  = !(Test-Path "C:\NulltackLab\mimikatz-master\")
    "Evidence archived"        = (Test-Path "C:\IR\NulltackLab_archive.zip")
    "Hashes documented"        = (Test-Path "C:\IR\artifact_hashes.txt")
    "Registry audited"         = (Test-Path "C:\IR\registry_audit.txt")
    "Scheduled tasks audited"  = (Test-Path "C:\IR\suspicious_scheduled_tasks.txt")
    "PS history cleaned"       = !(Test-Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
}

foreach ($check in $checks.GetEnumerator()) {
    $status = if ($check.Value) { "✅ PASS" } else { "❌ FAIL" }
    Write-Output "$status | $($check.Key)" 
}
```

---

*Eradication follows NIST SP 800-61r2 Section 3.3.4 — Eradication*  
*Reference: `report/APT28_DFIR_Report.pdf` Section 10.2*
