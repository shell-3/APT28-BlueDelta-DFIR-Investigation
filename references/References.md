# References — Operation BlueBalance

**Campaign ID:** `BLUEDELTA_20260607_072802`  
**Analyst:** Adham Alhamidi | Purple Team

---

## Primary Sources

| # | Source | Description | URL |
|---|--------|-------------|-----|
| 1 | MITRE ATT&CK — APT28 (G0007) | Primary MITRE reference for APT28 group profile, TTPs, and historical operations | https://attack.mitre.org/groups/G0007/ |
| 2 | MITRE ATT&CK T1566.001 | Spearphishing Attachment technique reference | https://attack.mitre.org/techniques/T1566/001/ |
| 3 | MITRE ATT&CK T1003.001 | OS Credential Dumping: LSASS Memory | https://attack.mitre.org/techniques/T1003/001/ |
| 4 | MITRE ATT&CK T1041 | Exfiltration Over C2 Channel | https://attack.mitre.org/techniques/T1041/ |
| 5 | MITRE ATT&CK T1134 | Access Token Manipulation | https://attack.mitre.org/techniques/T1134/ |

---

## Threat Intelligence

| # | Source | Description | URL |
|---|--------|-------------|-----|
| 6 | BlueDelta 2025 Campaign | BlueDelta credential harvesting against Turkish energy and EU think tanks | https://cybernoz.com/bluedelta-hackers-target-microsoft-owa-google-and-sophos-vpn-to-steal-credentials/ |
| 7 | MIVD Advisory Netherlands | Dutch Military Intelligence advisory on APT28 / BlueDelta operations | https://www.defensie.nl/actueel/nieuws/2025/05/21/mivd-nederland-ook-doelwit-spionagecampagne-russische-hackers |
| 8 | CISA APT28 Advisory | US Government advisory on Russian GRU cyber operations | https://www.cisa.gov/news-events/cybersecurity-advisories |
| 9 | Unit 42 APT28 Analysis | Palo Alto Unit 42 deep dive on APT28 tradecraft | https://unit42.paloaltonetworks.com/apt28-at-the-center-of-the-storm/ |
| 10 | Microsoft MSTIC APT28 | Microsoft Security Intelligence — Forest Blizzard tracking | https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/ |

---

## Detection & Forensics

| # | Source | Description | URL |
|---|--------|-------------|-----|
| 11 | Volatility 3 Documentation | Memory forensics framework used for RAM analysis | https://volatility3.readthedocs.io |
| 12 | Volatility Foundation | Volatility 3 GitHub repository | https://github.com/volatilityfoundation/volatility3 |
| 13 | Sysmon Sysinternals | Microsoft Sysinternals Sysmon download and documentation | https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon |
| 14 | SwiftOnSecurity Sysmon Config | Community Sysmon configuration (base used for this exercise) | https://github.com/SwiftOnSecurity/sysmon-config |
| 15 | Suricata Documentation | Suricata rule syntax and deployment guide | https://docs.suricata.io/en/latest/rules/ |
| 16 | Sigma Rules Repository | Community Sigma detection rules and format specification | https://github.com/SigmaHQ/sigma |
| 17 | Mimikatz (GitHub) | Gentilkiwi's Mimikatz — credential extraction tool documentation | https://github.com/gentilkiwi/mimikatz |
| 18 | Wireshark Documentation | Network protocol analyzer used for PCAP analysis | https://www.wireshark.org/docs/ |

---

## Standards & Frameworks

| # | Source | Description | URL |
|---|--------|-------------|-----|
| 19 | NIST SP 800-61r2 | Computer Security Incident Handling Guide — framework for IR lifecycle | https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final |
| 20 | NIST SP 800-63B | Digital Identity Guidelines — referenced in phishing lure | https://pages.nist.gov/800-63-3/sp800-63b.html |
| 21 | MITRE D3FEND | Defensive countermeasures framework used for IR recommendations | https://d3fend.mitre.org/ |
| 22 | Windows Credential Guard | Microsoft documentation on Credential Guard deployment | https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/ |
| 23 | Protected Users Group | Microsoft documentation on Protected Users security group | https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group |

---

## Academic & Training References

| # | Source | Description | URL |
|---|--------|-------------|-----|
| 24 | SANS DFIR Resources | SANS Institute DFIR training and resources | https://www.sans.org/cyber-security-courses/digital-forensics-incident-response/ |
| 25 | SANS FOR508 | Advanced Incident Response, Threat Hunting, and Digital Forensics | https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/ |
| 26 | ATT&CK Navigator | Interactive visualization tool for MITRE ATT&CK techniques | https://mitre-attack.github.io/attack-navigator/ |
| 27 | LM/NT Hash Explained | Understanding Windows NTLM hash format and Pass-the-Hash | https://docs.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview |

---

## Tools Used in This Investigation

| Tool | Version | Purpose |
|------|---------|---------|
| Sysmon 64 | Latest | Endpoint telemetry (EID 1, 3, 7, 10) |
| Wireshark | Latest | Network PCAP capture and analysis |
| DumpIt | v1.3.2.20110401 | Full RAM acquisition |
| Volatility 3 | Framework 2.28.1 | Memory forensics analysis |
| NulltackKatz.py | Custom | APT28 attack emulation |
| Mimikatz | 2.2.0 (64-bit) | Credential extraction demonstration |
| Obsidian | Latest | DFIR investigation canvas |
| PowerShell | v5.1 / v7 | Evidence collection and IR commands |

---

*All references accessed and verified as of 2026-06-07.*  
*This repository is maintained at: https://github.com/adhamalhamidi/APT28-BlueDelta-DFIR-Investigation*
