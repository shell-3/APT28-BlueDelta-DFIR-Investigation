# Security Policy

## Scope

This repository contains **defensive security research** documenting a controlled APT28 threat emulation exercise (Operation BlueBalance, Campaign ID: `BLUEDELTA_20260607_072802`). All content is provided for educational, defensive, and purple team purposes.

## Intended Use

This repository is intended for:

- 🔵 **Blue Team defenders** — learning detection techniques against APT28 TTPs
- 🟣 **Purple Team practitioners** — understanding attack-detect-respond cycles
- 🔴 **Red Team researchers** — understanding how APT28 tradecraft is detected
- 📚 **Security educators and students** — structured DFIR case study reference
- 🏢 **SOC analysts** — IOC ingestion, detection rule deployment, threat hunting

## Prohibited Uses

The following uses are explicitly prohibited:

- ❌ Using detection rules, IOCs, or techniques against systems you do not own or have explicit written authorization to test
- ❌ Deploying credential dumping tools (Mimikatz) against production environments
- ❌ Using phishing email templates for unauthorized campaigns
- ❌ Reverse-engineering the emulation techniques for offensive purposes without authorization

## Reporting a Security Concern

If you discover that any content in this repository could be misused or contains sensitive operational data that should not be public, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Contact the repository owner privately through GitHub's private reporting feature
3. Include a description of the concern and affected file(s)

## Responsible Disclosure

Response time: Within 5 business days for acknowledgment. Critical concerns will be addressed within 48 hours.

## Legal Notice

All credentials, hashes, and indicators in this repository originate from a **simulated lab environment** with no connection to real production systems. NTLM hashes and plaintext passwords documented herein are from isolated test accounts created solely for this exercise.

---

*Maintained by Adham Alhamidi | Purple Team | Supervised by Anmar Mohammed*
