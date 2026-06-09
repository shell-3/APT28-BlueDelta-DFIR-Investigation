# Contributing to APT28-BlueDelta-DFIR-Investigation

Thank you for your interest in contributing to this DFIR investigation repository. This project documents Operation BlueBalance — a controlled APT28 threat emulation exercise — and aims to serve the defensive security community.

## How to Contribute

### 🐛 Reporting Errors

If you find factual errors, incorrect MITRE mappings, or inaccurate technical details:

1. Open a GitHub Issue with the label `bug`
2. Include the specific file and section
3. Provide the correct information with a source reference

### 📖 Documentation Improvements

We welcome improvements to:

- Detection rules (Suricata, Sigma, Sysmon)
- IOC enrichment (additional context, threat intel cross-references)
- Incident response playbook improvements
- MITRE ATT&CK mapping refinements

### 🔬 Adding Detection Content

If you want to contribute additional detection rules:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/detection-rule-name`
3. Add your rule in the appropriate directory:
   - Suricata rules → `detection/suricata/`
   - Sigma rules → `detection/sigma/`
   - Sysmon config → `detection/sysmon/`
4. Include a comment block explaining what the rule detects and why
5. Submit a Pull Request with a clear description

### Pull Request Guidelines

- All contributions must be related to **defensive** security
- Reference specific evidence from the report where applicable
- Keep MITRE technique IDs consistent with the documented mappings
- Test any detection rules before submitting
- Do not submit content that could be used offensively without proper defensive framing

## Code of Conduct

All contributors are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Questions?

Open a GitHub Discussion if you have questions about the investigation methodology, detection logic, or forensic analysis.

---

*This is a defensive security research project. All contributions must align with the ethical and legal guidelines in [SECURITY.md](SECURITY.md).*
