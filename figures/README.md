# Evidence Figures

This directory contains all forensic evidence screenshots from Campaign BLUEDELTA_20260607_072802.

| File | Description | Report Section |
|------|-------------|---------------|
| `figure_01_attack_overview.png` | Full attack chain execution output showing Phase 1 through Phase 4 | §4.1 |
| `figure_02_phishing_email.png` | Phishing email log showing sender mismatch (key IoC) | §4.2.1 |
| `figure_03_sysmon_eventid1.png` | Sysmon EID 1 — NulltackKatz.py process creation chain | §5.3.1 |
| `figure_04_sysmon_eventid10.png` | Sysmon EID 10 — LSASS access GrantedAccess=0x1010 | §5.2.1 |
| `figure_05_memory_forensics.png` | Volatility 3 windows.pslist — full attack process chain | §5.5.4 |
| `figure_06_tls_smtp_gmail.png` | Wireshark tcp.port==587 — full TLS handshake to smtp.gmail.com | §5.4.3 |
| `figure_07_attack_knowledge_graph.png` | Figure 49 — APT28 Executive Attack Knowledge Graph (End-to-End) | §9.1 |
| `figure_08_obsidian_canvas.png` | Obsidian DFIR Investigation Canvas | §9.2 |

All figures are embedded in the full report: `../report/APT28_DFIR_Report.pdf`
