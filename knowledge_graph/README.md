# Knowledge Graph & Attack Visualization

This directory contains the two complementary attack visualization figures from Section 9.

## Figure 49 — Executive Attack Knowledge Graph

**File:** `Attack_Knowledge_Graph.png`

Purpose: Executive-level end-to-end attack lifecycle visualization.
Answers: *"How did the attack occur from beginning to end?"*

Layers covered:
- Threat Actor: APT28 / GRU Unit 26165
- Infrastructure: APT28 → DESKTOP-N56M5HA → LSASS → smtp.gmail.com
- MITRE ATT&CK: T1566.001 → T1204.002 → T1087/T1016/T1057 → T1134 → T1003.001 → T1041
- Evidence: Sysmon EID 1/3/10, Wireshark PCAP, Volatility 3
- Outcomes: Credential exposure, T1021 lateral movement risk

## Obsidian DFIR Investigation Canvas

**File:** `Obsidian_Canvas.png`

Purpose: Analyst-level investigation workflow and evidence correlation board.
Answers: *"How was the attack investigated and reconstructed?"*

Canvas covers:
- Evidence correlation nodes
- Investigation methodology workflow
- Detection workflow (which tool, which alert, analyst response)
- Timeline reconstruction (07:28 email delivery → 19:00 UTC memory acquisition)
- Artifact relationships (powershell → python → mimikatz → lsass)
- Analyst findings (GrantedAccess 0x1010, SNI=smtp.gmail.com)
- Root cause analysis

Both figures are embedded in the full report: `../report/APT28_DFIR_Report.pdf` (Sections 9.1 and 9.2)
