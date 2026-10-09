# Evidence Register

**Case:** Phenomenoc network intrusion (domain `phenomenoc[.]com`, LAN `10.0.76.0/24`)
**Source of materials:** Malware-Traffic-Analysis.net, "2019-06-22 - Traffic analysis exercise - Phenomenoc" (public training dataset, B. Duncan)
**Date received / hashed:** 10 October 2026
**Analyst(s):** Group G__ (Sajal Thapliyal, [Member 2], [Member 3], [Member 4])
**Handling:** Passive analysis only. The malware sample was hashed and identified, **never executed**. All hashes below were computed with `sha256sum` on the files as received; analysis was done on copies.

## 1. Items analysed

| Item ID | Description | File name | Size (bytes) | SHA-256 | Notes |
|---|---|---|---|---|---|
| EV-001 | Executable retrieved from the infected Windows host (malware sample) | `2019-06-22-malware-retrieved-from-the-infected-Windows-host.exe` | 584,192 | `39be5610259ffade85599720ee0af31187788a00791f1e4cb0cd05ef00105eda` | Hashed only; not executed. Not stored in this repository |
| EV-002 | Packet capture of the LAN segment | `2019-06-22-traffic-analysis-exercise.pcap` | 4,694,048 | `6a89013b9e9bc6d443810245b92f49db4df33c1671a43db03a6bbde8f2bc6e63` | 7,103 packets; 2019-06-22 23:46:30 to 23:50:22 UTC |
| EV-003 | IDS alert export (text) | `2019-06-22-traffic-analysis-exercise-alerts.txt` | 5,227 | `f4a1ef1b4df458de318e4030e2ac3ff1bc5d38212304e6f1bf5a8cc79d5667e3` | Signature alerts, 23:47 to 23:50 UTC |
| EV-004 | IDS alert export (image) | `2019-06-22-traffic-analysis-exercise-alerts.jpg` | 450,132 | `9c12beb16b6c5eb9d2a4daff6dd4bf1aa01ee96b73b96609b0279f98db8b62fe` | Screenshot of the alert console |

## 2. Archives as received (all password-protected ZIPs)

| Archive | SHA-256 |
|---|---|
| `2019-06-22-traffic-analysis-exercise.pcap.zip` | `ffbe24a2cf04d61cd540207db43f77f4f47fb5da5cb8d8ebcdc31a081e571875` |
| `2019-06-22-traffic-analysis-exercise-alerts.zip` | `63fe62e2ff7cce82a41ad84760a5ea5fd27fa7a5f2480fe52b261f8b373028e0` |
| `2019-06-22-malware-retrieved-from-the-infected-Windows-host.exe.zip` | `0d67140c1cb2feebe4c44316ca82938844b3e9c1cecd65c933bd08d617627265` |

## 3. Verification

The SHA-256 of EV-001 matches the value shown in the analyst's `sha256sum` screenshot (see `analysis/screenshots/`).

Reproduce with:

```bash
sha256sum 2019-06-22-malware-retrieved-from-the-infected-Windows-host.exe
sha256sum 2019-06-22-traffic-analysis-exercise.pcap
sha256sum 2019-06-22-traffic-analysis-exercise-alerts.txt
```

## 4. Chain of custody (training-case simulation)

| Date (UTC) | Action | By |
|---|---|---|
| 2019-06-22/23 | Capture and alerts produced and published by the exercise author | B. Duncan |
| 2026-10-10 | Archives received, extracted, hashed; analysis performed on working copies | Group G__ |
