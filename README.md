# Phenomenoc Network Forensics: RIG Exploit Kit to KPOT Stealer

Final Capstone Case (Cyber Security): DNS, URL and network forensic analysis of an infected Windows host, using **passive, legally compliant methods only**.

> Training dataset: *2019-06-22 Traffic analysis exercise – Phenomenoc* by Brad Duncan, <https://www.malware-traffic-analysis.net/2019/06/22/index.html>.
> No real organisation or person is affected. The malware sample was **hashed only and never executed**, and it is **not** stored in this repository.

## Findings at a glance

| Objective | Result |
|---|---|
| Infected host (IP / MAC / name) | `10.0.76.109` / `78:2b:cb:d4:a5:fe` / `BANGKOK-8AC2-PC` |
| Windows user | `edris.haight` |
| Delivery method | Drive-by download via **RIG exploit kit** over HTTP (outdated Flash) |
| External delivery IP | `37.46.135[.]170` (redirect from `letsdoitquick[.]site`) |
| SHA-256 of retrieved executable | `39be5610259ffade85599720ee0af31187788a00791f1e4cb0cd05ef00105eda` |
| Malware type (alerts) | **KPOT Stealer** (information stealer) |
| Post-infection IP | `8.209.83[.]76` |
| Post-infection domain | `fghjkmgru34[.]site` (HTTP POST to `/gQBljYzDJBnrt4JX/gate.php`) |

`10.0.76.193` (Bristol-C71F-PC, user `setsuko.overton`) was examined and **ruled out** as benign.

## Deliverables

| Required deliverable | Location |
|---|---|
| 1. Evidence register (with hashes) | [`evidence/evidence_register.md`](evidence/evidence_register.md) |
| 2. Analysis notes with screenshots | [`analysis/analysis_notes.md`](analysis/analysis_notes.md), [`analysis/screenshots/`](analysis/screenshots) |
| 3. Indicators of Compromise | [`iocs/iocs.md`](iocs/iocs.md), [`iocs/iocs.csv`](iocs/iocs.csv) |
| 4. Final technical investigation report | [`reports/Technical_Investigation_Report.pdf`](reports/Technical_Investigation_Report.pdf) |
| 5. One-page non-technical summary | [`reports/Non_Technical_Summary.pdf`](reports/Non_Technical_Summary.pdf) |

## Repository layout

```
.
├── README.md
├── docs/Final_task.pdf                  task sheet
├── evidence/
│   ├── evidence_register.md
│   └── alerts/                          IDS alert export (.txt, .jpg)
├── analysis/
│   ├── analysis_notes.md
│   ├── screenshots/
│   └── outputs/analyze_pcap_output.txt  script output from the real pcap
├── iocs/                                iocs.md, iocs.csv (defanged)
├── reports/                             technical report + one-page summary
└── scripts/                             analyze_pcap.py, requirements.txt
```

## Reproduce

1. Download the case files from the exercise page above (the ZIPs are password-protected; the password is given on that page). **Do not commit them**: `.gitignore` blocks `*.pcap`, `*.zip`, `*.exe`.
2. Verify hashes against [`evidence/evidence_register.md`](evidence/evidence_register.md):
   ```bash
   sha256sum 2019-06-22-traffic-analysis-exercise.pcap
   sha256sum 2019-06-22-malware-retrieved-from-the-infected-Windows-host.exe
   ```
3. Run the analysis (passive, read-only):
   ```bash
   pip install -r scripts/requirements.txt
   python3 scripts/analyze_pcap.py 2019-06-22-traffic-analysis-exercise.pcap \
       evidence/alerts/2019-06-22-traffic-analysis-exercise-alerts.txt
   ```
4. Confirm in Wireshark: `bootp`, `nbns`, `kerberos.CNameString && ip.src == 10.0.76.109`, `http.request`, `http.request.method == "POST"`, File > Export Objects > HTTP.

## Tools

Wireshark, Python (`dpkt`) for scripted verification, `sha256sum`, IDS alert export (Emerging Threats signatures).

## Constraints followed

Passive analysis only; no execution of samples; no interaction with live systems; no scanning, probing or exploitation. IOCs are defanged.

## Authors

Group G__: Sajal Thapliyal, [Member 2], [Member 3], [Member 4]
