# Analysis Notes

Case: Phenomenoc traffic analysis (domain `phenomenoc[.]com`, LAN `10.0.76.0/24`, DC `10.0.76.6`, gateway `10.0.76.1`).
Method: passive analysis of the pcap and alert export; the executable was hashed only, never run.
Reproducible output of the script: [`outputs/analyze_pcap_output.txt`](outputs/analyze_pcap_output.txt) (`scripts/analyze_pcap.py`).
Times are UTC. Capture: 7,103 packets, 23:46:30 to 23:50:22 on 2019-06-22.

## Answers to the investigation objectives

| # | Objective | Finding |
|---|---|---|
| 1 | Infected host IP / MAC / name | `10.0.76.109` / `78:2b:cb:d4:a5:fe` / `BANGKOK-8AC2-PC` |
| 2 | Windows user | `edris.haight` |
| 3 | Delivery method | Drive-by download via the RIG exploit kit over unencrypted HTTP (Flash exploit) |
| 4 | External IP used for delivery | `37.46.135[.]170` (reached via redirect from `letsdoitquick[.]site`, `91.235.129[.]60`) |
| 5 | SHA-256 of retrieved executable | `39be5610259ffade85599720ee0af31187788a00791f1e4cb0cd05ef00105eda` |
| 6 | Malware type from alerts | KPOT Stealer (information stealer) |
| 7 | Post-infection IP | `8.209.83[.]76` |
| 8 | Post-infection domain | `fghjkmgru34[.]site` |

## Step 1: Triage (Statistics > Endpoints, IDS alerts)

Two internal hosts are busy: `10.0.76.109` and `10.0.76.193`. The external addresses `37.46.135.170` (about 1.28 MB, mostly downloaded by the host) and `8.209.83.76` (about 722 kB *sent to* the server and only 29 kB received) stand out. An upload-heavy profile is typical of exfiltration.

![Endpoints](screenshots/01_wireshark_endpoints.png)

IDS alerts: exploit-kit and trojan signatures involve only `10.0.76.109`; `10.0.76.193` only has low-severity policy and web-bug alerts.

![Alerts](screenshots/03_ids_alerts_console.png)

## Step 2: Host and user identification

Wireshark filters used:

```
bootp                                         # DHCP: host name + MAC
nbns                                          # NetBIOS names
kerberos.CNameString && ip.src == 10.0.76.109 # user account (ignore names ending in $)
```

| IP | MAC | DHCP host name | Kerberos user (AS-REQ) |
|---|---|---|---|
| 10.0.76.109 | 78:2b:cb:d4:a5:fe | Bangkok-8ac2-PC | **edris.haight** |
| 10.0.76.193 | 00:1f:cf:61:19:64 | Bristol-c71f-PC | setsuko.overton |

Names ending in `$` (e.g. `bangkok-8ac2-pc$`) are machine accounts, not users. The 2037 ticket end-time in the AS-REQ is a normal "maximum" value, not an anomaly.

Note: `10.0.76.193` is a **different, benign** host. Its evidence is kept only to show it was ruled out:
[Kerberos](screenshots/07_second_host_kerberos_bristol_benign.png), [DHCP](screenshots/08_second_host_dhcp_bristol_benign.png), [user](screenshots/09_second_host_user_setsuko_benign.png).

## Step 3: Delivery reconstruction

Filter: `http.request` and *File > Export Objects > HTTP*.

| Time | Request from 10.0.76.109 | Meaning |
|---|---|---|
| 23:47:10 | GET `www.msftncsi.com/ncsi.txt` | Windows connectivity check (normal) |
| 23:48:04 | GET `letsdoitquick[.]site/` (91.235.129[.]60) | Redirect stage |
| 23:48:05 | GET `37.46.135[.]170/?MTQwMjg3&...` | RIG landing page |
| 23:48:07 | GET `37.46.135[.]170/?MTg0MzEy&...` | Flash exploit object |
| 23:48:10 / 23:48:16 | GET `37.46.135[.]170/?MzU4NjA0&...` / `?NDk4MTE5&...` | Payload downloads |

The exploit-kit server is addressed by IP (no domain). Randomised, base64-looking query strings match the RIG URI-structure alerts. The Flash version was flagged as outdated.

![HTTP objects](screenshots/02_http_object_list_packet4397.png)

Packet 4397 is a 584 kB `application/x-msdownload` object (the executable download).

## Step 4: Payload hash

```
$ sha256sum 2019-06-22-malware-retrieved-from-the-infected-Windows-host.exe
39be5610259ffade85599720ee0af31187788a00791f1e4cb0cd05ef00105eda
```

![sha256](screenshots/06_sha256sum_of_executable.png)

## Step 5: Post-infection traffic

From `10.0.76.109` to `8.209.83.76` (Host `fghjkmgru34.site`):

| Time | Request | Size |
|---|---|---|
| 23:48:23, 23:48:27 | GET `/gQBljYzDJBnrt4JX/gate.php` | n/a |
| 23:48:28 | POST `/gQBljYzDJBnrt4JX/gate.php` | Content-Length 346,854 |
| 23:48:29 | POST `/gQBljYzDJBnrt4JX/gate.php` | Content-Length 347,545 |

POSTs are `application/octet-stream`, have no Referer, and are large. The IDS labels this `ETPRO TROJAN KPOT Stealer Exfiltration M2`.

![POST](screenshots/04_http_post_gate_php.png)
![KPOT alert](screenshots/05_kpot_stealer_alert.png)

## Step 6: Alternative hypotheses tested

- **Emotet?** Not supported. No email delivery, no lateral movement and no Emotet-named alert; KPOT-specific signature fired.
- **Is 10.0.76.193 infected?** No. It generates more packets, but only low-severity alerts and no contact with the delivery or C2 servers.
- **Is 10.0.76.109 the delivery source?** No. It is the private (RFC 1918) victim address; the external delivery address is `37.46.135[.]170`.

## Limitations

No endpoint disk or memory image and no sandbox run, so the exact exploited flaw, persistence and stolen data are unverified. The malware family is *assessed* from IDS signatures.
