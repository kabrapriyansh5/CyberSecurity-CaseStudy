# Indicators of Compromise (IOCs)

All network indicators are **defanged** (`[.]`) so they cannot be clicked or resolved by accident. Re-fang only inside a controlled blocklist. Machine-readable version: [`iocs.csv`](iocs.csv).

## Network

| Type | Indicator | Context | First seen (UTC) |
|---|---|---|---|
| IPv4 | `37.46.135[.]170` | RIG exploit kit server (landing page, Flash exploit, executable) | 2019-06-22 23:48:05 |
| IPv4 | `8.209.83[.]76` | Post-infection C2 / exfiltration | 2019-06-22 23:48:23 |
| Domain | `fghjkmgru34[.]site` | Host header of C2 traffic | 2019-06-22 23:48:23 |
| Domain | `letsdoitquick[.]site` | Redirect stage that sent the victim to the exploit kit | 2019-06-22 23:48:04 |
| IPv4 | `91.235.129[.]60` | Server for `letsdoitquick[.]site` | 2019-06-22 23:48:04 |
| URL path | `/gQBljYzDJBnrt4JX/gate.php` | 2 GET then 2 POST (346,854 and 347,545 bytes) | 2019-06-22 23:48:23 |

## File

| Type | Indicator | Context |
|---|---|---|
| SHA-256 | `39be5610259ffade85599720ee0af31187788a00791f1e4cb0cd05ef00105eda` | Executable retrieved from the infected host (KPOT Stealer assessed) |

## Host / account

| Type | Indicator |
|---|---|
| Infected host IP | `10.0.76.109` |
| MAC address | `78:2b:cb:d4:a5:fe` |
| Host name | `BANGKOK-8AC2-PC` |
| User account | `edris.haight` (domain PHENOMENOC); credentials should be treated as compromised |

## IDS signatures that fired

- `ETPRO TROJAN KPOT Stealer Exfiltration M2`
- `ET TROJAN Trojan Generic - POST To gate.php with no referer` / `... with no accept headers`
- `ET TROJAN Generic gate.php GET with minimal headers`
- `ET CURRENT_EVENTS RIG EK URI Struct` (Jun 13 2017, Mar 13 2017 M2)
- `ETPRO CURRENT_EVENTS RIG EK Landing Apr 04 2017 M5`
- `ETPRO CURRENT_EVENTS RIG EK Flash Exploit Sep 05 2017 (FWS)`
- `ET POLICY Outdated Flash Version M1`

## Not indicators (checked and excluded)

`10.0.76.193` (Bristol-C71F-PC, user `setsuko.overton`) produced only low-severity alerts (Let's Encrypt certificate notice, web-bug GIF) and never contacted the exploit kit or C2 servers.
