# NuSecurity
Nushell config and helper commands for security research workflows.

## Available Commands
![commands](https://github.com/user-attachments/assets/2f467c46-e7c5-441d-91b4-2be33fd101bd)

Run `hlp` for the current command list, or `hlp <command>` for detailed usage and annotated examples (the image above may lag behind new commands).

## Requirements
- `nu` (Nushell) — targets 0.114+ (`str lowercase`/`str uppercase`)
- Common CLI tools (`python3`, `git`, `curl`/network access)
- Optional: `go` for auto-installing some tools (`httpx`, `hednsextractor`)
- Optional: `yara` for local rule scanning with `yrs`
- Optional: `dig` (or `nslookup`) for `vt` hash lookups via Team Cymru MHR
- Optional: `unzip` (or `python3`) for the `otx` full ThreatFox export
- Optional on Linux: `apt` + `sudo` for package helper commands
- Optional on Linux: `journalctl` for richer `log-hunt` output
- Optional on Windows: `winget` for package helper commands
- Optional on Windows: `powershell` for `windows-evt-hunt` / `log-hunt` / `persist-hunt`
- Optional on Windows: `procdump` (Sysinternals) for `proc-dump`

No API keys are required for the built-in threat-intel commands (`vt`, `abuse`,
`otx`). Only `rip` / `dchr` need a WHOISXMLAPI key, prompted once and saved to
`~/.whoisxmlkey.txt`.

## Setup
Run this in Nushell (Linux/macOS/Windows):

```nu
cp $nu.config-path $"($nu.config-path).backup"
cp configs/config.nu $nu.config-path
```

Restart your Nu shell after copying.

## Optional Startup Sysinfo
System info output (`neofetch`) is disabled by default.

Enable it with:

```nu
$env.NUSECURITY_SHOW_SYSINFO = true
```

## One-shot IOC report (`iocall`)
`iocall <ioc>` auto-detects a URL / domain / IP / hash and pulls everything from
the key-free sources into a single sectioned report with a 0-100 threat score:
```nu
iocall 160.20.109.75              # ip: score + VT engines + DNSBL + ports + related domains + C2 hits
iocall evil.example.com           # domain: reputation + VT + DNS + RDAP + crt.sh subdomains + resolved-IP geo/DNSBL
iocall https://bad.site/payload   # url: reputation + host VT/DNS/geo/RDAP + defanged form
iocall <sha256>                   # hash: ThreatFox + Cymru MHR + CIRCL + VT engines
iocall 160.20.109.75 --skip-ports # skip the TCP port scan (faster)
iocall evil.example.com --json    # structured record for piping/export
```
Sources (all key-free): ThreatFox export, Team Cymru MHR, CIRCL hashlookup,
ISC SANS DShield, ip-api, urlscan.io, RDAP, `dig`, HackerTarget + crt.sh +
VirusTotal passive resolutions (related domains), a curated DNSBL set, and the
VirusTotal UI endpoint for multi-engine verdicts. The VT endpoint is best-effort
and rate-limits quickly (shown as `available: false` when blocked). An IP report
runs a TCP port scan and several lookups, so it can take ~30s; use `--skip-ports`
or `--json` to speed it up.

## Threat Intelligence (no API key)
```nu
vt aadfc11ee472ecd3e8dae7acde9233dac75acfa7  # hash reputation (ThreatFox + Cymru MHR + CIRCL)
vt 160.20.109.75            # IP reputation (ThreatFox + DShield + ip-api geo/hosting)
vt evil.example.com         # domain reputation (ThreatFox + urlscan.io)
abuse 45.83.12.9            # IP reputation via ISC SANS DShield
ipinfo 8.8.8.8             # geo + ISP/ASN + reverse DNS enrichment
otx agenttesla             # search ThreatFox full export by malware family
otx 45.83.12.9             # search by IP/domain/URL substring
otx --refresh              # refresh the cached ThreatFox export (auto every 6h)
defang https://evil.example.com/x   # -> hxxps://evil[.]example[.]com/x
refang hxxps://evil[.]example[.]com # reverse of defang
hashf suspicious.bin        # md5 + sha1 + sha256 + size
```

`vt` aggregates a single verdict (`MALICIOUS` / `suspicious` / `no known reports` /
`unknown`) from key-free sources by IOC type. `otx` downloads and caches the full
ThreatFox export under `~/.nusecurity/cache` (6h TTL, `--refresh` to force).

### Country focus (`--cc`)
Filter feed commands to a single country — IPs are geolocated via ip-api and
domains matched by ccTLD:
```nu
otx cobaltstrike --cc TR    # only Turkey-based C2s
vrb --cc TR                 # only Turkey-based C2 panels (Viriback)
tfox --dtype all --cc TR    # only Turkey-based ThreatFox IOCs
haus online --cc TR --host-only  # only Turkey-based URLHaus hosts
pls --cc TR                 # only Turkish proxies (uses native geo field)
```

## Quick Examples
```nu
hlp                         # compact command list with summary + sample
hlp -v                      # verbose command list
hlp triage                  # show detailed usage/examples for one command
chkbgp 8.8.8.8              # BGP information for IP
bdc SGVsbG8=               # base64 decode  (bdc -e "text" to encode)
haus                        # URLHaus online feed (default)
haus normal --limit 20      # full feed, first 20 URLs
haus --host-only --contains "in.net" --limit 10  # unique hosts filtered by keyword
haus --host-ends-with ".tr" --host-only --limit 20 # hosts ending with .tr
rware TR --limit 20          # country-specific ransomware victims
rware --limit 20             # global recent ransomware victims
rware TR --monitor --interval 30  # live monitor mode for newly added entries
tfox --dtype url            # ThreatFox URL-only output
triage --family agenttesla --limit 5      # fetch reports + C2 candidates
triage --family remcos --limit 3          # includes C2 + MalwareConfig
triage --query "sha1:..." --limit 3 --no-c2 --no-config # fastest report listing
triage --query "sha256:..." --limit 1 | get 0.MalwareConfig  # expand parsed config fields
hx subdomains.txt           # httpx scan over a file
shx example.com             # subfinder + httpx
yrs suspicious.bin          # YARA scan using ~/rules
persist-hunt --contains cron --limit 50 # Linux/Windows persistence artifacts
proc-hunt --min-score 2 --limit 50      # heuristic suspicious process scoring
proc-dump lsass --out-dir C:\dumps      # dump process memory with ProcDump
proc-dump ollama.exe --out-dir C:\dumps --mini # mini dump
proc-dump notepad.exe --out-dir C:\dumps --full # full dump
log-hunt "failed password" --since-hours 24 --limit 100 # suspicious log lines
timeline-lite /var/tmp --with-hash --limit 100 # quick file timeline + optional SHA256
windows-evt-hunt --log Security --event-id 4625 --since-hours 24 # Windows event triage
```

`vt` / `abuse` / `otx` are key-free: `vt` combines ThreatFox, Team Cymru MHR (md5/sha1 via DNS), CIRCL hashlookup, ISC SANS DShield, ip-api, and urlscan.io depending on IOC type; `abuse` uses DShield; `otx` searches the cached full ThreatFox export.
`otx` matches malware family names with normalization (e.g. `agenttesla` matches `win.agent_tesla` / `Agent Tesla`); use `--recent` for the small live feed or `--refresh` to rebuild the cache.
`--cc <CC>` filters `otx`, `vrb`, `tfox`, `haus`, and `pls` to a country (IPs geolocated via ip-api, domains matched by ccTLD; `pls` uses its native geo field).
`triage` C2 output is heuristic and focuses on likely payload/C2 hosts from behavioral requests.
When available, domains are shown together with IP as `domain [ip]`.
`MalwareConfig` is now a structured record (`family/version/botnet/c2/URLs/Deobfuscated/credentials/mutex`) for cleaner table output.
`haus` supports `--limit`, `--host-only`, `--contains`, `--host-contains`, `--host-ends-with`, `--https-only`, `--cc`, and `--raw`.
`rware` supports `--monitor`, `--interval`, `--limit`, and `--max-cycles` (test/debug loop count).
`windows-evt-hunt` is Windows-only and uses PowerShell `Get-WinEvent`.
`persist-hunt` checks common persistence points (Linux cron/systemd/autostart/shell init, Windows Run keys/startup/scheduled tasks).
`proc-hunt` is heuristic scoring and may include false positives; tune with `--min-score` and `--contains`.
`proc-dump` is Windows-only and wraps Sysinternals ProcDump (`-ma` full dump by default, `--mini` for `-mp`); it auto-downloads ProcDump on first use and passes `-accepteula`.
`log-hunt` reads Linux log files + `journalctl` (if available) or Windows Event Logs.
`timeline-lite` supports `--with-hash` for SHA256 at extra runtime cost.

## Safety Notes
- `fixu` formats a disk. Double-check target device before running.
- `clean`, `aget`, `arem` run privileged operations.
- `upc` pulls config from GitHub and overwrites your current Nu config path.
- Threat-intel/enrichment commands (`vt`, `abuse`, `otx`, `ipinfo`, `--cc` filters, `haus`, `tfox`, `vrb`) send the IOCs/IPs you query to third-party services (ThreatFox, urlscan.io, ip-api, ISC SANS DShield, Team Cymru, CIRCL). Avoid submitting sensitive indicators you don't want disclosed.

## Update Config
After setup, you can pull the latest upstream config from inside Nu:

```nu
upc
```
