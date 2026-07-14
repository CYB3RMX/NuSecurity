$env.config.buffer_editor = "vim" # Can be anything for ex. (nvim, nano, ...)
$env.config.show_banner = false

# Ensure HOME exists on Windows sessions
let is_windows = (($nu.os-info.name | str lowercase) == "windows")
if ($is_windows and ($env.HOME? == null) and ($env.USERPROFILE? != null)) {
    $env.HOME = $env.USERPROFILE
}

# Optional startup system info; set $env.NUSECURITY_SHOW_SYSINFO = true to enable
let show_sysinfo = (try {
    let value = $env.NUSECURITY_SHOW_SYSINFO?
    if $value == null {
        false
    } else if (($value | describe) == "bool") {
        $value
    } else {
        let normalized = ($value | into string | str trim | str lowercase)
        $normalized in ["1", "true", "yes", "on"]
    }
} catch {
    false
})

let has_neofetch = (try {
    let command_paths = (which --all neofetch | where type == "external" | get path)
    (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
} catch {
    false
})

if ($show_sysinfo and $has_neofetch) {
    neofetch
}

# Add Go paths
let go_paths = if $is_windows {
    let windows_go = if ($env.ProgramFiles? != null) {
        $"($env.ProgramFiles)\\Go\\bin"
    } else {
        "C:\\Program Files\\Go\\bin"
    }
    [$"($env.HOME)\\go\\bin", $windows_go]
} else {
    [$"($env.HOME)/go/bin", "/usr/local/go/bin"]
}

for go_path in $go_paths {
    if (($env.PATH | to text | str contains $go_path) == false) {
        $env.PATH ++= [$go_path]
    }
}

# Apply the custom prompt
$env.PROMPT_COMMAND = {
    let username = (whoami | str trim)
    let hostname = (hostname | str trim)
    let current_dir = (pwd)
    $"\n(ansi blue_bold)<----- ($username)@($hostname) ----->\n[(ansi red)($current_dir)(ansi blue_bold)]"
}
$env.PROMPT_INDICATOR = $"(ansi blue_bold)>> "

# Get information about the target IP address using bgpview
def chkbgp [ipaddr: string] {
    let data = (http get $"https://api.bgpview.io/ip/($ipaddr)")
    if $data.status == "ok" {
        $data.data
    }
}

# Resolve an available Python interpreter (prefers python3)
def py-bin [] {
    for candidate in ["python3" "python"] {
        let found = (try {
            let command_paths = (which --all $candidate | where type == "external" | get path)
            (($command_paths | where { |p| ($p | str trim) != "" and ($p | path exists) } | length) > 0)
        } catch {
            false
        })
        if $found { return $candidate }
    }
    error make { msg: "Python not found. Install python3 (or python) first." }
}

# Geolocate and enrich an IP or host (ip-api.com, no API key required)
def ipinfo [target: string] {
    if (($target | str trim) == "") {
        error make { msg: "target cannot be empty." }
    }
    let fields = "status,message,query,continent,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"
    let data = (http get $"http://ip-api.com/json/($target | str trim)?fields=($fields)")
    if ($data.status? == "fail") {
        error make { msg: $"ip-api error: ($data.message? | default 'unknown')" }
    }
    $data
}

# Best-effort classification of an IOC string
def ioc-type [value: string] {
    let v = ($value | str trim)
    if (($v | parse --regex '^(?:\d{1,3}\.){3}\d{1,3}$' | length) > 0) {
        "ip"
    } else if (
        (($v | parse --regex '^[a-fA-F0-9]{32}$' | length) > 0)
        or (($v | parse --regex '^[a-fA-F0-9]{40}$' | length) > 0)
        or (($v | parse --regex '^[a-fA-F0-9]{64}$' | length) > 0)
    ) {
        "hash"
    } else if ($v | str lowercase | str starts-with "http") {
        "url"
    } else {
        "domain"
    }
}

# Extract the bare host/IP from an IOC value (url, ip:port, domain, ip)
def ioc-host [value: string] {
    mut h = ($value | str trim | str lowercase)
    $h = ($h | str replace --regex '^[a-z0-9+.-]+://' '')   # strip scheme
    $h = ($h | split row '/' | first)                        # strip path
    $h = ($h | split row '?' | first)                        # strip query
    $h = ($h | split row '@' | last)                         # strip userinfo
    $h = ($h | str replace --regex ':[0-9]+$' '')            # strip :port
    $h = ($h | str trim --char '[' | str trim --char ']')    # strip ipv6 brackets
    $h
}

# Batch-geolocate IPs via ip-api.com (no key). Returns a table {ip, cc, country, isp}.
def geo-batch [ips: list<string>] {
    mut rows = []
    for chunk in ($ips | uniq | chunks 100) {
        let resp = (try {
            http post --content-type application/json "http://ip-api.com/batch?fields=status,query,countryCode,country,isp" $chunk
        } catch {
            []
        })
        for r in $resp {
            if (($r.status? | default "") == "success") {
                $rows ++= [{
                    ip: ($r.query? | default "")
                    cc: ($r.countryCode? | default "")
                    country: ($r.country? | default "")
                    isp: ($r.isp? | default "")
                }]
            }
        }
        sleep 300ms   # stay under ip-api's batch rate limit
    }
    $rows
}

# Keep only rows attributed to a target country code.
#   - IP hosts are geolocated via ip-api (no key)
#   - domain hosts match by ccTLD (endswith .<cc>), plus common .com.<cc> style
# Each kept row gains `cc` (and `geo_isp` for IP rows). host_field extracts the IOC string.
def geo-filter [
    rows: list<any>          # input records
    cc: string               # ISO country code, e.g. TR
    host_field: closure      # extracts the host/ip/url string from a row
    --geo-cap: int = 500     # max unique IPs to geolocate
] {
    let target = ($cc | str trim | str uppercase)
    if $target == "" { return $rows }
    let cc_lower = ($target | str lowercase)

    let is_ipv4 = { |v: string| (($v | parse --regex '^(?:\d{1,3}\.){3}\d{1,3}$' | length) > 0) }

    let tagged = ($rows | each { |r|
        let host = (ioc-host (do $host_field $r | into string))
        { row: $r, host: $host, is_ip: (do $is_ipv4 $host) }
    })

    let ip_hosts = ($tagged | where is_ip | get host | uniq | first $geo_cap)
    let geo = (if (($ip_hosts | length) > 0) { geo-batch $ip_hosts } else { [] })

    let is_record = { |r| (($r | describe) | str starts-with "record") }

    $tagged | each { |t|
        if $t.is_ip {
            let match = ($geo | where ip == $t.host)
            if (($match | length) > 0) and (($match | get cc.0) == $target) {
                if (do $is_record $t.row) { $t.row | merge { cc: $target, geo_isp: ($match | get isp.0) } } else { $t.row }
            } else {
                null
            }
        } else {
            if (($t.host | str ends-with $".($cc_lower)")) {
                if (do $is_record $t.row) { $t.row | merge { cc: $target } } else { $t.row }
            } else {
                null
            }
        }
    } | where { |x| $x != null }
}

# Team Cymru Malware Hash Registry lookup via DNS (no key; md5/sha1 only)
def cymru-mhr [hash: string] {
    let h = ($hash | str trim | str lowercase)
    let len = ($h | str length)
    if ($len != 32 and $len != 40) {
        return { supported: false, known: false, detection_pct: null, last_seen: "-" }
    }
    let has_dig = (try { (which dig | where type == "external" | length) > 0 } catch { false })
    let raw = if $has_dig {
        (try { ^dig +short TXT $"($h).malware.hash.cymru.com" | complete | get stdout } catch { "" })
    } else {
        (try { ^nslookup -type=TXT $"($h).malware.hash.cymru.com" | complete | get stdout } catch { "" })
    }
    let m = ($raw | str replace --all '"' '' | parse --regex '(?<epoch>\d{9,})\s+(?<pct>\d{1,3})')
    if (($m | length) == 0) {
        { supported: true, known: false, detection_pct: null, last_seen: "-" }
    } else {
        let epoch = (try { $m | get epoch.0 | into int } catch { 0 })
        let pct = (try { $m | get pct.0 | into int } catch { 0 })
        let seen = (try { ($epoch * 1_000_000_000) | into datetime | format date "%Y-%m-%d" } catch { "-" })
        { supported: true, known: true, detection_pct: $pct, last_seen: $seen }
    }
}

# Find an exact IOC in the cached ThreatFox full export (no key). Returns record or null.
def threatfox-find [value: string, kind: string] {
    let path = (threatfox-cache)
    let v = ($value | str trim | str lowercase)
    let hits = (open $path | values | flatten | where { |e|
        let iv = ($e.ioc_value? | default "" | into string | str lowercase)
        if $kind == "ip" {
            ($iv == $v) or ($iv | str starts-with $"($v):")
        } else if $kind == "domain" {
            ($iv == $v) or ((ioc-host $iv) == $v)
        } else if $kind == "url" {
            $iv == $v
        } else {
            $iv == $v
        }
    })
    let hit = ($hits | get 0?)
    if ($hit == null) {
        null
    } else {
        {
            malware: ($hit.malware_printable? | default ($hit.malware? | default "-"))
            threat_type: ($hit.threat_type? | default "-")
            ioc_type: ($hit.ioc_type? | default "-")
            first_seen: ($hit.first_seen_utc? | default "-")
            reference: ($hit.reference? | default "-")
        }
    }
}

# True for popular legit hosts that commonly appear in IOCs as abused infra
def benign-host [host: string] {
    let known = [
        "google.com" "googleapis.com" "gstatic.com" "goo.gl"
        "github.com" "githubusercontent.com" "githubassets.com" "github.io"
        "microsoft.com" "windows.com" "office.com" "live.com" "msftconnecttest.com"
        "cloudflare.com" "cloudflare.net" "cloudflareinsights.com"
        "amazonaws.com" "amazon.com" "akamai.net" "akamaized.net" "fastly.net"
        "discord.com" "discordapp.com" "discord.gg" "telegram.org" "t.me"
        "pastebin.com" "bit.ly" "tinyurl.com" "ngrok.io" "ngrok-free.app"
        "dropbox.com" "dropboxusercontent.com" "onedrive.live.com" "1drv.ms"
        "wordpress.com" "blogspot.com" "wixsite.com" "weebly.com"
        "sourceforge.net" "gitlab.com" "bitbucket.org" "gitee.com"
        "gvt1.com" "digicert.com" "sectigo.com" "letsencrypt.org"
    ]
    let h = ($host | str lowercase | str trim)
    ($known | any { |b| $h == $b or ($h | str ends-with $".($b)") })
}

# Aggregate key-free IOC reputation from multiple sources.
#   hash   -> ThreatFox export + Team Cymru MHR (AV %) + CIRCL hashlookup
#   ip     -> ThreatFox export + ISC SANS DShield + ip-api (geo/hosting/proxy)
#   domain -> ThreatFox export + urlscan.io
#   url    -> ThreatFox export + urlscan.io
def vt [ioc: string, --type: string] {
    let value = ($ioc | str trim)
    if $value == "" { error make { msg: "ioc cannot be empty." } }
    let kind = if $type != null { ($type | str lowercase) } else { (ioc-type $value) }

    if ($kind in ["hash" "file"]) {
        let len = ($value | str length)
        let algo = if $len == 32 { "md5" } else if $len == 40 { "sha1" } else if $len == 64 { "sha256" } else {
            error make { msg: "hash must be md5(32), sha1(40) or sha256(64) hex chars." }
        }
        let tf = (threatfox-find $value "hash")
        let cymru = (cymru-mhr $value)
        let circl = (try { http get $"https://hashlookup.circl.lu/lookup/($algo)/($value)" } catch { null })
        let circl_known = ($circl != null and (($circl.message? | default "") !~ "(?i)not found"))

        let verdict = if ($tf != null or $cymru.known) {
            "MALICIOUS"
        } else if $circl_known {
            "known / likely benign"
        } else {
            "unknown (no source has it)"
        }

        {
            ioc: $value
            type: $algo
            verdict: $verdict
            threatfox: (if $tf != null { $tf.malware } else { "-" })
            threat_type: (if $tf != null { $tf.threat_type } else { "-" })
            cymru_av: (if $cymru.known { $"($cymru.detection_pct)% \(seen ($cymru.last_seen)\)" } else { "-" })
            circl_name: (if $circl_known { ($circl.FileName? | default "-") } else { "-" })
            first_seen: (if $tf != null { $tf.first_seen } else { "-" })
        }
    } else if $kind == "ip" {
        let tf = (threatfox-find $value "ip")
        let ds = (abuse $value)
        let geo = (try { ipinfo $value } catch { null })
        let reports = (try { $ds.reports | into int } catch { 0 })

        let verdict = if $tf != null {
            "MALICIOUS"
        } else if ($reports > 0) {
            "suspicious (DShield reports)"
        } else {
            "no known reports"
        }

        {
            ioc: $value
            type: "ip"
            verdict: $verdict
            threatfox: (if $tf != null { $tf.malware } else { "-" })
            threat_type: (if $tf != null { $tf.threat_type } else { "-" })
            dshield_reports: $reports
            country: ($ds.country? | default "-")
            asname: ($ds.asname? | default "-")
            isp: (if $geo != null { ($geo.isp? | default "-") } else { "-" })
            hosting: (if $geo != null { ($geo.hosting? | default "-") } else { "-" })
            proxy: (if $geo != null { ($geo.proxy? | default "-") } else { "-" })
            first_seen: (if $tf != null { $tf.first_seen } else { "-" })
        }
    } else if ($kind in ["domain" "url"]) {
        let tf = (threatfox-find $value $kind)
        let query = if $kind == "domain" { $"domain:($value)" } else { $"page.url:\"($value)\"" }
        let resp = (try {
            http get --max-time 12sec $"https://urlscan.io/api/v1/search/?q=($query)&size=100"
        } catch {
            null
        })
        let results = (if $resp != null { ($resp.results? | default []) } else { [] })
        let malicious = ($results | where { |r| ($r.verdicts?.overall?.malicious? | default false) } | length)
        let tags = ($results | each { |r| $r.task?.tags? | default [] } | flatten | uniq | first 10)

        let host_for_benign = if $kind == "domain" { $value } else { (ioc-host $value) }
        let benign = (benign-host $host_for_benign)
        let verdict = if ($tf != null and $benign) {
            "likely benign (popular host; appears in IOCs as abused infra)"
        } else if $tf != null {
            "MALICIOUS"
        } else if ($malicious > 0) {
            "suspicious (urlscan verdict)"
        } else {
            "no known reports"
        }

        {
            ioc: $value
            type: $kind
            verdict: $verdict
            threatfox: (if $tf != null { $tf.malware } else { "-" })
            threat_type: (if $tf != null { $tf.threat_type } else { "-" })
            urlscan_scans: ($results | length)
            urlscan_malicious: $malicious
            tags: $tags
            last_scan: (try { $results | get 0.task.time } catch { "-" })
        }
    } else {
        error make { msg: $"Unsupported --type: ($kind). Use ip|domain|hash|url." }
    }
}

# IP reputation via ISC SANS DShield (no API key required)
def abuse [ip: string] {
    let target = ($ip | str trim)
    if (($target | parse --regex '^(?:\d{1,3}\.){3}\d{1,3}$' | length) == 0) {
        error make { msg: "abuse expects an IPv4 address." }
    }

    let resp = (try {
        http get $"https://isc.sans.edu/api/ip/($target)?json"
    } catch { |err|
        error make { msg: $"DShield request failed: ($err.msg)" }
    })

    let d = ($resp.ip? | default {})
    let attacks = ($d.attacks? | default null)
    let reports = ($d.count? | default null)
    {
        ip: ($d.number? | default $target)
        reports: (if $reports == null { 0 } else { $reports })
        targets_attacked: (if $attacks == null { 0 } else { $attacks })
        max_risk: ($d.maxrisk? | default "-")
        as: ($d.as? | default "-")
        asname: ($d.asname? | default "-")
        country: ($d.ascountry? | default "-")
        network: ($d.network? | default "-")
        first_seen: ($d.mindate? | default "-")
        last_seen: ($d.maxdate? | default "-")
        abuse_contact: ($d.asabusecontact? | default "-")
    }
}

# Download + cache the full ThreatFox export (no API key). Returns the JSON path.
def threatfox-cache [--refresh, --ttl-hours: int = 6] {
    let has_external_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | where type == "external" | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    let cache_dir = ([$env.HOME ".nusecurity" "cache"] | path join)
    mkdir $cache_dir
    let json_path = ([$cache_dir "threatfox_full.json"] | path join)
    let zip_path = ([$cache_dir "threatfox_full.zip"] | path join)

    let is_fresh = (if ($json_path | path exists) {
        let age = ((date now) - (ls $json_path | get 0.modified))
        $age < ($ttl_hours * 1hr)
    } else {
        false
    })

    if ($refresh or (not $is_fresh)) {
        print $"(ansi cyan_bold)[otx](ansi reset) Refreshing ThreatFox full export \(cached ($ttl_hours)h\) ..."
        try {
            http get "https://threatfox.abuse.ch/export/json/full/" | save --force --raw $zip_path
        } catch { |err|
            error make { msg: $"ThreatFox full export download failed: ($err.msg)" }
        }

        let extracted = ([$cache_dir "full.json"] | path join)
        if ($extracted | path exists) { rm -f $extracted }

        if (do $has_external_cmd "unzip") {
            ^unzip -o -q -d $cache_dir $zip_path
        } else {
            # Cross-platform fallback via Python's stdlib zipfile
            run-external (py-bin) "-m" "zipfile" "-e" $zip_path $cache_dir
        }

        if (($extracted | path exists) == false) {
            error make { msg: "ThreatFox export extracted but full.json not found." }
        }
        mv -f $extracted $json_path
        rm -f $zip_path
    }

    $json_path
}

# Indicator/malware lookup against the ThreatFox export (no API key required).
# Default searches the full export (cached 6h); --recent uses the small live feed.
def otx [
    ioc?: string       # IP/domain/URL/hash substring OR malware family name
    --recent           # Search only the recent rolling feed (faster, less coverage)
    --refresh          # Force refresh of the cached full export
    --cc: string       # Keep only IOCs in this country (e.g. TR); geolocates IPs + ccTLD domains
    --limit: int = 50  # Max rows returned
] {
    # `otx --refresh` with no IOC just refreshes the cached export and exits.
    if ($ioc == null or (($ioc | str trim) == "")) {
        if $refresh {
            let path = (threatfox-cache --refresh)
            let count = (open $path | values | flatten | length)
            print $"(ansi green_bold)[otx](ansi reset) ThreatFox full export refreshed: ($count) IOCs cached."
            return
        }
        error make { msg: "Provide an IOC/family to search, or use `otx --refresh` to just refresh the cache." }
    }

    let raw_needle = ($ioc | str trim | str lowercase)
    let norm_needle = ($raw_needle | str replace --all --regex '[ ._-]' '')

    let entries = if $recent {
        let feed = (try {
            http get "https://threatfox.abuse.ch/export/json/recent/"
        } catch { |err|
            error make { msg: $"ThreatFox feed request failed: ($err.msg)" }
        })
        $feed | values | flatten
    } else {
        let path = (if $refresh { threatfox-cache --refresh } else { threatfox-cache })
        open $path | values | flatten
    }

    let matches = ($entries
        | where { |entry|
            let iocv = ($entry.ioc_value? | default "" | into string | str lowercase)
            let names = ([
                ($entry.malware? | default "")
                ($entry.malware_alias? | default "")
                ($entry.malware_printable? | default "")
                ($entry.threat_type? | default "")
            ] | str join " " | into string | str lowercase | str replace --all --regex '[ ._-]' '')
            ($iocv | str contains $raw_needle) or (($norm_needle != "") and ($names | str contains $norm_needle))
        }
        | each { |entry|
            {
                ioc: ($entry.ioc_value? | default "-")
                ioc_type: ($entry.ioc_type? | default "-")
                threat_type: ($entry.threat_type? | default "-")
                malware: ($entry.malware_printable? | default ($entry.malware? | default "-"))
                confidence: ($entry.confidence_level? | default "-")
                first_seen: ($entry.first_seen_utc? | default "-")
                last_seen: ($entry.last_seen_utc? | default "-")
                reference: ($entry.reference? | default "-")
            }
        }
        | uniq)

    let filtered = if ($cc != null and (($cc | str trim) != "")) {
        geo-filter $matches ($cc) { |row| $row.ioc }
    } else {
        $matches
    }

    let source = if $recent { "recent feed" } else { "full export" }
    if (($filtered | length) == 0) {
        let cc_note = if ($cc != null and (($cc | str trim) != "")) { $" in ($cc | str uppercase)" } else { "" }
        print $"(ansi yellow_bold)[otx](ansi reset) No match in ThreatFox ($source)($cc_note) for: ($ioc)."
    }
    if $limit > 0 { $filtered | first $limit } else { $filtered }
}

# DNS records for a domain via dig (A/AAAA/MX/NS/TXT/CNAME) — no key
def dns-records [domain: string] {
    mut out = {}
    for t in ["A" "AAAA" "MX" "NS" "TXT" "CNAME"] {
        let vals = (try {
            ^dig +short $t $domain
            | complete
            | get stdout
            | lines
            | each { |l| $l | str trim }
            | where { |l| $l != "" }
        } catch {
            []
        })
        $out = ($out | insert $t $vals)
    }
    $out
}

# Reverse-IP: other domains sharing an IP, via HackerTarget (no key)
def reverse-ip [ip: string, --limit: int = 50] {
    let body = (try { http get --max-time 10sec $"https://api.hackertarget.com/reverseiplookup/?q=($ip)" | into string } catch { "" })
    let lc = ($body | str lowercase)
    let bad = ($body == "" or ($lc | str contains "error") or ($lc | str contains "api count") or ($lc | str contains "no dns") or ($lc | str contains "no records"))
    if $bad {
        []
    } else {
        let rows = ($body | lines | each { |l| $l | str trim } | where { |l| $l != "" and ($l =~ '^[a-z0-9.-]+\.[a-z]{2,}$') })
        if $limit > 0 { $rows | first $limit } else { $rows }
    }
}

# VirusTotal multi-engine verdict via the key-free UI endpoint (ip, domain, or hash)
def vt-av [target: string] {
    let t = ($target | into string)
    let is_ip_t = (($t | parse --regex '^(?:\d{1,3}\.){3}\d{1,3}$' | length) > 0)
    let is_hash_t = (($t | parse --regex '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$' | length) > 0)
    let resource = if $is_ip_t { "ip_addresses" } else if $is_hash_t { "files" } else { "domains" }
    let headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
        "Accept": "application/json"
        "X-Tool": "vt-ui-main"
        "X-VT-Anti-Abuse-Header": "MTA3OTM2NjUwMjctWkc5dWRDQmlaU0JsZG1scy0xNzEwMzUyNjk1LjY1Nw=="
        "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8"
    }
    let d = (try { http get --max-time 12sec --headers $headers $"https://www.virustotal.com/ui/($resource)/($target)" } catch { null })
    if $d == null { return { available: false } }

    let attr = ($d.data?.attributes? | default {})
    let stats = ($attr.last_analysis_stats? | default {})
    let engines = ($attr.last_analysis_results? | default {})
    let detections = ($engines
        | items { |name, info| { engine: $name, result: ($info.result? | default "malicious") category: ($info.category? | default "") } }
        | where category == "malicious"
        | get engine
        | first 12)
    {
        available: true
        malicious: ($stats.malicious? | default 0)
        suspicious: ($stats.suspicious? | default 0)
        harmless: ($stats.harmless? | default 0)
        undetected: ($stats.undetected? | default 0)
        reputation: ($attr.reputation? | default 0)
        detected_by: $detections
    }
}

# Aggregate domains sharing an IP from several key-free sources
def related-domains [ip: string, --limit: int = 30] {
    mut found = {}   # domain -> list of sources
    let add = { |doms: list<string>, src: string, acc: record|
        mut a = $acc
        for d in $doms {
            let dom = ($d | str trim | str lowercase | str trim --char '.')
            if ($dom != "" and ($dom =~ '^[a-z0-9.-]+\.[a-z]{2,}$') and $dom != $ip) {
                let prev = ($a | get --optional $dom | default [])
                $a = ($a | upsert $dom ($prev | append $src | uniq))
            }
        }
        $a
    }

    # HackerTarget
    $found = (do $add (reverse-ip $ip --limit 500) "HackerTarget" $found)

    # crt.sh certificate transparency
    let crt = (try {
        http get --max-time 12sec $"https://crt.sh/?q=($ip)&output=json"
        | each { |e| $e.name_value? | default "" | split row "\n" }
        | flatten
        | each { |n| $n | str trim --char '*' | str trim --char '.' }
    } catch { [] })
    $found = (do $add $crt "crt.sh" $found)

    # VirusTotal passive resolutions (key-free UI endpoint)
    let vt = (try {
        let headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
            "Accept": "application/json"
            "X-Tool": "vt-ui-main"
            "X-VT-Anti-Abuse-Header": "MTA3OTM2NjUwMjctWkc5dWRDQmlaU0JsZG1scy0xNzEwMzUyNjk1LjY1Nw=="
            "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8"
        }
        http get --max-time 12sec --headers $headers $"https://www.virustotal.com/ui/ip_addresses/($ip)/resolutions?limit=40"
        | get data
        | each { |item| $item.attributes?.host_name? | default "" }
    } catch { [] })
    $found = (do $add $vt "VirusTotal" $found)

    let rows = ($found
        | items { |domain, sources| { domain: $domain, sources: ($sources | str join ", "), source_count: ($sources | length) } }
        | sort-by source_count --reverse)
    if $limit > 0 { $rows | first $limit } else { $rows }
}

# Check an IP against a curated set of DNS blacklists (validates 127.0.0.x)
def dnsbl-check [ip: string] {
    let lists = [
        "zen.spamhaus.org" "bl.spamcop.net" "b.barracudacentral.org"
        "cbl.abuseat.org" "dnsbl-1.uceprotect.net" "psbl.surriel.com"
        "dyna.spamrats.com" "noptr.spamrats.com" "spam.spamrats.com"
        "bl.mailspike.net" "db.wpbl.info" "rbl.interserver.net"
        "dnsbl.dronebl.org" "all.s5h.net" "spamrbl.imp.ch"
    ]
    let rev = ($ip | split row "." | reverse | str join ".")
    mut listed = []
    for bl in $lists {
        let ans = (try {
            ^dig +short A $"($rev).($bl)" | complete | get stdout | lines | each { |l| $l | str trim } | where { |l| $l != "" }
        } catch { [] })
        # A genuine listing answers in 127.0.0.0/8; anything else = block/error, ignore
        if (($ans | where { |a| $a | str starts-with "127." } | length) > 0) {
            $listed = ($listed | append $bl)
        }
    }
    { total_checked: ($lists | length), total_listed: ($listed | length), listed: $listed }
}

# Scan common TCP ports with nc (fast connect check)
def port-scan [ip: string, --timeout: int = 1] {
    let has_nc = (try { (which nc | where type == "external" | length) > 0 } catch { false })
    if (not $has_nc) { return [] }
    let ports = {
        "21": "FTP" "22": "SSH" "23": "Telnet" "25": "SMTP" "53": "DNS"
        "80": "HTTP" "110": "POP3" "143": "IMAP" "443": "HTTPS" "445": "SMB"
        "3306": "MySQL" "3389": "RDP" "5432": "PostgreSQL" "5900": "VNC"
        "6379": "Redis" "8080": "HTTP-Alt" "8443": "HTTPS-Alt" "27017": "MongoDB"
    }
    let risky = ["23" "445" "3306" "3389" "5900" "6379" "27017"]
    $ports | items { |port, service|
        let ok = (try {
            (^nc -z -w $timeout $ip $port | complete | get exit_code) == 0
        } catch { false })
        if $ok {
            { port: ($port | into int), service: $service, risk: (if ($port in $risky) { "HIGH" } else { "low" }) }
        } else {
            null
        }
    } | where { |x| $x != null } | sort-by port
}

# Registration info via RDAP (no key) for a domain or IP
def rdap-info [target: string] {
    let is_ip_target = ((($target | into string) | parse --regex '^(?:\d{1,3}\.){3}\d{1,3}$' | length) > 0)
    let url = if $is_ip_target { $"https://rdap.org/ip/($target)" } else { $"https://rdap.org/domain/($target)" }
    let d = (try { http get --redirect-mode follow $url | from json } catch { null })
    if $d == null { return {} }

    let ev = ($d.events? | default [])
    let ev_date = { |action| ($ev | where eventAction == $action | get eventDate.0? | default "-") }

    if $is_ip_target {
        {
            handle: ($d.handle? | default "-")
            name: ($d.name? | default "-")
            country: ($d.country? | default "-")
            type: ($d.type? | default "-")
            registration: (do $ev_date "registration")
            last_changed: (do $ev_date "last changed")
        }
    } else {
        let reg = ($d.entities? | default [] | where { |e| "registrar" in ($e.roles? | default []) } | get 0?)
        let registrar = (if $reg != null {
            (try {
                $reg.vcardArray.1 | where { |x| ($x | get 0?) == "fn" } | get 0.3?
            } catch { "-" } | default "-")
        } else { "-" })
        {
            handle: ($d.handle? | default "-")
            domain: ($d.ldhName? | default $target)
            registrar: $registrar
            status: ($d.status? | default [])
            registration: (do $ev_date "registration")
            expiration: (do $ev_date "expiration")
            last_changed: (do $ev_date "last changed")
        }
    }
}

# Map a 0-100 threat score to a level label
def threat-level [score: int] {
    if $score <= 10 { "CLEAN" } else if $score <= 30 { "LOW" } else if $score <= 50 { "MEDIUM" } else if $score <= 75 { "HIGH" } else { "CRITICAL" }
}

# Render an inline progress bar to stderr (overwrites its own line)
def iocall-progress [done: int, total: int, label: string] {
    let width = 22
    let filled = ($done * $width // $total)
    let barf = ("" | fill --width $filled --character "█")
    let bare = ("" | fill --width ($width - $filled) --character "░")
    let pct = ($done * 100 // $total)
    print -en $"\r(ansi cyan_bold)[($barf)($bare)](ansi reset) ($pct | into string | fill --width 3 --alignment right)%  ($label | fill --width 18 --alignment left)"
}

# Draw a boxed VERDICT panel (score bar + indicators), colored by severity
def verdict-panel [score: int, level: string, reasons: list<string>, color: string] {
    let iw = 74                       # inner content width (between the ┃ borders)
    let w = ($iw + 2)
    let cc = { |s: string| $"(ansi $color)($s)(ansi reset)" }
    let line = { |text: string| $"(do $cc '┃') ($text | fill --width $iw --alignment left) (do $cc '┃')" }

    let title = " VERDICT "
    let tlen = ($title | str length)
    let lpad = (($w - $tlen) // 2)
    let rpad = ($w - $tlen - $lpad)
    print (do $cc $"┏(''| fill --width $lpad --character '━')($title)(''| fill --width $rpad --character '━')┓")
    print (do $line $"Threat Score: ($score)/100  ($level)")
    print (do $line "")

    # colored bar — width computed on visible length so ansi codes don't misalign
    let filled = ($score // 2)
    let bar_visible = (2 + 50 + 2 + ($"($score)%" | str length))
    let pad_n = ([($iw - $bar_visible) 0] | math max)
    let bar = $"(ansi $color)(''| fill --width $filled --character '█')(ansi reset)(ansi dark_gray)(''| fill --width (50 - $filled) --character '░')(ansi reset)"
    print $"(do $cc '┃')   ($bar)  ($score)%(''| fill --width $pad_n --character ' ') (do $cc '┃')"
    print (do $line "")

    print (do $line "Threat Indicators:")
    for r in $reasons {
        let txt = $"  • ($r)"
        let clipped = (if (($txt | str length) > $iw) { $"($txt | str substring 0..($iw - 3))..." } else { $txt })
        print (do $line $clipped)
    }
    print (do $cc $"┗(''| fill --width $w --character '━')┛")
}

# Run a list of { label, key, run: closure } steps, showing a progress bar,
# and return a record of key -> result.
def run-steps [steps: list<any>, show_progress: bool] {
    let total = ($steps | length)
    mut data = {}
    for it in ($steps | enumerate) {
        if $show_progress { iocall-progress ($it.index + 1) $total ($it.item.label) }
        let v = (try { do $it.item.run } catch { null })
        $data = ($data | upsert $it.item.key $v)
    }
    if $show_progress {
        print -en $"\r(''| fill --width 55 --character ' ')\r"
    }
    $data
}

# One-shot IOC report: everything we know about a URL/domain/IP/hash from
# key-free sources, with a heuristic threat score and a live progress bar.
# Prints sectioned tables; use --json for a structured record.
def iocall [
    ioc: string        # URL, domain, IP, or file hash
    --json             # Return the aggregated record instead of printing
    --skip-ports       # Skip TCP port scan (IP/host)
    --no-progress      # Hide the progress bar
    --limit: int = 25  # Cap for list sections (related domains, subdomains, ...)
] {
    let raw = ($ioc | str trim)
    if $raw == "" { error make { msg: "ioc cannot be empty." } }
    let kind = (ioc-type $raw)
    let show_progress = ((not $json) and (not $no_progress))

    mut score = 0
    mut reasons = []
    mut results = {}

    if ($kind == "hash") {
        let steps = [
            { label: "Reputation", key: "reputation", run: { vt $raw } }
            { label: "VirusTotal", key: "virustotal", run: { vt-av $raw } }
        ]
        let data = (run-steps $steps $show_progress)
        let rep = ($data.reputation | default {})
        let av = ($data.virustotal | default { available: false })
        if (($rep.verdict? | default "") == "MALICIOUS") { $score = ($score + 40); $reasons = ($reasons | append "ThreatFox/Cymru: known malicious sample (+40)") }
        if (($av.available? | default false) and (($av.malicious? | default 0) > 0)) {
            let p = ([($av.malicious * 4) 40] | math min); $score = ($score + $p); $reasons = ($reasons | append $"VirusTotal: ($av.malicious) engine\(s) flagged as MALICIOUS \(+($p))")
        }
        $results = { reputation: $rep, virustotal: $av }
    } else if ($kind == "ip") {
        let steps = [
            { label: "VirusTotal", key: "virustotal", run: { vt-av $raw } }
            { label: "ThreatFox", key: "threatfox_hits", run: { otx $raw --limit $limit } }
            { label: "DShield", key: "dshield", run: { abuse $raw } }
            { label: "Geolocation", key: "geo", run: { ipinfo $raw } }
            { label: "BGP / ASN", key: "bgp", run: { chkbgp $raw } }
            { label: "RDAP", key: "rdap", run: { rdap-info $raw } }
            { label: "Reverse DNS", key: "reverse_dns", run: { ^dig +short -x $raw | complete | get stdout | lines | first | default "-" } }
            { label: "DNS blacklists", key: "dnsbl", run: { dnsbl-check $raw } }
            { label: "Port scan", key: "open_ports", run: { if $skip_ports { [] } else { port-scan $raw } } }
            { label: "Related domains", key: "related_domains", run: { related-domains $raw --limit $limit } }
        ]
        let data = (run-steps $steps $show_progress)

        let tf_hits = ($data.threatfox_hits | default [])
        let av = ($data.virustotal | default { available: false })
        let dnsbl = ($data.dnsbl | default { total_listed: 0 })
        let ports = ($data.open_ports | default [])
        let ds = ($data.dshield | default {})

        if (($tf_hits | length) > 0) { $score = ($score + 35); $reasons = ($reasons | append $"ThreatFox: known IOC (($tf_hits | get malware.0? | default 'malware')) \(+35)") }
        if (($av.available? | default false) and (($av.malicious? | default 0) > 0)) {
            let p = ([($av.malicious * 4) 40] | math min); $score = ($score + $p); $reasons = ($reasons | append $"VirusTotal: ($av.malicious) engine\(s) flagged as MALICIOUS \(+($p))")
        }
        let listed = ($dnsbl.total_listed? | default 0)
        if ($listed > 0) { let p = ([($listed * 8) 24] | math min); $score = ($score + $p); $reasons = ($reasons | append $"Listed on ($listed) DNS blacklist\(s) \(+($p))") }
        let risky = ($ports | where risk == "HIGH")
        if (($risky | length) > 0) { let p = (($risky | length) * 4); $score = ($score + $p); $reasons = ($reasons | append $"Risky open ports: (($risky | get service) | str join ', ') \(+($p))") }
        let reports = (try { $ds.reports | into int } catch { 0 })
        if ($reports > 0) { $score = ($score + 10); $reasons = ($reasons | append $"DShield: ($reports) attack report\(s) \(+10)") }

        $results = {
            virustotal: $av
            threatfox_hits: $tf_hits
            dshield: $ds
            geo: ($data.geo | default {})
            bgp: ($data.bgp | default {})
            rdap: ($data.rdap | default {})
            reverse_dns: ($data.reverse_dns | default "-")
            dnsbl: $dnsbl
            open_ports: $ports
            related_domains: ($data.related_domains | default [])
        }
    } else if ($kind == "domain") {
        let ips = (try { ^dig +short A $raw | complete | get stdout | lines | each { |l| $l | str trim } | where { |l| $l =~ '^(?:\d{1,3}\.){3}\d{1,3}$' } } catch { [] })
        let primary = ($ips | get 0?)
        let steps = [
            { label: "Reputation", key: "reputation", run: { vt $raw } }
            { label: "VirusTotal", key: "virustotal", run: { vt-av $raw } }
            { label: "DNS records", key: "dns", run: { dns-records $raw } }
            { label: "RDAP", key: "rdap", run: { rdap-info $raw } }
            { label: "Subdomains (crt.sh)", key: "subdomains", run: { crt $raw | first $limit } }
            { label: "Resolved-IP geo", key: "ip_geo", run: { if $primary != null { ipinfo $primary } else { {} } } }
            { label: "IP blacklists", key: "ip_dnsbl", run: { if $primary != null { dnsbl-check $primary } else { { total_listed: 0 } } } }
        ]
        let data = (run-steps $steps $show_progress)

        let rep = ($data.reputation | default {})
        let av = ($data.virustotal | default { available: false })
        let dnsbl = ($data.ip_dnsbl | default { total_listed: 0 })

        if (($rep.verdict? | default "") == "MALICIOUS") { $score = ($score + 35); $reasons = ($reasons | append $"ThreatFox: known malicious domain (($rep.threatfox? | default '')) \(+35)") }
        if (($rep.verdict? | default "") | str contains "suspicious") { $score = ($score + 10); $reasons = ($reasons | append "urlscan: suspicious verdict (+10)") }
        if (($av.available? | default false) and (($av.malicious? | default 0) > 0)) {
            let p = ([($av.malicious * 4) 40] | math min); $score = ($score + $p); $reasons = ($reasons | append $"VirusTotal: ($av.malicious) engine\(s) flagged as MALICIOUS \(+($p))")
        }
        let listed = ($dnsbl.total_listed? | default 0)
        if ($listed > 0) { let p = ([($listed * 8) 24] | math min); $score = ($score + $p); $reasons = ($reasons | append $"Resolved IP on ($listed) DNS blacklist\(s) \(+($p))") }

        $results = {
            resolved_ips: $ips
            reputation: $rep
            virustotal: $av
            dns: ($data.dns | default {})
            rdap: ($data.rdap | default {})
            subdomains: ($data.subdomains | default [])
            ip_geo: ($data.ip_geo | default {})
            ip_dnsbl: $dnsbl
        }
    } else {
        # url
        let host = (ioc-host $raw)
        let ips = (try { ^dig +short A $host | complete | get stdout | lines | each { |l| $l | str trim } | where { |l| $l =~ '^(?:\d{1,3}\.){3}\d{1,3}$' } } catch { [] })
        let primary = ($ips | get 0?)
        let steps = [
            { label: "URL reputation", key: "reputation", run: { vt $raw --type url } }
            { label: "Host reputation", key: "host_reputation", run: { vt $host } }
            { label: "VirusTotal (host)", key: "virustotal", run: { vt-av $host } }
            { label: "DNS records", key: "dns", run: { dns-records $host } }
            { label: "RDAP", key: "rdap", run: { rdap-info $host } }
            { label: "Resolved-IP geo", key: "ip_geo", run: { if $primary != null { ipinfo $primary } else { {} } } }
        ]
        let data = (run-steps $steps $show_progress)

        let rep = ($data.reputation | default {})
        let host_rep = ($data.host_reputation | default {})
        let av = ($data.virustotal | default { available: false })

        if (($rep.verdict? | default "") == "MALICIOUS" or ($host_rep.verdict? | default "") == "MALICIOUS") { $score = ($score + 35); $reasons = ($reasons | append "ThreatFox: known malicious URL/host (+35)") }
        if (($av.available? | default false) and (($av.malicious? | default 0) > 0)) {
            let p = ([($av.malicious * 4) 40] | math min); $score = ($score + $p); $reasons = ($reasons | append $"VirusTotal \(host): ($av.malicious) engine\(s) flagged as MALICIOUS \(+($p))")
        }

        $results = {
            host: $host
            defanged: (try { defang $raw } catch { $raw })
            reputation: $rep
            host_reputation: $host_rep
            virustotal: $av
            resolved_ips: $ips
            dns: ($data.dns | default {})
            rdap: ($data.rdap | default {})
            ip_geo: ($data.ip_geo | default {})
        }
    }

    let final_score = ([$score 100] | math min)
    let level = (threat-level $final_score)
    let summary = {
        ioc: $raw
        type: $kind
        threat_score: $"($final_score)/100"
        threat_level: $level
        indicators: (if (($reasons | length) == 0) { ["No significant threat indicators detected"] } else { $reasons })
    }

    let out = ({ summary: $summary } | merge $results)

    if $json {
        return $out
    }

    let level_color = (if $final_score <= 30 { "green_bold" } else if $final_score <= 50 { "yellow_bold" } else { "red_bold" })
    print $"(ansi cyan_bold)IOC:(ansi reset) ($raw)   (ansi cyan_bold)type:(ansi reset) ($kind)"
    $out | reject summary | items { |section, value|
        print $"\n(ansi green_bold)== ($section) ==(ansi reset)"
        print ($value | table -e)
    } | ignore
    print ""
    verdict-panel $final_score $level ($summary.indicators) $level_color
}

# Start HTTPSERVER
def hs [--path: string] {
    let py = (py-bin)
    if $path != null {
        let abs_path = ($path | str trim)
        run-external $py "-m" "http.server" "-d" $abs_path
    } else {
        run-external $py "-m" "http.server"
    }
}

# Output with syntax highlighting
def catt [targetfile: string] {
    run-external (py-bin) "-m" "rich.syntax" $targetfile
}

# Get Ifaces
alias ifc = sys net

# Get disks
alias sd = sys disks

# Verbose LS for disk usage checks
def lsv [] {
    ls -a -d -l | sort-by size
}

# Verbose LS for last created file and mime checks
def lsl [] {
    ls -a -m | sort-by modified
}

# Access shell of a docker image
def dosh [image_id: string] {
    docker run -it $image_id /bin/bash
}

# Remove selected docker image
def drmi [target_id: string] {
    docker rmi --force $target_id
}

# Install desired package
def aget [target_package: string] {
    let is_windows = (($nu.os-info.name | str lowercase) == "windows")
    let has_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    if $is_windows {
        if (do $has_cmd "winget") {
            winget install --accept-source-agreements --accept-package-agreements $target_package
        } else {
            error make { msg: "winget not found. Install App Installer from Microsoft Store first." }
        }
    } else {
        sudo apt install -y $target_package
    }
}

# Remove package
def arem [target_package: string] {
    let is_windows = (($nu.os-info.name | str lowercase) == "windows")
    let has_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    if $is_windows {
        if (do $has_cmd "winget") {
            winget uninstall $target_package
        } else {
            error make { msg: "winget not found. Install App Installer from Microsoft Store first." }
        }
    } else {
        sudo apt remove $target_package
    }
}

# List connections and listening ports
def netcon [] {
    let is_windows = (($nu.os-info.name | str lowercase) == "windows")
    let has_external_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | where type == "external" | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    if $is_windows {
        netstat -ano | lines | where { |line| ($line | str trim) =~ "LISTENING" }
    } else {
        if (do $has_external_cmd "lsof") {
            lsof -i4 -V -E -R | awk '$1 ~ /:*(-|$)/{ gsub(/:[^-]*/, "", $1); print $1,$2,$3,$4,$9,$10,$11 }' | to text | lines | split column " " | rename COMMAND PID PPID USER PROTO CONNECTION STATUS | skip 1
        } else if (do $has_external_cmd "ss") {
            ss -lntup
        } else if (do $has_external_cmd "netstat") {
            netstat -tulpn
        } else {
            error make { msg: "No supported network tool found (lsof/ss/netstat)." }
        }
    }
}

# Fetch last 50 C2 panels from Viriback (optionally filter by country)
def vrb [--cc: string] {
    let rows = (http get https://tracker.viriback.com/last50.php)
    if ($cc != null and (($cc | str trim) != "")) {
        geo-filter $rows ($cc) { |row| $row.IP? | default ($row.URL? | default "") }
    } else {
        $rows
    }
}

# Fetch data from URLHAUS
def haus [
    datatype?: string = "online" # online | normal
    --limit: int = 0             # Limit output rows (0 = unlimited)
    --host-only                  # Return unique hosts instead of URLs
    --contains: string           # Case-insensitive contains filter
    --host-contains: string      # Case-insensitive host contains filter
    --host-ends-with: string     # Host suffix filter, e.g. .tr
    --https-only                 # Keep only https URLs
    --cc: string                 # Keep only entries in this country (geolocates hosts), e.g. TR
    --raw                        # Return raw feed without cleanup/filtering
] {
    let url_host = { |url_value: string|
        (try {
            $url_value | parse --regex '^https?://([^/:?#]+)' | get 0.capture0
        } catch {
            null
        })
    }

    let normalized_type = ($datatype | str trim | str lowercase)
    let source_type = if ($normalized_type in ["normal", "full"]) {
        "normal"
    } else if ($normalized_type in ["online", "active"]) {
        "online"
    } else {
        error make { msg: "Invalid datatype. Use: online | normal" }
    }

    let source_url = if $source_type == "normal" {
        "https://urlhaus.abuse.ch/downloads/text"
    } else {
        "https://urlhaus.abuse.ch/downloads/text_online"
    }

    let content = (http get $source_url)
    if $raw {
        if $limit > 0 {
            $content | lines | first $limit
        } else {
            $content | lines
        }
    } else {
        mut urls = ($content
            | lines
            | each { |line| $line | str trim }
            | where { |line| $line != "" and ($line | str starts-with "http") }
            | uniq)

        if $https_only {
            $urls = ($urls | where { |u| $u | str starts-with "https://" })
        }

        if ($contains != null) {
            let needle = ($contains | str lowercase)
            $urls = ($urls | where { |u| ($u | str lowercase | str contains $needle) })
        }

        if ($host_contains != null) {
            let needle = ($host_contains | str lowercase)
            $urls = ($urls | where { |u|
                let host = (do $url_host $u)
                $host != null and ($host | str lowercase | str contains $needle)
            })
        }

        if ($host_ends_with != null) {
            let suffix = ($host_ends_with | str lowercase)
            $urls = ($urls | where { |u|
                let host = (do $url_host $u)
                $host != null and ($host | str lowercase | str ends-with $suffix)
            })
        }

        if ($cc != null and (($cc | str trim) != "")) {
            $urls = (geo-filter $urls ($cc) { |u| $u })
        }

        if $host_only {
            let hosts = ($urls | each { |u| do $url_host $u } | where { |h| $h != null and ($h | str trim) != "" } | uniq)
            if $limit > 0 { $hosts | first $limit } else { $hosts }
        } else {
            if $limit > 0 { $urls | first $limit } else { $urls }
        }
    }
}

# Fetch data from ThreatFox (optionally filter by country)
def tfox [--dtype: string, --cc: string] {
    let buffer = http get https://threatfox.abuse.ch/export/json/urls/recent/ | values
    let has_cc = ($cc != null and (($cc | str trim) != ""))
    mut data_array = []
    if $dtype == "all" {
        for data in ($buffer) {
            $data_array ++= [{
                "ioc": $data.ioc_value.0,
                "threat_type": $data.threat_type.0,
                "malware": $data.malware.0,
                "malware_printable": $data.malware_printable.0,
                "tags": $data.tags,
                "reference": $data.reference
            }]
        }
        if $has_cc {
            geo-filter $data_array ($cc) { |row| $row.ioc }
        } else {
            $data_array
        }
    } else if $dtype == "url" {
        for data in ($buffer) {
            $data_array ++= [($data | get 0 | get ioc_value | to text)]
        }
        if $has_cc {
            geo-filter $data_array ($cc) { |u| $u }
        } else {
            $data_array
        }
    } else {
        "You must use: --dtype all/url"
    }
}

# Perform httpx scan against list of urls
def hx [listfile: string] {
    let has_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    if (($listfile | path exists) == false) {
        error make { msg: $"List file not found: ($listfile)" }
    }
    if ((do $has_cmd "httpx") == false) {
        if ((do $has_cmd "go") == false) {
            error make { msg: "Go is not installed. Please install Go first." }
        }
        print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Installing: (ansi green_bold)httpx(ansi reset)"
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    }
    httpx -l $listfile -silent -td -title -sc
}

# Projectdiscovery tool downloader
def pdsc [tool_name: string] {
    print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Installing: (ansi green_bold)($tool_name)"
    go install -v github.com/projectdiscovery/($tool_name)/cmd/($tool_name)@latest
}

# Get project commands with compact usage/samples
def hlp [command?: string, --verbose (-v)] {
    let summaries = {
        chkbgp: "Fetch ASN/BGP details for an IP."
        ipinfo: "Geolocate/enrich an IP or host (ip-api)."
        vt: "Aggregated key-free IOC reputation (ThreatFox+Cymru+urlscan)."
        iocall: "Full one-shot report for any IOC (url/domain/ip/hash)."
        abuse: "IP reputation via ISC SANS DShield (no key)."
        otx: "IOC/family lookup in ThreatFox full export (no key)."
        hs: "Start a quick HTTP file server."
        catt: "Show a file with syntax highlighting."
        ifc: "List network interfaces."
        sd: "List disks."
        lsv: "Sort files by size."
        lsl: "Sort files by modified time."
        dosh: "Run bash inside a Docker image."
        drmi: "Force remove a Docker image."
        aget: "Install a package via APT."
        arem: "Remove a package via APT."
        netcon: "List IPv4 connections and listening ports."
        vrb: "Fetch latest 50 panel entries from Viriback."
        haus: "Fetch and filter URLHaus feed entries."
        tfox: "Fetch recent URL IoCs from ThreatFox."
        hx: "Scan a target list with httpx."
        pdsc: "Install a ProjectDiscovery tool with Go."
        hlp: "Show commands and usage examples."
        shx: "Run subfinder + httpx domain scan."
        bdc: "Decode/encode Base64 text."
        defang: "Defang IOCs for safe sharing."
        refang: "Refang defanged IOCs."
        hashf: "Compute md5/sha1/sha256 of a file."
        hdns: "Hunt candidate C2 domains with hednsextractor."
        "windows-evt-hunt": "Hunt Windows Event Log entries quickly."
        "persist-hunt": "Hunt persistence artifacts on host."
        "proc-hunt": "Score suspicious running processes."
        "proc-dump": "Dump a running process with ProcDump."
        "log-hunt": "Hunt suspicious auth/system log lines."
        "timeline-lite": "Build quick file timeline for a path."
        upc: "Pull latest config from GitHub."
        clean: "Run APT and cache cleanup."
        arpt: "Parse and list ARP table entries."
        ff: "Search files by name system-wide."
        serv: "Show service active/inactive status."
        dls: "List disk partitions via lsblk."
        fixu: "Format disk with wipefs + vfat."
        yrs: "Scan a file with YARA rules."
        rware: "List/monitor ransomware victim feed."
        pls: "Fetch proxy list with geo/ISP info."
        crt: "Enumerate subdomains via crt.sh."
        rip: "Run reverse IP lookup."
        dchr: "Query DNS history (A records)."
        gf: "Extract href file names from open directory."
        triage: "Fetch tria.ge reports and C2/config summary."
    }

    let samples = {
        chkbgp: "chkbgp 8.8.8.8"
        ipinfo: "ipinfo 8.8.8.8"
        vt: "vt 44d88612fea8a8f36de82e1278abb02f"
        iocall: "iocall evil.example.com"
        abuse: "abuse 45.83.12.9"
        otx: "otx agenttesla"
        hs: "hs --path /tmp/share"
        catt: "catt configs/config.nu"
        ifc: "ifc"
        sd: "sd"
        lsv: "lsv"
        lsl: "lsl"
        dosh: "dosh ubuntu:24.04"
        drmi: "drmi <image_id>"
        aget: "aget nmap"
        arem: "arem nmap"
        netcon: "netcon"
        vrb: "vrb --cc TR"
        haus: "haus normal --limit 20"
        tfox: "tfox --dtype url"
        hx: "hx subdomains.txt"
        pdsc: "pdsc nuclei"
        hlp: "hlp -v"
        shx: "shx example.com"
        bdc: "bdc SGVsbG8="
        defang: "defang https://evil.example.com/path"
        refang: "refang hxxps://evil[.]example[.]com/path"
        hashf: "hashf suspicious.bin"
        hdns: "hdns suspicious-domain.com"
        "windows-evt-hunt": "windows-evt-hunt --log Security --event-id 4625 --since-hours 24"
        "persist-hunt": "persist-hunt --contains cron --limit 50"
        "proc-hunt": "proc-hunt --min-score 2 --limit 50"
        "proc-dump": "proc-dump lsass --out-dir C:\\dumps"
        "log-hunt": "log-hunt \"failed password\" --since-hours 24 --limit 100"
        "timeline-lite": "timeline-lite /var/tmp --with-hash --limit 100"
        upc: "upc"
        clean: "clean"
        arpt: "arpt"
        ff: "ff sshd_config"
        serv: "serv"
        dls: "dls"
        fixu: "fixu /dev/sdb1"
        yrs: "yrs suspicious.bin"
        rware: "rware tr --limit 20"
        pls: "pls"
        crt: "crt example.com"
        rip: "rip 1.1.1.1"
        dchr: "dchr example.com"
        gf: "gf https://example.com/open/"
        triage: "triage --family remcos --limit 3"
    }

    let examples = {
        chkbgp: [
            "chkbgp 8.8.8.8            # ASN / prefix / RIR details for an IP"
        ]
        ipinfo: [
            "ipinfo 8.8.8.8           # geo + ISP/ASN + reverse DNS"
            "ipinfo example.com       # resolve + enrich a hostname"
        ]
        vt: [
            "vt aadfc11ee472ecd3e8dae7acde9233dac75acfa7   # hash -> ThreatFox + Cymru MHR"
            "vt 160.20.109.75                     # ip -> ThreatFox + DShield + geo"
            "vt evil.example.com                  # domain -> ThreatFox + urlscan.io"
            "vt https://evil.example.com/x --type url   # force type when auto-detect is wrong"
        ]
        iocall: [
            "iocall 160.20.109.75             # ip: score + VT engines + DNSBL + ports + related domains + C2"
            "iocall evil.example.com          # domain: rep + VT + DNS + rdap + subdomains + IP geo/DNSBL"
            "iocall https://bad.site/payload  # url: rep + host VT/DNS/geo + defanged"
            "iocall <sha256>                  # hash: ThreatFox + Cymru + CIRCL + VT engines"
            "iocall 160.20.109.75 --skip-ports  # skip the TCP port scan (faster)"
            "iocall evil.example.com --json   # structured record (pipe/export)"
        ]
        abuse: [
            "abuse 45.83.12.9         # IP reputation via ISC SANS DShield"
        ]
        otx: [
            "otx agenttesla           # by malware family name (full export)"
            "otx 45.83.12.9           # by IP/domain/url substring"
            "otx cobaltstrike --cc TR # only Turkey-based C2s"
            "otx remcos --recent      # fast, recent feed only"
            "otx --refresh            # just refresh the cached full export"
        ]
        hs: [
            "hs                       # serve current dir on :8000"
            "hs --path /tmp/share     # serve a specific folder"
        ]
        catt: [
            "catt configs/config.nu   # print a file with syntax highlighting"
        ]
        ifc: [ "ifc                      # list network interfaces + addresses" ]
        sd: [ "sd                       # list disks (size, model, mount)" ]
        lsv: [ "lsv                      # ls sorted by size (biggest last)" ]
        lsl: [ "lsl                      # ls sorted by modified time + mime" ]
        dosh: [ "dosh ubuntu:24.04        # drop into bash inside an image" ]
        drmi: [ "drmi 3a1b2c4d5e6f        # force-remove an image by id" ]
        aget: [ "aget nmap                # install a package (apt / winget)" ]
        arem: [ "arem nmap                # remove a package (apt / winget)" ]
        netcon: [ "netcon                   # IPv4 connections + listening ports" ]
        vrb: [
            "vrb                      # latest 50 C2 panels (Viriback)"
            "vrb --cc TR              # only Turkey-based C2 panels"
        ]
        haus: [
            "haus normal --limit 20              # newest 20 malware URLs"
            "haus --host-only --contains in.net --limit 10   # unique hosts matching a string"
            "haus --host-ends-with .tr --host-only --limit 20 # only .tr hosts"
            "haus online --cc TR --host-only     # only IOCs geolocated to Turkey"
        ]
        tfox: [
            "tfox --dtype url         # recent IOC URLs only"
            "tfox --dtype all         # full records (malware, tags, refs)"
            "tfox --dtype all --cc TR # only Turkey-based IOCs"
        ]
        hx: [
            "hx subdomains.txt        # httpx probe a list (status/title/tech)"
        ]
        pdsc: [
            "pdsc nuclei              # go install a ProjectDiscovery tool"
            "pdsc subfinder"
        ]
        hlp: [
            "hlp                      # list all project commands"
            "hlp -v                   # verbose: usage + params for each"
            "hlp otx                  # full detail + examples for one command"
        ]
        shx: [ "shx example.com          # subfinder | httpx (live subdomains)" ]
        bdc: [
            "bdc SGVsbG8=             # base64 decode"
            "bdc -e 'Hello World'     # base64 encode"
        ]
        defang: [
            "defang https://evil.example.com/x   # -> hxxps://evil[.]example[.]com/x"
        ]
        refang: [
            "refang hxxps://evil[.]example[.]com # -> https://evil.example.com"
        ]
        hashf: [
            "hashf suspicious.bin     # md5 + sha1 + sha256 + size of a file"
        ]
        hdns: [
            "hdns suspicious-domain.com  # pivot to related C2 domains (hedns)"
        ]
        "windows-evt-hunt": [
            "windows-evt-hunt --log Security --event-id 4625 --since-hours 24   # failed logons"
            "windows-evt-hunt --log System --contains error --since-hours 12"
        ]
        "persist-hunt": [
            "persist-hunt                    # dump autostart/persistence points"
            "persist-hunt --contains cron --limit 50   # filter by keyword"
        ]
        "proc-hunt": [
            "proc-hunt                       # score all processes"
            "proc-hunt --min-score 2 --limit 50   # only suspicious ones"
            "proc-hunt --contains powershell"
        ]
        "proc-dump": [
            "proc-dump lsass --out-dir C:\\dumps          # full memory dump (Windows)"
            "proc-dump notepad.exe --out-dir C:\\dumps --mini"
            "proc-dump 4242 --out-dir C:\\dumps --full    # by PID"
        ]
        "log-hunt": [
            "log-hunt                        # scan auth/syslog for common IOCs"
            "log-hunt \"failed password\" --since-hours 24 --limit 100"
        ]
        "timeline-lite": [
            "timeline-lite /var/tmp                     # files by mtime"
            "timeline-lite /var/tmp --with-hash --limit 100   # add sha256"
        ]
        upc: [ "upc                      # pull latest config.nu from GitHub" ]
        clean: [ "clean                    # apt autoremove/autoclean + cache purge" ]
        arpt: [ "arpt                     # ARP/neighbor table (IP + MAC + iface)" ]
        ff: [
            "ff sshd_config           # find a file by name, system-wide"
            "ff .env"
        ]
        serv: [ "serv                     # active/inactive status of services" ]
        dls: [ "dls                      # list block devices/partitions (lsblk)" ]
        fixu: [
            "fixu /dev/sdb1           # WIPE + format a USB as FAT32 (careful!)"
        ]
        yrs: [
            "yrs suspicious.bin       # YARA-scan a file (auto-fetches rules)"
        ]
        rware: [
            "rware                    # global recent ransomware victims"
            "rware tr --limit 20      # victims in a country"
            "rware tr --monitor --interval 30 --max-cycles 20   # live watch"
        ]
        pls: [
            "pls                      # proxy list with geo/ISP"
            "pls --cc TR              # only Turkish proxies"
        ]
        crt: [ "crt example.com          # subdomains from crt.sh (fast, no httpx)" ]
        rip: [ "rip 1.1.1.1              # reverse-IP: other domains on that host" ]
        dchr: [ "dchr example.com         # historical A records for a domain" ]
        gf: [ "gf https://example.com/open/   # list file names in an open dir" ]
        triage: [
            "triage --family remcos --limit 3          # recent reports for a family"
            "triage --family agenttesla --limit 5"
            "triage --query \"sha256:...\" --limit 1 | get 0.MalwareConfig   # pull config"
            "triage --query \"sha1:...\" --limit 3 --no-c2 --no-config"
        ]
    }

    let tracked_names = ($samples | columns)
    let format_usage_part = { |param: record|
        let is_option = ($param.name | str starts-with "--")
        if $is_option {
            if $param.type == "switch" {
                if $param.required { $param.name } else { $"[($param.name)]" }
            } else {
                if $param.required { $"($param.name) <($param.type)>" } else { $"[($param.name) <($param.type)>]" }
            }
        } else {
            if $param.required { $"<($param.name):($param.type)>" } else { $"[($param.name):($param.type)]" }
        }
    }

    let commands = (help commands
        | where command_type =~ "custom"
        | where { |cmd| ($tracked_names | any { |n| $n == $cmd.name }) }
        | each { |cmd|
            let command_params = ($cmd.params | where { |p| ($p.name | str starts-with "--help") == false })
            let usage_parts = ($command_params | each { |p| do $format_usage_part $p })
            let usage_text = (([$cmd.name] | append $usage_parts) | str join " ")
            let params_detail = (if (($command_params | length) == 0) {
                "-"
            } else {
                $command_params
                | each { |p| if $p.required { $"($p.name)*" } else { $p.name } }
                | str join ", "
            })
            let summary_text = (try {
                $summaries | get $cmd.name
            } catch {
                let raw_desc = ($cmd.description | str trim)
                if (($raw_desc | str length) > 60) {
                    $"(($raw_desc | str substring 0..57))..."
                } else {
                    $raw_desc
                }
            })
            let sample_text = (try { $samples | get $cmd.name } catch { "-" })
            $cmd | merge { usage: $usage_text, params_detail: $params_detail, sample: $sample_text, summary: $summary_text }
        }
        | sort-by name)

    if $command != null {
        let selected = ($commands | where { |c| $c.name == $command })
        if (($selected | length) == 0) {
            error make { msg: $"Unknown command: ($command). Use 'hlp' to list available project commands." }
        }
        let cmd = ($selected | first)
        let cmd_examples = (try { $examples | get $cmd.name } catch { [$cmd.sample] })
        let cmd_params = ($cmd.params | where { |p| ($p.name | str starts-with "--help") == false } | select name type required description)
        let example_lines = (if (($cmd_examples | length) == 0) {
            "  - -"
        } else {
            $cmd_examples | each { |ex| $"  - ($ex)" } | str join "\n"
        })
        let param_lines = (if (($cmd_params | length) == 0) {
            "  - -"
        } else {
            $cmd_params | each { |p|
                let req = (if $p.required { "required" } else { "optional" })
                $"  - ($p.name) <($p.type)> [($req)] :: ($p.description)"
            } | str join "\n"
        })

        $"
name: ($cmd.name)
description: ($cmd.description)
usage: ($cmd.usage)
sample: ($cmd.sample)
examples:
($example_lines)
params:
($param_lines)"
    } else if $verbose {
        ($commands
            | each { |cmd|
                $"
($cmd.name)
  desc: ($cmd.description)
  usage: ($cmd.usage)
  sample: ($cmd.sample)
  params: ($cmd.params_detail)"
            }
            | str join "\n\n")
    } else {
        $commands | select name summary sample | rename name description sample
    }
}

# Enumerate subdomains using subfinder/httpx combination
def shx [target_domain: string] {
    subfinder -silent -d $target_domain | httpx -silent -mc 200 -sc -title -td
}

# Base64 decode/encode (native, cross-platform)
def bdc [pattern: string, --encode (-e)] {
    if $encode {
        $pattern | encode base64
    } else {
        $pattern | decode base64 | decode
    }
}

# Defang IOCs so URLs/IPs/domains are safe to paste in reports/chats
def defang [ioc: string] {
    $ioc
    | str replace --all "https://" "hxxps://"
    | str replace --all "http://" "hxxp://"
    | str replace --all "." "[.]"
    | str replace --all "@" "[@]"
}

# Refang defanged IOCs back into their original form
def refang [ioc: string] {
    $ioc
    | str replace --all "[.]" "."
    | str replace --all "(.)" "."
    | str replace --all "[@]" "@"
    | str replace --all "[:]" ":"
    | str replace --all "hxxps://" "https://"
    | str replace --all "hxxp://" "http://"
    | str replace --all "hxxps" "https"
    | str replace --all "hxxp" "http"
}

# Compute file hashes (md5/sha256 native, sha1 via sha1sum when present)
def hashf [target_file: string] {
    if (($target_file | path exists) == false) {
        error make { msg: $"File not found: ($target_file)" }
    }
    if ((try { $target_file | path type } catch { "other" }) != "file") {
        error make { msg: $"Not a file: ($target_file)" }
    }

    let bytes = (open --raw $target_file)
    let sha1 = (try {
        let out = (^sha1sum $target_file | complete)
        if $out.exit_code == 0 {
            $out.stdout | str trim | split row " " | first
        } else {
            "-"
        }
    } catch {
        "-"
    })

    {
        file: $target_file
        size: (ls $target_file | get 0.size)
        md5: ($bytes | hash md5)
        sha1: $sha1
        sha256: ($bytes | hash sha256)
    }
}

# Normalize parsed JSON output to a list of records
def normalize-json-rows [parsed_value: any] {
    let parsed_desc = ($parsed_value | describe)
    if ($parsed_desc | str starts-with "record") {
        [$parsed_value]
    } else if (($parsed_desc | str starts-with "list") or ($parsed_desc | str starts-with "table")) {
        $parsed_value
    } else {
        []
    }
}

# Execute PowerShell and always return decoded text output
def powershell-text [command_text: string] {
    let has_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | where type == "external" | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    # Force UTF-8 output from PowerShell to avoid mojibake on Turkish locales.
    let prelude = "$OutputEncoding = [System.Text.UTF8Encoding]::new($false); [Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false); [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)"
    let full_command = $"($prelude); ($command_text)"

    let raw = if (do $has_cmd "pwsh") {
        (pwsh -NoProfile -NonInteractive -Command $full_command)
    } else {
        (powershell -NoProfile -NonInteractive -Command $full_command)
    }
    let raw_desc = ($raw | describe)

    if ($raw_desc | str starts-with "binary") {
        let utf8_decoded = (try {
            $raw | decode utf-8
        } catch {
            (try {
                $raw | decode utf-16
            } catch {
                (try {
                    $raw | decode cp1254
                } catch {
                    ""
                })
            })
        })

        if ($utf8_decoded | str contains "�") {
            (try {
                $raw | decode cp1254
            } catch {
                $utf8_decoded
            })
        } else {
            $utf8_decoded
        }
    } else if (($raw_desc | str starts-with "list") or ($raw_desc | str starts-with "table")) {
        ($raw | each { |line| $line | into string } | str join "\n")
    } else {
        (try {
            $raw | into string
        } catch {
            ""
        })
    }
}

# Hunt suspicious Windows events quickly
def windows-evt-hunt [
    --log: string = "Security"  # Security | System | Application
    --event-id: int             # Optional exact EventID filter
    --contains: string          # Optional case-insensitive keyword filter for Message
    --since-hours: int = 24     # Search window in hours
    --limit: int = 200          # Max returned rows
] {
    let is_windows = (($nu.os-info.name | str lowercase) == "windows")
    if ($is_windows == false) {
        error make { msg: "windows-evt-hunt can only run on Windows." }
    }

    let safe_log = ($log | str trim)
    if $safe_log == "" {
        error make { msg: "--log cannot be empty." }
    }

    let safe_contains = if $contains != null {
        ($contains | str replace --all "'" "''")
    } else {
        null
    }

    mut ps_lines = [
        "$ErrorActionPreference = 'SilentlyContinue'"
        ("$start = (Get-Date).AddHours(-" + ($since_hours | into string) + ")")
        ("$events = Get-WinEvent -FilterHashtable @{LogName='" + $safe_log + "'; StartTime=$start}")
    ]

    if $event_id != null {
        $ps_lines ++= [("$events = $events | Where-Object { $_.Id -eq " + ($event_id | into string) + " }")]
    }

    if $safe_contains != null {
        $ps_lines ++= [("$events = $events | Where-Object { $_.Message -like '*" + $safe_contains + "*' }")]
    }

    $ps_lines ++= [("$events | Sort-Object TimeCreated -Descending | Select-Object -First " + ($limit | into string) + " @{Name='TimeCreated';Expression={ if ($_.TimeCreated) { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { '' } }}, Id, LevelDisplayName, ProviderName, MachineName, Message | ConvertTo-Json -Depth 4")]

    let raw = (powershell-text ($ps_lines | str join "; "))
    if (($raw | str trim) == "") {
        []
    } else {
        let parsed = (try { $raw | from json } catch { [] })
        normalize-json-rows $parsed
    }
}

# Hunt persistence artifacts on Linux/Windows
def persist-hunt [
    --contains: string  # Optional case-insensitive keyword filter
    --limit: int = 300  # Max returned rows
] {
    let is_windows = (($nu.os-info.name | str lowercase) == "windows")
    let keyword = if $contains != null { ($contains | str lowercase | str trim) } else { null }

    if $is_windows {
        let safe_keyword = if $keyword != null {
            ($keyword | str replace --all "'" "''")
        } else {
            null
        }

        mut ps_lines = [
            "$ErrorActionPreference = 'SilentlyContinue'"
            "$items = @()"
            "$runPaths = @('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run')"
            "foreach ($p in $runPaths) { if (Test-Path $p) { $props = Get-ItemProperty -Path $p; foreach ($prop in $props.PSObject.Properties) { if ($prop.Name -notmatch '^PS') { $items += [PSCustomObject]@{ category='registry-run'; location=$p; name=$prop.Name; value=[string]$prop.Value } } } } }"
            "$startupDirs = @(\"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\", \"$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\")"
            "foreach ($d in $startupDirs) { if (Test-Path $d) { Get-ChildItem -Path $d -Force | ForEach-Object { $items += [PSCustomObject]@{ category='startup-folder'; location=$_.FullName; name=$_.Name; value=$_.FullName } } } }"
            "$tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } | Select-Object TaskName, TaskPath, State"
            "foreach ($t in $tasks) { $items += [PSCustomObject]@{ category='scheduled-task'; location=$t.TaskPath; name=$t.TaskName; value=[string]$t.State } }"
        ]

        if $safe_keyword != null {
            $ps_lines ++= [("$items = $items | Where-Object { (($_.location + ' ' + $_.name + ' ' + $_.value).ToLower()) -like '*" + $safe_keyword + "*' }")]
        }

        $ps_lines ++= [("$items | Select-Object -First " + ($limit | into string) + " | ConvertTo-Json -Depth 4")]
        let raw = (powershell-text ($ps_lines | str join "; "))
        if (($raw | str trim) == "") {
            []
        } else {
            let parsed = (try { $raw | from json } catch { [] })
            let parsed_desc = ($parsed | describe)
            if ($parsed_desc | str starts-with "record") {
                [$parsed]
            } else if ($parsed_desc | str starts-with "list") {
                $parsed
            } else {
                []
            }
        }
    } else {
        let candidates = [
            "/etc/crontab"
            "/etc/cron.d/*"
            "/etc/cron.daily/*"
            "/etc/cron.hourly/*"
            "/etc/cron.weekly/*"
            "/etc/cron.monthly/*"
            "/etc/systemd/system/*.service"
            "/etc/systemd/system/*.timer"
            "/lib/systemd/system/*.service"
            $"($env.HOME)/.config/systemd/user/*.service"
            $"($env.HOME)/.config/autostart/*.desktop"
            "/etc/rc.local"
            $"($env.HOME)/.bashrc"
            $"($env.HOME)/.profile"
            $"($env.HOME)/.zshrc"
        ]

        mut rows = []
        for pattern in $candidates {
            let matches = (try { glob $pattern } catch { [] })
            for path_item in $matches {
                if (($path_item | path exists) == false) {
                    continue
                }
                if ((try { $path_item | path type } catch { "other" }) != "file") {
                    continue
                }

                let path_text = ($path_item | into string)
                let lc_path = ($path_text | str lowercase)
                let category = if ($lc_path | str contains "/cron") {
                    "cron"
                } else if ($lc_path | str contains "systemd") {
                    "systemd"
                } else if ($lc_path | str contains "autostart") {
                    "autostart"
                } else if ($lc_path | str ends-with "rc.local") {
                    "rc-local"
                } else if (($lc_path | str ends-with ".bashrc") or ($lc_path | str ends-with ".profile") or ($lc_path | str ends-with ".zshrc")) {
                    "shell-init"
                } else {
                    "persistence-file"
                }

                let clue = (try {
                    open $path_item
                    | lines
                    | each { |line| $line | str trim }
                    | where { |line| $line != "" and (($line | str starts-with "#") == false) and (($line | str starts-with ";") == false) }
                    | first
                } catch {
                    "-"
                })

                let matches_keyword = if $keyword == null {
                    true
                } else {
                    (($path_text | str lowercase | str contains $keyword) or ($clue | str lowercase | str contains $keyword))
                }

                if $matches_keyword {
                    let meta = (try { ls -a $path_item | first } catch { null })
                    if $meta != null {
                        $rows ++= [{
                            category: $category
                            path: $path_text
                            modified: (try { $meta.modified } catch { null })
                            size: (try { $meta.size } catch { 0 })
                            clue: $clue
                        }]
                    }
                }
            }
        }

        let out = ($rows | sort-by modified -r)
        if $limit > 0 { $out | first $limit } else { $out }
    }
}

# Score suspicious running processes
def proc-hunt [
    --contains: string  # Optional case-insensitive keyword filter
    --min-score: int = 1 # Minimum heuristic score to keep
    --limit: int = 200   # Max returned rows
] {
    let is_windows = (($nu.os-info.name | str lowercase) == "windows")
    let needle = if $contains != null { ($contains | str lowercase | str trim) } else { null }

    let process_rows = if $is_windows {
        let raw = (powershell-text "Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine | ConvertTo-Json -Depth 4")
        let parsed = (try { $raw | from json } catch { [] })
        let rows = (normalize-json-rows $parsed)

        $rows | each { |p|
            {
                pid: (try { $p.ProcessId | into int } catch { 0 })
                ppid: (try { $p.ParentProcessId | into int } catch { 0 })
                user: "-"
                name: (try { $p.Name | into string } catch { "-" })
                cmdline: (try { $p.CommandLine | into string } catch { "" })
            }
        }
    } else {
        let raw = (^ps -eo pid=,ppid=,user=,comm=,args=)
        $raw
        | lines
        | parse --regex '^\s*(?<pid>\d+)\s+(?<ppid>\d+)\s+(?<user>\S+)\s+(?<name>\S+)\s*(?<cmdline>.*)$'
        | each { |p|
            {
                pid: (try { $p.pid | into int } catch { 0 })
                ppid: (try { $p.ppid | into int } catch { 0 })
                user: (try { $p.user | into string } catch { "-" })
                name: (try { $p.name | into string } catch { "-" })
                cmdline: (try { $p.cmdline | into string } catch { "" })
            }
        }
    }

    let scored = ($process_rows | each { |proc|
        let cmd = ($proc.cmdline | str lowercase)
        mut score = 0
        mut reasons = []

        if ($cmd =~ '(/tmp/|/dev/shm/)') {
            $score = ($score + 2)
            $reasons ++= ["temp-exec-path"]
        }
        if ($cmd =~ '(curl|wget).*(http|https)') {
            $score = ($score + 2)
            $reasons ++= ["download-behavior"]
        }
        if ($cmd =~ '(powershell.+-enc|encodedcommand|frombase64string|base64 -d)') {
            $score = ($score + 3)
            $reasons ++= ["encoded-payload"]
        }
        if ($cmd =~ '(certutil|mshta|rundll32|regsvr32)') {
            $score = ($score + 2)
            $reasons ++= ["lolbin-usage"]
        }
        if ($cmd =~ '(nc |ncat |socat |reverse shell|/dev/tcp/)') {
            $score = ($score + 3)
            $reasons ++= ["shell-tunneling"]
        }
        if (($proc.name | str lowercase) =~ '(python|bash|sh|powershell|cmd|wscript|cscript)') and ($cmd =~ '(http://|https://)') {
            $score = ($score + 1)
            $reasons ++= ["script-with-url"]
        }

        let matches_needle = if $needle == null {
            true
        } else {
            ((($proc.name | str lowercase) | str contains $needle) or ($cmd | str contains $needle))
        }

        if ($score >= $min_score and $matches_needle) {
            {
                pid: $proc.pid
                ppid: $proc.ppid
                user: $proc.user
                name: $proc.name
                score: $score
                reasons: ($reasons | str join ", ")
                cmdline: $proc.cmdline
            }
        } else {
            null
        }
    } | where { |item| $item != null } | sort-by score -r)

    if $limit > 0 { $scored | first $limit } else { $scored }
}

# Dump a running process with Sysinternals ProcDump (Windows only)
def proc-dump [
    target: string             # Process name (e.g. lsass) or PID
    --out-dir: string = "."    # Output directory for dump file
    --full (-f)                # Full dump (-ma)
    --mini (-m)                # Mini dump (-mp)
    --wait (-w)                # Wait for process if not running yet
    --count (-n): int = 1      # Number of dumps to capture
    --name: string             # Optional dump filename (defaults to auto-generated)
] {
    let is_windows = (($nu.os-info.name | str lowercase) == "windows")
    if ($is_windows == false) {
        error make { msg: "proc-dump can only run on Windows." }
    }

    if (($target | str trim) == "") {
        error make { msg: "target cannot be empty." }
    }

    let normalized_target = ($target | str trim)

    let has_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | where type == "external" | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    let install_dir = ([$env.HOME ".nusecurity" "tools" "procdump"] | path join)
    let local64 = ([$install_dir "procdump64.exe"] | path join)
    let local32 = ([$install_dir "procdump.exe"] | path join)

    mut procdump_cmd = ""
    if (do $has_cmd "procdump64.exe") {
        $procdump_cmd = "procdump64.exe"
    } else if (do $has_cmd "procdump.exe") {
        $procdump_cmd = "procdump.exe"
    } else if (do $has_cmd "procdump64") {
        $procdump_cmd = "procdump64"
    } else if (do $has_cmd "procdump") {
        $procdump_cmd = "procdump"
    } else if ($local64 | path exists) {
        $procdump_cmd = ($local64 | into string)
    } else if ($local32 | path exists) {
        $procdump_cmd = ($local32 | into string)
    }

    if $procdump_cmd == "" {
        let install_dir_text = ($install_dir | into string)
        let safe_install_dir = ($install_dir_text | str replace --all "'" "''")
        print $"(ansi cyan_bold)[proc-dump](ansi reset) ProcDump not found. Downloading to: (ansi green_bold)($install_dir_text)(ansi reset)"

        let bootstrap_lines = [
            "$ErrorActionPreference = 'Stop'"
            ("$installDir = '" + $safe_install_dir + "'")
            "$zipPath = Join-Path $installDir 'Procdump.zip'"
            "$url = 'https://download.sysinternals.com/files/Procdump.zip'"
            "New-Item -ItemType Directory -Path $installDir -Force | Out-Null"
            "Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zipPath"
            "Expand-Archive -Path $zipPath -DestinationPath $installDir -Force"
            "Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue"
        ]

        try {
            powershell-text ($bootstrap_lines | str join "; ") | ignore
        } catch {
            error make { msg: "Auto-install failed. Install Sysinternals ProcDump manually or check internet access." }
        }

        if ($local64 | path exists) {
            $procdump_cmd = ($local64 | into string)
        } else if ($local32 | path exists) {
            $procdump_cmd = ($local32 | into string)
        } else {
            error make { msg: "ProcDump download completed but executable not found." }
        }
    }

    if ($count < 1) {
        error make { msg: "--count must be >= 1." }
    }

    if ($full and $mini) {
        error make { msg: "Use only one dump mode: --full or --mini." }
    }

    if (($out_dir | path exists) == false) {
        mkdir $out_dir
    } else if ((try { $out_dir | path type } catch { "other" }) != "dir") {
        error make { msg: $"--out-dir is not a directory: ($out_dir)" }
    }

    let mode_flag = if $mini { "-mp" } else { "-ma" }
    let timestamp = (date now | format date "%Y%m%d_%H%M%S")
    let default_name = $"($normalized_target)_($timestamp).dmp"
    let dump_name = if $name != null and (($name | str trim) != "") {
        ($name | str trim)
    } else {
        $default_name
    }
    let dump_path = ([$out_dir $dump_name] | path join)

    mut args = ["-accepteula" $mode_flag]
    if $wait {
        $args ++= ["-w"]
    }
    if $count > 1 {
        $args ++= ["-n" ($count | into string)]
    }
    $args ++= [$normalized_target $dump_path]

    run-external $procdump_cmd ...$args

    {
        tool: $procdump_cmd
        target: $normalized_target
        mode: (if $mini { "mini" } else { "full" })
        output: $dump_path
        count: $count
    }
}
# Hunt suspicious log lines quickly
def log-hunt [
    pattern?: string      # Optional keyword/regex-like text match (case-insensitive contains)
    --since-hours: int = 24 # Journal/Event lookback in hours
    --limit: int = 300      # Max returned rows
] {
    let is_windows = (($nu.os-info.name | str lowercase) == "windows")
    let default_pattern = "failed password|authentication failure|invalid user|sudo:|powershell|cmd.exe|wget|curl|base64|rundll32|mshta|certutil"
    let needle = if $pattern != null { ($pattern | str trim | str lowercase) } else { null }
    let auth_failure_hint = if $needle == null {
        true
    } else {
        $needle =~ "(failed password|authentication failure|invalid user|logon fail|login fail|oturum a[cç]ama|hesap oturum a[cç]amad[ıi])"
    }

    if $is_windows {
        let safe_pattern = if $pattern != null {
            ($pattern | str replace --all "'" "''")
        } else {
            $default_pattern
        }

        mut ps = [
            "$ErrorActionPreference = 'SilentlyContinue'"
            ("$start = (Get-Date).AddHours(-" + ($since_hours | into string) + ")")
            "$events = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$start} -ErrorAction SilentlyContinue"
            "$events += Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$start} -ErrorAction SilentlyContinue"
            "$events += Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$start} -ErrorAction SilentlyContinue"
        ]

        if $auth_failure_hint {
            $ps ++= [("$events = $events | Where-Object { ($_.Id -eq 4625) -or ($_.Message -match '(?i)" + $safe_pattern + "') }")]
        } else {
            $ps ++= [("$events = $events | Where-Object { $_.Message -match '(?i)" + $safe_pattern + "' }")]
        }

        $ps ++= [
            "$events = $events | Sort-Object TimeCreated -Descending | Select-Object @{Name='TimeCreated';Expression={ if ($_.TimeCreated) { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { '' } }}, Id, LogName, ProviderName, Message"
            ("$events | Select-Object -First " + ($limit | into string) + " | ConvertTo-Json -Depth 4")
        ]

        let raw = (powershell-text ($ps | str join "; "))
        if (($raw | str trim) == "") {
            []
        } else {
            let parsed = (try { $raw | from json } catch { [] })
            normalize-json-rows $parsed
        }
    } else {
        let has_journalctl = (try {
            let cmd_paths = (which --all journalctl | where type == "external" | get path)
            (($cmd_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })

        let file_candidates = [
            "/var/log/auth.log"
            "/var/log/secure"
            "/var/log/syslog"
            "/var/log/messages"
        ]

        mut rows = []
        for log_file in $file_candidates {
            if (($log_file | path exists) == false) {
                continue
            }

            let found = (try {
                open $log_file
                | lines
                | enumerate
                | where { |row|
                    let line = ($row.item | str lowercase)
                    if $needle != null {
                        $line | str contains $needle
                    } else {
                        $line =~ $default_pattern
                    }
                }
                | each { |row|
                    {
                        source: $log_file
                        line: ($row.index + 1)
                        message: ($row.item | str trim)
                    }
                }
            } catch {
                []
            })
            $rows = ($rows | append $found)
        }

        if $has_journalctl {
            let journal_lines = (try {
                journalctl --since $"($since_hours) hours ago" --no-pager
                | lines
                | where { |line|
                    let lc = ($line | str lowercase)
                    if $needle != null {
                        $lc | str contains $needle
                    } else {
                        $lc =~ $default_pattern
                    }
                }
                | each { |line| { source: "journalctl", line: "-", message: ($line | str trim) } }
            } catch {
                []
            })
            $rows = ($rows | append $journal_lines)
        }

        if $limit > 0 { $rows | first $limit } else { $rows }
    }
}

# Build a quick file timeline for a directory
def timeline-lite [
    target_path?: string = "."  # Directory to timeline
    --contains: string          # Optional path keyword filter
    --limit: int = 300          # Max returned rows
    --with-hash                 # Include SHA256 (slower)
] {
    if (($target_path | path exists) == false) {
        error make { msg: $"Path not found: ($target_path)" }
    }

    let needle = if $contains != null { ($contains | str lowercase | str trim) } else { null }
    mut files = (glob $"($target_path)/**")
    $files = ($files | where { |entry| (try { ($entry | path type) == "file" } catch { false }) })

    if $needle != null {
        $files = ($files | where { |entry| (($entry | into string | str lowercase) | str contains $needle) })
    }

    let rows = ($files | each { |entry|
        let meta = (try { ls -a $entry | first } catch { null })
        if $meta == null {
            null
        } else {
            let digest = if $with_hash {
                (try { open --raw $entry | hash sha256 } catch { "-" })
            } else {
                "-"
            }

            {
                path: ($entry | into string)
                size: (try { $meta.size } catch { 0 })
                modified: (try { $meta.modified } catch { null })
                created: (try { $meta.created } catch { null })
                sha256: $digest
            }
        }
    } | where { |item| $item != null } | sort-by modified -r)

    if $limit > 0 { $rows | first $limit } else { $rows }
}

# Hunt possible C2 domains using hednsextractor
def hdns [target_domain: string] {
    let has_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    if (($target_domain | str trim) == "") {
        error make { msg: "Target domain cannot be empty." }
    }
    if ((do $has_cmd "hednsextractor") == false) {
        if ((do $has_cmd "go") == false) {
            error make { msg: "Go is not installed. Please install Go first." }
        }
        print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Installing: (ansi green_bold)hednsextractor(ansi reset)"
        go install -v github.com/HuntDownProject/hednsextractor/cmd/hednsextractor@latest
    }
    echo $target_domain | hednsextractor -silent -only-domains
}

# Get latest config.nu from repository
def upc [] {
    try {
        http get https://raw.githubusercontent.com/CYB3RMX/NuSecurity/refs/heads/main/configs/config.nu | save -f $nu.config-path
        print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Config updated successfully! Restart Nu shell to apply changes."
    } catch {
        error make { msg: "Unable to fetch latest config from GitHub." }
    }
}

#System Cleaner
def clean [] {
    let is_windows = (($nu.os-info.name | str lowercase) == "windows")
    let has_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    let confirm = (input $"(ansi red_bold)System cache will be cleaned. Are you sure? [Y/n]: (ansi reset)" | str trim | str lowercase)
    if $confirm == "y" or $confirm == "" {
        if $is_windows {
            if (do $has_cmd "powershell") {
                powershell -NoProfile -Command 'Get-ChildItem -Path $env:TEMP -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue'
            } else {
                error make { msg: "powershell not found in PATH." }
            }
        } else {
            sudo apt autoremove -y
            sudo apt autoclean -y
            sudo rm -rf ~/.cache/*
        }
        echo "System Cleaned!"
    } else {
        echo "Operation cancelled."
    }
}

# Get ARP/neighbor table with style!
def arpt [] {
    let is_windows = (($nu.os-info.name | str lowercase) == "windows")
    let has_external_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | where type == "external" | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    if $is_windows {
        arp -a
        | lines
        | parse --regex '\s*(?<IP_Address>(?:[0-9]{1,3}\.){3}[0-9]{1,3})\s+(?<MAC_Address>[0-9a-fA-F-]{11,17})\s+(?<Type>\w+)'
    } else if (do $has_external_cmd "ip") {
        ip neigh
        | lines
        | parse --regex '^(?<IP_Address>\S+)\s+dev\s+(?<Interface>\S+)(?:\s+lladdr\s+(?<MAC_Address>\S+))?.*\s(?<State>\S+)\s*$'
        | where { |row| ($row.MAC_Address? | default "") != "" }
    } else if (do $has_external_cmd "arp") {
        arp -a | lines | split column " " | select column2 column4 column5 column7 | rename IP_Address MAC_Address Proto Interface
    } else {
        error make { msg: "No ARP source found (need 'ip' or 'arp')." }
    }
}

# Search for target file in the system
def ff [target_file: string] {
    let is_windows = (($nu.os-info.name | str lowercase) == "windows")
    let has_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }
    let has_external_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | where type == "external" | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    if $is_windows {
        let matches = (glob $"**/*($target_file)*" | where { |entry| ($entry | path type) == "file" })
        $matches
        return
    }

    if (do $has_external_cmd "fdfind") {
        fdfind -H --glob -t f $target_file / | lines
    } else {
        if (do $has_cmd "apt") and (do $has_cmd "sudo") {
            print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi red_bold) fd-find not found, installing automatically...(ansi reset)"
            aget fd-find
        }

        if (do $has_external_cmd "fdfind") {
            fdfind -H --glob -t f $target_file / | lines
        } else {
            print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi yellow_bold) Falling back to recursive glob in current directory(ansi reset)"
            glob $"**/*($target_file)*" | where { |entry| ($entry | path type) == "file" }
        }
    }
}

# List active and inactive services
def serv [] {
    let is_windows = (($nu.os-info.name | str lowercase) == "windows")
    if $is_windows {
        powershell -NoProfile -Command 'Get-Service | Select-Object Name,Status | Sort-Object Name'
        return
    }

    let services = (ls /etc/init.d/ | get name) 
    $services | each { |serv_path|
        let serv_name = ($serv_path | path basename | str trim)
        let status_output = (try { systemctl is-active $serv_name } catch { 'unknown' })
        if ($status_output == "active") {
            let status = $"(ansi green_bold)active(ansi reset)"
            { service: $serv_name, status: $status }
        } else {
            let status = $"(ansi red_bold)inactive(ansi reset)"
            { service: $serv_name, status: $status }
        }
    }
}

# List disk partitions (lsblk with style!)
def dls [] {
    let is_windows = (($nu.os-info.name | str lowercase) == "windows")
    let has_external_cmd = { |command: string|
        (try {
            let command_paths = (which --all $command | where type == "external" | get path)
            (($command_paths | where { |candidate| ($candidate | str trim) != "" and ($candidate | path exists) } | length) > 0)
        } catch {
            false
        })
    }

    if $is_windows {
        sys disks
    } else {
        if (do $has_external_cmd "lsblk") {
            lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT | detect columns
        } else {
            sys disks
        }
    }
}

# Format/fix USB or USB like devices
def fixu [target_disk: string] {
    let is_windows = (($nu.os-info.name | str lowercase) == "windows")
    if $is_windows {
        error make { msg: "fixu is disabled on Windows. Use Disk Management or diskpart carefully." }
    }

    print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Formatting: (ansi green_bold)($target_disk)(ansi reset)"
    sudo wipefs --all $target_disk
    sudo mkfs.vfat -F 32 $target_disk
    print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi green_bold) ($target_disk)(ansi reset) formatted successfully!"
}

# Perform YARA scan against the given file
def yrs [target_file: string] {
    # Check rules first!
    if (($"($env.HOME)/rules" | path exists) == true ) {
        print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Performing YARA scan against: (ansi green_bold)($target_file)(ansi reset) Please wait!"
        let rule_arr = (glob $"($env.HOME)/rules/**")
        mut matched_rules = []
        for rul in ($rule_arr) {
            if (($rul | str contains ".yar") == true) {
                try {
                    let rulz = (yara -w $rul $target_file | str replace --all $target_file "")
                    for rr in ($rulz) {
                        if (($matched_rules | to text | str contains $rr) == false) {
                            $matched_rules ++= [$rr]
                        }
                    }
                } catch {}
            }
        }
        $matched_rules | split row "\n" | uniq | table
    } else {
        print $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Downloading latest YARA rules from: (ansi green_bold)https://github.com/Yara-Rules/rules(ansi reset)"
        git clone https://github.com/Yara-Rules/rules $"($env.HOME)/rules"
        print $"\n(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Download complete. (ansi yellow_bold)You must re-execute the command!"
    }
}

# Fetch ransomware victims (country or global) with optional monitoring mode
def rware [
    country_code?: string   # Optional ISO country code (TR, US). If empty, uses global recent feed.
    --limit: int = 0        # Limit output rows (0 = unlimited)
    --monitor (-m)          # Poll feed continuously and print only new entries
    --interval: int = 30    # Monitor poll interval in seconds
    --max-cycles: int = 0   # Monitor loop count (0 = infinite)
] {
    let field = { |entry: record, field_name: string|
        if ($entry | columns | any { |column| $column == $field_name }) {
            (try { $entry | get $field_name | into string | str trim } catch { "" })
        } else {
            ""
        }
    }

    let first_nonempty = { |values: list<any>|
        (try {
            $values
            | each { |v| $v | into string | str trim }
            | where { |v| $v != "" }
            | first
        } catch {
            ""
        })
    }

    let entry_id = { |entry: record|
        let url_id = (do $first_nonempty [
            (do $field $entry "url")
            (do $field $entry "post_url")
            (do $field $entry "claim_url")
        ])

        if $url_id != "" {
            $url_id
        } else {
            let victim = (do $first_nonempty [(do $field $entry "victim"), (do $field $entry "post_title")])
            let group = (do $first_nonempty [(do $field $entry "group"), (do $field $entry "group_name")])
            let published = (do $first_nonempty [(do $field $entry "attackdate"), (do $field $entry "published"), (do $field $entry "discovered")])
            $"($victim)|($group)|($published)"
        }
    }

    let entry_datetime = { |entry: record|
        let raw_value = (do $first_nonempty [
            (do $field $entry "discovered")
            (do $field $entry "published")
            (do $field $entry "attackdate")
        ])

        if $raw_value == "" {
            null
        } else {
            (try { $raw_value | into datetime } catch { null })
        }
    }

    let fetch = { |selected_country_code?|
        if ($selected_country_code != null and (($selected_country_code | str trim) != "")) {
            let code = ($selected_country_code | str trim | str uppercase)
            let data = (http get $"https://api.ransomware.live/v2/countryvictims/($code)" | to json | from json)
            $data | each { |d|
                {
                    post_title: $d.post_title
                    published: $d.published
                    group_name: $d.group_name
                    website: $d.website
                    post_url: $d.post_url
                    country: (try { $d.country } catch { "" })
                    discovered: (try { $d.discovered } catch { "" })
                }
            }
        } else {
            let data = (http get "https://api.ransomware.live/v2/recentvictims" | to json | from json)
            $data | each { |d|
                {
                    victim: $d.victim
                    attackdate: $d.attackdate
                    group: $d.group
                    domain: $d.domain
                    country: $d.country
                    url: $d.url
                    claim_url: $d.claim_url
                    discovered: (try { $d.discovered } catch { "" })
                }
            }
        }
    }

    if $interval < 5 {
        error make { msg: "--interval must be at least 5 seconds" }
    }

    if $monitor {
        let monitor_started_at = (date now)
        let initial = (do $fetch $country_code)
        let initial_total = ($initial | length)
        let first_batch = if $limit > 0 { $initial | first $limit } else { $initial }
        print $"(ansi cyan_bold)[rware](ansi reset) Monitoring started. Baseline entries: ($initial_total). Interval: ($interval)s"
        if (($first_batch | length) > 0) {
            print ($first_batch | table -e)
        }

        mut seen_ids = ($initial | each { |entry| do $entry_id $entry } | uniq)
        mut cycle = 0

        loop {
            if ($max_cycles > 0 and $cycle >= $max_cycles) {
                break
            }

            sleep ($interval * 1sec)
            let latest = (do $fetch $country_code)
            let new_entries = ($latest | where { |entry|
                let current_entry_id = (do $entry_id $entry)
                let entry_time = (do $entry_datetime $entry)
                let is_recent = if $entry_time == null { true } else { $entry_time >= $monitor_started_at }
                $is_recent and (($seen_ids | any { |id| $id == $current_entry_id }) == false)
            })

            if (($new_entries | length) > 0) {
                let now = (date now | format date "%Y-%m-%d %H:%M:%S")
                print $"(ansi green_bold)[rware](ansi reset) New entries detected at ($now): ($new_entries | length)"
                let out = if $limit > 0 { $new_entries | first $limit } else { $new_entries }
                print ($out | table -e)
            }

            let latest_ids = ($latest | each { |entry| do $entry_id $entry })
            $seen_ids = (($seen_ids | append $latest_ids | uniq | last 5000))
            $cycle = ($cycle + 1)
        }
    } else {
        let data = (do $fetch $country_code)
        if $limit > 0 { $data | first $limit } else { $data }
    }
}

# Fetch latest proxy list (optionally filter by country)
def pls [--cc: string] {
    let pdata = (http get https://raw.githubusercontent.com/themiralay/Proxy-List-World/refs/heads/master/data-with-geolocation.json | to json | from json)
    mut p_array = []
    for d in ($pdata) {
        $p_array ++= [{
            "ip": $d.ip,
            "port": $d.port,
            "country": $d.geolocation.country,
            "country_code": $d.geolocation.countryCode,
            "isp": $d.geolocation.isp,
            "org": $d.geolocation.org,
            "as": $d.geolocation.as
        }]
    }
    if ($cc != null and (($cc | str trim) != "")) {
        let target = ($cc | str trim | str uppercase)
        $p_array | where { |row| ($row.country_code | into string | str uppercase) == $target }
    } else {
        $p_array
    }
}

# Enumerate subdomains using crt.sh (faster than shx command but no httpx!)
def crt [target_domain: string] {
    let resp = (http get $"https://crt.sh/?q=%25.($target_domain)&output=json")
    mut r_array = []
    for d in ($resp) {
        $r_array ++= [{
            "common_name": $d.common_name
        }]
    }
    $r_array | uniq
}

# Perform reverse IP lookup
def rip [target_ipaddr: string] {
    let key_file = $"($env.HOME)/.whoisxmlkey.txt"
    let api_key = if ($key_file | path exists) {
        open $key_file | str trim
    } else {
        let entered_key = (input $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Enter your WHOISXMLAPI key: " | str trim)
        if $entered_key == "" {
            error make { msg: "WHOISXMLAPI key cannot be empty." }
        }
        $entered_key | save -f $key_file
        print $"\n(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Key saved."
        $entered_key
    }
    let response = (http get $"https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=($api_key)&ip=($target_ipaddr)" | get result)
    $response
}

# Perform DNS Chronicle lookup
def dchr [target_domain: string] {
    let key_file = $"($env.HOME)/.whoisxmlkey.txt"
    let api_key = if ($key_file | path exists) {
        open $key_file | str trim
    } else {
        let entered_key = (input $"(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Enter your WHOISXMLAPI key: " | str trim)
        if $entered_key == "" {
            error make { msg: "WHOISXMLAPI key cannot be empty." }
        }
        $entered_key | save -f $key_file
        print $"\n(ansi cyan_bold)[(ansi red_bold)+(ansi cyan_bold)](ansi reset) Key saved."
        $entered_key
    }
    let response = (http post --content-type application/json https://dns-history.whoisxmlapi.com/api/v1 {"apiKey": $api_key, "searchType": "forward", "recordType": "a", "domainName": $target_domain} | get result)
    if (($response | get count) > 0) {
        $response | get records
    }
}

# Fetch file names from target open directory
def gf [target_url: string] {
    http get $target_url | lines | parse --regex 'href="([^"]+)"' | rename Files
}

# Triage IoC query
def triage [
    --family: string    # For ex: snakekeylogger
    --query: string     # For ex: domain, hash etc.
    --limit: int = 10   # Max report count
    --no-c2             # Skip C2 candidate extraction
    --no-config         # Skip malware config extraction
] {
    let known_benign = [
        "bing.com"
        "bing.net"
        "msedge.net"
        "microsoft.com"
        "windows.com"
        "ipify.org"
        "ip-api.com"
        "google.com"
        "googleapis.com"
        "gstatic.com"
        "github.com"
        "githubassets.com"
        "githubusercontent.com"
        "backblazeb2.com"
        "openh264.org"
        "vx-underground.org"
        "pki.goog"
        "cloudflare.com"
    ]

    let benign_host = { |host: string|
        let normalized = ($host | str lowercase | str trim)
        (($known_benign | where { |item|
            ($normalized == $item) or ($normalized | str ends-with $".($item)")
        } | length) > 0)
    }

    let url_host = { |url_value: string|
        let cleaned = ($url_value | str replace --all "\\u0026" "&" | str replace --all "\\/" "/")
        (try {
            $cleaned | parse --regex '^https?://([^/:?#]+)' | get 0.capture0
        } catch {
            null
        })
    }

    let is_ipv4 = { |value: string|
        (($value | str trim | parse --regex '^(?:\d{1,3}\.){3}\d{1,3}$' | length) > 0)
    }

    let suspicious_host = { |host: string|
        let normalized = ($host | str lowercase | str trim)
        if $normalized == "" {
            false
        } else if (do $benign_host $normalized) {
            false
        } else if (
            ($normalized | str starts-with "10.")
            or ($normalized | str starts-with "127.")
            or ($normalized | str starts-with "192.168.")
            or ($normalized | str starts-with "169.254.")
            or ($normalized | str starts-with "0.")
        ) {
            false
        } else if (($normalized | str starts-with "172.") and (try {
            let second_octet = ($normalized | split row "." | get 1 | into int)
            $second_octet >= 16 and $second_octet <= 31
        } catch {
            false
        })) {
            false
        } else {
            true
        }
    }

    let behavior_html = { |report_id: string|
        let behavior_url = $"https://tria.ge/($report_id)/behavioral1"
        (try { http get $behavior_url } catch { "" })
    }

    let first_capture = { |source: string, pattern: string|
        (try {
            $source | parse --regex $pattern | get 0.capture0 | str trim
        } catch {
            ""
        })
    }

    let clean_html_text = { |value: string|
        ($value
            | str replace --all --regex '<[^>]+>' ''
            | str replace --all '&amp;' '&'
            | str replace --all '&#160;' ' '
            | str replace --all '&nbsp;' ' '
            | str replace --all '&quot;' '"'
            | str replace --all '&#34;' '"'
            | str replace --all '&#39;' "'"
            | str replace --all '&#43;' '+'
            | str replace --all '&lt;' '<'
            | str replace --all '&gt;' '>'
            | str replace --all '&#10;' ' '
            | str replace --all '&#13;' ' '
            | str trim)
    }

    let config_block = { |config_section: string, heading: string|
        let marker = $"<div class=\"config-entry-heading\">($heading)</div>"
        (try {
            $config_section
            | split row $marker
            | get 1
            | split row '<div class="config-entry-heading">'
            | get 0
        } catch {
            ""
        })
    }

    let clean_list = { |items: list<any>, list_limit: int = 3|
        ($items
            | each { |item| do $clean_html_text ($item | into string) }
            | where { |v| ($v | str trim) != "" }
            | uniq
            | first $list_limit)
    }

    let c2_candidates = { |current_behavior_html: string|
        if (($current_behavior_html | str length) == 0) {
            return "-"
        }

        let raw_urls = (try {
            $current_behavior_html | parse --regex '"url":"(https?://[^"]+)"' | get capture0
        } catch {
            []
        })
        let flow_pairs = (try {
            $current_behavior_html | parse --regex '"domain":"([^"]+)","dst":"([^"]+)"'
        } catch {
            []
        })

        let download_urls = ($raw_urls | where { |u|
            ($u | str lowercase) =~ '\.(bin|exe|dll|dat|ps1|vbs|scr|bat|cmd|zip|rar|7z|hta|msi|jar)(\?|$)'
        })

        let download_hosts = ($download_urls | each { |u| do $url_host $u } | where { |h| $h != null and ($h | str trim) != "" })
        let url_hosts = ($raw_urls | each { |u| do $url_host $u } | where { |h| $h != null and ($h | str trim) != "" })
        let ipv4_hosts = ($url_hosts | where { |h| do $is_ipv4 $h })

        let candidates = ($download_hosts | append $ipv4_hosts | uniq | where { |h| do $suspicious_host $h })
        mut ip_domain_pairs = []

        for pair in $flow_pairs {
            let flow_domain = $pair.capture0
            let dst_host = (try {
                $pair.capture1 | parse --regex '^([^:]+)' | get 0.capture0
            } catch {
                ""
            })

            if (
                (do $is_ipv4 $dst_host)
                and ((do $is_ipv4 $flow_domain) == false)
                and (do $suspicious_host $flow_domain)
            ) {
                $ip_domain_pairs ++= [{ ip: $dst_host, domain: $flow_domain }]
            }
        }

        mut formatted_candidates = []
        for host in $candidates {
            if (do $is_ipv4 $host) {
                let mapped_domains = (try {
                    $ip_domain_pairs | where ip == $host | get domain | uniq
                } catch {
                    []
                })

                if (($mapped_domains | length) > 0) {
                    for domain in ($mapped_domains | first 3) {
                        $formatted_candidates ++= [$"($domain) [($host)]"]
                    }
                } else {
                    $formatted_candidates ++= [$host]
                }
            } else {
                $formatted_candidates ++= [$host]
            }
        }

        let final_candidates = ($formatted_candidates | uniq)

        if (($final_candidates | length) == 0) {
            "-"
        } else {
            $final_candidates | first 5 | str join ", "
        }
    }

    let malware_config = { |current_behavior_html: string|
        let empty_config = {
            family: "-"
            version: "-"
            botnet: "-"
            c2: []
            URLs: []
            Deobfuscated: []
            credentials: []
            mutex: "-"
        }

        if (($current_behavior_html | str length) == 0) {
            return $empty_config
        }

        let config_section = (try {
            $current_behavior_html
            | split row '<div id="malware-config-container"'
            | get 1
            | split row '<div id="signatures"'
            | get 0
        } catch {
            ""
        })

        if (($config_section | str length) == 0) {
            return $empty_config
        }

        let family = (do $clean_html_text (do $first_capture $config_section '(?s)<div class="config-entry-heading">Family</div>.*?<p[^>]*>(.*?)</p>'))
        let version = (do $clean_html_text (do $first_capture $config_section '(?s)<div class="config-entry-heading">Version</div>.*?<p[^>]*>(.*?)</p>'))
        let botnet = (do $clean_html_text (do $first_capture $config_section '(?s)<div class="config-entry-heading">Botnet</div>.*?<p[^>]*>(.*?)</p>'))
        let mutex = (do $clean_html_text (do $first_capture $config_section '(?s)<b>mutex</b><p class="prewrap">(.*?)</p>'))

        let c2_entries = (try {
            let c2_block = (do $config_block $config_section "C2")
            $c2_block | parse --regex '(?s)<p[^>]*>(.*?)</p>' | get capture0
        } catch {
            []
        })

        let url_entries = (try {
            let urls_block = (do $config_block $config_section "URLs")
            let labeled_urls = (try {
                $urls_block
                | parse --regex '(?s)<b>([^<]+)</b>\s*<p>(https?://[^<" ]+)</p>'
                | each { |row|
                    let source = (do $clean_html_text $row.capture0)
                    let url = (do $clean_html_text $row.capture1)
                    if ($source != "" and $url != "") { $"($source): ($url)" } else { null }
                }
                | where { |v| $v != null }
            } catch {
                []
            })
            let clipboard_urls = (try {
                $urls_block
                | parse --regex '(?s)data-clipboard="([^"]+)"'
                | get capture0
                | each { |item|
                    $item
                    | str replace --all '&#10;' "\n"
                    | str replace --all '&amp;' '&'
                    | split row "\n"
                }
                | flatten
                | each { |entry| $entry | str trim }
                | where { |entry| ($entry | str lowercase | str starts-with "http") }
            } catch {
                []
            })
            if (($labeled_urls | length) > 0) {
                $labeled_urls
            } else {
                $clipboard_urls
            }
        } catch {
            []
        })

        let deobfuscated_entries = (try {
            let deobfuscated_block = (do $config_block $config_section "Deobfuscated")
            let code_content_rows = (try {
                $deobfuscated_block
                | parse --regex '(?s)data-code-content="(.*?)"\s+data-code'
                | get capture0
            } catch {
                []
            })
            let line_content_rows = (try {
                $deobfuscated_block
                | parse --regex '(?s)code-block__line__content[^>]*>(.*?)</div>'
                | get capture0
            } catch {
                []
            })
            let pre_rows = (try {
                $deobfuscated_block
                | parse --regex '(?s)<pre[^>]*>(.*?)</pre>'
                | get capture0
            } catch {
                []
            })
            let code_rows = (try {
                $deobfuscated_block
                | parse --regex '(?s)<code[^>]*>(.*?)</code>'
                | get capture0
            } catch {
                []
            })
            let paragraph_rows = (try {
                $deobfuscated_block
                | parse --regex '(?s)<p[^>]*>(.*?)</p>'
                | get capture0
            } catch {
                []
            })

            $code_content_rows | append $line_content_rows | append $pre_rows | append $code_rows | append $paragraph_rows
        } catch {
            []
        })

        let credential_entries = (try {
            let cred_block = ($config_section | parse --regex '(?s)<div class="credentials">.*?<ul class="list">(.*?)</ul>' | get 0.capture0)
            $cred_block
            | parse --regex '(?s)<li class="nano"><b>(?:<br>)?([^<:]+):\s*</b>(.*?)</li>'
            | each { |row|
                let k = (do $clean_html_text $row.capture0 | str lowercase)
                let v = (do $clean_html_text $row.capture1)
                if ($k != "" and $v != "") { $"($k)=($v)" } else { null }
            }
            | where { |x| $x != null }
        } catch {
            []
        })

        let cleaned_c2 = (do $clean_list $c2_entries 4)
        let cleaned_urls = ($url_entries
            | each { |entry| do $clean_html_text ($entry | into string) }
            | each { |entry| $entry | str replace --all '&#10;' ' ' | str replace --all --regex '\s+' ' ' | str trim }
            | where { |value| $value != "" }
            | uniq
            | first 8)
        let cleaned_deobfuscated = ($deobfuscated_entries
            | each { |entry|
                let text = (($entry | into string)
                    | str replace --all '\\/' '/'
                    | str replace --all '&amp;' '&'
                    | str replace --all '&quot;' '"'
                    | str replace --all '&#34;' '"'
                    | str replace --all '&#39;' "'"
                    | str replace --all '&#43;' '+'
                    | str replace --all '&#10;' "\n"
                    | str replace --all '&#13;' "\n"
                    | str replace --all --regex '<[^>]+>' ''
                    | str trim)
                $text
            }
            | where { |value| ($value | str trim) != "" }
            | uniq)
        let cleaned_credentials = (do $clean_list $credential_entries 8)

        {
            family: (if $family != "" { $family } else { "-" })
            version: (if $version != "" { $version } else { "-" })
            botnet: (if $botnet != "" { $botnet } else { "-" })
            c2: $cleaned_c2
            URLs: $cleaned_urls
            Deobfuscated: $cleaned_deobfuscated
            credentials: $cleaned_credentials
            mutex: (if $mutex != "" { $mutex } else { "-" })
        }
    }

    let base_url = if ($family != null) {
        $"https://tria.ge/s/family:($family)"
    } else if ($query != null) {
        $"https://tria.ge/s?q=($query)"
    } else {
        error make { msg: "You must provide either --family or --query" }
    }

    let html = http get $base_url
    let names = $html | parse --regex '<div class="column-target"[^>]*>(.*?)</div>' | get capture0
    let ids   = $html | parse --regex 'data-sample-id="(.*?)"' | get capture0
    let scores = $html | parse --regex '<div class="score"[^>]*>(.*?)</div>' | get capture0

    let rows = ($names | zip $ids | zip $scores | each { |row|
        {
            FileName: $row.0.0
            ReportID: $row.0.1
            Score: $row.1
        }
    })

    let selected_rows = if $limit > 0 { $rows | first $limit } else { $rows }

    if $no_c2 and $no_config {
        $selected_rows
    } else {
        $selected_rows | each { |row|
            let current_behavior_html = (do $behavior_html $row.ReportID)
            mut out = $row

            if ($no_c2 == false) {
                $out = ($out | merge { C2: (do $c2_candidates $current_behavior_html) })
            }

            if ($no_config == false) {
                $out = ($out | merge { MalwareConfig: (do $malware_config $current_behavior_html) })
            }

            $out
        }
    }
}
