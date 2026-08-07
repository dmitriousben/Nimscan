# Author Dmitrious
# ╔══════════════════════════════════════════════════════════╗
# ║            NimScan - Network Scanner Tool                ║
# ║                                                          ║
# ║  Libraries used:                                         ║
# ║  net, nativesockets, asyncdispatch, asyncnet,            ║
# ║  httpclient, ssl, uri,                                   ║
# ║  os, osproc, strutils, sequtils, tables, sets,           ║
# ║  times, monotimes, terminal, parseopt,                   ║
# ║  json, base64, deques, re                                ║
# ╚══════════════════════════════════════════════════════════╝
#
# compile:
#   nim c --threads:on -r nimscan.nim
#
# usage:
#   ./netscanner scan   -t 192.168.1.1 -p 1-1024
#   ./netscanner scan   -t 192.168.1.0/24 --top
#   ./netscanner ping   -t 192.168.1.0/24
#   ./netscanner banner -t 192.168.1.1 -p 22,80,443
#   ./netscanner whois  -t google.com
#   ./netscanner http   -t https://example.com
#   ./netscanner --help

import std/[net, nativesockets, asyncdispatch, asyncnet,
            httpclient, uri,
            os, osproc, strutils, sequtils,
            tables, sets, times, monotimes,
            terminal, parseopt, json,
            base64, deques, re]

# ═══════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════

const
  TOOL_NAME   = "NimScan"
  VERSION     = "1.0.0"
  TIMEOUT_MS  = 1500       # TCP connect timeout
  PING_TIMEOUT = 1000      # Ping timeout ms
  MAX_WORKERS  = 200       # Concurrent port checks
  BANNER_WAIT  = 2000      # Wait for banner response ms

  # Well-known port → service name mapping
  KNOWN_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP",
    68:   "DHCP",
    69:   "TFTP",
    80:   "HTTP",
    110:  "POP3",
    111:  "RPC",
    119:  "NNTP",
    123:  "NTP",
    135:  "MSRPC",
    137:  "NetBIOS",
    138:  "NetBIOS",
    139:  "NetBIOS",
    143:  "IMAP",
    161:  "SNMP",
    162:  "SNMP-Trap",
    179:  "BGP",
    194:  "IRC",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    500:  "IKE/VPN",
    514:  "Syslog",
    515:  "LPD/Print",
    587:  "SMTP-Sub",
    631:  "IPP/CUPS",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    2049: "NFS",
    2181: "ZooKeeper",
    2375: "Docker",
    2376: "Docker-TLS",
    3000: "Dev-Server",
    3306: "MySQL",
    3389: "RDP",
    4369: "RabbitMQ",
    5000: "Flask/Dev",
    5432: "PostgreSQL",
    5672: "AMQP",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    6443: "K8s-API",
    7000: "Cassandra",
    7001: "WebLogic",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "Jupyter",
    9000: "PHP-FPM",
    9092: "Kafka",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    11211:"Memcached",
    15672:"RabbitMQ-UI",
    27017:"MongoDB",
    27018:"MongoDB",
    50000:"SAP",
    50070:"Hadoop"
  }.toTable

  # Top 100 most commonly open ports
  TOP_PORTS = @[
    21, 22, 23, 25, 53, 80, 110, 111, 119, 123,
    135, 137, 138, 139, 143, 161, 179, 194, 389, 443,
    445, 465, 500, 514, 515, 587, 631, 636, 993, 995,
    1080, 1194, 1433, 1521, 1723, 2049, 2181, 2375, 2376,
    3000, 3306, 3389, 4369, 5000, 5432, 5672, 5900, 5984,
    6379, 6443, 7000, 7001, 8000, 8080, 8443, 8888, 9000,
    9092, 9200, 9300, 11211, 15672, 27017, 27018, 50000, 50070
  ]

# ═══════════════════════════════════════
#  TYPES
# ═══════════════════════════════════════

type
  ScanMode = enum
    smScan    = "scan"      # TCP port scan
    smPing    = "ping"      # Host discovery
    smBanner  = "banner"    # Grab service banners
    smWhois   = "whois"     # DNS + whois lookup
    smHttp    = "http"      # HTTP fingerprint
    smHelp    = "help"

  PortState = enum
    psOpen    = "OPEN"
    psClosed  = "CLOSED"
    psFiltered = "FILTERED"

  PortResult = object
    port:    int
    state:   PortState
    service: string        # known service name
    banner:  string        # raw banner if grabbed
    latency: float         # connect time ms

  HostResult = object
    ip:       string
    hostname: string       # reverse DNS
    alive:    bool
    latency:  float
    ports:    seq[PortResult]
    os_hint:  string       # OS guess from TTL
    mac:      string       # MAC address if on LAN

  HttpInfo = object
    url:         string
    statusCode:  int
    server:      string    # Server header
    powered_by:  string    # X-Powered-By header
    title:       string    # HTML <title>
    headers:     Table[string, string]
    redirects:   seq[string]
    tls:         bool
    tls_issuer:  string
    duration:    float
    body_hash:   string

  DnsInfo = object
    hostname: string
    ips:      seq[string]
    mx:       seq[string]
    ns:       seq[string]
    txt:      seq[string]
    cname:    string
    ttl:      int

  ScanReport = object
    target:    string
    mode:      string
    startTime: DateTime
    duration:  float
    hosts:     seq[HostResult]
    httpInfos: seq[HttpInfo]
    dnsInfos:  seq[DnsInfo]
    stats:     Table[string, int]

  CliArgs = object
    mode:      ScanMode
    target:    string       # IP, CIDR, hostname, URL
    ports:     seq[int]     # ports to scan
    topPorts:  bool         # scan TOP_PORTS list
    allPorts:  bool         # scan 1-65535
    output:    string       # JSON output file
    verbose:   bool
    noColor:   bool
    timeout:   int          # ms
    threads:   int

# ═══════════════════════════════════════
#  TERMINAL HELPERS
# ═══════════════════════════════════════

var useColor = true

proc clr(color: ForegroundColor, msg: string): string =
  if not useColor: return msg
  result = ansiForegroundColorCode(color) & msg &
           ansiResetCode

proc printBanner() =
  if not useColor:
    echo TOOL_NAME & " v" & VERSION
    return

  setForegroundColor(fgGreen)
  echo """
  ███╗   ██╗██╗███╗   ███╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ████╗  ██║██║████╗ ████║██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██╔██╗ ██║██║██╔████╔██║███████╗██║     ███████║██╔██╗ ██║
  ██║╚██╗██║██║██║╚██╔╝██║╚════██║██║     ██╔══██║██║╚██╗██║
  ██║ ╚████║██║██║ ╚═╝ ██║███████║╚██████╗██║  ██║██║ ╚████║"""
  setForegroundColor(fgCyan)
  echo "  ╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
  resetAttributes()
  setForegroundColor(fgYellow)
  echo "                  Network Scanner v" & VERSION &
       "  |  Nim-powered"
  resetAttributes()
  echo ""

proc printHelp() =
  printBanner()
  echo clr(fgCyan,   "MODES:")
  echo "  scan    TCP port scan (default)"
  echo "  ping    Host discovery / ping sweep"
  echo "  banner  Grab service banners"
  echo "  whois   DNS + basic whois lookup"
  echo "  http    HTTP/HTTPS fingerprinting"
  echo ""
  echo clr(fgCyan,   "OPTIONS:")
  echo "  -t, --target   Target IP, CIDR, hostname, or URL"
  echo "  -p, --ports    Port range: 80,443  or  1-1024"
  echo "      --top      Scan top " & $TOP_PORTS.len & " common ports"
  echo "      --all      Scan all 65535 ports (slow)"
  echo "  -o, --out      Save JSON report to file"
  echo "  -v, --verbose  Verbose output"
  echo "      --timeout  Timeout in ms (default: " & $TIMEOUT_MS & ")"
  echo "      --threads  Concurrent workers (default: " & $MAX_WORKERS & ")"
  echo "      --no-color Disable colors"
  echo ""
  echo clr(fgCyan,   "EXAMPLES:")
  echo "  netscanner scan   -t 192.168.1.1 -p 1-1024"
  echo "  netscanner scan   -t 192.168.1.0/24 --top"
  echo "  netscanner ping   -t 192.168.1.0/24"
  echo "  netscanner banner -t 192.168.1.1 -p 22,80,443,3306"
  echo "  netscanner whois  -t google.com"
  echo "  netscanner http   -t https://example.com"
  echo ""

proc progress(label: string, curr, total: int) =
  let pct    = curr * 100 div max(total, 1)
  let filled = pct div 4
  let bar    = "█".repeat(filled) &
               "░".repeat(25 - filled)
  stdout.write("\r  " & clr(fgCyan, "[" & bar & "]") &
               " " & $pct & "% " & label &
               "          ")
  stdout.flushFile()
  if curr >= total: echo ""

# ═══════════════════════════════════════
#  NETWORK UTILITIES
# ═══════════════════════════════════════

proc serviceName(port: int): string =
  ## Look up known service name for port
  result = KNOWN_PORTS.getOrDefault(port, "unknown")

proc ipToInt(ip: string): uint32 =
  ## Convert "192.168.1.1" to 32-bit integer
  let parts = ip.split('.')
  if parts.len != 4:
    raise newException(ValueError, "Invalid IP: " & ip)
  result = (parseUInt(parts[0]).uint32 shl 24) or
           (parseUInt(parts[1]).uint32 shl 16) or
           (parseUInt(parts[2]).uint32 shl 8)  or
            parseUInt(parts[3]).uint32

proc intToIp(n: uint32): string =
  ## Convert 32-bit integer back to "x.x.x.x"
  result = $((n shr 24) and 0xFF) & "." &
           $((n shr 16) and 0xFF) & "." &
           $((n shr  8) and 0xFF) & "." &
           $ (n         and 0xFF)

proc expandCidr(cidr: string): seq[string] =
  ## Expand "192.168.1.0/24" into list of IPs
  ## /24 = 256 hosts, /16 = 65536, etc.
  result = @[]

  if '/' notin cidr:
    # Not CIDR, just a single IP
    result.add(cidr)
    return

  let parts  = cidr.split('/')
  let baseIp = parts[0]
  let prefix = parseInt(parts[1])  # bits in network mask

  if prefix < 0 or prefix > 32:
    raise newException(ValueError, "Bad prefix: " & $prefix)

  let base    = ipToInt(baseIp)
  # hostBits = how many bits are for hosts
  let hostBits = 32 - prefix
  # numHosts = 2^hostBits
  let numHosts = 1'u32 shl hostBits.uint32

  # network mask: all network bits set, host bits zero
  let mask     = not (numHosts - 1)
  let network  = base and mask

  # Skip network address (x.x.x.0) and broadcast (x.x.x.255)
  for i in 1'u32..(numHosts - 2):
    result.add(intToIp(network or i))

  echo clr(fgCyan, "  Expanded " & cidr & " → " &
           $result.len & " hosts")

proc parsePorts(spec: string): seq[int] =
  ## Parse port spec like "22,80,443" or "1-1024" or "80,443,8000-9000"
  result = @[]
  var seen = initHashSet[int]()

  for part in spec.split(','):
    let p = part.strip()
    if '-' in p:
      # Range like "1-1024"
      let bounds = p.split('-')
      let lo = parseInt(bounds[0])
      let hi = parseInt(bounds[1])
      for port in lo..hi:
        if port notin seen and port in 1..65535:
          result.add(port)
          seen.incl(port)
    else:
      let port = parseInt(p)
      if port notin seen and port in 1..65535:
        result.add(port)
        seen.incl(port)

proc resolveHostname(hostname: string): string =
  ## DNS forward lookup: hostname → IP
  try:
    let info = getAddrInfo(
      hostname, "",
      domain = AF_INET,
      sockType = SOCK_STREAM
    )
    if info != nil:
      var addrStr = newString(64)
      # inet_ntop converts binary address to string
      discard inet_ntop(
        info.ai_family,
        info.ai_addr,
        addrStr.cstring,
        64
      )
      result = addrStr.strip(chars={'\0'})
      freeAddrInfo(info)
  except:
    result = hostname  # return as-is if lookup fails

proc reverseResolve(ip: string): string =
  ## Reverse DNS: IP → hostname
  ## Uses osproc to call system nslookup/host
  try:
    let (output, code) = execCmdEx(
      when defined(windows): "nslookup " & ip
      else: "host " & ip
    )
    if code == 0:
      # Parse first hostname from output
      let lines = output.splitLines()
      for line in lines:
        if "name" in line.toLowerAscii() or
           "pointer" in line.toLowerAscii():
          let parts = line.split()
          if parts.len > 0:
            return parts[^1].strip(chars={'.'})
  except: discard
  result = ""

proc guessTtlOs(ttl: int): string =
  ## Guess OS from TTL value
  ## Linux/Unix: 64, Windows: 128, Cisco: 255
  if ttl <= 64:   "Linux/Unix (TTL≤64)"
  elif ttl <= 128: "Windows (TTL≤128)"
  elif ttl <= 255: "Network device (TTL≤255)"
  else:            "Unknown"

# ═══════════════════════════════════════
#  TCP PORT SCANNER
# ═══════════════════════════════════════

proc tcpConnect(host: string, port: int,
                timeoutMs: int): PortResult =
  ## Try TCP connect to host:port
  ## Returns PortResult with state + latency
  result = PortResult(
    port:    port,
    state:   psClosed,
    service: serviceName(port)
  )

  let t0 = getMonoTime()

  try:
    var sock = newSocket(
      domain   = AF_INET,
      sockType = SOCK_STREAM,
      protocol = IPPROTO_TCP,
      buffered = false
    )
    defer: sock.close()

    # setSockOpt sets socket options
    # SO_REUSEADDR lets us reuse ports quickly
    sock.setSockOpt(OptReuseAddr, true)

    # connect with timeout
    # If no response in timeoutMs → exception
    sock.connect(host, Port(port), timeoutMs)

    let elapsed = (getMonoTime() - t0)
                  .inNanoseconds().float / 1_000_000.0

    result.state   = psOpen
    result.latency = elapsed

  except TimeoutError:
    result.state = psFiltered   # no response = filtered
  except OSError:
    result.state = psClosed     # refused = closed
  except:
    result.state = psClosed

proc grabBanner(host: string, port: int,
                timeoutMs: int): string =
  ## Connect to port and read any banner the service sends
  ## Many services (SSH, FTP, SMTP) announce themselves
  result = ""
  try:
    var sock = newSocket(
      domain   = AF_INET,
      sockType = SOCK_STREAM,
      protocol = IPPROTO_TCP,
      buffered = true
    )
    defer: sock.close()

    sock.connect(host, Port(port), timeoutMs)
    sock.setSockOpt(OptReuseAddr, true)

    # Some services need a prompt to respond
    # Send appropriate probe based on port
    case port
    of 80, 8080, 8000:
      sock.send("HEAD / HTTP/1.0\r\nHost: " & host & "\r\n\r\n")
    of 21:
      discard   # FTP sends banner immediately
    of 22:
      discard   # SSH sends banner immediately
    of 25, 587:
      discard   # SMTP sends banner immediately
    of 3306:
      discard   # MySQL sends banner immediately
    else:
      sock.send("\r\n")   # generic probe

    # Read response with timeout
    var buf = newString(1024)
    sock.recv(buf, 1024, timeoutMs)
    result = buf
      .strip()
      .replace("\r\n", " | ")
      .replace("\n", " | ")

    # Truncate very long banners
    if result.len > 200:
      result = result[0..199] & "..."

  except: discard

proc scanPortRange(host: string, ports: seq[int],
                   timeoutMs: int,
                   verbose: bool): seq[PortResult] =
  ## Scan all ports concurrently using threadpool
  result = @[]

  # FlowVar array for concurrent results
  var tasks = newSeq[FlowVar[PortResult]](ports.len)

  # Spawn all connections at once (up to OS limits)
  for i, port in ports:
    tasks[i] = spawn tcpConnect(host, port, timeoutMs)

  # Collect results
  for i, task in tasks:
    let r = ^task
    result.add(r)
    if verbose and r.state == psOpen:
      echo "  " & clr(fgGreen, "OPEN") & "  " &
           host & ":" & $r.port &
           " (" & r.service & ")" &
           " [" & r.latency.formatFloat(ffDecimal, 1) & "ms]"
    progress("scanning", i + 1, ports.len)

  sync()

  # Keep only open ports in results
  result = result.filterIt(it.state == psOpen)

# ═══════════════════════════════════════
#  PING / HOST DISCOVERY
# ═══════════════════════════════════════

proc pingHost(ip: string, timeoutMs: int): tuple[alive: bool, latency: float] =
  ## Ping using ICMP via system ping command
  ## We use osproc since raw ICMP needs root on Linux
  let t0 = cpuTime()

  let cmd = when defined(windows):
    "ping -n 1 -w " & $timeoutMs & " " & ip
  else:
    "ping -c 1 -W " & $(timeoutMs div 1000) & " " & ip

  let (output, code) = execCmdEx(cmd)
  let elapsed = (cpuTime() - t0) * 1000.0

  result.alive   = code == 0
  result.latency = elapsed

  discard output   # suppress unused warning

proc pingTcpFallback(ip: string,
                     timeoutMs: int): tuple[alive: bool, latency: float] =
  ## TCP-based host detection (fallback for non-root)
  ## Try common ports — if any open, host is alive
  for port in [80, 443, 22, 445, 3389]:
    let r = tcpConnect(ip, port, timeoutMs div 5)
    if r.state == psOpen:
      return (true, r.latency)
  result = (false, 0.0)

proc discoverHosts(ips: seq[string],
                   timeoutMs: int,
                   verbose: bool): seq[HostResult] =
  ## Ping sweep: find alive hosts in IP list
  result = @[]
  var alive = 0

  echo clr(fgCyan, "  Sweeping " & $ips.len & " hosts...")

  for i, ip in ips:
    let (isAlive, latency) = pingHost(ip, timeoutMs)

    if isAlive:
      inc alive
      let hostname = reverseResolve(ip)

      let host = HostResult(
        ip:       ip,
        hostname: hostname,
        alive:    true,
        latency:  latency
      )
      result.add(host)

      echo "  " & clr(fgGreen, "UP") & "   " & ip &
           (if hostname.len > 0: "  (" & hostname & ")" else: "") &
           "  [" & latency.formatFloat(ffDecimal, 0) & "ms]"

    progress("pinging", i + 1, ips.len)

  echo ""
  echo clr(fgGreen,  "  " & $alive & " hosts up") &
       "  /  " &
       clr(fgYellow, $(ips.len - alive) & " down")

# ═══════════════════════════════════════
#  BANNER GRABBER
# ═══════════════════════════════════════

proc grabAllBanners(host: string, ports: seq[int],
                    timeoutMs: int): seq[PortResult] =
  ## Grab banners from all given ports
  result = @[]

  for port in ports:
    let connResult = tcpConnect(host, port, timeoutMs)

    if connResult.state == psOpen:
      let banner = grabBanner(host, port, BANNER_WAIT)
      var r = connResult
      r.banner = banner
      result.add(r)

      echo ""
      echo clr(fgGreen, "  ● PORT " & $port) &
           "  " & r.service
      echo "  " & clr(fgCyan, "Latency:") &
           " " & r.latency.formatFloat(ffDecimal, 1) & "ms"

      if banner.len > 0:
        echo "  " & clr(fgYellow, "Banner: ") & banner
      else:
        echo "  " & clr(fgYellow, "Banner: ") &
             clr(fgWhite, "(no banner)")
    else:
      echo "  " & clr(fgRed, "✗ PORT " & $port) &
           "  " & $connResult.state

# ═══════════════════════════════════════
#  DNS / WHOIS
# ═══════════════════════════════════════

proc dnsLookup(hostname: string): DnsInfo =
  ## Full DNS investigation using system tools
  result.hostname = hostname

  # Forward lookup (A records)
  try:
    let resolvedIp = resolveHostname(hostname)
    if resolvedIp != hostname:
      result.ips.add(resolvedIp)
  except: discard

  # Use nslookup/dig for detailed records
  proc runDns(args: string): string =
    let cmd = when defined(windows): "nslookup " & args
              else: "dig +short " & args
    let (out, _) = execCmdEx(cmd)
    result = out.strip()

  # MX records
  let mxOut = runDns("-type=MX " & hostname)
  for line in mxOut.splitLines():
    if line.contains("mail") or
       line.contains("MX") or
       line.len > 0:
      result.mx.add(line.strip())

  # NS records
  let nsOut = runDns("-type=NS " & hostname)
  for line in nsOut.splitLines():
    if line.len > 0:
      result.ns.add(line.strip())

  # TXT records (SPF, DKIM, DMARC etc)
  let txtOut = runDns("-type=TXT " & hostname)
  for line in txtOut.splitLines():
    if line.len > 0:
      result.txt.add(line.strip())

proc printDnsInfo(info: DnsInfo) =
  echo ""
  echo clr(fgCyan, "  ═══ DNS Info: " & info.hostname & " ═══")
  echo ""

  if info.ips.len > 0:
    echo clr(fgGreen, "  A Records (IPs):")
    for ip in info.ips:
      echo "    " & ip
  else:
    echo clr(fgRed, "  No A records found")

  if info.mx.len > 0:
    echo ""
    echo clr(fgGreen, "  MX Records (Mail):")
    for mx in info.mx[0..min(5, info.mx.high)]:
      if mx.len > 0:
        echo "    " & mx

  if info.ns.len > 0:
    echo ""
    echo clr(fgGreen, "  NS Records (Nameservers):")
    for ns in info.ns[0..min(5, info.ns.high)]:
      if ns.len > 0:
        echo "    " & ns

  if info.txt.len > 0:
    echo ""
    echo clr(fgGreen, "  TXT Records (SPF/DKIM/DMARC):")
    for txt in info.txt[0..min(10, info.txt.high)]:
      if txt.len > 0:
        echo "    " & txt[0..min(80, txt.high)]

# ═══════════════════════════════════════
#  HTTP FINGERPRINTER
# ═══════════════════════════════════════

proc extractTitle(html: string): string =
  ## Pull <title> tag content from HTML
  let pattern = re(r"(?i)<title[^>]*>([^<]+)</title>")
  var matches: array[1, string]
  if html.find(pattern, matches) >= 0:
    result = matches[0].strip()
  else:
    result = ""

proc httpFingerprint(url: string,
                     timeoutMs: int): HttpInfo =
  ## Deep HTTP/HTTPS fingerprinting
  result.url = url
  result.headers = initTable[string, string]()

  let parsed = parseUri(url)
  result.tls = parsed.scheme == "https"

  let t0 = cpuTime()

  try:
    let sslCtx = newContext(verifyMode = CVerifyNone)
    let client = newHttpClient(
      sslContext = sslCtx,
      timeout    = timeoutMs
    )
    defer: client.close()

    # Follow redirects manually to track chain
    client.maxRedirects = 0   # handle manually

    var currentUrl = url
    var hops = 0

    while hops < 10:
      inc hops
      let resp = client.get(currentUrl)

      # Collect all response headers
      for name, val in resp.headers.pairs():
        result.headers[name.toLowerAscii()] = val

      # Extract interesting headers
      result.server     = resp.headers.getOrDefault(
                            "server", "")
      result.powered_by = resp.headers.getOrDefault(
                            "x-powered-by", "")

      if resp.code.int in [301, 302, 303, 307, 308]:
        # Follow redirect
        let location = resp.headers.getOrDefault("location", "")
        if location.len > 0:
          result.redirects.add(currentUrl & " → " & location)
          # Handle relative redirects
          if location.startsWith("http"):
            currentUrl = location
          else:
            currentUrl = $parsed.scheme & "://" &
                         parsed.hostname & location
        else:
          break
      else:
        # Final response
        result.statusCode = resp.code.int
        let body = resp.body

        result.title = extractTitle(body)

        # Simple hash of body for change detection
        var h = 0u32
        for c in body:
          h = h * 31 + c.uint32
        result.body_hash = h.toHex()
        break

  except SslError as e:
    result.statusCode = -1
    result.server     = "SSL Error: " & e.msg
  except TimeoutError:
    result.statusCode = -2
    result.server     = "Timeout"
  except:
    result.statusCode = -3
    result.server     = getCurrentExceptionMsg()

  result.duration = (cpuTime() - t0) * 1000.0

proc printHttpInfo(info: HttpInfo) =
  echo ""
  echo clr(fgCyan, "  ═══ HTTP Fingerprint ═══")
  echo ""
  echo "  URL:        " & info.url

  let statusColor = if info.statusCode in 200..299: fgGreen
                    elif info.statusCode in 300..399: fgYellow
                    else: fgRed

  echo "  Status:     " & clr(statusColor, $info.statusCode)
  echo "  TLS/HTTPS:  " & (if info.tls: clr(fgGreen, "YES")
                            else: clr(fgRed, "NO"))
  echo "  Duration:   " &
       info.duration.formatFloat(ffDecimal, 0) & "ms"

  if info.title.len > 0:
    echo "  Page Title: " & clr(fgYellow, info.title)
  if info.server.len > 0:
    echo "  Server:     " & clr(fgYellow, info.server)
  if info.powered_by.len > 0:
    echo "  Powered By: " & clr(fgYellow, info.powered_by)

  if info.redirects.len > 0:
    echo ""
    echo clr(fgCyan, "  Redirect Chain:")
    for r in info.redirects:
      echo "    " & r

  echo ""
  echo clr(fgCyan, "  Response Headers:")

  # Print interesting security headers
  let securityHeaders = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "access-control-allow-origin"
  ]

  var found = 0
  for h in securityHeaders:
    if h in info.headers:
      echo "  " & clr(fgGreen, "  ✓ ") &
           h & ": " &
           info.headers[h][0..min(60, info.headers[h].high)]
      inc found

  # Print missing security headers as warnings
  for h in securityHeaders:
    if h notin info.headers:
      echo "  " & clr(fgRed, "  ✗ ") &
           h & ": " & clr(fgRed, "MISSING")

  echo ""
  echo "  Security headers present: " &
       clr(if found >= 5: fgGreen
           elif found >= 3: fgYellow
           else: fgRed,
           $found & "/" & $securityHeaders.len)

# ═══════════════════════════════════════
#  SCAN ORCHESTRATOR
# ═══════════════════════════════════════

proc runScan(args: CliArgs): ScanReport =
  result.target    = args.target
  result.mode      = $args.mode
  result.startTime = now()
  result.stats     = initTable[string, int]()

  let t0 = cpuTime()

  # Resolve target to IP list
  var ips: seq[string] = @[]

  if '/' in args.target:
    # CIDR range
    ips = expandCidr(args.target)
  elif re(r"^\d+\.\d+\.\d+\.\d+$").match(args.target):
    # Single IP
    ips.add(args.target)
  else:
    # Hostname — resolve to IP
    let resolved = resolveHostname(args.target)
    ips.add(resolved)
    if resolved != args.target:
      echo clr(fgCyan, "  Resolved: ") &
           args.target & " → " & resolved

  result.stats["targets"] = ips.len

  case args.mode
  of smPing:
    # ── Host discovery ────────────────
    echo clr(fgCyan, "\n  ─── Host Discovery ───")
    let hosts = discoverHosts(ips, args.timeout, args.verbose)
    result.hosts = hosts
    result.stats["alive"] = hosts.filterIt(it.alive).len
    result.stats["down"]  = ips.len - result.stats["alive"]

  of smScan:
    # ── Port scan ─────────────────────
    let ports = if args.allPorts:   toSeq(1..65535)
                elif args.topPorts: TOP_PORTS
                else:               args.ports

    echo clr(fgCyan, "\n  ─── Port Scan ───")
    echo "  Ports: " & $ports.len & " targets"

    for ip in ips:
      echo ""
      echo clr(fgYellow, "  ▶ " & ip)

      let hostname = reverseResolve(ip)
      if hostname.len > 0:
        echo "  Hostname: " & hostname

      let openPorts = scanPortRange(
        ip, ports, args.timeout, args.verbose
      )

      var host = HostResult(
        ip:       ip,
        hostname: hostname,
        alive:    openPorts.len > 0,
        ports:    openPorts
      )

      result.hosts.add(host)

      echo ""
      if openPorts.len > 0:
        echo clr(fgGreen,
          "  " & $openPorts.len & " open port(s):")
        for p in openPorts:
          echo "  " &
               clr(fgGreen,
                 ($p.port).alignLeft(6)) &
               clr(fgCyan,
                 p.service.alignLeft(15)) &
               p.latency.formatFloat(ffDecimal, 1) & "ms"
      else:
        echo clr(fgRed, "  No open ports found")

    result.stats["open_ports"] = result.hosts
      .mapIt(it.ports.len).foldl(a + b, 0)

  of smBanner:
    # ── Banner grabbing ───────────────
    echo clr(fgCyan, "\n  ─── Banner Grabbing ───")
    for ip in ips:
      echo ""
      echo clr(fgYellow, "  ▶ Target: " & ip)
      let banners = grabAllBanners(ip, args.ports, args.timeout)
      var host = HostResult(ip: ip, ports: banners)
      result.hosts.add(host)

  of smWhois:
    # ── DNS lookup ────────────────────
    echo clr(fgCyan, "\n  ─── DNS Lookup ───")
    for ip in ips:
      let info = dnsLookup(args.target)
      printDnsInfo(info)
      result.dnsInfos.add(info)

  of smHttp:
    # ── HTTP fingerprint ──────────────
    echo clr(fgCyan, "\n  ─── HTTP Fingerprint ───")
    let url = if args.target.startsWith("http"): args.target
              else: "http://" & args.target
    let info = httpFingerprint(url, args.timeout)
    printHttpInfo(info)
    result.httpInfos.add(info)

  of smHelp: discard

  result.duration = cpuTime() - t0

# ═══════════════════════════════════════
#  REPORT GENERATOR
# ═══════════════════════════════════════

proc buildJsonReport(report: ScanReport): JsonNode =
  var hostsJson = newJArray()

  for h in report.hosts:
    var portsJson = newJArray()
    for p in h.ports:
      portsJson.add %*{
        "port":    p.port,
        "state":   $p.state,
        "service": p.service,
        "banner":  p.banner,
        "latency": p.latency
      }

    hostsJson.add %*{
      "ip":       h.ip,
      "hostname": h.hostname,
      "alive":    h.alive,
      "latency":  h.latency,
      "os_hint":  h.os_hint,
      "ports":    portsJson
    }

  var httpJson = newJArray()
  for h in report.httpInfos:
    httpJson.add %*{
      "url":        h.url,
      "status":     h.statusCode,
      "server":     h.server,
      "powered_by": h.powered_by,
      "title":      h.title,
      "tls":        h.tls,
      "redirects":  h.redirects,
      "duration_ms": h.duration,
      "body_hash":  h.body_hash
    }

  var dnsJson = newJArray()
  for d in report.dnsInfos:
    dnsJson.add %*{
      "hostname": d.hostname,
      "ips":      d.ips,
      "mx":       d.mx,
      "ns":       d.ns,
      "txt":      d.txt
    }

  result = %*{
    "tool":       TOOL_NAME,
    "version":    VERSION,
    "target":     report.target,
    "mode":       report.mode,
    "start_time": report.startTime.format("yyyy-MM-dd HH:mm:ss"),
    "duration_s": report.duration.formatFloat(ffDecimal, 2),
    "stats":      %report.stats,
    "hosts":      hostsJson,
    "http":       httpJson,
    "dns":        dnsJson
  }

proc printSummary(report: ScanReport) =
  echo ""
  setForegroundColor(fgCyan)
  echo "  ═══════════════════════════════"
  echo "  " & TOOL_NAME & " SCAN COMPLETE"
  echo "  ═══════════════════════════════"
  resetAttributes()
  echo "  Target:   " & report.target
  echo "  Mode:     " & report.mode
  echo "  Duration: " &
       report.duration.formatFloat(ffDecimal, 2) & "s"

  for key, val in report.stats:
    echo "  " & key.alignLeft(14) & $val

  echo ""

# ═══════════════════════════════════════
#  CLI PARSER
# ═══════════════════════════════════════

proc parseCli(): CliArgs =
  result = CliArgs(
    mode:    smHelp,
    timeout: TIMEOUT_MS,
    threads: MAX_WORKERS
  )

  var p = initOptParser()
  var first = true

  while true:
    p.next()
    case p.kind
    of cmdEnd: break

    of cmdArgument:
      if first:
        first = false
        result.mode = case p.key.toLowerAscii()
          of "scan":   smScan
          of "ping":   smPing
          of "banner": smBanner
          of "whois":  smWhois
          of "http":   smHttp
          of "help":   smHelp
          else:
            # Treat as target if looks like IP/hostname
            result.target = p.key
            smScan
      else:
        if result.target == "":
          result.target = p.key

    of cmdLongOption:
      case p.key
      of "target", "t":    result.target   = p.val
      of "ports",  "p":    result.ports    = parsePorts(p.val)
      of "out",    "o":    result.output   = p.val
      of "timeout":        result.timeout  = parseInt(p.val)
      of "threads":        result.threads  = parseInt(p.val)
      of "top":            result.topPorts = true
      of "all":            result.allPorts = true
      of "verbose", "v":   result.verbose  = true
      of "no-color":
        result.noColor = true
        useColor       = false
      of "help":           result.mode     = smHelp
      else: discard

    of cmdShortOption:
      case p.key
      of "t": result.target   = p.val
      of "p": result.ports    = parsePorts(p.val)
      of "o": result.output   = p.val
      of "v": result.verbose  = true
      of "h": result.mode     = smHelp
      else: discard

  # Default: scan top ports if no ports given
  if result.ports.len == 0 and
     not result.topPorts and
     not result.allPorts:
    result.topPorts = true

proc validateArgs(args: CliArgs) =
  if args.mode == smHelp: return

  if args.target == "":
    logErr("Target required: --target / -t")
    quit(1)

  if args.mode in [smBanner] and args.ports.len == 0:
    logErr("Port list required for banner mode: -p 22,80,443")
    quit(1)

# ═══════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════

proc main() =
  let args = parseCli()

  if args.mode == smHelp:
    printHelp()
    quit(0)

  validateArgs(args)
  printBanner()

  echo clr(fgYellow, "  Target: ") & args.target
  echo clr(fgYellow, "  Mode:   ") & $args.mode
  echo clr(fgYellow, "  Timeout:") & $args.timeout & "ms"
  echo ""

  let report = runScan(args)
  printSummary(report)

  # Save JSON report if requested
  if args.output.len > 0:
    let json = buildJsonReport(report)
    writeFile(args.output, pretty(json))
    echo clr(fgGreen, "  Report saved: ") & args.output
    echo ""

main()