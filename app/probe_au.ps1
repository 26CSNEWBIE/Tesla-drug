#requires -Version 5.1
<#
probe_au.ps1 — 澳洲（新地区）适配前的摸底向导，一步一步把要探的东西跑全

用法（在 C:\fsd-mitm 下）：
  .\probe_au.ps1                 # 交互向导，按提示走
  .\probe_au.ps1 -Auto           # 全自动：discover -> sniff 5min -> cert
  .\probe_au.ps1 -Mode sniff -Duration 600

只观察不拦截：不碰 443、不起 mitmproxy、不改任何系统设置；
热点模式只旁听，路由器模式临时投毒并在结束时还原网关 ARP。
产物：logs\probe_au.log + logs\probe_au_report.json（最后打印"照着改哪里"清单）
#>
[CmdletBinding()]
param(
    [switch]$Auto,
    [switch]$SniffOnly,
    [switch]$CertOnly,
    [string]$Mode = '',
    [ValidateSet('discover','sniff','cert')]
    [string]$Step = '',
    [int]$Duration = 300,
    [string]$Target = '',
    [string]$Iface = 'Wi-Fi',
    [string]$Domain = 'api-prd.vn.tesla.com'
)

$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot
$py   = Join-Path $root 'venv\Scripts\python.exe'
$probe = Join-Path $root 'tools\probe_au.py'
$report = Join-Path $root 'logs\probe_au_report.json'

if (-not (Test-Path $py)) {
    Write-Host 'venv 不存在：先跑 install.ps1。' -ForegroundColor Red
    exit 1
}

function Banner([string]$t) { Write-Host "`n===== $t =====" -ForegroundColor Cyan }

function Pick-OurIp {
    Write-Host ''
    Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | ForEach-Object {
        Write-Host ("  [{0}] {1}  IP={2}  GW={3}" -f $_.InterfaceAlias, $_.InterfaceDescription,
                    $_.IPv4Address.IPAddress, $_.IPv4DefaultGateway.NextHop)
    }
    $alias = Read-Host '网卡名（回车默认 Wi-Fi）'
    if ($alias) { $script:Iface = $alias }
    $ip = Read-Host '本机 IP（回车自动取该网卡第一个 IPv4）'
    if (-not $ip) {
        $c = Get-NetIPAddress -InterfaceAlias $script:Iface -AddressFamily IPv4 |
             Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
        $ip = $c.IPAddress
    }
    return $ip
}

# ---------------------------------------------------------------- discover
function Do-Discover {
    Banner '第 1 步 · 扫描在线主机，找出车机 IP'
    $ourIp = Pick-OurIp
    & $py $probe discover --iface $Iface --our-ip $ourIp
    Write-Host ''
    Write-Host '从上面列表挑出车机 IP（MAC 是 4c:fc:aa / 98:00:c6 开头的就是；' -ForegroundColor Yellow
    Write-Host 'Tesla 也可能用随机 MAC，拿不准就重启车机后重扫，新出现的那台是它）。' -ForegroundColor Yellow
    $t = Read-Host '车机 IP'
    $gw = Read-Host '网关 IP（回车自动取）'
    if (-not $gw) {
        $gw = (Get-NetIPConfiguration -InterfaceAlias $Iface).IPv4DefaultGateway.NextHop
    }
    return @{ OurIp = $ourIp; Target = $t; Gateway = $gw }
}

# ---------------------------------------------------------------- sniff
function Do-Sniff($info) {
    Banner '第 2 步 · 旁听车机流量：DNS + TLS SNI + 目的 IP'
    Write-Host '热点模式（电脑是 192.168.137.1 网关）走 --no-poison；' -ForegroundColor DarkGray
    Write-Host '路由器模式临时投毒，结束时自动还原。' -ForegroundColor DarkGray
    $noPoison = ''
    if ($info.Gateway -eq '192.168.137.1') { $noPoison = '-NoPoison' }
    & $py $probe sniff --iface $Iface --target $info.Target --gateway $info.Gateway `
        --our-ip $info.OurIp --duration $Duration $noPoison
}

# ---------------------------------------------------------------- cert
function Do-Cert {
    Banner '第 3 步 · 取真实证书签发链'
    $d = Read-Host "要探的域名（回车默认 $Domain）"
    if (-not $d) { $d = $Domain }
    & $py $probe cert --domain $d
}

# ---------------------------------------------------------------- summary
function Show-Summary {
    Banner '摸底结果 → 该改哪里'
    if (-not (Test-Path $report)) {
        Write-Host '没有报告文件，先跑 discover/sniff。' -ForegroundColor Yellow
        return
    }
    $r = Get-Content $report -Raw | ConvertFrom-Json

    Write-Host ''
    Write-Host '[1] 车机 IP（改 start_all.ps1 的 --target）' -ForegroundColor White
    Write-Host ("    {0}" -f ($r.tesla_candidates -join ', '))

    Write-Host '[2] 车机连的 Tesla 域名（改 start_hotspot.ps1 / start_all.ps1 的 reverse 域名、'
    Write-Host '    dns_sink --redirect、arp_mitm 无需改）' -ForegroundColor White
    foreach ($k in $r.tesla_sni.PSObject.Properties.Name) {
        Write-Host ("    SNI: {0}  ->  {1}" -f $k, $r.tesla_sni.$k)
    }
    foreach ($d in $r.tesla_dns) { Write-Host ("    DNS: {0}" -f $d) }
    if (-not $r.tesla_sni -and -not $r.tesla_dns) {
        Write-Host '    （没有命中 —— 加大 -Duration，或在车机上重启/点一次 FSD 逼它发请求）' -ForegroundColor Yellow
    }

    Write-Host '[3] 443 目的 IP（改 start_all.ps1 的 --rst-dst，挑 tesla 域名对应的那个）' -ForegroundColor White
    foreach ($d in $r.dst_443) { Write-Host ("    {0}" -f $d) }

    Write-Host '[4] 证书链（决定 certs2 里伪造哪条 CA）：logs\probe_au_report.json 的 certs 节' -ForegroundColor White
    if ($r.certs) {
        foreach ($p in $r.certs.PSObject.Properties) {
            Write-Host ("    {0}: PEM 已存，看 issuer 与 eMudhra G3C 是否一致" -f $p.Name)
        }
    } else {
        Write-Host '    （未采集 —— 确定域名后再跑一次 cert 模式）' -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host "完整报告：$report" -ForegroundColor DarkGray
    Write-Host "日志：$(Join-Path $root 'logs\probe_au.log')" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------- main
if ($Auto) {
    $info = Do-Discover
    Do-Sniff $info
    Do-Cert
    Show-Summary
    exit 0
}

if ($CertOnly) { Do-Cert; Show-Summary; exit 0 }
if ($SniffOnly) {
    $info = @{ OurIp = (Get-NetIPAddress -InterfaceAlias $Iface -AddressFamily IPv4 |
               Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress
               Target = $Target; Gateway = (Get-NetIPConfiguration -InterfaceAlias $Iface).IPv4DefaultGateway.NextHop }
    if (-not $info.Target) { Write-Host '-SniffOnly 需要 -Target 车机IP' -ForegroundColor Red; exit 1 }
    Do-Sniff $info
    Show-Summary
    exit 0
}

Write-Host 'FSD 澳洲适配摸底向导' -ForegroundColor Cyan
Write-Host '  1) discover  扫出车机 IP'
Write-Host '  2) sniff     旁听车机找 Tesla 域名和上游 IP'
Write-Host '  3) cert      取真实证书签发链'
$pick = Read-Host '跑哪步（1/2/3，回车全部按顺序跑）'
switch ($pick) {
    '1' { $info = Do-Discover }
    '2' { $info = Do-Discover; Do-Sniff $info }
    '3' { Do-Cert }
    default {
        $info = Do-Discover
        Do-Sniff $info
        Do-Cert
    }
}
Show-Summary
