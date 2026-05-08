<#
.SYNOPSIS
    Windows 10 安全基线检查脚本（兼容中文版）
.DESCRIPTION
    检查账号策略、审核策略、用户权限、共享、防火墙等安全配置。
.NOTES
    版本: 2.0 (基线版)
    要求: 管理员权限
#>

# 需要管理员权限
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "请以管理员身份运行此脚本！" -ForegroundColor Red
    exit 1
}

# 报告路径
$ReportDir = "$env:USERPROFILE\Desktop\SecurityBaselineReport"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }
$HtmlReport = "$ReportDir\BaselineReport_$env:COMPUTERNAME.html"
$CsvReport = "$ReportDir\BaselineReport_$env:COMPUTERNAME.csv"

# 临时导出安全策略配置文件
$SecConfigFile = "$env:TEMP\secpol_$env:COMPUTERNAME.cfg"
secedit /export /cfg $SecConfigFile | Out-Null
if (-not (Test-Path $SecConfigFile)) {
    Write-Warning "无法导出本地安全策略，部分检查项将不可用"
}

# 解析安全策略函数
function Get-SecPolicyValue {
    param($Section, $Key)
    if (-not (Test-Path $SecConfigFile)) { return $null }
    $content = Get-Content $SecConfigFile -ErrorAction SilentlyContinue
    $inSection = $false
    foreach ($line in $content) {
        if ($line -match "^\[$Section\]") { $inSection = $true; continue }
        if ($inSection -and $line -match "^\[") { $inSection = $false }
        if ($inSection -and $line -match "^$Key\s*=\s*(.*)") { return $matches[1].Trim() }
    }
    return $null
}

# 获取审核状态（兼容中英文）
function Get-AuditStatus {
    param($SubEn, $SubZh)
    $output = auditpol /get /subcategory:"*" 2>$null
    $line = $output | Select-String -Pattern "$SubEn|$SubZh" | Select-Object -First 1
    if ($line) {
        $status = ($line -split '\s+')[-1]
        if ($status -match 'Success and Failure') { return 'Success and Failure' }
        if ($status -match 'Success') { return 'Success' }
        if ($status -match 'Failure') { return 'Failure' }
        if ($status -match 'No Auditing') { return 'No Auditing' }
    }
    return 'Not Found'
}

# 主机信息
$HostInfo = [PSCustomObject]@{
    主机名   = $env:COMPUTERNAME
    IP地址   = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"} | Select-Object -First 1).IPAddress
    操作系统 = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
    版本号   = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
    检查时间 = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

$Results = @()

# ---------- 辅助函数 ----------
function Test-RegistryValue {
    param($Path, $Name, $ExpectedValue)
    $value = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($value -eq $null) { return $false, $null }
    return ($value -eq $ExpectedValue), $value
}

# ========================= 开始检查 =========================
Write-Host "开始安全基线检查，请稍候..." -ForegroundColor Cyan

# 1. 账号管理
$Results += [PSCustomObject]@{
    编号 = "WIN-01"; 名称 = "按照用户分配账号"; 要求 = "设定不同的账户和账户组"
    实际值 = "本地用户：$( (Get-LocalUser).Name -join ', ' )"; 期望值 = "存在Administrator，Guest已禁用"
    状态 = "信息"; 备注 = "请人工确认是否按角色分配了必要账户"
}

$guestDisabled = (Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue).Enabled -eq $false
$Results += [PSCustomObject]@{
    编号 = "WIN-02"; 名称 = "删除或锁定无关账号"; 要求 = "删除或锁定与设备运行维护无关的账号"
    实际值 = "Guest已禁用: $guestDisabled"; 期望值 = "Guest禁用，无多余账号"
    状态 = if ($guestDisabled) { "合规" } else { "不合规" }; 备注 = "建议禁用Guest"
}

$adminName = (Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue).Name
$adminRenamed = ($adminName -ne "Administrator")
$Results += [PSCustomObject]@{
    编号 = "WIN-03"; 名称 = "更改默认管理员名称并禁用Guest"; 要求 = "Administrator改名，Guest停用"
    实际值 = "管理员名: $adminName, Guest禁用: $guestDisabled"; 期望值 = "Administrator已改名，Guest禁用"
    状态 = if ($adminRenamed -and $guestDisabled) { "合规" } else { "不合规" }; 备注 = "若未改名建议修改"
}

$lockoutThreshold = (net accounts | Select-String "锁定阈值|Lockout threshold" | ForEach-Object { ($_ -split ":")[-1].Trim() })
$lockoutOK = ($lockoutThreshold -match '^\d+$' -and [int]$lockoutThreshold -le 20)
$Results += [PSCustomObject]@{
    编号 = "WIN-04"; 名称 = "账户锁定阀值"; 要求 = "连续认证失败次数超过20次锁定账号"
    实际值 = "锁定阈值: $lockoutThreshold 次"; 期望值 = "≤20"; 状态 = if ($lockoutOK) { "合规" } else { "不合规" }; 备注 = ""
}

# 2. 口令策略
$minPwdLen = Get-SecPolicyValue "System Access" "MinimumPasswordLength"
$complexity = Get-SecPolicyValue "System Access" "PasswordComplexity"
$pwdComplexOK = ($complexity -eq "1")
$Results += [PSCustomObject]@{
    编号 = "WIN-05"; 名称 = "密码复杂性要求"; 要求 = "最短6位，含至少三类字符"
    实际值 = "最小长度: $minPwdLen, 复杂性启用: $pwdComplexOK"; 期望值 = "最小长度≥6，复杂性=1"
    状态 = if ($pwdComplexOK -and [int]$minPwdLen -ge 6) { "合规" } else { "不合规" }; 备注 = ""
}

$maxPwdAge = Get-SecPolicyValue "System Access" "MaximumPasswordAge"
$maxAgeOK = ([int]$maxPwdAge -le 90 -and [int]$maxPwdAge -gt 0)
$Results += [PSCustomObject]@{
    编号 = "WIN-06"; 名称 = "密码最长存留期"; 要求 = "不长于90天"
    实际值 = "最长密码期限: $maxPwdAge 天"; 期望值 = "≤90"; 状态 = if ($maxAgeOK) { "合规" } else { "不合规" }; 备注 = ""
}

$pwdHistory = Get-SecPolicyValue "System Access" "PasswordHistorySize"
$historyOK = ([int]$pwdHistory -ge 3)
$Results += [PSCustomObject]@{
    编号 = "WIN-07"; 名称 = "强制密码历史"; 要求 = "不能重复使用最近3次口令"
    实际值 = "记住密码数量: $pwdHistory"; 期望值 = "≥3"; 状态 = if ($historyOK) { "合规" } else { "不合规" }; 备注 = "可选"
}

# 3. 用户权利指派
function Get-UserRight {
    param($RightName)
    if (-not (Test-Path $SecConfigFile)) { return $null }
    $content = Get-Content $SecConfigFile -ErrorAction SilentlyContinue
    $inRight = $false
    foreach ($line in $content) {
        if ($line -match "^\[Privilege Rights\]") { $inRight = $true; continue }
        if ($inRight -and $line -match "^\[") { break }
        if ($inRight -and $line -match "^$RightName\s*=\s*(.*)") { return $matches[1] }
    }
    return $null
}

$rightShutdown = Get-UserRight "SeRemoteShutdownPrivilege"
$shutdownOK = ($rightShutdown -eq "*S-1-5-32-544")
$Results += [PSCustomObject]@{
    编号 = "WIN-08"; 名称 = "从远端系统强制关机"; 要求 = "只指派给Administrators组"
    实际值 = "当前授权: $rightShutdown"; 期望值 = "Administrators"; 状态 = if ($shutdownOK) { "合规" } else { "不合规" }; 备注 = ""
}

$rightShutSys = Get-UserRight "SeShutdownPrivilege"
$shutSysOK = ($rightShutSys -eq "*S-1-5-32-544")
$Results += [PSCustomObject]@{
    编号 = "WIN-09"; 名称 = "关闭系统"; 要求 = "只指派给Administrators组"
    实际值 = "当前授权: $rightShutSys"; 期望值 = "Administrators"; 状态 = if ($shutSysOK) { "合规" } else { "不合规" }; 备注 = ""
}

$rightTakeOwn = Get-UserRight "SeTakeOwnershipPrivilege"
$takeOwnOK = ($rightTakeOwn -eq "*S-1-5-32-544")
$Results += [PSCustomObject]@{
    编号 = "WIN-10"; 名称 = "取得文件或其它对象的所有权"; 要求 = "只指派给Administrators"
    实际值 = "当前授权: $rightTakeOwn"; 期望值 = "Administrators"; 状态 = if ($takeOwnOK) { "合规" } else { "不合规" }; 备注 = ""
}

$rightLocalLogon = Get-UserRight "SeInteractiveLogonRight"
$Results += [PSCustomObject]@{
    编号 = "WIN-11"; 名称 = "允许本地登陆"; 要求 = "指定授权用户"
    实际值 = "当前授权: $rightLocalLogon"; 期望值 = "仅授权的特定用户"; 状态 = "信息"; 备注 = "请人工确认"
}

$rightNetwork = Get-UserRight "SeNetworkLogonRight"
$netAccessOK = ($rightNetwork -notlike "*Everyone*")
$Results += [PSCustomObject]@{
    编号 = "WIN-12"; 名称 = "从网络访问此计算机"; 要求 = "只允许授权帐号"
    实际值 = "当前授权: $rightNetwork"; 期望值 = "特定授权用户"; 状态 = if ($netAccessOK) { "合规" } else { "不合规" }; 备注 = ""
}

# 4. 审核策略（兼容中文）
$auditLogon = Get-AuditStatus -SubEn "Logon" -SubZh "登录"
$logonOK = ($auditLogon -eq "Success and Failure")
$Results += [PSCustomObject]@{
    编号 = "WIN-13"; 名称 = "审核登录事件"; 要求 = "记录登录成功和失败"
    实际值 = "当前设置: $auditLogon"; 期望值 = "Success and Failure"; 状态 = if ($logonOK) { "合规" } else { "不合规" }; 备注 = ""
}

$auditPolicyChange = Get-AuditStatus -SubEn "Policy Change" -SubZh "策略更改"
$policyChangeOK = ($auditPolicyChange -eq "Success and Failure")
$Results += [PSCustomObject]@{
    编号 = "WIN-14"; 名称 = "审核策略更改"; 要求 = "成功和失败都要审核"
    实际值 = "当前设置: $auditPolicyChange"; 期望值 = "Success and Failure"; 状态 = if ($policyChangeOK) { "合规" } else { "不合规" }; 备注 = ""
}

$auditObject = Get-AuditStatus -SubEn "File System" -SubZh "文件系统"
$objectOK = ($auditObject -eq "Success and Failure")
$Results += [PSCustomObject]@{
    编号 = "WIN-15"; 名称 = "审核对象访问"; 要求 = "成功和失败都要审核"
    实际值 = "文件系统审核: $auditObject"; 期望值 = "Success and Failure"; 状态 = if ($objectOK) { "合规" } else { "不合规" }; 备注 = ""
}

$auditDS = Get-AuditStatus -SubEn "Directory Service Access" -SubZh "目录服务访问"
$dsOK = ($auditDS -eq "Success and Failure" -or $auditDS -eq "Failure")
$Results += [PSCustomObject]@{
    编号 = "WIN-16"; 名称 = "审核目录服务访问"; 要求 = "失败"
    实际值 = "当前: $auditDS"; 期望值 = "Failure 或 Success and Failure"; 状态 = if ($dsOK) { "合规" } else { "不合规" }; 备注 = ""
}

$auditPriv = Get-AuditStatus -SubEn "Sensitive Privilege Use" -SubZh "敏感权限使用"
$privOK = ($auditPriv -eq "Success and Failure")
$Results += [PSCustomObject]@{
    编号 = "WIN-17"; 名称 = "审核特权使用"; 要求 = "成功和失败都要审核"
    实际值 = "当前: $auditPriv"; 期望值 = "Success and Failure"; 状态 = if ($privOK) { "合规" } else { "不合规" }; 备注 = ""
}

$auditSys = Get-AuditStatus -SubEn "Security System Extension" -SubZh "安全系统扩展"
$sysOK = ($auditSys -eq "Success and Failure")
$Results += [PSCustomObject]@{
    编号 = "WIN-18"; 名称 = "审核系统事件"; 要求 = "成功和失败都要审核"
    实际值 = "当前: $auditSys"; 期望值 = "Success and Failure"; 状态 = if ($sysOK) { "合规" } else { "不合规" }; 备注 = ""
}

$auditAccount = Get-AuditStatus -SubEn "User Account Management" -SubZh "用户帐户管理"
$accountOK = ($auditAccount -eq "Success and Failure")
$Results += [PSCustomObject]@{
    编号 = "WIN-19"; 名称 = "审核帐户管理"; 要求 = "成功和失败都要审核"
    实际值 = "当前: $auditAccount"; 期望值 = "Success and Failure"; 状态 = if ($accountOK) { "合规" } else { "不合规" }; 备注 = ""
}

$auditProc = Get-AuditStatus -SubEn "Process Creation" -SubZh "进程创建"
$procOK = ($auditProc -eq "Failure")
$Results += [PSCustomObject]@{
    编号 = "WIN-20"; 名称 = "审核过程追踪"; 要求 = "失败"
    实际值 = "当前: $auditProc"; 期望值 = "Failure"; 状态 = if ($procOK) { "合规" } else { "不合规" }; 备注 = ""
}

# 5. 日志大小
$logSizes = @()
foreach ($log in ("Application","System","Security")) {
    $logObj = Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue
    if ($logObj) {
        $sizeMB = [math]::Round($logObj.MaximumSizeInBytes / 1MB, 2)
        $logSizes += "$log : ${sizeMB}MB, 溢出行为: $($logObj.OverflowAction)"
    } else {
        $logSizes += "$log : 无法获取"
    }
}
$Results += [PSCustomObject]@{
    编号 = "WIN-21~23"; 名称 = "日志文件大小（应用、系统、安全）"; 要求 = "至少8192KB，按需要改写"
    实际值 = ($logSizes -join "; "); 期望值 = "≥8MB，Overwrite as needed"; 状态 = "信息"; 备注 = "请检查溢出策略是否为按需改写"
}

# 6. IP协议安全
$filterEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableSecurityFilters" -ErrorAction SilentlyContinue).EnableSecurityFilters -eq 1
$Results += [PSCustomObject]@{
    编号 = "WIN-24"; 名称 = "TCP/IP筛选"; 要求 = "只开放业务所需端口"
    实际值 = "是否启用筛选: $filterEnabled"; 期望值 = "根据业务开启"; 状态 = "信息"; 备注 = "请人工确认"
}

$fwStatus = Get-NetFirewallProfile -All -ErrorAction SilentlyContinue | Select-Object Name, Enabled
$fwEnabled = ($fwStatus | Where-Object {$_.Enabled -eq $true}).Count -ge 1
$Results += [PSCustomObject]@{
    编号 = "WIN-25"; 名称 = "启用Windows防火墙"; 要求 = "启用并配置允许程序"
    实际值 = ($fwStatus | Out-String); 期望值 = "至少域或专用配置文件启用"; 状态 = if ($fwEnabled) { "合规" } else { "不合规" }; 备注 = "请检查防火墙规则"
}

$synVal = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Name "SynAttackProtect" -ErrorAction SilentlyContinue).SynAttackProtect
$synOK = ($synVal -eq 2)
$Results += [PSCustomObject]@{
    编号 = "WIN-26"; 名称 = "SYN攻击保护"; 要求 = "SynAttackProtect=2"
    实际值 = "SynAttackProtect=$synVal"; 期望值 = "2"; 状态 = if ($synOK) { "合规" } else { "不合规" }; 备注 = "需检查其他三项注册表值"
}

# 7. 屏保、远程空闲、默认共享等
$scrEnabled = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue).ScreenSaveActive
$scrTimeout = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue).ScreenSaveTimeOut
$scrSecure = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue).ScreenSaverIsSecure
$scrOK = ($scrEnabled -eq "1" -and $scrTimeout -le 20 -and $scrSecure -eq "1")
$Results += [PSCustomObject]@{
    编号 = "WIN-27"; 名称 = "带密码的屏幕保护"; 要求 = "时间设定20分钟，恢复时使用密码"
    实际值 = "启用: $scrEnabled, 超时: $scrTimeout 分钟, 安全: $scrSecure"; 期望值 = "启用，超时≤20，安全=1"; 状态 = if ($scrOK) { "合规" } else { "不合规" }; 备注 = "当前用户配置"
}

$idleTime = Get-SecPolicyValue "System Access" "MaxIdleTime"
$idleOK = ([int]$idleTime -le 15 -and [int]$idleTime -gt 0)
$Results += [PSCustomObject]@{
    编号 = "WIN-28"; 名称 = "远程登录不活动断连"; 要求 = "设置15分钟"
    实际值 = "空闲时间: $idleTime 分钟"; 期望值 = "≤15"; 状态 = if ($idleOK) { "合规" } else { "不合规" }; 备注 = ""
}

# 默认共享检查 – 先判断Server服务是否运行
$serverSvc = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
if ($serverSvc.Status -ne 'Running') {
    $defaultShares = @()
    $sharesDisabled = $true
} else {
    $defaultShares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {$_.Name -match '^[A-Z]\$$' -or $_.Name -eq 'ADMIN$'}
    $sharesDisabled = ($defaultShares.Count -eq 0)
}
$Results += [PSCustomObject]@{
    编号 = "WIN-29"; 名称 = "关闭默认共享"; 要求 = "非域服务器关闭C$、D$等默认共享"
    实际值 = "存在的默认共享: $($defaultShares.Name -join ', ')"; 期望值 = "无默认共享"; 状态 = if ($sharesDisabled) { "合规" } else { "不合规" }; 备注 = "建议通过注册表 AutoShareServer=0 禁用"
}

if ($serverSvc.Status -eq 'Running') {
    $allShares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {$_.Special -eq $false}
    $sharePerms = @()
    foreach ($share in $allShares) {
        $acl = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
        $sharePerms += "$($share.Name): $($acl.AccountName -join ',')"
    }
    $shareDisplay = ($sharePerms -join "; ")
} else {
    $shareDisplay = "Server服务未运行，无法获取共享列表"
}
$Results += [PSCustomObject]@{
    编号 = "WIN-30"; 名称 = "共享文件夹权限"; 要求 = "只允许授权账户拥有权限"
    实际值 = $shareDisplay; 期望值 = "不含Everyone"; 状态 = "信息"; 备注 = "请人工核实"
}

$ntpServer = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "NtpServer" -ErrorAction SilentlyContinue).NtpServer
$timeSyncOK = ($ntpServer -ne $null)
$Results += [PSCustomObject]@{
    编号 = "WIN-31"; 名称 = "时间同步"; 要求 = "配置时间同步源"
    实际值 = "NTP服务器: $ntpServer"; 期望值 = "已配置同步源"; 状态 = if ($timeSyncOK) { "合规" } else { "不合规" }; 备注 = ""
}

$osVersion = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
$Results += [PSCustomObject]@{
    编号 = "WIN-32"; 名称 = "最新Service Pack"; 要求 = "安装最新的Service Pack"
    实际值 = "Windows 10 版本 $osVersion"; 期望值 = "21H2或更高（建议）"; 状态 = "信息"; 备注 = "请确保已安装最新累积更新"
}

$lastHotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
$hotfixDate = $lastHotfix.InstalledOn
$hotfixOK = ($hotfixDate -and $hotfixDate -gt (Get-Date).AddMonths(-3))
$Results += [PSCustomObject]@{
    编号 = "WIN-33"; 名称 = "最新Hotfix补丁"; 要求 = "安装最新的Hotfix补丁"
    实际值 = "最后安装补丁: $($lastHotfix.HotFixID) 于 $hotfixDate"; 期望值 = "近3个月内"; 状态 = if ($hotfixOK) { "合规" } else { "不合规" }; 备注 = "建议保持自动更新"
}

$avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntivirusProduct" -ErrorAction SilentlyContinue
$avInstalled = ($avProducts -ne $null -and @($avProducts).Count -gt 0)
$avUptodate = $false
if ($avInstalled) {
    foreach ($product in $avProducts) {
        $state = [int]$product.productState
        if (($state -band 0x1000) -ne 0) { $avUptodate = $true; break }
    }
}
$Results += [PSCustomObject]@{
    编号 = "WIN-34"; 名称 = "防病毒软件安装与更新"; 要求 = "安装防病毒软件，并及时更新"
    实际值 = if ($avInstalled) { "已安装: $($avProducts.displayName -join ',')" } else { "未安装" }
    期望值 = "已安装且病毒库最新"; 状态 = if ($avInstalled -and $avUptodate) { "合规" } else { "不合规" }; 备注 = "请确认病毒库更新日期"
}

$depPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "EnforceDEP" -ErrorAction SilentlyContinue
$depOK = ($depPolicy.EnforceDEP -eq 1)
$Results += [PSCustomObject]@{
    编号 = "WIN-35"; 名称 = "数据执行保护(DEP)"; 要求 = "为基本Windows程序和服务启用DEP"
    实际值 = "EnforceDEP = $($depPolicy.EnforceDEP)"; 期望值 = "1"; 状态 = if ($depOK) { "合规" } else { "不合规" }; 备注 = "可选"
}

$criticalServices = @('W32Time', 'WinDefend', 'Dhcp', 'Dnscache', 'EventLog', 'LanmanWorkstation', 'LanmanServer', 'RpcSs')
$runningServices = Get-Service | Where-Object {$_.StartType -ne 'Disabled' -and $_.Status -eq 'Running'} | Select-Object Name
$extraServices = $runningServices | Where-Object { $_.Name -notin $criticalServices }
$Results += [PSCustomObject]@{
    编号 = "WIN-36"; 名称 = "所需服务列表"; 要求 = "不在此列表的服务需关闭"
    实际值 = "运行中的额外服务: $($extraServices.Name -join ', ')"; 期望值 = "仅授权服务"; 状态 = "信息"; 备注 = "请根据业务需要确认"
}

$snmpSvc = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue
if ($snmpSvc -and $snmpSvc.Status -eq 'Running') {
    $community = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -ErrorAction SilentlyContinue).PSObject.Properties.Name
    $communityOK = ($community -notcontains 'public')
} else {
    $communityOK = $true
}
$Results += [PSCustomObject]@{
    编号 = "WIN-37"; 名称 = "SNMP团体名"; 要求 = "修改默认的public"
    实际值 = if ($snmpSvc -and $snmpSvc.Status -eq 'Running') { "团体名: $($community -join ',')" } else { "SNMP未运行" }
    期望值 = "非public"; 状态 = if ($communityOK) { "合规" } else { "不合规" }; 备注 = "可选"
}

$iisInstalled = Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -ErrorAction SilentlyContinue
if ($iisInstalled.State -eq 'Enabled') {
    $iisVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -Name "VersionString" -ErrorAction SilentlyContinue).VersionString
} else {
    $iisVersion = "未安装"
}
$Results += [PSCustomObject]@{
    编号 = "WIN-38"; 名称 = "IIS服务补丁"; 要求 = "升级到最新补丁"
    实际值 = "IIS版本: $iisVersion"; 期望值 = "最新"; 状态 = "信息"; 备注 = "若启用IIS需定期更新"
}

$rdpPort = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -ErrorAction SilentlyContinue).PortNumber
$rdpPortOK = ($rdpPort -ne 3389 -or $rdpPort -eq $null)
$Results += [PSCustomObject]@{
    编号 = "WIN-39"; 名称 = "远程桌面端口修改"; 要求 = "修改默认3389端口"
    实际值 = "当前RDP端口: $rdpPort"; 期望值 = "非3389"; 状态 = if ($rdpPortOK) { "合规" } else { "不合规" }; 备注 = "若开放远程桌面建议修改"
}

$startupItems = Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name, Command, Location
$startupSummary = $startupItems | ForEach-Object { "$($_.Name) : $($_.Command)" }
$Results += [PSCustomObject]@{
    编号 = "WIN-40"; 名称 = "启动项"; 要求 = "列出自动加载的进程和服务，不在此列表的需关闭"
    实际值 = ($startupSummary -join "; "); 期望值 = "仅业务必需"; 状态 = "信息"; 备注 = "请人工审核启动项"
}

$autoPlay = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
$autoPlayOK = ($autoPlay.NoDriveTypeAutoRun -eq 255)
$Results += [PSCustomObject]@{
    编号 = "WIN-41"; 名称 = "关闭自动播放"; 要求 = "所有驱动器关闭自动播放"
    实际值 = "NoDriveTypeAutoRun = $($autoPlay.NoDriveTypeAutoRun)"; 期望值 = "255"; 状态 = if ($autoPlayOK) { "合规" } else { "不合规" }; 备注 = ""
}

# 清理临时文件
Remove-Item $SecConfigFile -Force -ErrorAction SilentlyContinue

# 生成HTML报告
$style = @"
<style>
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; }
h1 { color: #2c3e50; border-bottom: 1px solid #ccc; }
h2 { color: #34495e; margin-top: 30px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
th { background-color: #2c3e50; color: white; padding: 8px; text-align: left; }
td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
tr:nth-child(even) { background-color: #f2f2f2; }
.compliant { background-color: #d4edda; }
.noncompliant { background-color: #f8d7da; }
.info { background-color: #d1ecf1; }
.footer { margin-top: 30px; font-size: 0.9em; color: #777; text-align: center; }
</style>
"@

$html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Windows 10 安全基线报告 - $($HostInfo.主机名)</title>
    $style
</head>
<body>
    <h1>主机安全基线检查报告</h1>
    <p><strong>主机名：</strong> $($HostInfo.主机名)</p>
    <p><strong>IP地址：</strong> $($HostInfo.IP地址)</p>
    <p><strong>操作系统：</strong> $($HostInfo.操作系统) (版本 $($HostInfo.版本号))</p>
    <p><strong>检查时间：</strong> $($HostInfo.检查时间)</p>
    
    <h2>检查结果汇总</h2>
    <table>
        <thead>
            <tr><th>编号</th><th>名称</th><th>要求</th><th>实际值</th><th>期望值</th><th>状态</th><th>备注</th></tr>
        </thead>
        <tbody>
"@

foreach ($item in $Results) {
    $statusClass = switch ($item.状态) {
        "合规" { "compliant" }
        "不合规" { "noncompliant" }
        default { "info" }
    }
    $html += "<tr class='$statusClass'>"
    $html += "<td>$($item.编号)</td><td>$($item.名称)</td><td>$($item.要求)</td><td>$($item.实际值)</td><td>$($item.期望值)</td><td>$($item.状态)</td><td>$($item.备注)</td>"
    $html += "</tr>"
}

$html += @"
        </tbody>
     </div></table>
    <div class="footer">
        注：状态 "合规" 表示满足要求，"不合规" 表示不满足，"信息" 项需人工确认。<br>
        本报告为系统安全基线检查结果，仅供参考。
    </div>
</body>
</html>
"@

$html | Out-File -FilePath $HtmlReport -Encoding UTF8
$Results | Export-Csv -Path $CsvReport -NoTypeInformation -Encoding UTF8

Write-Host "检查完成！报告已生成：" -ForegroundColor Green
Write-Host "HTML报告: $HtmlReport" -ForegroundColor Yellow
Write-Host "CSV报告: $CsvReport" -ForegroundColor Yellow