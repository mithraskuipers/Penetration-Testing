#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Security Posture Assessment (WSPA). Read-only local enumeration with realtime report logging.

.DESCRIPTION
    Shows a numbered list of checks, runs the selected ones, and streams every result to a report file
    as it is produced (flushed on every write). Each step runs in an isolated runspace, so a crash,
    error or hang is recorded and never stops the run.

    Controls during a run:
      S   skip the current check
      Q   abort the run (report and summary are still written)

    All operations are read-only. Nothing is modified and nothing is exploited.
    Secrets are never copied into the report (PowerShell history and environment values are
    reduced to keyword matches and names only).

.PARAMETER Checks
    Check IDs to run without the menu, for example: -Checks 1,3,5-7

.PARAMETER All
    Run every check without the menu.

.PARAMETER OutputDir
    Folder for the report. Default: .\reports next to the script (falls back to %TEMP%).

.PARAMETER StepTimeoutSec
    Maximum seconds a single step may run before it is stopped and recorded as TIMEOUT. Default 180.

.PARAMETER TargetPath
    Optional path for an extra ACL review (icacls and Get-Acl) in check 4.

.PARAMETER DeepScan
    Recurse fully in check 4 (Program Files) and check 11 (unattend files on the system drive). Slow.

.PARAMETER IncludeWin32Product
    Also query Win32_Product in check 8. Slow, and it triggers MSI consistency checks.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-SecurityAssessment.ps1

.EXAMPLE
    .\Invoke-SecurityAssessment.ps1 -Checks 1-3,9 -OutputDir D:\Audit
#>
[CmdletBinding()]
param(
    [string[]]$Checks,
    [switch]$All,
    [string]$OutputDir,
    [ValidateRange(10, 3600)][int]$StepTimeoutSec = 180,
    [string]$TargetPath,
    [switch]$DeepScan,
    [switch]$IncludeWin32Product
)

if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    Write-Host 'This tool supports Windows only.' -ForegroundColor Red
    return
}

$ErrorActionPreference = 'Continue'
$script:Version        = '1.0.0'
$script:Writer         = $null
$script:ReportPath     = $null
$script:LogFailed      = $false
$script:Results        = New-Object System.Collections.Generic.List[object]
$script:Findings       = New-Object System.Collections.Generic.List[object]
$script:Issues         = New-Object System.Collections.Generic.List[object]
$script:CurrentCheck   = ''
$script:CurFindings    = 0
$script:LastBlank      = $true
$script:AbortRequested = $false
$script:SelectedIds    = @()
$script:RuleWidth      = 78
$script:StatusColor    = @{
    'COMPLETED' = 'Green'; 'PARTIAL' = 'Yellow'; 'FAILED' = 'Red'; 'SKIPPED' = 'Yellow'
    'ABORTED' = 'Red'; 'NOT RUN' = 'DarkGray'; 'NOT SELECTED' = 'DarkGray'; 'RUNNING' = 'Cyan'
}

$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$script:CanReadKeys = $true
try { [void][Console]::KeyAvailable } catch { $script:CanReadKeys = $false }

$script:Ctx = @{
    IsAdmin             = $script:IsAdmin
    DeepScan            = [bool]$DeepScan
    TargetPath          = $TargetPath
    IncludeWin32Product = [bool]$IncludeWin32Product
}

# ----------------------------------------------------------------------------------------------
# Runspace prelude: helpers available to every step script
# ----------------------------------------------------------------------------------------------
$script:Prelude = @'
param($Code, $Ctx)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$BadSid = @{ 'S-1-1-0' = 'Everyone'; 'S-1-5-32-545' = 'BUILTIN\Users'; 'S-1-5-11' = 'Authenticated Users' }
function T {
    param([Parameter(ValueFromPipeline = $true)]$o, [switch]$List)
    begin { $a = New-Object System.Collections.ArrayList }
    process { if ($null -ne $o) { [void]$a.Add($o) } }
    end {
        if ($a.Count -gt 0) {
            if ($List) { $a | Format-List | Out-String -Width 220 }
            else { $a | Format-Table -AutoSize -Wrap | Out-String -Width 220 }
        }
    }
}
function Flag { param($Sev, $Msg) "[FINDING:$Sev] $Msg" }
function Get-BadWrite {
    param($Acl, [int]$Mask = 6)
    foreach ($r in $Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($r.AccessControlType -ne 'Allow') { continue }
        $sid = $r.IdentityReference.Value
        if (-not $BadSid.ContainsKey($sid)) { continue }
        $rights = if ($null -ne $r.FileSystemRights) { $r.FileSystemRights } else { $r.RegistryRights }
        if (([int]$rights -band $Mask) -ne 0) { [pscustomobject]@{ Identity = $BadSid[$sid]; Rights = "$rights" } }
    }
}
$sb = [scriptblock]::Create($Code)
& $sb $Ctx | Out-String -Stream -Width 220
'@

# ----------------------------------------------------------------------------------------------
# Check catalog
# ----------------------------------------------------------------------------------------------
$script:Catalog = @(

    @{ Id = 1; Name = 'System Information'; Admin = $false
        Guide = @(
            'Build number vs the latest supported build for this Windows version (patched, still in support?).',
            'Missing cumulative updates for 3+ months is a red flag.',
            'Architecture mismatches (32-bit installs on a 64-bit OS can hide old DLLs).')
        Steps = @(
            @{ N = 'systeminfo'; S = { param($Ctx)
                systeminfo 2>&1
            } },
            @{ N = 'Operating system summary'; S = { param($Ctx)
                Get-CimInstance Win32_OperatingSystem |
                    Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime | T -List
                "PROCESSOR_ARCHITECTURE : $env:PROCESSOR_ARCHITECTURE"
            } },
            @{ N = 'Installed hotfixes (newest first)'; S = { param($Ctx)
                $hf = @(Get-HotFix | Sort-Object InstalledOn -Descending)
                $hf | Select-Object HotFixID, Description, InstalledBy, InstalledOn | T
                $latest = $hf | Where-Object { $_.InstalledOn } | Select-Object -First 1
                if (-not $latest) { Flag 'LOW' 'No hotfix install dates available, patch level could not be verified' }
                elseif (((Get-Date) - $latest.InstalledOn).Days -gt 90) {
                    Flag 'MEDIUM' ('Most recent hotfix was installed {0}, over 90 days ago' -f $latest.InstalledOn.ToString('yyyy-MM-dd'))
                }
            } },
            @{ N = 'Legacy patch view (wmic qfe)'; S = { param($Ctx)
                if (Get-Command wmic.exe -ErrorAction SilentlyContinue) { wmic qfe list 2>&1 }
                else { 'wmic.exe is not present on this system (removed in recent Windows 11 builds).' }
            } }
        ) },

    @{ Id = 2; Name = 'User and Group Enumeration'; Admin = $false
        Guide = @(
            'Stale or disabled accounts still in the Administrators group.',
            'Accounts with PasswordRequired False or non-expiring passwords.',
            'Shared or generic accounts (svc_, backup, temp) with admin rights.',
            'Guest account should be disabled.')
        Steps = @(
            @{ N = 'Current user, groups and privileges (whoami /all)'; S = { param($Ctx)
                whoami /all 2>&1
            } },
            @{ N = 'Local accounts (net user)'; S = { param($Ctx)
                net user 2>&1
            } },
            @{ N = 'Local administrators (net localgroup)'; S = { param($Ctx)
                $g = (Get-LocalGroup -SID 'S-1-5-32-544').Name
                net localgroup $g 2>&1
            } },
            @{ N = 'Local user detail'; S = { param($Ctx)
                $u = @(Get-LocalUser)
                $u | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordExpires | T
                foreach ($x in $u) {
                    if (-not $x.Enabled) { continue }
                    if (-not $x.PasswordRequired) { Flag 'MEDIUM' "Enabled account '$($x.Name)' does not require a password" }
                    elseif ($null -eq $x.PasswordExpires) { Flag 'LOW' "Enabled account '$($x.Name)' has a non-expiring password" }
                }
            } },
            @{ N = 'Administrators group members'; S = { param($Ctx)
                $m = @(Get-LocalGroupMember -SID 'S-1-5-32-544')
                $m | Select-Object Name, ObjectClass, PrincipalSource | T
                foreach ($x in $m) {
                    if ($x.PrincipalSource -ne 'Local' -or $x.ObjectClass -ne 'User') { continue }
                    $lu = Get-LocalUser -SID $x.SID -ErrorAction SilentlyContinue
                    if ($lu -and -not $lu.Enabled) { Flag 'LOW' "Disabled account '$($x.Name)' is still a member of Administrators" }
                }
            } },
            @{ N = 'Guest account status'; S = { param($Ctx)
                $gu = @(Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' })
                $gu | Select-Object Name, Enabled | T
                foreach ($x in $gu) { if ($x.Enabled) { Flag 'MEDIUM' "Guest account '$($x.Name)' is enabled" } }
            } }
        ) },

    @{ Id = 3; Name = 'Privilege Tokens'; Admin = $false
        Guide = @(
            'SeImpersonate, SeAssignPrimaryToken, SeDebug, SeBackup, SeRestore, SeTakeOwnership and SeLoadDriver on an account that does not need them deserve investigation.',
            'They are the classic building blocks of local privilege escalation.')
        Steps = @(
            @{ N = 'Current token privileges (whoami /priv)'; S = { param($Ctx)
                $notable = 'SeImpersonatePrivilege', 'SeAssignPrimaryTokenPrivilege', 'SeDebugPrivilege', 'SeBackupPrivilege',
                           'SeRestorePrivilege', 'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege'
                $raw = @(whoami /priv 2>&1)
                $raw
                if ($Ctx.IsAdmin) {
                    'Elevated session: these privileges are expected on an administrator token, findings suppressed.'
                }
                else {
                    foreach ($p in $notable) {
                        if ($raw -match "\b$p\b") { Flag 'MEDIUM' "Non-admin token holds $p (verify it is required)" }
                    }
                }
            } }
        ) },

    @{ Id = 4; Name = 'File, Folder and Registry Permissions'; Admin = $false
        Guide = @(
            'Service binaries, scheduled task scripts or startup items writable by Everyone, Authenticated Users or BUILTIN\Users.',
            'Overly broad registry ACLs on service keys let a low-privilege user repoint a service binary path.')
        Steps = @(
            @{ N = 'Writable folders under Program Files'; S = { param($Ctx)
                $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) |
                    Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
                $dirs = foreach ($r in $roots) {
                    Get-Item -LiteralPath $r
                    if ($Ctx.DeepScan) { Get-ChildItem -LiteralPath $r -Directory -Recurse -ErrorAction SilentlyContinue }
                    else { Get-ChildItem -LiteralPath $r -Directory -ErrorAction SilentlyContinue }
                }
                $n = 0
                $hits = foreach ($d in $dirs) {
                    $n++
                    try { $acl = Get-Acl -LiteralPath $d.FullName -ErrorAction Stop } catch { continue }
                    foreach ($b in @(Get-BadWrite $acl 6)) {
                        [pscustomobject]@{ Path = $d.FullName; Identity = $b.Identity; Rights = $b.Rights }
                    }
                }
                $scope = if ($Ctx.DeepScan) { 'full recursion' } else { 'top-level folders, use -DeepScan for full recursion' }
                "Folders inspected: $n ($scope)"
                $hits | T
                foreach ($h in @($hits)) { Flag 'HIGH' "Writable by $($h.Identity): $($h.Path) ($($h.Rights))" }
                if (-not $hits) { 'No Everyone, Users or Authenticated Users write access found.' }
            } },
            @{ N = 'Registry ACL: Services root key'; S = { param($Ctx)
                $acl = Get-Acl -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services'
                $acl | T -List
                foreach ($b in @(Get-BadWrite $acl 6)) { Flag 'HIGH' "Services key writable by $($b.Identity) ($($b.Rights))" }
            } },
            @{ N = 'Registry ACL: individual service keys'; S = { param($Ctx)
                $n = 0; $found = 0
                foreach ($k in Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue) {
                    $n++
                    try { $acl = Get-Acl -LiteralPath $k.PSPath -ErrorAction Stop } catch { continue }
                    foreach ($b in @(Get-BadWrite $acl 6)) {
                        $found++
                        Flag 'HIGH' "Service key '$($k.PSChildName)' writable by $($b.Identity) ($($b.Rights))"
                    }
                }
                "Service keys inspected: $n, with weak permissions: $found"
            } },
            @{ N = 'Custom path ACL (-TargetPath)'; S = { param($Ctx)
                if (-not $Ctx.TargetPath) { 'No -TargetPath supplied. Step not applicable.'; return }
                icacls $Ctx.TargetPath 2>&1
                Get-Acl -LiteralPath $Ctx.TargetPath | T -List
            } }
        ) },

    @{ Id = 5; Name = 'Services'; Admin = $false
        Guide = @(
            'Services running as LocalSystem with a binary path writable by non-admins.',
            'Unquoted paths containing spaces can let Windows run a planted executable from an intermediate folder.',
            'Services running as a domain or service account with a weak or reused password.')
        Steps = @(
            @{ N = 'Running services'; S = { param($Ctx)
                Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name, DisplayName, Status | T
            } },
            @{ N = 'Service configuration (account, start mode, binary path)'; S = { param($Ctx)
                Get-CimInstance Win32_Service | Select-Object Name, StartName, StartMode, PathName | T
            } },
            @{ N = 'Unquoted service paths containing spaces'; S = { param($Ctx)
                $hits = foreach ($s in @(Get-CimInstance Win32_Service)) {
                    $p = $s.PathName
                    if (-not $p -or $p -match '^\s*"') { continue }
                    if ($p -match '^(?<exe>.+?\.exe)(\s|$)') { $exe = $Matches['exe'] } else { $exe = $p }
                    if ($exe -match '\s') { [pscustomobject]@{ Name = $s.Name; StartName = $s.StartName; PathName = $p } }
                }
                $hits | T
                foreach ($h in @($hits)) { Flag 'MEDIUM' "Unquoted service path: $($h.Name) ($($h.StartName)) -> $($h.PathName)" }
                if (-not $hits) { 'No unquoted service paths with spaces detected.' }
            } },
            @{ N = 'Service binary permissions'; S = { param($Ctx)
                $n = 0; $found = 0
                foreach ($s in @(Get-CimInstance Win32_Service)) {
                    $p = $s.PathName
                    if (-not $p) { continue }
                    if ($p -match '^\s*"([^"]+)"') { $exe = $Matches[1] }
                    elseif ($p -match '^(.+?\.exe)(\s|$)') { $exe = $Matches[1] }
                    else { $exe = $p }
                    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { continue }
                    try { $acl = Get-Acl -LiteralPath $exe -ErrorAction Stop } catch { continue }
                    $n++
                    foreach ($b in @(Get-BadWrite $acl 6)) {
                        $found++
                        Flag 'HIGH' "Service '$($s.Name)' ($($s.StartName)) binary writable by $($b.Identity): $exe"
                    }
                }
                "Service binaries inspected: $n, with weak permissions: $found"
            } },
            @{ N = 'Service permissions (Sysinternals accesschk)'; S = { param($Ctx)
                $ac = Get-Command accesschk64.exe, accesschk.exe -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not $ac) { 'accesschk.exe was not found on PATH. Step not applicable (optional Sysinternals tool).'; return }
                & $ac.Source -uwcqv 'Authenticated Users' * -accepteula 2>&1
            } }
        ) },

    @{ Id = 6; Name = 'Scheduled Tasks and Autoruns'; Admin = $false
        Guide = @(
            'Tasks or startup entries pointing at scripts or binaries in user-writable locations (%TEMP%, Downloads, world-writable shares).',
            'Tasks running as SYSTEM that call a script a standard user can edit.',
            'Sysinternals Autoruns gives the most complete picture when available.')
        Steps = @(
            @{ N = 'Active scheduled tasks'; S = { param($Ctx)
                $t = @(Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' })
                $t | Select-Object TaskName, TaskPath, State | T
                foreach ($x in $t) {
                    foreach ($a in @($x.Actions)) {
                        if (-not $a.Execute) { continue }
                        $e = [Environment]::ExpandEnvironmentVariables($a.Execute)
                        if ($e -match '\\(Temp|Downloads)\\|\\Users\\Public\\') {
                            Flag 'MEDIUM' "Task '$($x.TaskPath)$($x.TaskName)' runs from a user-writable location: $e"
                        }
                    }
                }
            } },
            @{ N = 'Scheduled tasks, verbose (schtasks)'; S = { param($Ctx)
                schtasks /query /fo LIST /v 2>&1
            } },
            @{ N = 'Startup commands'; S = { param($Ctx)
                $s = @(Get-CimInstance Win32_StartupCommand)
                $s | Select-Object Name, Command, Location, User | T
                foreach ($x in $s) {
                    if ($x.Command -match '\\(Temp|Downloads)\\|\\Users\\Public\\') {
                        Flag 'MEDIUM' "Startup item '$($x.Name)' runs from a user-writable location: $($x.Command)"
                    }
                }
            } },
            @{ N = 'Run key (HKLM)'; S = { param($Ctx)
                reg query 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run' 2>&1
            } },
            @{ N = 'Run key (HKCU)'; S = { param($Ctx)
                reg query 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' 2>&1
            } },
            @{ N = 'Autoruns (Sysinternals autorunsc)'; S = { param($Ctx)
                $ar = Get-Command autorunsc64.exe, autorunsc.exe -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not $ar) { 'autorunsc.exe was not found on PATH. Step not applicable (optional Sysinternals tool).'; return }
                & $ar.Source -a * -c -nobanner -accepteula 2>&1
            } }
        ) },

    @{ Id = 7; Name = 'Network Configuration and Exposure'; Admin = $true
        Guide = @(
            'Listening services bound to 0.0.0.0 that should only be on 127.0.0.1.',
            'Firewall disabled on any profile, or broad inbound Allow rules (any port, any source).',
            'Open shares: review the permissions on each share path.')
        Steps = @(
            @{ N = 'IP configuration (ipconfig /all)'; S = { param($Ctx)
                ipconfig /all 2>&1
            } },
            @{ N = 'Listening TCP ports'; S = { param($Ctx)
                $procs = @{}
                Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }
                $l = @(Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
                    Select-Object LocalAddress, LocalPort, OwningProcess, @{ n = 'Process'; e = { $procs[[int]$_.OwningProcess] } })
                $l | T
                $wide = @($l | Where-Object { $_.LocalAddress -in '0.0.0.0', '::' })
                "Listeners bound to all interfaces: $($wide.Count) of $($l.Count)"
            } },
            @{ N = 'Connections (netstat -ano)'; S = { param($Ctx)
                netstat -ano 2>&1
            } },
            @{ N = 'Firewall profiles'; S = { param($Ctx)
                $fp = @(Get-NetFirewallProfile)
                $fp | Select-Object Name, Enabled | T
                foreach ($p in $fp) {
                    if ("$($p.Enabled)" -eq 'False') { Flag 'HIGH' "Windows Firewall is disabled on the $($p.Name) profile" }
                }
            } },
            @{ N = 'Enabled inbound firewall rules'; S = { param($Ctx)
                Get-NetFirewallRule -Enabled True -Direction Inbound | Select-Object DisplayName, Action, Profile | T
            } },
            @{ N = 'ARP cache'; S = { param($Ctx)
                arp -a 2>&1
            } },
            @{ N = 'Routing table'; S = { param($Ctx)
                route print 2>&1
            } },
            @{ N = 'Open shares (net share)'; S = { param($Ctx)
                net share 2>&1
            } },
            @{ N = 'Share path permissions'; S = { param($Ctx)
                $sh = @(Get-SmbShare -ErrorAction Stop)
                $sh | Select-Object Name, Path, Description | T
                foreach ($s in $sh) {
                    if ($s.Path -and -not $s.Special) { "--- icacls $($s.Path)"; icacls $s.Path 2>&1 }
                }
            } }
        ) },

    @{ Id = 8; Name = 'Installed Software and Patch Hygiene'; Admin = $false
        Guide = @(
            'Old or unsupported versions (browsers, Java, 7-Zip, Adobe products are common offenders).',
            'Software installed outside Program Files with weak folder permissions.')
        Steps = @(
            @{ N = 'Installed software (registry uninstall keys)'; S = { param($Ctx)
                $paths = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                         'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
                    Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName | T
            } },
            @{ N = 'Win32_Product (opt-in)'; S = { param($Ctx)
                if (-not $Ctx.IncludeWin32Product) {
                    'Not run. Win32_Product triggers MSI consistency checks. Use -IncludeWin32Product to enable.'
                    return
                }
                Get-CimInstance Win32_Product | Select-Object Name, Version | Sort-Object Name | T
            } }
        ) },

    @{ Id = 9; Name = 'Security Controls'; Admin = $true
        Guide = @(
            'Defender (or the third-party AV) real-time protection disabled.',
            'UAC turned off or set to never notify.',
            'LSA Protection (RunAsPPL) off makes credential dumping from LSASS easier.',
            'System drive not encrypted.')
        Steps = @(
            @{ N = 'Defender status'; S = { param($Ctx)
                $d = Get-MpComputerStatus -ErrorAction Stop
                $d | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntispywareEnabled, AntivirusSignatureLastUpdated | T -List
                if (-not $d.AntivirusEnabled) { Flag 'MEDIUM' 'Defender antivirus is disabled (verify a third-party AV is active)' }
                if (-not $d.RealTimeProtectionEnabled) { Flag 'MEDIUM' 'Defender real-time protection is disabled (verify a third-party AV is active)' }
            } },
            @{ N = 'UAC configuration'; S = { param($Ctx)
                $p = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                $p | Select-Object EnableLUA, ConsentPromptBehaviorAdmin, ConsentPromptBehaviorUser, FilterAdministratorToken | T -List
                if ($p.EnableLUA -eq 0) { Flag 'HIGH' 'UAC is disabled (EnableLUA = 0)' }
                if ($p.ConsentPromptBehaviorAdmin -eq 0) { Flag 'MEDIUM' 'UAC admin prompt is set to never notify (ConsentPromptBehaviorAdmin = 0)' }
            } },
            @{ N = 'LSA protection (RunAsPPL)'; S = { param($Ctx)
                $v = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
                $shown = if ($null -eq $v) { '<not set>' } else { $v }
                "RunAsPPL = $shown"
                if ($v -notin 1, 2) { Flag 'LOW' 'LSA protection (RunAsPPL) is not enabled' }
            } },
            @{ N = 'Device Guard and Credential Guard'; S = { param($Ctx)
                Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
                    Select-Object SecurityServicesConfigured, SecurityServicesRunning, VirtualizationBasedSecurityStatus | T -List
            } },
            @{ N = 'BitLocker volumes'; S = { param($Ctx)
                $bl = @(Get-BitLockerVolume -ErrorAction Stop)
                $bl | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage | T
                foreach ($v in $bl) {
                    if ($v.MountPoint -eq $env:SystemDrive -and "$($v.ProtectionStatus)" -ne 'On') {
                        Flag 'MEDIUM' "System drive $($v.MountPoint) is not protected by BitLocker"
                    }
                }
            } }
        ) },

    @{ Id = 10; Name = 'Auditing and Logging'; Admin = $true
        Guide = @(
            'Logon auditing (success and failure) not enabled makes after-the-fact detection hard.',
            'A small Security log with overwrite-as-needed means events roll off quickly.')
        Steps = @(
            @{ N = 'Audit policy (auditpol)'; S = { param($Ctx)
                $o = @(auditpol /get /category:* 2>&1)
                $o
                if ($LASTEXITCODE -ne 0) { throw "auditpol exited with code $LASTEXITCODE (administrator rights are required)" }
            } },
            @{ N = 'Logon auditing state'; S = { param($Ctx)
                $g = '{0CCE9215-69AE-11D9-BED3-505054503030}'
                $o = @(auditpol /get "/subcategory:$g" /r 2>&1)
                if ($LASTEXITCODE -ne 0) { throw "auditpol exited with code $LASTEXITCODE (administrator rights are required)" }
                $line = $o | Where-Object { "$_" -match '0CCE9215' } | Select-Object -First 1
                if (-not $line) { 'Logon audit setting could not be parsed.'; return }
                $v = ("$line" -split ',')[-1].Trim()
                "Logon subcategory setting value: $v (0 = none, 1 = success, 2 = failure, 3 = success and failure)"
                if ($v -eq '0') { Flag 'MEDIUM' 'Logon auditing is not enabled (no success or failure events)' }
                elseif ($v -ne '3') { Flag 'LOW' 'Logon auditing is only partially enabled (success or failure missing)' }
            } },
            @{ N = 'Security log configuration (wevtutil)'; S = { param($Ctx)
                $o = @(wevtutil gl Security 2>&1)
                $o
                if ($LASTEXITCODE -ne 0) { throw "wevtutil exited with code $LASTEXITCODE (administrator rights are required)" }
            } },
            @{ N = 'Security log size'; S = { param($Ctx)
                $l = Get-WinEvent -ListLog Security -ErrorAction Stop
                $l | Select-Object LogName, IsEnabled, LogMode, MaximumSizeInBytes, RecordCount | T -List
                if ($l.MaximumSizeInBytes -lt 100MB) {
                    Flag 'LOW' ('Security log maximum size is {0} MB (below 100 MB), events may roll off quickly' -f [math]::Round($l.MaximumSizeInBytes / 1MB))
                }
            } }
        ) },

    @{ Id = 11; Name = 'Credential Exposure'; Admin = $false
        Guide = @(
            'Leftover unattended-install or sysprep files with embedded credentials.',
            'Passwords visible in shell history or environment variables.',
            'The report never contains history content or environment values, only matches and names.')
        Steps = @(
            @{ N = 'Saved credentials (cmdkey /list)'; S = { param($Ctx)
                cmdkey /list 2>&1
            } },
            @{ N = 'Unattended install files'; S = { param($Ctx)
                $names = 'Unattend.xml', 'sysprep.inf', 'sysprep.xml'
                $found = @()
                if ($Ctx.DeepScan) {
                    'Scope: full recursion of the system drive.'
                    $found = @(Get-ChildItem -Path "$env:SystemDrive\" -Recurse -Force -File -Include $names -ErrorAction SilentlyContinue)
                }
                else {
                    'Scope: common locations, use -DeepScan for full recursion.'
                    $locs = @("$env:SystemDrive\", $env:SystemRoot, "$env:SystemRoot\Panther", "$env:SystemRoot\Panther\Unattend",
                              "$env:SystemRoot\System32", "$env:SystemRoot\System32\Sysprep", "$env:SystemRoot\System32\Sysprep\Panther")
                    foreach ($l in $locs) {
                        if (Test-Path -LiteralPath $l) {
                            $found += @(Get-ChildItem -LiteralPath $l -File -Force -ErrorAction SilentlyContinue |
                                Where-Object { $names -contains $_.Name })
                        }
                    }
                }
                $found | Select-Object FullName, Length, LastWriteTime | T
                foreach ($f in $found) { Flag 'MEDIUM' "Unattend or sysprep file present, review for embedded credentials: $($f.FullName)" }
                if (-not $found) { 'No unattended or sysprep files found in the scanned locations.' }
            } },
            @{ N = 'PowerShell history (keyword matches only)'; S = { param($Ctx)
                $h = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
                if (-not (Test-Path -LiteralPath $h)) { "No PSReadLine history file at $h"; return }
                $pat = 'passw(or)?d|pwd|secret|token|api[-_]?key|ConvertTo-SecureString|-Credential|Authorization'
                $lines = @(Get-Content -LiteralPath $h -ErrorAction Stop)
                "History file: $h ($($lines.Count) lines). Content is not copied to this report."
                $hits = New-Object System.Collections.ArrayList
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    if ($lines[$i] -match $pat) { [void]$hits.Add(('line {0} (keyword: {1})' -f ($i + 1), $Matches[0])) }
                }
                $hits | Select-Object -First 50
                if ($hits.Count -gt 0) { Flag 'MEDIUM' "$($hits.Count) PowerShell history line(s) contain credential-related keywords" }
                else { 'No credential-related keywords found in history.' }
            } },
            @{ N = 'Environment variables (names only)'; S = { param($Ctx)
                $all = @(Get-ChildItem Env:)
                "Total environment variables: $($all.Count). Values are not copied to this report."
                $sus = @($all | Where-Object { $_.Name -match 'pass|pwd|secret|token|key|credential' })
                $sus | Select-Object Name, @{ n = 'ValueLength'; e = { "$($_.Value)".Length } } | T
                foreach ($s in $sus) { Flag 'LOW' "Environment variable '$($s.Name)' has a secret-like name, review its value" }
            } }
        ) }
)

# ----------------------------------------------------------------------------------------------
# Helpers: logging and console
# ----------------------------------------------------------------------------------------------
function Write-Log {
    param([string]$Text = '')
    if ($null -eq $script:Writer) { return }
    try { $script:Writer.WriteLine($Text) }
    catch {
        if (-not $script:LogFailed) {
            $script:LogFailed = $true
            Write-Host "  [!] Report write failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Emit {
    param([string]$Text = '', [string]$Color = 'Gray')
    Write-Host $Text -ForegroundColor $Color
    Write-Log $Text
}

function Get-Width {
    try { $w = $Host.UI.RawUI.WindowSize.Width; if ($w -ge 40) { return $w } } catch { }
    return 100
}

function Fit {
    param([string]$s, [int]$n)
    if ($s.Length -le $n) { return $s }
    return $s.Substring(0, [Math]::Max(0, $n - 3)) + '...'
}

function Format-Time {
    param([double]$Seconds)
    $t = [TimeSpan]::FromSeconds($Seconds)
    return ('{0:00}:{1:00}' -f [math]::Floor($t.TotalMinutes), $t.Seconds)
}

function Show-Progress {
    param([string]$Text)
    $w = (Get-Width) - 1
    Write-Host ("`r" + (Fit $Text $w).PadRight($w)) -NoNewline -ForegroundColor Cyan
}

function Clear-Progress {
    $w = (Get-Width) - 1
    Write-Host ("`r" + (' ' * $w) + "`r") -NoNewline
}

function Write-BoxRow {
    param([string]$Text, [string]$Color = 'Cyan')
    Write-Host ('  | ' + (Fit $Text 72).PadRight(72) + ' |') -ForegroundColor $Color
}

function Show-Banner {
    $rule  = '  +' + ('-' * 74) + '+'
    $title = 'WINDOWS SECURITY POSTURE ASSESSMENT'
    $ver   = "v$($script:Version)"
    $elev  = if ($script:IsAdmin) { 'Elevated: yes' } else { 'Elevated: NO' }
    Write-Host ''
    Write-Host $rule -ForegroundColor DarkCyan
    Write-BoxRow ($title + $ver.PadLeft(72 - $title.Length)) 'White'
    Write-BoxRow 'Read-only local enumeration. No changes are made to this system.' 'Gray'
    Write-BoxRow ("Host: $env:COMPUTERNAME   User: $env:USERDOMAIN\$env:USERNAME   $elev") $(if ($script:IsAdmin) { 'Gray' } else { 'Yellow' })
    Write-Host $rule -ForegroundColor DarkCyan
}

function Show-Menu {
    Write-Host ''
    Write-Host ('  {0,-5}{1,-44}{2,-8}{3}' -f 'ID', 'CHECK', 'STEPS', 'ELEVATION') -ForegroundColor Cyan
    Write-Host ('  ' + ('-' * 74)) -ForegroundColor DarkGray
    foreach ($c in $script:Catalog) {
        $e = if ($c.Admin) { 'recommended' } else { '-' }
        $col = if ($c.Admin -and -not $script:IsAdmin) { 'Yellow' } else { 'Gray' }
        Write-Host ('  {0,-5}{1,-44}{2,-8}{3}' -f ('{0:D2}' -f $c.Id), $c.Name, $c.Steps.Count, $e) -ForegroundColor $col
    }
    Write-Host ('  ' + ('-' * 74)) -ForegroundColor DarkGray
}

function Resolve-Selection {
    param([string[]]$Tokens, [int]$Max)
    $ids = New-Object 'System.Collections.Generic.SortedSet[int]'
    foreach ($t in (($Tokens -join ',') -split '[,\s;]+')) {
        if (-not $t) { continue }
        if ($t -match '^(\d+)-(\d+)$') {
            $a = [int]$Matches[1]; $b = [int]$Matches[2]
            if ($a -gt $b) { $a, $b = $b, $a }
            for ($i = $a; $i -le $b; $i++) { [void]$ids.Add($i) }
        }
        elseif ($t -match '^\d+$') { [void]$ids.Add([int]$t) }
        else { return $null }
    }
    if ($ids.Count -eq 0) { return $null }
    foreach ($i in $ids) { if ($i -lt 1 -or $i -gt $Max) { return $null } }
    return [int[]]@($ids)
}

function Read-Selection {
    while ($true) {
        $in = Read-Host '  Select checks [A = all | e.g. 1,3,5-7 | Q = quit]'
        if ($in -match '^\s*q(uit)?\s*$') { return $null }
        if ($in -match '^\s*a(ll)?\s*$') { return [int[]](1..$script:Catalog.Count) }
        $sel = Resolve-Selection -Tokens @($in) -Max $script:Catalog.Count
        if ($sel) { return $sel }
        Write-Host "  Invalid selection. Use numbers 1-$($script:Catalog.Count), ranges like 2-4, A or Q." -ForegroundColor Red
    }
}

# ----------------------------------------------------------------------------------------------
# Report file
# ----------------------------------------------------------------------------------------------
function Open-Report {
    param([string]$Dir)
    if (-not $Dir) {
        $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $Dir = Join-Path $base 'reports'
    }
    $name = 'WSPA_{0}_{1}.txt' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss')
    foreach ($d in @($Dir, (Join-Path ([IO.Path]::GetTempPath()) 'WSPA-reports'))) {
        try {
            if (-not (Test-Path -LiteralPath $d)) { [void](New-Item -ItemType Directory -Path $d -Force -ErrorAction Stop) }
            $path = Join-Path $d $name
            $fs = New-Object System.IO.FileStream($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            $w = New-Object System.IO.StreamWriter($fs, (New-Object System.Text.UTF8Encoding($true)))
            $w.AutoFlush = $true
            $script:Writer = $w
            $script:ReportPath = $path
            return $true
        }
        catch { Write-Host "  [!] Cannot write to '$d': $($_.Exception.Message)" -ForegroundColor Yellow }
    }
    return $false
}

function Write-ReportHeader {
    $os = try { (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { [Environment]::OSVersion.VersionString }
    $rule = '=' * $script:RuleWidth
    Write-Log $rule
    Write-Log "WINDOWS SECURITY POSTURE ASSESSMENT  v$($script:Version)"
    Write-Log 'Mode            : read-only enumeration'
    Write-Log $rule
    Write-Log "Host            : $env:COMPUTERNAME"
    Write-Log "User            : $env:USERDOMAIN\$env:USERNAME"
    Write-Log "Elevated        : $(if ($script:IsAdmin) { 'yes' } else { 'NO (some checks return partial results)' })"
    Write-Log "Operating system: $os"
    Write-Log "PowerShell      : $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
    Write-Log "Started         : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Log "Report file     : $($script:ReportPath)"
    Write-Log ("Options         : StepTimeout={0}s DeepScan={1} Win32Product={2} TargetPath={3}" -f $StepTimeoutSec, [bool]$DeepScan, [bool]$IncludeWin32Product, $(if ($TargetPath) { $TargetPath } else { '-' }))
    Write-Log ("Selected checks : {0}" -f (($script:SelectedIds | ForEach-Object { '{0:D2}' -f $_ }) -join ', '))
    Write-Log $rule
}

# ----------------------------------------------------------------------------------------------
# Step execution engine
# ----------------------------------------------------------------------------------------------
function Write-Chunk {
    param([string]$Text)
    foreach ($line in ($Text -split "\r?\n")) {
        $l = $line.TrimEnd()
        if ($l.Length -eq 0) {
            if ($script:LastBlank) { continue }
            $script:LastBlank = $true
            Write-Log ''
            continue
        }
        $script:LastBlank = $false
        if ($l -match '^\[FINDING:(HIGH|MEDIUM|LOW)\]\s*(.*)$') {
            $sev = $Matches[1]; $msg = $Matches[2]
            $script:Findings.Add([pscustomobject]@{ Sev = $sev; Check = $script:CurrentCheck; Message = $msg })
            $script:CurFindings++
            Write-Log ('     >> FINDING [{0}] {1}' -f $sev, $msg)
        }
        else { Write-Log ('     ' + $l) }
    }
}

function Receive-StepData {
    param($Ps, $Out, [ref]$OutIdx, [ref]$ErrIdx, $Res)
    while ($OutIdx.Value -lt $Out.Count) {
        $item = $Out[$OutIdx.Value]
        $OutIdx.Value++
        Write-Chunk ("$item")
    }
    $errs = $Ps.Streams.Error
    while ($ErrIdx.Value -lt $errs.Count) {
        $e = $errs[$ErrIdx.Value]
        $ErrIdx.Value++
        $Res.Warnings++
        Write-Log ('     [WARN] ' + (($e.ToString()) -replace '\s+', ' '))
    }
}

function Invoke-Step {
    param($Step, $Check, [int]$Index, [int]$Count)

    $res = @{ Status = 'OK'; Warnings = 0; Message = '' }
    $ps = $null
    $abandon = $false
    $oi = [ref]0
    $ei = [ref]0
    $sw = [Diagnostics.Stopwatch]::StartNew()

    Write-Log ''
    Write-Log ('  >> Step {0}/{1}: {2}' -f $Index, $Count, $Step.N)
    Write-Log ''
    $script:LastBlank = $true

    try {
        $ps  = [powershell]::Create()
        $in  = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
        $in.Complete()
        $out = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
        [void]$ps.AddScript($script:Prelude).AddArgument($Step.S.ToString()).AddArgument($script:Ctx)
        $h = $ps.BeginInvoke($in, $out)
        $lastUi = -1000

        while (-not $h.IsCompleted) {
            Receive-StepData -Ps $ps -Out $out -OutIdx $oi -ErrIdx $ei -Res $res

            if ($script:CanReadKeys) {
                try {
                    while ([Console]::KeyAvailable) {
                        $k = [Console]::ReadKey($true)
                        if ($k.Key -eq 'S') { $res.Status = 'SKIPPED' }
                        elseif ($k.Key -eq 'Q') { $res.Status = 'ABORTED' }
                    }
                }
                catch { $script:CanReadKeys = $false }
                if ($res.Status -in 'SKIPPED', 'ABORTED') { break }
            }

            if ($sw.Elapsed.TotalSeconds -ge $StepTimeoutSec) { $res.Status = 'TIMEOUT'; break }

            if (($sw.ElapsedMilliseconds - $lastUi) -ge 250) {
                $hint = if ($script:CanReadKeys) { '  |  [S] skip  [Q] abort' } else { '' }
                Show-Progress ('  [{0:D2}/{1:D2}] {2}  |  step {3}/{4}: {5}  |  {6}{7}' -f `
                    $Check.Id, $script:Catalog.Count, $Check.Name, $Index, $Count, $Step.N, $sw.Elapsed.ToString('mm\:ss'), $hint)
                $lastUi = $sw.ElapsedMilliseconds
            }
            Start-Sleep -Milliseconds 80
        }

        if ($res.Status -in 'SKIPPED', 'ABORTED', 'TIMEOUT') {
            try {
                $ar = $ps.BeginStop($null, $null)
                if (-not $ar.AsyncWaitHandle.WaitOne(3000)) { $abandon = $true }
            }
            catch { $abandon = $true }
        }
        else {
            try { $null = $ps.EndInvoke($h) }
            catch {
                $res.Status = 'FAIL'
                $m = $_.Exception.Message
                if ($_.Exception.InnerException) { $m = $_.Exception.InnerException.Message }
                $res.Message = ($m -replace '\s+', ' ')
            }
        }
        Receive-StepData -Ps $ps -Out $out -OutIdx $oi -ErrIdx $ei -Res $res
    }
    catch {
        $res.Status = 'FAIL'
        $res.Message = ($_.Exception.Message -replace '\s+', ' ')
    }
    finally {
        if ($ps -and -not $abandon) { try { $ps.Dispose() } catch { } }
    }

    if ($res.Status -eq 'OK' -and $res.Warnings -gt 0) { $res.Status = 'WARN' }
    $sec = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    Write-Log ''
    switch ($res.Status) {
        'OK'      { Write-Log ('  << OK ({0} s)' -f $sec) }
        'WARN'    { Write-Log ('  << COMPLETED WITH WARNINGS: {0} ({1} s)' -f $res.Warnings, $sec) }
        'FAIL'    { Write-Log ('  << FAILED ({0} s): {1}' -f $sec, $res.Message) }
        'TIMEOUT' { Write-Log ('  << TIMEOUT after {0} s, step stopped' -f $StepTimeoutSec) }
        'SKIPPED' { Write-Log ('  << SKIPPED by user after {0} s, remaining steps of this check not run' -f $sec) }
        'ABORTED' { Write-Log ('  << RUN ABORTED by user after {0} s' -f $sec) }
    }

    if ($res.Status -in 'WARN', 'FAIL', 'TIMEOUT') {
        $detail = switch ($res.Status) {
            'WARN'    { "completed with $($res.Warnings) warning(s), see report" }
            'FAIL'    { $res.Message }
            'TIMEOUT' { "no result after $StepTimeoutSec s" }
        }
        $script:Issues.Add([pscustomobject]@{ Check = $script:CurrentCheck; Step = $Step.N; Kind = $res.Status; Message = $detail })
    }
    return $res
}

function New-Result {
    param($Check, [string]$Status)
    return [pscustomobject]@{
        Id = $Check.Id; Name = $Check.Name; Status = $Status; Seconds = 0.0
        StepsTotal = $Check.Steps.Count; StepsDone = 0; Findings = 0
    }
}

function Show-CheckResult {
    param($R)
    Clear-Progress
    $line = '  [{0:D2}/{1:D2}] {2,-42}{3,-11}{4,-9}{5,-3} findings   {6}' -f `
        $R.Id, $script:Catalog.Count, (Fit $R.Name 41), $R.Status, ('{0}/{1}' -f $R.StepsDone, $R.StepsTotal), $R.Findings, (Format-Time $R.Seconds)
    Write-Host $line -ForegroundColor $script:StatusColor[$R.Status]
}

function Invoke-Check {
    param($Check)

    $r = New-Result -Check $Check -Status 'RUNNING'
    $script:Results.Add($r)
    $script:CurrentCheck = '{0:D2} {1}' -f $Check.Id, $Check.Name
    $script:CurFindings = 0
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $failedSteps = 0
    $stopped = $false

    Write-Log ''
    Write-Log ('=' * $script:RuleWidth)
    Write-Log ('[{0:D2}/{1:D2}] {2}   (started {3})' -f $Check.Id, $script:Catalog.Count, $Check.Name.ToUpper(), (Get-Date -Format 'HH:mm:ss'))
    Write-Log ('=' * $script:RuleWidth)

    try {
        $n = 0
        foreach ($step in $Check.Steps) {
            $n++
            $sr = Invoke-Step -Step $step -Check $Check -Index $n -Count $Check.Steps.Count
            switch ($sr.Status) {
                'SKIPPED' {
                    $r.Status = 'SKIPPED'; $stopped = $true
                    $script:Issues.Add([pscustomobject]@{ Check = $script:CurrentCheck; Step = $step.N; Kind = 'SKIPPED'; Message = "skipped by user during step $n of $($Check.Steps.Count)" })
                }
                'ABORTED' {
                    $r.Status = 'ABORTED'; $stopped = $true; $script:AbortRequested = $true
                    $script:Issues.Add([pscustomobject]@{ Check = $script:CurrentCheck; Step = $step.N; Kind = 'ABORTED'; Message = "run aborted by user during step $n of $($Check.Steps.Count)" })
                }
                'FAIL'    { $failedSteps++ }
                'TIMEOUT' { $failedSteps++ }
                default   { $r.StepsDone++ }
            }
            if ($stopped) { break }
        }
    }
    catch {
        $r.Status = 'FAILED'
        $stopped = $true
        Write-Log ''
        Write-Log "  [CRASH] Unexpected error in check runner: $($_.Exception.Message)"
        $script:Issues.Add([pscustomobject]@{ Check = $script:CurrentCheck; Step = '(runner)'; Kind = 'FAIL'; Message = $_.Exception.Message })
    }

    if (-not $stopped) {
        if ($failedSteps -eq 0) { $r.Status = 'COMPLETED' }
        elseif ($failedSteps -ge $Check.Steps.Count) { $r.Status = 'FAILED' }
        else { $r.Status = 'PARTIAL' }
    }

    $r.Seconds  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    $r.Findings = $script:CurFindings

    Write-Log ''
    Write-Log ('-' * $script:RuleWidth)
    Write-Log '  Review guidance:'
    foreach ($g in $Check.Guide) { Write-Log ('    - ' + $g) }
    Write-Log ''
    Write-Log ('  RESULT: {0} | steps done {1}/{2} | findings {3} | {4}' -f $r.Status, $r.StepsDone, $r.StepsTotal, $r.Findings, (Format-Time $r.Seconds))
    Show-CheckResult $r
}

# ----------------------------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------------------------
function Write-Summary {
    param([bool]$Interrupted, [datetime]$RunStart)

    $byId = @{}
    foreach ($x in $script:Results) {
        if ($x.Status -eq 'RUNNING') { $x.Status = 'ABORTED' }
        $byId[$x.Id] = $x
    }
    $rows = foreach ($c in $script:Catalog) {
        if ($byId.ContainsKey($c.Id)) { $byId[$c.Id] }
        elseif ($script:SelectedIds -contains $c.Id) { New-Result -Check $c -Status 'NOT RUN' }
        else { New-Result -Check $c -Status 'NOT SELECTED' }
    }

    $cnt = @{}
    foreach ($r in $rows) { $cnt[$r.Status] = 1 + [int]$cnt[$r.Status] }
    $get = { param($k) [int]$cnt[$k] }
    $high = @($script:Findings | Where-Object { $_.Sev -eq 'HIGH' }).Count
    $med  = @($script:Findings | Where-Object { $_.Sev -eq 'MEDIUM' }).Count
    $low  = @($script:Findings | Where-Object { $_.Sev -eq 'LOW' }).Count
    $runStatus = if ($Interrupted) { 'INTERRUPTED' } elseif ($script:AbortRequested) { 'ABORTED BY USER' } else { 'FINISHED' }
    $elapsed = ((Get-Date) - $RunStart).TotalSeconds
    $rule = '=' * $script:RuleWidth
    $thin = '-' * $script:RuleWidth

    Clear-Progress
    Emit ''
    Emit $rule 'DarkCyan'
    Emit 'ASSESSMENT SUMMARY' 'White'
    Emit $rule 'DarkCyan'
    Emit ('  Run status   : {0}' -f $runStatus) $(if ($runStatus -eq 'FINISHED') { 'Green' } else { 'Yellow' })
    Emit ('  Completed    : {0}    Partial: {1}    Failed: {2}    Skipped: {3}    Aborted/Not run: {4}' -f (& $get 'COMPLETED'), (& $get 'PARTIAL'), (& $get 'FAILED'), (& $get 'SKIPPED'), ((& $get 'ABORTED') + (& $get 'NOT RUN')))
    Emit ('  Findings     : {0} high, {1} medium, {2} low' -f $high, $med, $low) $(if ($high -gt 0) { 'Red' } elseif ($med -gt 0) { 'Yellow' } else { 'Gray' })
    Emit ('  Duration     : {0}' -f (Format-Time $elapsed))
    Emit ''
    Emit ('  {0,-5}{1,-42}{2,-14}{3,-8}{4,-10}{5}' -f 'ID', 'CHECK', 'STATUS', 'STEPS', 'FINDINGS', 'TIME') 'Cyan'
    Emit ('  ' + ('-' * 74)) 'DarkGray'
    foreach ($r in $rows) {
        $steps = if ($r.Status -in 'NOT SELECTED', 'NOT RUN') { '-' } else { '{0}/{1}' -f $r.StepsDone, $r.StepsTotal }
        $time  = if ($r.Status -in 'NOT SELECTED', 'NOT RUN') { '-' } else { Format-Time $r.Seconds }
        $fnd   = if ($r.Status -in 'NOT SELECTED', 'NOT RUN') { '-' } else { "$($r.Findings)" }
        Emit ('  {0,-5}{1,-42}{2,-14}{3,-8}{4,-10}{5}' -f ('{0:D2}' -f $r.Id), (Fit $r.Name 41), $r.Status, $steps, $fnd, $time) $script:StatusColor[$r.Status]
    }

    $sections = @(
        @{ Title = 'CHECKED';                Mark = '[x]'; Color = 'Green';    Match = @('COMPLETED', 'PARTIAL') },
        @{ Title = 'SKIPPED BY USER';        Mark = '[-]'; Color = 'Yellow';   Match = @('SKIPPED') },
        @{ Title = 'FAILED, ABORTED OR NOT RUN'; Mark = '[!]'; Color = 'Red';  Match = @('FAILED', 'ABORTED', 'NOT RUN') }
    )
    foreach ($s in $sections) {
        $items = @($rows | Where-Object { $_.Status -in $s.Match })
        if ($items.Count -eq 0) { continue }
        Emit ''
        Emit ('  {0} ({1})' -f $s.Title, $items.Count) $s.Color
        foreach ($i in $items) {
            $tag = if ($i.Status -eq 'PARTIAL') { '  (some steps failed, see below)' } else { '' }
            Emit ('    {0} {1:D2} {2}{3}' -f $s.Mark, $i.Id, $i.Name, $tag) $s.Color
        }
    }

    if ($script:Issues.Count -gt 0) {
        Emit ''
        Emit ('  STEP ISSUES ({0})' -f $script:Issues.Count) 'Yellow'
        foreach ($i in $script:Issues) {
            Emit ('    - [{0}] {1} / {2}: {3}' -f $i.Kind, $i.Check, $i.Step, $i.Message) 'Yellow'
        }
    }

    if ($script:Findings.Count -gt 0) {
        Emit ''
        Emit ('  FINDINGS ({0})' -f $script:Findings.Count) 'White'
        $rank = @{ 'HIGH' = 0; 'MEDIUM' = 1; 'LOW' = 2 }
        $col  = @{ 'HIGH' = 'Red'; 'MEDIUM' = 'Yellow'; 'LOW' = 'Gray' }
        foreach ($f in ($script:Findings | Sort-Object { $rank[$_.Sev] }, Check)) {
            Emit ('    [{0,-6}] {1}: {2}' -f $f.Sev, $f.Check, $f.Message) $col[$f.Sev]
        }
    }

    Emit ''
    Emit $thin 'DarkGray'
    Emit ('  Report saved : {0}' -f $script:ReportPath) 'Cyan'
    Emit ('  Finished     : {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) 'DarkGray'
    Emit $rule 'DarkCyan'
}

# ----------------------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------------------
Show-Banner
$interactive = -not ($Checks -or $All)

if ($interactive) {
    Show-Menu
    $sel = Read-Selection
    if (-not $sel) { Write-Host '  Cancelled.' -ForegroundColor DarkGray; return }
}
elseif ($All) { $sel = [int[]](1..$script:Catalog.Count) }
else {
    $sel = Resolve-Selection -Tokens $Checks -Max $script:Catalog.Count
    if (-not $sel) { Write-Host "  Invalid -Checks value. Use IDs 1-$($script:Catalog.Count), for example 1,3,5-7." -ForegroundColor Red; return }
}
$script:SelectedIds = @($sel)

if (-not (Open-Report -Dir $OutputDir)) { Write-Host '  Could not create a report file. Aborting.' -ForegroundColor Red; return }
Write-ReportHeader

Write-Host ''
Write-Host ('  Checks selected : ' + (($script:SelectedIds | ForEach-Object { '{0:D2}' -f $_ }) -join ', ')) -ForegroundColor Gray
Write-Host ('  Report (live)   : ' + $script:ReportPath) -ForegroundColor Cyan
Write-Host ('  Follow live     : Get-Content -Wait -LiteralPath "{0}"' -f $script:ReportPath) -ForegroundColor DarkGray
if ($script:CanReadKeys) { Write-Host '  Controls        : [S] skip current check   [Q] abort run' -ForegroundColor Gray }
else { Write-Host '  Controls        : unavailable in this host (use a powershell.exe or pwsh console to skip checks)' -ForegroundColor Yellow }
$needAdmin = @($script:Catalog | Where-Object { $_.Admin -and ($script:SelectedIds -contains $_.Id) })
if ($needAdmin.Count -gt 0 -and -not $script:IsAdmin) {
    Write-Host ('  Note            : not elevated, checks {0} return partial results.' -f (($needAdmin | ForEach-Object { '{0:D2}' -f $_.Id }) -join ', ')) -ForegroundColor Yellow
}
Write-Host ''

$runStart = Get-Date
$interrupted = $true
try {
    foreach ($c in $script:Catalog) {
        if ($script:SelectedIds -notcontains $c.Id) { continue }
        if ($script:AbortRequested) { break }
        Invoke-Check -Check $c
    }
    $interrupted = $false
}
catch {
    Write-Log ''
    Write-Log "[FATAL] $($_.Exception.Message)"
    Write-Host "  [FATAL] $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    if ($interrupted) {
        Write-Log ''
        Write-Log '*** RUN INTERRUPTED BEFORE ALL SELECTED CHECKS FINISHED ***'
    }
    Write-Summary -Interrupted $interrupted -RunStart $runStart
    if ($script:Writer) { try { $script:Writer.Dispose() } catch { } }
}

if ($interactive -and $script:CanReadKeys) {
    Write-Host ''
    [void](Read-Host '  Press Enter to exit')
}
