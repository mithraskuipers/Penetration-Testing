# Windows Local Security Assessment Checklist

A practical, non-destructive checklist for reviewing a Windows machine's security
posture: what's installed, who can do what, and where common misconfigurations
tend to hide. Everything here is read-only enumeration, no exploitation steps.

---

## 1. System Information

```powershell
systeminfo
Get-ComputerInfo | Select OsName, OsVersion, OsBuildNumber, OsArchitecture
Get-HotFix | Sort-Object InstalledOn -Descending   # installed patches
wmic qfe list                                       # alt. patch view (legacy)
$env:PROCESSOR_ARCHITECTURE
```

What to check:
- Build number vs. the latest supported build for that Windows version (is it
  patched, still in support?).
- Missing cumulative updates for 3+ months is a red flag.
- Architecture mismatches (32-bit app installs on 64-bit OS can hide old DLLs).

## 2. User & Group Enumeration

```powershell
whoami /all                      # current user, groups, privileges, SID
net user                         # local accounts
net localgroup administrators    # who has local admin
Get-LocalUser | Select Name, Enabled, LastLogon, PasswordRequired, PasswordExpires
Get-LocalGroupMember Administrators
```

What to check:
- Stale or disabled accounts still in the Administrators group.
- Accounts with `PasswordRequired: False` or non-expiring passwords.
- Shared or generic accounts (e.g. `svc_`, `backup`, `temp`) with admin rights.
- Guest account status: `net user guest`, should be disabled.

## 3. Privilege Tokens (what the current session can actually do)

```powershell
whoami /priv
```

Privileges worth flagging if present and enabled on a non-admin or service
account: `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`,
`SeDebugPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`,
`SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`. Any of these on an
account that shouldn't need them is worth investigating. They're the classic
building blocks of local privilege escalation.

## 4. File, Folder & Registry Permissions (ACLs)

```powershell
# NTFS permissions on a path
icacls "C:\Path\To\Check"
Get-Acl "C:\Path\To\Check" | Format-List

# Find world-writable or "Everyone"/"Authenticated Users"-writable folders
# under Program Files (classic misconfig)
icacls "C:\Program Files" /T /C 2>$null | findstr /i "Everyone BUILTIN\Users"

# Registry key permissions
Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services" | Format-List
```

What to check:
- Any service binary, scheduled task script, or startup folder item writable
  by a non-admin group (`Everyone`, `Authenticated Users`, `BUILTIN\Users`).
- Overly broad registry ACLs on service keys (lets a low-priv user repoint a
  service's binary path).

## 5. Services

```powershell
Get-Service | Where-Object {$_.Status -eq 'Running'}
sc.exe query state= all
Get-WmiObject win32_service | Select Name, StartName, PathName, StartMode

# Unquoted service paths with a space (classic misconfig)
Get-WmiObject win32_service | Where-Object {
  $_.PathName -notmatch '^"' -and $_.PathName -match ' '
} | Select Name, PathName

# Service binary/config permission check (needs Sysinternals accesschk)
accesschk.exe -uwcqv "Authenticated Users" * -accepteula
```

What to check:
- Services running as `LocalSystem` with a binary path writable by
  non-admins.
- Unquoted paths containing spaces (`C:\Program Files\My App\service.exe` with
  no quotes, which can let Windows be tricked into running a planted
  executable from an intermediate folder).
- Services configured to run as a domain or service account with a weak or
  reused password.

## 6. Scheduled Tasks & Autoruns

```powershell
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} |
  Select TaskName, TaskPath, State
schtasks /query /fo LIST /v

# Startup items
Get-CimInstance Win32_StartupCommand | Select Name, Command, Location, User
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

Sysinternals **Autoruns** (GUI or `autorunsc.exe -a * -c`) gives the most
complete picture. It covers services, drivers, scheduled tasks, WMI
subscriptions, shell extensions, and more in one pass.

What to check:
- Tasks or startup entries pointing at scripts or binaries in user-writable
  locations (`%TEMP%`, `Downloads`, a world-writable share).
- Tasks running as SYSTEM that call a script a standard user can edit.

## 7. Network Configuration & Exposure

```powershell
ipconfig /all
Get-NetTCPConnection -State Listen | Select LocalAddress, LocalPort, OwningProcess
netstat -ano
Get-NetFirewallProfile | Select Name, Enabled
Get-NetFirewallRule -Enabled True -Direction Inbound |
  Select DisplayName, Action, Profile
arp -a
route print
```

What to check:
- Listening services bound to `0.0.0.0` that should only be on `127.0.0.1`.
- Firewall disabled on any profile, or broad inbound "Allow" rules (any
  port, any source).
- Open shares: `net share`, then `icacls` on each share path.

## 8. Installed Software & Patch Hygiene

```powershell
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select DisplayName, DisplayVersion, Publisher | Sort DisplayName
Get-WmiObject -Class Win32_Product | Select Name, Version   # slower, triggers MSI repair checks, use sparingly
```

What to check:
- Old or unsupported software versions (browsers, Java, 7-Zip, Adobe products
  are common offenders).
- Software installed outside `Program Files` with weak folder permissions.

## 9. Security Controls

```powershell
# Defender status
Get-MpComputerStatus | Select AntivirusEnabled, RealTimeProtectionEnabled, AntispywareEnabled

# UAC level
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin

# LSA / Credential Guard
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# BitLocker
Get-BitLockerVolume
```

What to check:
- Defender (or your AV) real-time protection disabled.
- UAC turned off or set to "never notify."
- LSA Protection (`RunAsPPL`) off, which makes credential dumping from LSASS
  easier if something malicious does run.
- System drive not encrypted.

## 10. Auditing & Logging

```powershell
auditpol /get /category:*
wevtutil gl Security   # Security log size/retention policy
```

What to check:
- Logon auditing (success/failure) not enabled, which makes it hard to notice
  anything after the fact.
- Security log set to a small max size with "overwrite as needed" (events
  roll off quickly).

## 11. Credential Exposure Checks

```powershell
# Saved credentials
cmdkey /list

# Unattended install files that sometimes contain plaintext creds
Get-ChildItem -Path C:\ -Recurse -Include Unattend.xml,sysprep.inf,sysprep.xml -ErrorAction SilentlyContinue

# PowerShell history (can contain pasted passwords)
Get-Content (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

# Env vars (occasionally contain secrets someone hardcoded)
Get-ChildItem Env:
```

What to check:
- Leftover unattended-install or sysprep files with embedded credentials.
- Passwords visible in shell history or environment variables.

## 12. Useful Tools (read-only enumeration, widely used by IT/security teams)

| Tool | What it's for |
|---|---|
| **Sysinternals Suite** (Microsoft): `Autoruns`, `Process Explorer`, `AccessChk`, `TCPView` | Deep, trustworthy visibility into what's running, starting, and who has access to what. Signed by Microsoft. |
| **WinPEAS** | Automates most of the checks above into one report (system, services, ACLs, creds, scheduled tasks). |
| **PrivescCheck** (PowerShell) | Similar automated enumeration, PowerShell-native, easy to read source before running. |
| **BloodHound** (domain-joined machines) | Maps AD permission relationships. Overkill for a single standalone machine, useful if this box is on a domain. |

Before running any third-party tool, read its source (they're small and
readable) and confirm the download hash and source. These tools are popular
enough to be impersonated by actual malware.