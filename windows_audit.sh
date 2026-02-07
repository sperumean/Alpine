#==============================================================================
# Windows Server Audit & Hardening Script
# Targets: tahoe(.14/AD+DNS) victoria(.22/Wiki+Tickets) baikal(.28/Billing+HR)
#
# Usage:
#   .\windows-audit.ps1                  # Audit only
#   .\windows-audit.ps1 -Harden         # Audit + harden
#   .\windows-audit.ps1 -Snapshot       # Save baseline
#   .\windows-audit.ps1 -Diff           # Compare to baseline
#   .\windows-audit.ps1 -Monitor        # Continuous watch
#   .\windows-audit.ps1 -Passwords      # Bulk password change
#==============================================================================

param(
    [switch]$Harden,
    [switch]$Snapshot,
    [switch]$Diff,
    [switch]$Monitor,
    [switch]$Passwords
)

$ErrorActionPreference = "SilentlyContinue"
$BackupDir = "C:\wrccdc-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$SnapshotDir = "C:\wrccdc-snapshot"
$LogFile = "C:\wrccdc-audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Log($msg) { $msg | Tee-Object -FilePath $LogFile -Append }
function Header($msg) { Log "`n============================================================"; Log "  $msg"; Log "============================================================" }
function Pass($msg) { Log "  [PASS] $msg" }
function Warn($msg) { Log "  [WARN] $msg" }
function Fail($msg) { Log "  [FAIL] $msg" }
function Info($msg) { Log "  [INFO] $msg" }

function Detect-Role {
    $script:Roles = @()
    if (Get-WindowsFeature AD-Domain-Services -EA 0 | Where Installed) { $script:Roles += "AD" }
    if (Get-WindowsFeature DNS -EA 0 | Where Installed) { $script:Roles += "DNS" }
    if (Get-WindowsFeature Web-Server -EA 0 | Where Installed) { $script:Roles += "IIS" }
    if (Get-WindowsFeature DHCP -EA 0 | Where Installed) { $script:Roles += "DHCP" }
    if (Get-Service MSSQLSERVER -EA 0) { $script:Roles += "SQL" }
    if (Get-Service W3SVC -EA 0) { $script:Roles += "IIS" }
    if (Get-Service WinRM -EA 0 | Where Status -eq Running) { $script:Roles += "WinRM" }
    if (Get-Service TermService -EA 0 | Where Status -eq Running) { $script:Roles += "RDP" }
    $script:Roles = $script:Roles | Sort -Unique
}

#==============================================================================
# SNAPSHOT / DIFF / MONITOR / PASSWORDS
#==============================================================================
function Do-Snapshot {
    Header "SAVING SNAPSHOT"
    New-Item -ItemType Directory -Path $SnapshotDir -Force | Out-Null
    Get-LocalUser | Export-Csv "$SnapshotDir\local-users.csv" -NoTypeInformation
    Get-Service | Export-Csv "$SnapshotDir\services.csv" -NoTypeInformation
    Get-ScheduledTask | Export-Csv "$SnapshotDir\scheduled-tasks.csv" -NoTypeInformation
    Get-NetFirewallRule | Export-Csv "$SnapshotDir\firewall-rules.csv" -NoTypeInformation
    Get-NetTCPConnection -State Listen | Export-Csv "$SnapshotDir\tcp-listen.csv" -NoTypeInformation
    Get-NetIPAddress | Export-Csv "$SnapshotDir\ip-addresses.csv" -NoTypeInformation
    Get-NetRoute | Export-Csv "$SnapshotDir\routes.csv" -NoTypeInformation
    Get-SmbShare | Export-Csv "$SnapshotDir\smb-shares.csv" -NoTypeInformation
    Get-LocalGroupMember -Group "Administrators" | Export-Csv "$SnapshotDir\local-admins.csv" -NoTypeInformation
    if ($Roles -contains "AD") {
        Get-ADUser -Filter * -Properties Enabled,LastLogonDate,MemberOf | Export-Csv "$SnapshotDir\ad-users.csv" -NoTypeInformation
        Get-ADGroupMember "Domain Admins" | Export-Csv "$SnapshotDir\domain-admins.csv" -NoTypeInformation
    }
    Info "Snapshot saved to $SnapshotDir"
}

function Do-Diff {
    Header "COMPARING TO SNAPSHOT"
    if (-not (Test-Path $SnapshotDir)) { Fail "No snapshot found!"; return }
    $changes = 0
    # Users
    $old = Import-Csv "$SnapshotDir\local-users.csv" | Select -Expand Name
    $new = Get-LocalUser | Select -Expand Name
    $added = Compare-Object $old $new | Where SideIndicator -eq "=>"
    if ($added) { Fail "NEW USERS: $($added.InputObject -join ', ')"; $changes++ } else { Pass "Users unchanged" }
    # Admins
    $oldA = Import-Csv "$SnapshotDir\local-admins.csv" | Select -Expand Name
    $newA = Get-LocalGroupMember -Group "Administrators" | Select -Expand Name
    $addedA = Compare-Object $oldA $newA | Where SideIndicator -eq "=>"
    if ($addedA) { Fail "NEW ADMINS: $($addedA.InputObject -join ', ')"; $changes++ } else { Pass "Admins unchanged" }
    # Ports
    $oldP = Import-Csv "$SnapshotDir\tcp-listen.csv" | Select -Expand LocalPort | Sort -Unique
    $newP = Get-NetTCPConnection -State Listen | Select -Expand LocalPort | Sort -Unique
    $addedP = Compare-Object $oldP $newP | Where SideIndicator -eq "=>"
    if ($addedP) { Fail "NEW PORTS: $($addedP.InputObject -join ', ')"; $changes++ } else { Pass "Ports unchanged" }
    # Tasks
    $oldT = Import-Csv "$SnapshotDir\scheduled-tasks.csv" | Select -Expand TaskName
    $newT = Get-ScheduledTask | Select -Expand TaskName
    $addedT = Compare-Object $oldT $newT | Where SideIndicator -eq "=>"
    if ($addedT) { Fail "NEW TASKS: $($addedT.InputObject -join ', ')"; $changes++ } else { Pass "Tasks unchanged" }
    Log ""; if ($changes -eq 0) { Log "No changes." } else { Log "$changes change(s) detected!" }
}

function Do-Monitor {
    Header "CONTINUOUS MONITORING - Ctrl+C to stop"
    $bu = (Get-LocalUser).Count; $bp = (Get-NetTCPConnection -State Listen | Select -Unique LocalPort).Count
    $ba = (Get-LocalGroupMember -Group "Administrators").Count; $bt = (Get-ScheduledTask).Count
    while ($true) {
        $ts = Get-Date -Format "HH:mm:ss"
        $nu = (Get-LocalUser).Count; $np = (Get-NetTCPConnection -State Listen | Select -Unique LocalPort).Count
        $na = (Get-LocalGroupMember -Group "Administrators").Count; $nt = (Get-ScheduledTask).Count
        $nc = (Get-NetTCPConnection -State Established).Count
        $alert = ""
        if ($nu -ne $bu) { $alert += " USERS:$nu(was $bu)" }
        if ($na -ne $ba) { $alert += " ADMINS:$na(was $ba)" }
        if ($nt -ne $bt) { $alert += " TASKS:$nt(was $bt)" }
        if ($np -ne $bp) { $alert += " PORTS:$np(was $bp)" }
        if ($alert) { Write-Host "`n[$ts] ALERT:$alert" -ForegroundColor Red }
        Write-Host -NoNewline "`r[$ts] Users:$nu Ports:$np Admins:$na Tasks:$nt Conns:$nc  "
        Start-Sleep 30
    }
}

function Do-Passwords {
    Header "BULK PASSWORD CHANGE"
    Warn "SUBMIT PCRs IN QUOTIENT AFTER CHANGING!"
    $users = Get-LocalUser | Where Enabled -eq $true
    $newPass = Read-Host "New password for all users (or type 'individual')" -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPass))
    if ($plain -eq "individual") {
        foreach ($u in $users) { $p = Read-Host "Password for $($u.Name)" -AsSecureString; Set-LocalUser -Name $u.Name -Password $p; Pass "Changed: $($u.Name)" }
    } else {
        foreach ($u in $users) { Set-LocalUser -Name $u.Name -Password $newPass; Pass "Changed: $($u.Name)" }
    }
    if ($Roles -contains "AD") {
        $ca = Read-Host "Change AD passwords too? (y/n)"
        if ($ca -eq "y") {
            $ap = Read-Host "New AD password" -AsSecureString
            Get-ADUser -Filter {Enabled -eq $true} | Where { $_.SamAccountName -ne "krbtgt" } | ForEach-Object {
                Set-ADAccountPassword -Identity $_ -NewPassword $ap -Reset; Pass "AD: $($_.SamAccountName)"
            }
        }
    }
    Warn ">>> SUBMIT PCRs IN QUOTIENT <<<"
}

#==============================================================================
# AUDIT FUNCTIONS
#==============================================================================
function Audit-SystemInfo {
    Header "SYSTEM INFORMATION"
    Detect-Role
    $os = Get-CimInstance Win32_OperatingSystem
    Info "Hostname:  $env:COMPUTERNAME"
    Info "OS:        $($os.Caption) $($os.Version)"
    Info "Domain:    $((Get-CimInstance Win32_ComputerSystem).Domain)"
    Info "Roles:     $($Roles -join ', ')"
    Info "IPs:       $((Get-NetIPAddress -AddressFamily IPv4 | Where { $_.IPAddress -ne '127.0.0.1' }).IPAddress -join ', ')"
}

function Audit-Users {
    Header "USER ACCOUNTS"
    Info "Local users:"
    Get-LocalUser | Format-Table Name,Enabled,LastLogon,PasswordRequired -Auto | Out-String | Log
    Info "Local Administrators:"
    Get-LocalGroupMember -Group "Administrators" | Format-Table Name,ObjectClass -Auto | Out-String | Log
    Info "Remote Desktop Users:"
    Get-LocalGroupMember -Group "Remote Desktop Users" -EA 0 | Format-Table Name -Auto | Out-String | Log
    # Suspicious accounts
    $sus = Get-LocalUser | Where { $_.Enabled -and ($_.Name -match '^\$|admin[0-9]|svc_|test|tmp' -or $_.Description -eq '') }
    if ($sus) { Warn "Suspicious accounts:"; $sus | Format-Table Name,Enabled | Out-String | Log }
    # AD
    if ($Roles -contains "AD") {
        Info "=== ACTIVE DIRECTORY ==="
        Info "Domain Admins:"; Get-ADGroupMember "Domain Admins" | Format-Table Name,SamAccountName -Auto | Out-String | Log
        Info "Enterprise Admins:"; Get-ADGroupMember "Enterprise Admins" -EA 0 | Format-Table Name,SamAccountName -Auto | Out-String | Log
        Info "Recently created AD users (7d):"; Get-ADUser -Filter * -Properties WhenCreated | Where { $_.WhenCreated -gt (Get-Date).AddDays(-7) } | Format-Table SamAccountName,WhenCreated -Auto | Out-String | Log
        Info "Password never expires:"; Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} | Format-Table SamAccountName | Out-String | Log
        Info "Kerberoastable (SPN set):"; Get-ADUser -Filter {ServicePrincipalName -ne "$null" -and Enabled -eq $true} -Properties ServicePrincipalName | Format-Table SamAccountName,ServicePrincipalName -Auto | Out-String | Log
    }
}

function Audit-Services {
    Header "SERVICES"
    Info "Running:"; Get-Service | Where Status -eq Running | Sort Name | Format-Table Name,DisplayName,StartType -Auto | Out-String | Log
    $sus = Get-CimInstance Win32_Service | Where { $_.State -eq "Running" -and ($_.PathName -match "temp|tmp|appdata|public|downloads" -or $_.PathName -match "powershell|cmd\.exe|wscript|mshta") }
    if ($sus) { Fail "Suspicious service paths:"; $sus | Format-Table Name,PathName -Auto | Out-String | Log } else { Pass "No suspicious services" }
}

function Audit-Network {
    Header "NETWORK"
    Info "IPs:"; Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias,IPAddress,PrefixLength -Auto | Out-String | Log
    Info "Default Gateway:"; Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Format-Table NextHop,InterfaceAlias -Auto | Out-String | Log
    Info "DNS Servers:"; Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table InterfaceAlias,ServerAddresses -Auto | Out-String | Log
    Info "Hosts file:"; Get-Content C:\Windows\System32\drivers\etc\hosts | Where { $_ -notmatch "^#|^$" } | ForEach-Object { Log "    $_" }
    Info "SMB Shares:"; Get-SmbShare | Format-Table Name,Path,Description -Auto | Out-String | Log
}

function Audit-Firewall {
    Header "FIREWALL"
    Info "Profiles:"; Get-NetFirewallProfile | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction -Auto | Out-String | Log
    $dis = Get-NetFirewallProfile | Where Enabled -eq $false
    if ($dis) { Fail "Disabled profiles: $($dis.Name -join ', ')" } else { Pass "All profiles enabled" }
    Info "Inbound allow (non-default):"; Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where { $_.DisplayGroup -notmatch "Core Networking|File and Printer" } | Select DisplayName,Profile | Format-Table -Auto | Out-String | Log
}

function Audit-Ports {
    Header "LISTENING PORTS"
    Info "TCP:"; Get-NetTCPConnection -State Listen | Sort LocalPort | Select LocalAddress,LocalPort,OwningProcess,@{N='Process';E={(Get-Process -Id $_.OwningProcess -EA 0).Name}} | Format-Table -Auto | Out-String | Log
    $sus = Get-NetTCPConnection -State Listen | Where { $_.LocalPort -in @(4444,5555,6666,7777,8888,9999,1337,31337,12345,6969) }
    if ($sus) { Fail "Suspicious ports!"; $sus | Format-Table LocalPort,@{N='Proc';E={(Get-Process -Id $_.OwningProcess -EA 0).Name}} -Auto | Out-String | Log } else { Pass "No backdoor ports" }
    Info "Established:"; Get-NetTCPConnection -State Established | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,@{N='Proc';E={(Get-Process -Id $_.OwningProcess -EA 0).Name}} | Format-Table -Auto | Out-String | Log
}

function Audit-ScheduledTasks {
    Header "SCHEDULED TASKS"
    Info "Non-Microsoft tasks:"; Get-ScheduledTask | Where { $_.Author -notmatch "Microsoft" -and $_.TaskPath -notmatch "Microsoft" } | Format-Table TaskName,TaskPath,State -Auto | Out-String | Log
    Info "Tasks as SYSTEM:"; Get-ScheduledTask | Where { $_.Principal.UserId -match "SYSTEM|LocalSystem" } | Format-Table TaskName,State,@{N='Action';E={($_.Actions.Execute -join '; ')}} -Auto | Out-String | Log
}

function Audit-Persistence {
    Header "PERSISTENCE"
    # Registry
    $regPaths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
    foreach ($rp in $regPaths) {
        if (Test-Path $rp) {
            $items = Get-ItemProperty $rp -EA 0; $props = $items.PSObject.Properties | Where { $_.Name -notmatch "^PS" }
            if ($props) { Warn "Registry: $rp"; foreach ($p in $props) { Log "    $($p.Name) = $($p.Value)" } }
        }
    }
    # WMI
    $wmi = Get-WMIObject -Namespace root\Subscription -Class __EventFilter -EA 0
    if ($wmi) { Fail "WMI Event Filters!"; $wmi | Format-Table Name,Query -Auto | Out-String | Log } else { Pass "No WMI persistence" }
    # Startup folders
    @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") | ForEach-Object {
        if (Test-Path $_) { Get-ChildItem $_ -EA 0 | ForEach-Object { Warn "Startup: $($_.FullName)" } }
    }
    # Webshells
    if ($Roles -contains "IIS") {
        Info "IIS webshell scan:"
        $wr = "C:\inetpub\wwwroot"
        if (Test-Path $wr) {
            Get-ChildItem $wr -Recurse -Include "*.aspx","*.asp","*.ashx" -EA 0 | Where { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | ForEach-Object {
                $c = Get-Content $_.FullName -Raw -EA 0
                if ($c -match "eval|exec|cmd\.exe|powershell|WebShell|upload") { Fail "WEBSHELL: $($_.FullName)" }
            }
        }
    }
}

function Audit-Processes {
    Header "PROCESSES"
    $sus = Get-Process | Where { $_.Path -match "temp|tmp|appdata|public" -or $_.Name -match "nc|ncat|netcat|meterpreter|beacon|cobalt|mimikatz|chisel|sliver|rubeus" }
    if ($sus) { Fail "Suspicious:"; $sus | Format-Table Name,Id,Path -Auto | Out-String | Log } else { Pass "No suspicious processes" }
    $ps = Get-Process powershell,pwsh -EA 0
    if ($ps) { Warn "PowerShell processes: $($ps.Count)" }
}

function Audit-DNS {
    if ($Roles -notcontains "DNS") { return }
    Header "DNS"; Info "Zones:"; Get-DnsServerZone | Format-Table ZoneName,ZoneType -Auto | Out-String | Log
    Info "Forwarders:"; Get-DnsServerForwarder | Format-Table IPAddress -Auto | Out-String | Log
}

function Audit-AD {
    if ($Roles -notcontains "AD") { return }
    Header "ACTIVE DIRECTORY"
    Info "Domain:"; Get-ADDomain | Format-List Name,DNSRoot,DomainMode | Out-String | Log
    Info "DCs:"; Get-ADDomainController -Filter * | Format-Table Name,IPv4Address -Auto | Out-String | Log
    Info "GPOs:"; Get-GPO -All | Format-Table DisplayName,GpoStatus,ModificationTime -Auto | Out-String | Log
    Info "Password Policy:"; Get-ADDefaultDomainPasswordPolicy | Format-List | Out-String | Log
    Info "Unconstrained Delegation:"; Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Format-Table Name -Auto | Out-String | Log
}

function Audit-RDP {
    Header "RDP"
    $nla = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").UserAuthentication
    if ($nla -eq 1) { Pass "NLA enabled" } else { Fail "NLA disabled" }
}

function Audit-Logs {
    Header "LOGS"
    @("Security","System","Application","Windows PowerShell") | ForEach-Object {
        $el = Get-WinEvent -ListLog $_ -EA 0
        if ($el) { if ($el.RecordCount -eq 0) { Fail "$_ EMPTY!" } else { Pass "$_: $($el.RecordCount) events" } }
    }
    Info "Recent failed logons:"; Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 20 -EA 0 | Select TimeCreated,@{N='Acct';E={$_.Properties[5].Value}},@{N='Src';E={$_.Properties[19].Value}} | Format-Table -Auto | Out-String | Log
    Info "Recent account creations:"; Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720} -MaxEvents 10 -EA 0 | Select TimeCreated,@{N='NewAcct';E={$_.Properties[0].Value}} | Format-Table -Auto | Out-String | Log
}

function Audit-Connectivity {
    Header "CONNECTIVITY"
    @(@{I="192.168.220.2";N="ontario"},@{I="192.168.220.10";N="arrowhead"},@{I="192.168.220.14";N="tahoe"},@{I="192.168.220.16";N="mead"},@{I="192.168.220.20";N="stupidlake"},@{I="192.168.220.22";N="victoria"},@{I="192.168.220.23";N="wikey"},@{I="192.168.220.24";N="pychgynmygytgyn"},@{I="192.168.220.26";N="elsinore"},@{I="192.168.220.28";N="baikal"},@{I="192.168.220.240";N="berryessa"}) | ForEach-Object {
        if (Test-Connection $_.I -Count 1 -Quiet -TimeoutSeconds 1) { Pass "$($_.I) ($($_.N))" } else { Fail "$($_.I) ($($_.N)) UNREACHABLE" }
    }
}

#==============================================================================
# HARDENING
#==============================================================================
function Harden-Backup { Header "BACKUP"; New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null; netsh advfirewall export "$BackupDir\firewall.wfw" | Out-Null; if ($Roles -contains "AD") { Backup-GPO -All -Path $BackupDir -EA 0 }; Info "Backup: $BackupDir" }

function Harden-Firewall {
    Header "HARDENING FIREWALL"
    Set-NetFirewallProfile -All -Enabled True; Pass "All profiles enabled"
    Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow; Pass "Default: Block inbound, Allow outbound"
    @(@{N="RDP";P=3389;Pr="TCP"},@{N="SSH";P=22;Pr="TCP"},@{N="HTTP";P=80;Pr="TCP"},@{N="HTTPS";P=443;Pr="TCP"},@{N="DNS-TCP";P=53;Pr="TCP"},@{N="DNS-UDP";P=53;Pr="UDP"},@{N="SMB";P=445;Pr="TCP"},@{N="WinRM";P=5985;Pr="TCP"},@{N="LDAP";P=389;Pr="TCP"},@{N="LDAPS";P=636;Pr="TCP"},@{N="Kerberos";P=88;Pr="TCP"},@{N="SMTP";P=25;Pr="TCP"},@{N="IMAP";P=143;Pr="TCP"},@{N="POP3";P=110;Pr="TCP"}) | ForEach-Object {
        Remove-NetFirewallRule -DisplayName "WRCCDC-$($_.N)" -EA 0
        New-NetFirewallRule -DisplayName "WRCCDC-$($_.N)" -Direction Inbound -Action Allow -Protocol $_.Pr -LocalPort $_.P -Profile Any -EA 0 | Out-Null
        Info "Allowed: $($_.N) ($($_.P)/$($_.Pr))"
    }
}

function Harden-RDP { Header "HARDENING RDP"; Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1; Pass "NLA enabled"; Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MaxIdleTime" -Value 600000; Pass "Idle timeout: 10min" }

function Harden-SMB { Header "HARDENING SMB"; Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -EA 0; Pass "SMBv1 disabled"; Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -EA 0; Pass "Signing required" }

function Harden-Audit { Header "HARDENING AUDIT POLICY"; @("Account Logon","Account Management","Logon/Logoff","Object Access","Policy Change","Privilege Use","System") | ForEach-Object { auditpol /set /category:"$_" /success:enable /failure:enable 2>&1 | Out-Null }; Pass "Full auditing enabled" }

function Harden-Services { Header "HARDENING SERVICES"; @("RemoteRegistry","TlntSvr","SNMPTRAP","SSDPSRV","upnphost") | ForEach-Object { $s = Get-Service $_ -EA 0; if ($s -and $s.Status -eq "Running") { Stop-Service $_ -Force -EA 0; Set-Service $_ -StartupType Disabled -EA 0; Warn "Disabled: $_" } } }

function Generate-Summary {
    Header "SUMMARY"
    Log "  Hostname:      $env:COMPUTERNAME"
    Log "  Roles:         $($Roles -join ', ')"
    Log "  Local Users:   $((Get-LocalUser | Where Enabled).Count)"
    Log "  Admins:        $((Get-LocalGroupMember 'Administrators' -EA 0).Count)"
    Log "  TCP Listeners: $((Get-NetTCPConnection -State Listen | Select -Unique LocalPort).Count)"
    Log "  Connections:   $((Get-NetTCPConnection -State Established).Count)"
    Log ""; Log "  REMINDERS:"; Log "  * SLAs: 50pts (before 11AM) / 25pts (after)"
    Log "  * PCRs in Quotient after pw changes!"; Log "  * Orange team: 10.100.1XX.Y"
    Log "  * Incident reports = 50% persistence penalty reduction"; Log "  * Log: $LogFile"
}

#==============================================================================
# MAIN
#==============================================================================
Detect-Role
if ($Snapshot) { Do-Snapshot; exit }; if ($Diff) { Do-Diff; exit }
if ($Monitor) { Do-Monitor; exit }; if ($Passwords) { Do-Passwords; exit }

Log "WRCCDC 2026 - Windows Audit ($env:COMPUTERNAME) - $(if($Harden){'HARDEN'}else{'AUDIT'}) - $(Get-Date)"
if ($Harden) { Harden-Backup }
Audit-SystemInfo; Audit-Users; Audit-Services; Audit-Network; Audit-Firewall
Audit-Ports; Audit-ScheduledTasks; Audit-Persistence; Audit-Processes
Audit-DNS; Audit-AD; Audit-RDP; Audit-Logs; Audit-Connectivity
if ($Harden) { Harden-Firewall; Harden-RDP; Harden-SMB; Harden-Audit; Harden-Services }
Generate-Summary
