#Requires -RunAsAdministrator
#Requires -Version 4.0

<#
    .SYNOPSIS
        This script checks against all of the CIS_Microsoft_Windows_Server_2022_Benchmark_v1.0.0 benchmarks as outlined in their documentation

    .DESCRIPTION
        This script currently checks if the registry key exists but does not yet check if the value is correct, this will be updated in future versions.
        It only outputs to screen for now, but it is CSV friendly where you can copy/paste into an excel sheet, this will be updated in future versions.

    .REQUIREMENTS:
        - Script must be run as an Administrator
        - Script must have a minimum PowerShell version of 4.0


    .NOTES
	    Version History:

	    0.0.1 - 11/20/2022 - Michael de Blok
              - Initial build of script


    .PARAMETER placeholder
    description to be added

    .PARAMETER placeholder2
    description to be added


    .PARAMETER placeholder3
    description to be added

    .EXAMPLE
    .\CIS-Benchmark-Server2022.ps1

#>

$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"

$null = secedit.exe /export /cfg c:\windows\temp\security-policy.inf
$secpolicy = Get-Content "C:\windows\temp\security-policy.inf"


$value = $null ; $valueToSet = $null
$valueToSet = "24"
$Value = $secpolicy | where {$_ -like "*PasswordHistorySize*"}
$value = $value -replace "PasswordHistorySize = "
if ($value -ge $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "1.1.1; (L1) Ensure 'Enforce password history' is set to '24 or more password(s)';Expected value was >$($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "365"
$Value = $secpolicy | where {$_ -like "*MaximumPasswordAge = *"}
$value = $value -replace "MaximumPasswordAge = "
if ($value -ge 1 -and $value -le $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "1.1.2; (L1) Ensure 'Maximum password age' is set to '365 or fewer days, but not 0';Expected value was <$($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "1"
$Value = $secpolicy | where {$_ -like "*MinimumPasswordAge = *"}
$value = $value -replace "MinimumPasswordAge = "
if ($value -ge $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "1.1.3; (L1) Ensure 'Minimum password age' is set to '1 or more day(s)';Expected value was >$($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "14"
$Value = $secpolicy | where {$_ -like "*MinimumPasswordLength = *"}
$value = $value -replace "MinimumPasswordLength = "
if ($value -ge $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "1.1.4; (L1) Ensure 'Minimum password length' is set to '14 or more character(s)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "1"
$Value = $secpolicy | where {$_ -like "*PasswordComplexity = *"}
$value = $value -replace "PasswordComplexity = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "1.1.5; (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\System\CurrentControlSet\Control\SAM" -Name RelaxMinimumPasswordLengthLimits
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "1.1.6; (L1) Ensure 'Relax minimum password length limits' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "0"
$Value = $secpolicy | where {$_ -like "*ClearTextPassword = *"}
$value = $value -replace "ClearTextPassword = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "1.1.7; (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "15"
$Value = $secpolicy | where {$_ -like "*LockoutDuration = *"}
$value = $value -replace "LockoutDuration = "
if ($value -ge $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "1.2.1; (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = 5
$Value = $secpolicy | where {$_ -like "*LockoutBadCount = *"}
$value = $value -replace "LockoutBadCount = "
if ($value -ge 1 -and $value -le $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "1.2.2; (L1) Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "15"
$Value = $secpolicy | where {$_ -like "*ResetLockoutCount = *"}
$value = $value -replace "ResetLockoutCount = "
if ($value -ge $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "1.2.3; (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "Pre-Windows 2000 Compatible Access,*S-1-1-0,*S-1-5-9,*S-1-5-11,*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeTrustedCredManAccessPrivilege = *"}
$value = $value -replace "SeTrustedCredManAccessPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.1; (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-11,*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeNetworkLogonRight = *"}
$value = $value -replace "SeNetworkLogonRight = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.3; (L1) Ensure 'Access this computer from the network'  is set to 'Administrators, Authenticated Users' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "<blank> (i.e. None)"
$Value = $secpolicy | where {$_ -like "*SeTcbPrivilege = *"}
if ($value -eq $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.4; (L1) Ensure 'Act as part of the operating system' is set to 'No One';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-19,*S-1-5-20,*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeIncreaseQuotaPrivilege = *"}
$value = $value -replace "SeIncreaseQuotaPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.6; (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeInteractiveLogonRight = *"}
$value = $value -replace "SeInteractiveLogonRight = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.7; (L1) Ensure 'Allow log on locally' is set to 'Administrators';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544,*S-1-5-32-555"
$Value = $secpolicy | where {$_ -like "*SeRemoteInteractiveLogonRight = *"}
$value = $value -replace "SeRemoteInteractiveLogonRight = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.9; (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeBackupPrivilege = *"}
$value = $value -replace "SeBackupPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.10; (L1) Ensure 'Back up files and directories' is set to 'Administrators';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-19,*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeSystemtimePrivilege = *"}
$value = $value -replace "SeSystemtimePrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.11; (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-19,*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeTimeZonePrivilege = *"}
$value = $value -replace "SeTimeZonePrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.12; (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeCreatePagefilePrivilege = *"}
$value = $value -replace "SeCreatePagefilePrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.13; (L1) Ensure 'Create a pagefile' is set to 'Administrators';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "<blank> (i.e. None)"
$Value = $secpolicy | where {$_ -like "*SeCreateTokenPrivilege = *"}
if ($value -eq $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.14; (L1) Ensure 'Create a token object' is set to 'No One';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"
$Value = $secpolicy | where {$_ -like "*SeCreateGlobalPrivilege = *"}
$value = $value -replace "SeCreateGlobalPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.15; (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "<blank> (i.e. None)"
$Value = $secpolicy | where {$_ -like "*SeCreatePermanentPrivilege = *"}
if ($value -eq $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.16; (L1) Ensure 'Create permanent shared objects' is set to 'No One';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeCreateSymbolicLinkPrivilege = *"}
$value = $value -replace "SeCreateSymbolicLinkPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.18; (L1) Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeDebugPrivilege = *"}
$value = $value -replace "SeDebugPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.19; (L1) Ensure 'Debug programs' is set to 'Administrators';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-114,*S-1-5-32-546"
$Value = $secpolicy | where {$_ -like "*SeDenyNetworkLogonRight = *"}
$value = $value -replace "SeDenyNetworkLogonRight = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.21; (L1) Ensure 'Deny access to this computer from the network' to include 'Guests, Local account and member of Administrators group' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-546"
$Value = $secpolicy | where {$_ -like "*SeDenyBatchLogonRight = *"}
$value = $value -replace "SeDenyBatchLogonRight = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.22; (L1) Ensure 'Deny log on as a batch job' to include 'Guests';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-546"
$Value = $secpolicy | where {$_ -like "*SeDenyServiceLogonRight = *"}
$value = $value -replace "SeDenyServiceLogonRight = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.23; (L1) Ensure 'Deny log on as a service' to include 'Guests';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-546"
$Value = $secpolicy | where {$_ -like "*SeDenyInteractiveLogonRight = *"}
$value = $value -replace "SeDenyInteractiveLogonRight = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.24; (L1) Ensure 'Deny log on locally' to include 'Guests';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-113,*S-1-5-32-546"
$Value = $secpolicy | where {$_ -like "*SeDenyRemoteInteractiveLogonRight = *"}
$value = $value -replace "SeDenyRemoteInteractiveLogonRight = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.26; (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "<blank> (i.e. None)"
$Value = $secpolicy | where {$_ -like "*SeEnableDelegationPrivilege = *"}
if ($value -eq $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.28; (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeRemoteShutdownPrivilege = *"}
$value = $value -replace "SeRemoteShutdownPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.29; (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-19,*S-1-5-20"
$Value = $secpolicy | where {$_ -like "*SeAssignPrimaryTokenPrivilege = *"}
$value = $value -replace "SeAssignPrimaryTokenPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.30; (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"
$Value = $secpolicy | where {$_ -like "*SeImpersonatePrivilege = *"}
$value = $value -replace "SeImpersonatePrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.32; (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544,*S-1-5-90-0"
$Value = $secpolicy | where {$_ -like "*SeIncreaseBasePriorityPrivilege = *"}
$value = $value -replace "SeIncreaseBasePriorityPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.33; (L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeLoadDriverPrivilege = *"}
$value = $value -replace "SeLoadDriverPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.34; (L1) Ensure 'Load and unload device drivers' is set to 'Administrators';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "<blank> (i.e. None)"
$Value = $secpolicy | where {$_ -like "*SeLockMemoryPrivilege = *"}
if ($value -eq $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.35; (L1) Ensure 'Lock pages in memory' is set to 'No One';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeSecurityPrivilege = *"}
$value = $value -replace "SeSecurityPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.38; (L1) Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "<blank> (i.e. None)"
$Value = $secpolicy | where {$_ -like "*SeRelabelPrivilege = *"}
if ($value -eq $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.39; (L1) Ensure 'Modify an object label' is set to 'No One';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeSystemEnvironmentPrivilege = *"}
$value = $value -replace "SeSystemEnvironmentPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.40; (L1) Ensure 'Modify firmware environment values' is set to 'Administrators';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeManageVolumePrivilege = *"}
$value = $value -replace "SeManageVolumePrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.41; (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeProfileSingleProcessPrivilege = *"}
$value = $value -replace "SeProfileSingleProcessPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.42; (L1) Ensure 'Profile single process' is set to 'Administrators';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
$Value = $secpolicy | where {$_ -like "*SeSystemProfilePrivilege = *"}
$value = $value -replace "SeSystemProfilePrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.43; (L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


<#
$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-19,*S-1-5-20"
$Value = $secpolicy | where {$_ -like "*SeUnsolicitedInputPrivilege = *"}
$value = $value -replace "SeUnsolicitedInputPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.44; (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan
#>

$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-19,*S-1-5-20"
$Value = $secpolicy | where {$_ -like "*SeUnsolicitedInputPrivilege = *"}
if ($value -eq $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.44; (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE';Expected value was $($valueToSet), and value was not found in cfg file (normal)" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeRestorePrivilege = *"}
$value = $value -replace "SeRestorePrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.45; (L1) Ensure 'Restore files and directories' is set to 'Administrators';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeShutdownPrivilege = *"}
$value = $value -replace "SeShutdownPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.46; (L1) Ensure 'Shut down the system' is set to 'Administrators';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "*S-1-5-32-544"
$Value = $secpolicy | where {$_ -like "*SeTakeOwnershipPrivilege = *"}
$value = $value -replace "SeTakeOwnershipPrivilege = "
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.2.48; (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan
























$localusers = $null ; $value = $null ; $valueToSet = $null
$localusers = Get-LocalUser
$valueToSet = "Administrator"
$value = Get-LocalUser | where {$_.Description -like "*administering*" -or $_.Name -like "*admin*" -or $_.Name -like "*adm*"}
if ($value.Enabled -eq $False) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.1.1; (L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled' (MS only);Expected value was for the $($valueToSet) account to be disabled, and the value Enabled:'$($value.Enabled)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "3"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name NoConnectedUser
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.1.2; (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$localusers = $null ; $value = $null ; $valueToSet = $null
$localusers = Get-LocalUser
$valueToSet = "Guest"
$value = Get-LocalUser | where {$_.Description -like "*guest*" -or $_.Name -like "*guest*" -or $_.Name -like "*guest*"}
if ($value.Enabled -eq $False) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.1.3; (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only);Expected value was for the $($valueToSet) account to be disabled, and the value Enabled:'$($value.Enabled)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LimitBlankPasswordUse
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.1.4; (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$localusers = $null ; $value = $null ; $valueToSet = $null
$localusers = Get-LocalUser
$valueToSet = "Administrator"
$value = Get-LocalUser | where {$_.Description -like "*administering*" -or $_.Name -like "*admin*" -or $_.Name -like "*adm*"}
if ($value.Name -ne "Administrator") {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.1.5; (L1) Configure 'Accounts: Rename administrator account';Expected value was for the $($valueToSet) account to be renamed, and the value '$($value.Name)' was found" -ForeGroundColor Cyan

$localusers = $null ; $value = $null ; $valueToSet = $null
$localusers = Get-LocalUser
$valueToSet = "Guest"
$value = Get-LocalUser | where {$_.Description -like "*guest*" -or $_.Name -like "*guest*" -or $_.Name -like "*guest*"}
if ($value.Name -ne "Guest") {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.1.6; (L1) Configure 'Accounts: Rename guest account';Expected value was for the $($valueToSet) account to be renamed, and the value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name SCENoApplyLegacyAuditPolicy
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.2.1; (L1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name CrashOnAuditFail
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.2.2; (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AllocateDASD
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.4.1; (L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name AddPrinterDrivers
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.4.2; (L1) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name RequireSignOrSeal
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.6.1; (L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name SealSecureChannel
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.6.2; (L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name SignSecureChannel
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.6.3; (L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name DisablePasswordChange
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.6.4; (L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "30"
$value = Get-ItemPropertyValue "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name MaximumPasswordAge
if ($value -ge "1" -and $value -le "30") {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.6.5; (L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name RequireStrongKey
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.6.6; (L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name DisableCAD
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.7.1; (L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name DontDisplayLastUserName
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.7.2; (L1) Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "900 or fewer second(s), but not 0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name InactivityTimeoutSecs
if ($value -ge "1" -and $value -le "900") {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.7.3; (L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "Type in a text that's needed for your organization, as long as value is not empty it will pass"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LegalNoticeText
if ($value -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.7.4; (L1) Configure 'Interactive logon: Message text for users attempting to log on';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "Type in a text that's needed for your organization, as long as value is not empty it will pass"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LegalNoticeCaption
if ($value -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.7.5; (L1) Configure 'Interactive logon: Message title for users attempting to log on';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "4 or fewer logon(s)"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount
if ($value -le "4") {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.7.6; (L2) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "between 5 and 14 days"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name PasswordExpiryWarning
if ($value -ge "5" -and $value -le "14") {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.7.7; (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name ForceUnlockLogon
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.7.8; (L1) Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name ScRemoveOption
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.7.9; (L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher;Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name RequireSecuritySignature
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.8.1; (L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name EnableSecuritySignature
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.8.2; (L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name EnablePlainTextPassword
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.8.3; (L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "15 or fewer minute(s)"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name AutoDisconnect
if ($value -le "15") {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.9.1; (L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name RequireSecuritySignature
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.9.2; (L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name EnableSecuritySignature
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.9.3; (L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name enableforcedlogoff
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.9.4; (L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name SMBServerNameHardeningLevel
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.9.5; (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\System\CurrentControlSet\Control\Lsa" -Name TurnOffAnonymousBlock
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.10.1; (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymousSAM
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.10.2; (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.10.3; (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name DisableDomainCreds
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.10.4; (L2) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name EveryoneIncludesAnonymous
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.10.5; (L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "<blank> (i.e. None), or (when the legacy _Computer Browser_ service is enabled) BROWSER"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name NullSessionPipes
if ($value) {$request += "/" + $value}
if ($request -eq $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.10.7; (L1) Configure 'Network access: Named Pipes that can be accessed anonymously' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan
$request = $null

$value = $null ; $valueToSet = $null
$value1 = "System\CurrentControlSet\Control\ProductOptions"
$value2 = "System\CurrentControlSet\Control\Server Applications"
$value3 = "Software\Microsoft\Windows NT\CurrentVersion"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" -Name Machine
if ($value -like "*$value1*" -and $value -like "*$value2*" -and $value -like "*$value3*") {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.10.8; (L1) Configure 'Network access: Remotely accessible registry paths' is configured;Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan






$CertSrvc = $null ; $WinsSrvc = $null ; $WINS = $null ; $Cert = $null ; $value1 = $null ; $value2 = $null ; $value3 = $null ; $value4 = $null ; $value5 = $null ; $value6 = $null ; $value7 = $null ; $value8 = $null ; $value9 = $null ; $value10 = $null ; $value11 = $null ; $value12 = $null ; $valueToSet = $null
$Value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" -Name Machine
$Value1 = $Value | where {$_ -like "*System\CurrentControlSet\Control\Print\Printers*"}
$Value2 = $Value | where {$_ -like "*System\CurrentControlSet\Services\Eventlog*"}
$Value3 = $Value | where {$_ -like "*Software\Microsoft\OLAP Server*"}
$Value4 = $Value | where {$_ -like "*Software\Microsoft\Windows NT\CurrentVersion\Print*"}
$Value5 = $Value | where {$_ -like "*Software\Microsoft\Windows NT\CurrentVersion\Windows*"}
$Value6 = $Value | where {$_ -like "*System\CurrentControlSet\Control\ContentIndex*"}
$Value7 = $Value | where {$_ -like "*System\CurrentControlSet\Control\Terminal Server*"}
$Value8 = $Value | where {$_ -like "*System\CurrentControlSet\Control\Terminal Server\UserConfig*"}
$Value9 = $Value | where {$_ -like "*System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration*"}
$Value10 = $Value | where {$_ -like "*Software\Microsoft\Windows NT\CurrentVersion\Perflib*"}
$Value11 = $Value | where {$_ -like "*System\CurrentControlSet\Services\SysmonLog*"}

$CertSrvc = Get-Service CertSvc
    if ($CertSrvc -ne $null) {$Cert = $value | where {$_ -like "*System\CurrentControlSet\Services\CertSvc*"} }
$WinsSrvc = Get-Service wins
    if ($WinsSrvc -ne $null) {$WINS = $value | where {$_ -like "*System\CurrentControlSet\Services\WINS*"} }

if ($value1 -ne $null -and $value2 -ne $null -and $value3 -ne $null -and $value4 -ne $null -and $value5 -ne $null -and $value6 -ne $null -and $value7 -ne $null -and $value8 -ne $null -and $value9 -ne $null -and $value10 -ne $null -and $value11 -ne $null) {$Answer = $True} else {$Answer = $False}
if ($Answer -eq $true -and $CertSrvc -eq $null -and $Cert -eq $null) {$Answer = $True} else {$Answer = $False}
if ($Answer -eq $true -and $WinsSrvc -eq $null -and $WINS -eq $null) {$Answer = $True} else {$Answer = $False}

if ($Answer -eq $True) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.10.9; (L1) Configure 'Network access: Remotely accessible registry paths and sub-paths' is configured;Expected value was 11 items set, and "$value.count" items were set"  -ForeGroundColor Cyan
$CertSrvc = $null ; $WinsSrvc = $null ; $WINS = $null ; $Cert = $null ; $value1 = $null ; $value2 = $null ; $value3 = $null ; $value4 = $null ; $value5 = $null ; $value6 = $null ; $value7 = $null ; $value8 = $null ; $value9 = $null ; $value10 = $null ; $value11 = $null ; $value12 = $null ; $valueToSet = $null








$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name RestrictNullSessAccess
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.10.10; (L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "O:BAG:BAD:(A;;RC;;;BA)"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name restrictremotesam
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.10.11; (L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "<blank> (i.e. None)."
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name NullSessionShares
if ($value) {$request += "/" + $value}
if ($request -eq $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.10.12; (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name ForceGuest
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.10.13; (L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name UseMachineId
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.11.1; (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name AllowNullSessionFallback
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.11.2; (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" -Name AllowOnlineID
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.11.3; (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "2147483640"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name SupportedEncryptionTypes
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.11.4; (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name NoLMHash
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.11.5; (L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan



Write-Host "MANUAL CHECK; 2.3.11.6; (L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'" -ForeGroundColor Magenta





$value = $null ; $valueToSet = $null
$valueToSet = "5"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.11.7; (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name LDAPClientIntegrity
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.11.8; (L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher;Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "537395200"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name NTLMMinClientSec
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.11.9; (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "537395200"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name NTLMMinServerSec
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.11.10; (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ShutdownWithoutLogon
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.13.1; (L1) Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name ObCaseInsensitive
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.15.1; (L1) Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name ProtectionMode
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.15.2; (L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name FilterAdministratorToken
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.17.1; (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "2"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.17.2; (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorUser
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.17.3; (L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableInstallerDetection
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.17.4; (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableSecureUIAPaths
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.17.5; (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.17.6; (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name PromptOnSecureDesktop
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.17.7; (L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableVirtualization
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "2.3.17.8; (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "4"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" -Name Start
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "5.2; (L2) Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name EnableFirewall
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.1.1; (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name DefaultInboundAction
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.1.2; (L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name DefaultOutboundAction
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.1.3; (L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name DisableNotifications
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.1.4; (L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name LogFilePath
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.1.5; (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "16384"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name LogFileSize
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.1.6; (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name LogDroppedPackets
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.1.7; (L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name LogSuccessfulConnections
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.1.8; (L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name EnableFirewall
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.2.1; (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name DefaultInboundAction
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.2.2; (L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name DefaultOutboundAction
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.2.3; (L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name DisableNotifications
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.2.4; (L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name LogFilePath
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.2.5; (L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "16384"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name LogFileSize
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.2.6; (L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name LogDroppedPackets
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.2.7; (L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" -Name LogSuccessfulConnections
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.2.8; (L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name EnableFirewall
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.3.1; (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name DefaultInboundAction
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.3.2; (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name DefaultOutboundAction
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.3.3; (L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name DisableNotifications
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.3.4; (L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name AllowLocalPolicyMerge
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.3.5; (L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name AllowLocalIPsecPolicyMerge
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.3.6; (L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "%SystemRoot%\System32\logfiles\firewall\publicfw.log"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name LogFilePath
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.3.7; (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "16384"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name LogFileSize
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.3.8; (L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name LogDroppedPackets
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.3.9; (L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" -Name LogSuccessfulConnections
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "9.3.10; (L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$auditpol = AuditPol /get /category:*

$var = $auditpol | where {$_ -like "*Credential Validation*"} | where {$_ -like "*Success and Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.1.1; (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Kerberos Authentication Service*"} | where {$_ -like "*Success and Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.1.2; (L1) Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure' (DC Only)"  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Kerberos Service Ticket Operations*"} | where {$_ -like "*Success and Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.1.3; (L1) Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure' (DC Only)"  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Application Group Management*"} | where {$_ -like "*Success and Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.2.1; (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Computer Account Management*"} | where {$_ -like "*Success*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.2.2; (L1) Ensure 'Audit Computer Account Management' is set to include 'Success' (DC only)"  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Distribution Group Management*"} | where {$_ -like "*Success*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.2.3; (L1) Ensure 'Audit Distribution Group Management' is set to include 'Success' (DC only)"  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Other Account Management Events*"} | where {$_ -like "*Success*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.2.4; (L1) Ensure 'Audit Other Account Management Events' is set to include 'Success' (DC only) "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Security Group Management*"} | where {$_ -like "*Success*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.2.5; (L1) Ensure 'Audit Security Group Management' is set to include 'Success' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*User Account Management*"} | where {$_ -like "*Success and Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.2.6; (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*PNP Activity*"} | where {$_ -like "*Success*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.3.1; (L1) Ensure 'Audit PNP Activity' is set to include 'Success' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Process Creation*"} | where {$_ -like "*Success*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.3.2; (L1) Ensure 'Audit Process Creation' is set to include 'Success' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Directory Service Access*"} | where {$_ -like "*Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.4.1; (L1) Ensure 'Audit Directory Service Access' is set to include 'Failure' (DC only)"  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Directory Service Changes*"} | where {$_ -like "*Success*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.4.2; (L1) Ensure 'Audit Directory Service Changes' is set to include 'Success' (DC only)"  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Account Lockout*"} | where {$_ -like "*Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.5.1; (L1) Ensure 'Audit Account Lockout' is set to include 'Failure' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Group Membership*"} | where {$_ -like "*Success*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.5.2; (L1) Ensure 'Audit Group Membership' is set to include 'Success' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Logoff*"} | where {$_ -like "*Success*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.5.3; (L1) Ensure 'Audit Logoff' is set to include 'Success' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Logon*"} | where {$_ -like "*Success and Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.5.4; (L1) Ensure 'Audit Logon' is set to 'Success and Failure' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Other Logon/Logoff Events*"} | where {$_ -like "*Success and Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.5.5; (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Special Logon*"} | where {$_ -like "*Success*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.5.6; (L1) Ensure 'Audit Special Logon' is set to include 'Success' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Detailed File Share*"} | where {$_ -like "*Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.6.1; (L1) Ensure 'Audit Detailed File Share' is set to include 'Failure'"  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*File Share*"} | where {$_ -like "*Success and Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.6.2; (L1) Ensure 'Audit File Share' is set to 'Success and Failure'"  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Other Object Access Events*"} | where {$_ -like "*Success and Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.6.3; (L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'"  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Removable Storage*"} | where {$_ -like "*Success and Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.6.4; (L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Policy Change*"} | where {$_ -like "*Success*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.7.1; (L1) Ensure 'Audit Audit Policy Change' is set to include 'Success' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Authentication Policy Change*"} | where {$_ -like "*Success*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.7.2; (L1) Ensure 'Audit Authentication Policy Change' is set to include 'Success' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Authorization Policy Change*"} | where {$_ -like "*Success*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.7.3; (L1) Ensure 'Audit Authorization Policy Change' is set to include 'Success' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*MPSSVC Rule-Level Policy Change*"} | where {$_ -like "*Success and Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.7.4; (L1) Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'"  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Other Policy Change Events*"} | where {$_ -like "*Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.7.5; (L1) Ensure 'Audit Other Policy Change Events' is set to include 'Failure'"  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Sensitive Privilege Use*"} | where {$_ -like "*Success and Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.8.1; (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*IPsec Driver*"} | where {$_ -like "*Success and Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.9.1; (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Other System Events*"} | where {$_ -like "*Success and Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.9.2; (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Security State Change*"} | where {$_ -like "*Success*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.9.3; (L1) Ensure 'Audit Security State Change' is set to include 'Success' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*Security System Extension*"} | where {$_ -like "*Success*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.9.4; (L1) Ensure 'Audit Security System Extension' is set to include 'Success' "  -ForeGroundColor Cyan

$var = $auditpol | where {$_ -like "*System Integrity*"} | where {$_ -like "*Success and Failure*"}
if ($var -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "17.9.5; (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure' "  -ForeGroundColor Cyan

<#

# Set every audit to Success and Failure

AuditPol /get /category:*
AuditPol /set /category:System /success:enable /failure:enable
AuditPol /set /category:"Logon/Logoff" /success:enable /failure:enable
AuditPol /set /category:"Object Access" /success:enable /failure:enable
AuditPol /set /category:"Privilege Use" /success:enable /failure:enable
AuditPol /set /category:"Detailed Tracking" /success:enable /failure:enable
AuditPol /set /category:"Policy Change" /success:enable /failure:enable
AuditPol /set /category:"Account Management" /success:enable /failure:enable
AuditPol /set /category:"DS Access" /success:enable /failure:enable
AuditPol /set /category:"Account Logon" /success:enable /failure:enable
AuditPol /get /category:*


#>





$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name NoLockScreenCamera
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.1.1.1; (L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name NoLockScreenSlideshow
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.1.1.2; (L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name AllowInputPersonalization
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.1.2.2; (L1) Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name AllowOnlineTips
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.1.3; (L2) Ensure 'Allow Online Tips' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "C:\Program Files\LAPS\CSE\AdmPwd.dll"
$value1 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}" -Name DllName
$value2 = Get-ChildItem "C:\Program Files\LAPS\CSE\AdmPwd.dll"
if ($value1 -eq $valueToSet -and $value2 -ne $null) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.2.1; (L1) Ensure LAPS AdmPwd GPO Extension / CSE is installed (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan
$value1 = $null ; $value2 = $null

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name PwdExpirationProtectionEnabled
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.2.2; (L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name AdmPwdEnabled
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.2.3; (L1) Ensure 'Enable Local Admin Password Management' is set to 'Enabled' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "4"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name PasswordComplexity
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.2.4; (L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "Enabled: 15 or more"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name PasswordLength
if ($value -ge "15") {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.2.5; (L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "Enabled: 30 or fewer"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name PasswordAgeDays
if ($value -le "30") {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.2.6; (L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.3.1; (L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "4"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name Start
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.3.2; (L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.3.3; (L1) Ensure 'Configure SMB v1 server' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name DisableExceptionChainValidation
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.3.4; (L1) Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name RestrictDriverInstallationToAdministrators 
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.3.5; (L1) Ensure 'Limits print driver installation to Administrators' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "2"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name NodeType
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.3.6; (L1) Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.3.7; (L1) Ensure 'WDigest Authentication' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.4.1; (L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "2"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name DisableIPSourceRouting
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.4.2; (L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "2"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name DisableIPSourceRouting
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.4.3; (L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name EnableICMPRedirect
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.4.4; (L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "300000"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name KeepAliveTime
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.4.5; (L2) Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name NoNameReleaseOnDemand
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.4.6; (L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name PerformRouterDiscovery
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.4.7; (L2) Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name SafeDllSearchMode
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.4.8; (L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "5"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name ScreenSaverGracePeriod
if ($value -le $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.4.9; (L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "3"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name TcpMaxDataRetransmissions
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.4.10; (L2) Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "3"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name TcpMaxDataRetransmissions
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.4.11; (L2) Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "90"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" -Name WarningLevel
if ($value -le $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.4.12; (L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "2"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name DoHPolicy
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.4.1; (L1) Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher;Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.4.2; (L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name EnableFontProviders
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.5.1; (L2) Ensure 'Enable Font Providers' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name AllowInsecureGuestAuth
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.8.1; (L1) Ensure 'Enable insecure guest logons' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan














$value1 = $null ; $value2 = $null ; $value3 = $null ; $value4 = $null ; $valueToSet = $null
$valueToSet = "0"
$value1 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name AllowLLTDIOOnDomain
$value2 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name AllowLLTDIOOnPublicNet
$value3 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name EnableLLTDIO
$value4 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name ProhibitLLTDIOOnPrivateNet
if ($value1 -eq $valueToSet -and $value2 -eq $valueToSet -and $value3 -eq $valueToSet -and $value4 -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.9.1; (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value1 = $null ; $value2 = $null ; $value3 = $null ; $value4 = $null ; $valueToSet = $null
$valueToSet = "0"
$value1 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name AllowRspndrOnDomain
$value2 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name AllowRspndrOnPublicNet
$value3 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name EnableRspndr
$value4 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name ProhibitRspndrOnPrivateNet
if ($value1 -eq $valueToSet -and $value2 -eq $valueToSet -and $value3 -eq $valueToSet -and $value4 -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.9.2; (L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan












$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -Name Disabled
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.10.2; (L2) Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name NC_AllowNetBridge_NLA
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.11.2; (L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name NC_ShowSharedAccessUI
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.11.3; (L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name NC_StdDomainUserSetLocation
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.11.4; (L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan











$value1 = $null ; $value2 = $null ; $valueToSet = $null
$valueToSet = "RequireMutualAuthentication=1, RequireIntegrity=1"
$value1 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name \\*\NETLOGON
$value2 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name \\*\SYSVOL
if ($value1 -eq $valueToSet -and $value2 -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.14.1; (L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan












$value = $null ; $valueToSet = $null
$valueToSet = "255"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name DisabledComponents
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.19.2.1; (L2) Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)');Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan











$value1 = $null ; $value2 = $null ; $value3 = $null ; $value4 = $null ; $value5 = $null ; $valueToSet = $null
$valueToSet = "0"
$value1 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name EnableRegistrars
$value2 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name DisableUPnPRegistrar
$value3 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name DisableInBand802DOT11Registrar
$value4 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name DisableFlashConfigRegistrar
$value5 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name DisableWPDRegistrar
if ($value1 -eq $valueToSet -and $value2 -eq $valueToSet -and $value3 -eq $valueToSet -and $value4 -eq $valueToSet -and $value5 -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.20.1; (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


















$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name DisableWcnUi
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.20.2; (L2) Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "3"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name fMinimizeConnections
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.21.1; (L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name fBlockNonDomain
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.5.21.2; (L2) Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "2"
$value = Get-ItemPropertyValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name RegisterSpoolerRemoteRpcEndPoint
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.6.1; (L1) Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name NoWarningNoElevationOnInstall
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.6.2; (L1) Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name UpdatePromptSettings
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.6.3; (L1) Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name NoCloudApplicationNotification
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.7.1.1; (L2) Ensure 'Turn off notifications network usage' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.3.1; (L1) Ensure 'Include command line in process creation events' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Name AllowEncryptionOracle
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.4.1; (L1) Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name AllowProtectedCreds
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.4.2; (L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name EnableVirtualizationBasedSecurity
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.5.1; (NG) Ensure 'Turn On Virtualization Based Security' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "3"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name RequirePlatformSecurityFeatures
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.5.2; (NG) Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name HypervisorEnforcedCodeIntegrity
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.5.3; (NG) Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name HVCIMATRequired
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.5.4; (NG) Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name LsaCfgFlags
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.5.5; (NG) Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock' (MS Only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name LsaCfgFlags
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.5.6; (NG) Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Disabled' (DC Only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name ConfigureSystemGuardLaunch
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.5.7; (NG) Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name PreventDeviceMetadataFromNetwork
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.7.2; (L1) Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "3"
$value = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name DriverLoadPolicy
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.14.1; (L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name NoBackgroundPolicy
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.21.2; (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name NoGPOListChanges
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.21.3; (L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name EnableCdp
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.21.4; (L1) Ensure 'Continue experiences on this device' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = $null
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name DisableBkGndGroupPolicy
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.21.5; (L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name DisableWebPnPDownload
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.22.1.1; (L1) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name PreventHandwritingDataSharing
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.22.1.2; (L2) Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name PreventHandwritingErrorReports
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.22.1.3; (L2) Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -Name ExitOnMSICW
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.22.1.4; (L2) Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoWebServices
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.22.1.5; (L1) Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name DisableHTTPPrinting
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.22.1.6; (L2) Ensure 'Turn off printing over HTTP' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" -Name NoRegistration
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.22.1.7; (L2) Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" -Name DisableContentFileUpdates
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.22.1.8; (L2) Ensure 'Turn off Search Companion content file updates' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoOnlinePrintsWizard
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.22.1.9; (L2) Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoPublishingWizard
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.22.1.10; (L2) Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "2"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name CEIP
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.22.1.11; (L2) Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name CEIPEnable
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.22.1.12; (L2) Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan











$value1 = $null ; $value2 = $null ; $valueToSet = $null
$valueToSet = "1"
$value1 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name Disabled
$value2 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name DoReport
if ($value1 -eq "1" -and $value2 -eq "0") {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.22.1.13; (L2) Ensure 'Turn off Windows Error Reporting' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value1) & $($value2)' was found" -ForeGroundColor Cyan



$value1 = $null ; $value2 = $null ; $valueToSet = $null
$valueToSet = "Enabled: Automatic"
$value1 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" -Name DevicePKInitBehavior
$value2 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" -Name DevicePKInitEnabled
if ($value1 -eq "0" -and $value2 -eq "1") {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.25.1; (L2) Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic';Expected value was $($valueToSet), and value '$($value1) & $($value2)' was found" -ForeGroundColor Cyan






$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" -Name DeviceEnumerationPolicy
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.26.1; (L1) Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Name BlockUserInputMethodsForSignIn
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.27.1; (L2) Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name BlockUserFromShowingAccountDetailsOnSignin
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.28.1; (L1) Ensure 'Block user from showing account details on sign-in' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name DontDisplayNetworkSelectionUI
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.28.2; (L1) Ensure 'Do not display network selection UI' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name DontEnumerateConnectedUsers
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.28.3; (L1) Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name EnumerateLocalUsers
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.28.4; (L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name DisableLockScreenAppNotifications
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.28.5; (L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name BlockDomainPicturePassword
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.28.6; (L1) Ensure 'Turn off picture password sign-in' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name AllowDomainPINLogon
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.28.7; (L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name AllowCrossDeviceClipboard
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.31.1; (L2) Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name UploadUserActivities
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.31.2; (L2) Ensure 'Allow upload of User Activities' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name DCSettingIndex
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.34.6.1; (L2) Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name ACSettingIndex
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.34.6.2; (L2) Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name DCSettingIndex
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.34.6.3; (L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name ACSettingIndex
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.34.6.4; (L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fAllowUnsolicited
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.36.1; (L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fAllowToGetHelp
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.36.2; (L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name EnableAuthEpResolution
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.37.1; (L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name RestrictRemoteClients
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.37.2; (L2) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name DisableQueryRemoteServer
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.48.5.1; (L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Name ScenarioExecutionEnabled
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.48.11.1; (L2) Ensure 'Enable/Disable PerfTrack' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name DisabledByGroupPolicy
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.50.1; (L2) Ensure 'Turn off the advertising ID' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -Name Enabled
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.53.1.1; (L2) Ensure 'Enable Windows NTP Client' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" -Name Enabled
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.8.53.1.2; (L2) Ensure 'Enable Windows NTP Server' is set to 'Disabled' (MS only);Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" -Name AllowSharedLocalAppData
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.4.1; (L2) Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name MSAOptional
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.6.1; (L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name NoAutoplayfornonVolume
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.8.1; (L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoAutorun
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.8.2; (L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "255"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.8.3; (L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name EnhancedAntiSpoofing
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.10.1.1; (L1) Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Camera" -Name AllowCamera
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.12.1; (L2) Ensure 'Allow Use of Camera' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableConsumerAccountStateContent
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.14.1; (L1) Ensure 'Turn off cloud consumer account state content' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsConsumerFeatures
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.14.2; (L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Name RequirePinForPairing
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.15.1; (L1) Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name DisablePasswordReveal
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.16.1; (L1) Ensure 'Do not display the password reveal button' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name EnumerateAdministrators
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.16.2; (L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.17.1; (L1) Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name DisableEnterpriseAuthProxy
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.17.2; (L2) Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name DisableOneSettingsDownloads
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.17.3; (L1) Ensure 'Disable OneSettings Downloads' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name DoNotShowFeedbackNotifications
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.17.4; (L1) Ensure 'Do not show feedback notifications' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name EnableOneSettingsAuditing
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.17.5; (L1) Ensure 'Enable OneSettings Auditing' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name LimitDiagnosticLogCollection
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.17.6; (L1) Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name LimitDumpCollection
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.17.7; (L1) Ensure 'Limit Dump Collection' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name AllowBuildPreview
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.17.8; (L1) Ensure 'Toggle user control over Insider builds' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name Retention
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.27.1.1; (L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "32768"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name MaxSize
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.27.1.2; (L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name Retention
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.27.2.1; (L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "196608"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name MaxSize
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.27.2.2; (L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name Retention
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.27.3.1; (L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "32768"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name MaxSize
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.27.3.2; (L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name Retention
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.27.4.1; (L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "32768"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name MaxSize
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.27.4.2; (L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name NoDataExecutionPrevention
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.31.2; (L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name NoHeapTerminationOnCorruption
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.31.3; (L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name PreXPSP2ShellProtocolBehavior
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.31.4; (L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name DisableLocation
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.41.1; (L2) Ensure 'Turn off location' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name AllowMessageSync
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.45.1; (L2) Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" -Name DisableUserAuth
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.46.1; (L1) Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name LocalSettingOverrideSpynetReporting
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.47.4.1; (L1) Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name SpynetReporting
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.47.4.2; (L2) Ensure 'Join Microsoft MAPS' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name ExploitGuard_ASR_Rules
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.47.5.1.1; (L1) Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan













$value1 = $null ; $value2 = $null ; $value3 = $null ; $value4 = $null ; $value5 = $null ; $value6 = $null ; $value7 = $null ; $value8 = $null ; $value9 = $null ; $value10 = $null ; $value11 = $null ; $value12 = $null ; $valueToSet = $null
$value1 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name 26190899-1602-49e8-8b27-eb1d0a1ce869
$value2 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name 3b576869-a4ec-4529-8536-b80a7769e899
$value3 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name 5beb7efe-fd9a-4556-801d-275e5ffc04cc
$value4 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84
$value5 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c
$value6 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b
$value7 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
$value8 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4
$value9 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name be9ba2d9-53ea-4cdc-84e5-9b1eeee46550
$value10 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name d3e037e1-3eb8-44c8-a917-57927947596d
$value11 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name d4f940ab-401b-4efc-aadc-ad5f3c50688a
$value12 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name e6db77e5-3df2-4cf1-b95a-636979351e5b
if ($value1 -eq "1" -and $value2 -eq "1" -and $value3 -eq "1" -and $value4 -eq "1" -and $value5 -eq "1" -and $value6 -eq "1" -and $value7 -eq "1" -and $value8 -eq "1" -and $value9 -eq "1" -and $value10 -eq "1" -and $value11 -eq "1" -and $value12 -eq "1") {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.47.5.1.2; (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured;Expected value was $($valueToSet), and value '$($value1)' was found" -ForeGroundColor Cyan
$value1 = $null ; $value2 = $null ; $value3 = $null ; $value4 = $null ; $value5 = $null ; $value6 = $null ; $value7 = $null ; $value8 = $null ; $value9 = $null ; $value10 = $null ; $value11 = $null ; $value12 = $null ; $valueToSet = $null















$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name EnableNetworkProtection
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.47.5.3.1; (L1) Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name EnableFileHashComputation
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.47.6.1; (L2) Ensure 'Enable file hash computation feature' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name DisableIOAVProtection
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.47.9.1; (L1) Ensure 'Scan all downloaded files and attachments' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name DisableRealtimeMonitoring
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.47.9.2; (L1) Ensure 'Turn off real-time protection' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name DisableBehaviorMonitoring
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.47.9.3; (L1) Ensure 'Turn on behavior monitoring' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name DisableScriptScanning
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.47.9.4; (L1) Ensure 'Turn on script scanning' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name DisableGenericRePorts
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.47.11.1; (L2) Ensure 'Configure Watson events' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name DisableRemovableDriveScanning
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.47.12.1; (L1) Ensure 'Scan removable drives' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name DisableEmailScanning
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.47.12.2; (L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name PUAProtection
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.47.15; (L1) Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.47.16; (L1) Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name DisableFileSyncNGSC
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.58.1; (L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall" -Name DisablePushToInstall
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.64.1; (L2) Ensure 'Turn off Push To Install service' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name DisablePasswordSaving
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.2.2; (L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fSingleSessionPerUser
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.2.1; (L2) Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name EnableUiaRedirection
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.3.1; (L2) Ensure 'Allow UI Automation redirection' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fDisableCcm
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.3.2; (L2) Ensure 'Do not allow COM port redirection' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fDisableCdm
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.3.3; (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fDisableLocationRedir
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.3.4; (L2) Ensure 'Do not allow location redirection' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fDisableLPT
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.3.5; (L2) Ensure 'Do not allow LPT port redirection' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fDisablePNPRedir
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.3.6; (L2) Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fPromptForPassword
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.9.1; (L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fEncryptRPCTraffic
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.9.2; (L1) Ensure 'Require secure RPC communication' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "2"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name SecurityLayer
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.9.3; (L1) Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name UserAuthentication
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.9.4; (L1) Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "3"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name MinEncryptionLevel
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.9.5; (L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "Enabled: 15 minutes or less, but not Never (0)"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name MaxIdleTime
if ($value -ge "1" -and $value -le "900000") {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.10.1; (L2) Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less, but not Never (0)';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "60000"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name MaxDisconnectionTime
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.10.2; (L2) Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name DeleteTempDirsOnExit
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.11.1; (L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name PerSessionTempDir
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.65.3.11.2; (L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name DisableEnclosureDownload
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.66.1; (L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowCloudSearch
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.67.2; (L2) Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowIndexingEncryptedStoresOrItems
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.67.3; (L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name NoGenTicket
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.72.1; (L2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

















##############################################################################################

# BETTER VERBIAGE FOR MULTI VALUE OUTPUTS

##############################################################################################


$value1 = $null ; $value2 = $null ; $valueToSet = $null ; $valueToSet2 = $null
$valueToSet1 = "1"
$valueToSet2 = "Block"
$value1 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name EnableSmartScreen
$value2 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name ShellSmartScreenLevel
if ($value1 -eq $valueToSet1 -and $value2 -eq $valueToSet2) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.85.1.1; (L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass';Expected values are '$($valueToSet1)' & '$($valueToSet2)', and value '$($value1)' & '$($value2)' were found" -ForeGroundColor Cyan
$value1 = $null ; $value2 = $null ; $valueToSet = $null ; $valueToSet2 = $null












$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name AllowSuggestedAppsInWindowsInkWorkspace
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.89.1; (L2) Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name AllowWindowsInkWorkspace
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.89.2; (L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name EnableUserControl
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.90.1; (L1) Ensure 'Allow user control over installs' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.90.2; (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name SafeForScripting
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.90.3; (L2) Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name DisableAutomaticRestartSignOn
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.91.1; (L1) Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.100.1; (L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name EnableTranscripting
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.100.2; (L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name AllowBasic
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.102.1.1; (L1) Ensure 'Allow Basic authentication' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name AllowUnencryptedTraffic
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.102.1.2; (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name AllowDigest
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.102.1.3; (L1) Ensure 'Disallow Digest authentication' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name AllowBasic
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.102.2.1; (L1) Ensure 'Allow Basic authentication' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name AllowAutoConfig
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.102.2.2; (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name AllowUnencryptedTraffic
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.102.2.3; (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name DisableRunAs
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.102.2.4; (L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name AllowRemoteShellAccess
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.103.1; (L2) Ensure 'Allow Remote Shell Access' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Name DisallowExploitProtectionOverride
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.105.2.1; (L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoRebootWithLoggedOnUsers
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.108.1.1; (L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.108.2.1; (L1) Ensure 'Configure Automatic Updates' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name ScheduledInstallDay
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.108.2.2; (L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name ManagePreviewBuildsPolicyValue
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.108.4.1; (L1) Ensure 'Manage preview builds' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan










$value1 = $null ; $value2 = $null ; $valueToSet = $null ; $valueToSet2 = $null
$valueToSet1 = "1"
$valueToSet2 = "180"
$value1 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name DeferFeatureUpdates
$value2 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name DeferFeatureUpdatesPeriodInDays
if ($value1 -eq $valueToSet1 -and $value2 -ge $valueToSet2) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.108.4.2; (L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days';Expected values are '$($valueToSet1)' & '$($valueToSet2)', and value '$($value1)' & '$($value2)' were found" -ForeGroundColor Cyan









$value1 = $null ; $value2 = $null ; $valueToSet = $null
$valueToSet1 = "1"
$valueToSet2 = "0"
$value1 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name DeferQualityUpdates
$value2 = Get-ItemPropertyValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name DeferQualityUpdatesPeriodInDays
if ($value1 -eq $valueToSet1 -and $value2 -eq $valueToSet2) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "18.9.108.4.3; (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days';Expected values are '$($valueToSet1)' & '$($valueToSet2)', and value '$($value1)' & '$($value2)' were found" -ForeGroundColor Cyan















$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name ScreenSaveActive
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "19.1.3.1; (L1) Ensure 'Enable screen saver' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name ScreenSaverIsSecure
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "19.1.3.2; (L1) Ensure 'Password protect the screen saver' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "Enabled: 900 seconds or fewer, but not 0"
$value = Get-ItemPropertyValue "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name ScreenSaveTimeOut
if ($value -ge "1" -and $value -le "900") {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "19.1.3.3; (L1) Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name NoToastApplicationNotificationOnLockScreen
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "19.5.1.1; (L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0" -Name NoImplicitFeedback
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "19.6.6.1.1; (L2) Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "2"
$value = Get-ItemPropertyValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name SaveZoneInformation
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "19.7.4.1; (L1) Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "3"
$value = Get-ItemPropertyValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name ScanWithAntiVirus
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "19.7.4.2; (L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "2"
$value = Get-ItemPropertyValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name ConfigureWindowsSpotlight
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "19.7.8.1; (L1) Ensure 'Configure Windows spotlight on lock screen' is set to Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableThirdPartySuggestions
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "19.7.8.2; (L1) Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableTailoredExperiencesWithDiagnosticData
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "19.7.8.3; (L2) Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsSpotlightFeatures
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "19.7.8.4; (L2) Ensure 'Turn off all Windows spotlight features' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableSpotlightCollectionOnDesktop
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "19.7.8.5; (L1) Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoInplaceSharing
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "19.7.28.1; (L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

$value = $null ; $valueToSet = $null
$valueToSet = "0"
$value = Get-ItemPropertyValue "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "19.7.43.1; (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan


$value = $null ; $valueToSet = $null
$valueToSet = "1"
$value = Get-ItemPropertyValue "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name PreventCodecDownload
if ($value -eq $valueToSet) {Write-Host "YES; " -ForeGroundColor Green -NoNewLine} else {Write-host "NO; " -ForeGroundColor Red -NoNewLine}
Write-Host "19.7.47.2.1; (L2) Ensure 'Prevent Codec Download' is set to 'Enabled';Expected value was $($valueToSet), and value '$($value)' was found" -ForeGroundColor Cyan

