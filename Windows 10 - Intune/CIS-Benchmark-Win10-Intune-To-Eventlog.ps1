
#Requires -RunAsAdministrator
#Requires -Version 4.0

<#
    .SYNOPSIS
        This script checks against all of the CIS_Microsoft_Intune_for_Windows_10_Release_2004_Benchmark_v1.0.1 benchmarks as outlined in their documentation

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
    .\CIS-Benchmark-Win10-Intune.ps1

#>

$ErrorActionPreference = "continue"
$WarningPreference = "continue"


$UserSid = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\FileAssociations -Name UserSid).UserSid
$RegHive = (gci HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers -Recurse | where {$_.Name -like "*$UserSid*" -and $_.PSIsContainer -eq $true} | select -First 1).Name -replace "HKEY_LOCAL_MACHINE","HKLM:"
$noSIDinGuid = $RegHive -replace "\\$UserSid",""

$null = secedit.exe /export /cfg c:\windows\temp\security-policy.inf
$secpolicy = Get-Content "C:\windows\temp\security-policy.inf"

New-EventLog -Source CIS-Benchmarks -LogName dbx-corpfleet -ErrorAction SilentlyContinue

$CISBenchmarks = @()
$CISBenchmarks += "ENABLED/NO,CONTROL NO.,DESCRIPTION,SETTING FOUND"

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock -Name DevicePasswordHistory_ProviderSet
$var2 = Get-ItemPropertyValue $noSIDinGuid\Device\DeviceLock -Name DevicePasswordHistory
if ($var1 -ge 1 -and $var2 -ge 24) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|1.1.1|(L1) Ensure 'Enforce password history' is set to '24 or more passwords'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock -Name DevicePasswordExpiration_ProviderSet
$var2 = Get-ItemPropertyValue $noSIDinGuid\Device\DeviceLock -Name evicePasswordExpiration
if ($var1 -ge 1 -and $var2 -le 60) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|1.1.2|(L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock -Name MinimumPasswordAge_ProviderSet
$var2 = Get-ItemPropertyValue $noSIDinGuid\Device\DeviceLock -Name MinimumPasswordAge
if ($var1 -eq 1 -and $var2 -ge 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|1.1.3|(L1) Ensure 'Minimum password age' is set to '1 or more day(s)'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock -Name MinDevicePasswordLength_ProviderSet
$var2 = Get-ItemPropertyValue $noSIDinGuid\Device\DeviceLock -Name MinDevicePasswordLength
if ($var1 -eq 1 -and $var2 -ge 14){$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|1.1.4|(L1) Ensure 'Minimum password length' is set to '14 or more characters'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock -Name MinDevicePasswordComplexCharacters_ProviderSet
$var2 = Get-ItemPropertyValue $noSIDinGuid\Device\DeviceLock -Name MinDevicePasswordComplexCharacters
if ($var1 -eq 1 -and $var2 -eq 2){$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|1.1.5|(L1) Ensure 'Password must meet complexity requirements' is set to 'Numbers, lowercase, uppercase and special characters required'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name AccessCredentialManagerAsTrustedCaller_ProviderSet
$var2 = Get-ItemPropertyValue $noSIDinGuid\Device\UserRights -Name AccessCredentialManagerAsTrustedCaller
if ($var1 -eq 1 -and $var2 -eq "No one") {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.1|(L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name AccessFromNetwork_ProviderSet
$var2 = Get-ItemPropertyValue $noSIDinGuid\Device\UserRights -Name AccessFromNetwork
if ($var1 -eq 1 -and $var2 -eq "Administrators, Remote Desktop Users") {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.2|(L1) Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name ActAsPartOfTheOperatingSystem_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.3|(L1) Ensure 'Act as part of the operating system' is set to 'No One'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name AllowLocalLogOn_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.4|(L1) Ensure 'Allow log on locally' is set to 'Administrators, Users'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name BackupFilesAndDirectories_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.5|(L1) Ensure 'Back up files and directories' is set to 'Administrators'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name ChangeSystemTime_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.6|(L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name CreatePageFile_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.7|(L1) Ensure 'Create a pagefile' is set to 'Administrators'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name CreateToken_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.8|(L1) Ensure 'Create a token object' is set to 'No One'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name CreateGlobalObjects_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.9|(L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name CreatePermanentSharedObjects_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.10|(L1) Ensure 'Create permanent shared objects' is set to 'No One'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name CreateSymbolicLinks_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.11|(L1) Configure 'Create symbolic links' is set to 'Administrators'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name DebugPrograms_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.12|(L1) Ensure 'Debug programs' is set to 'Administrators'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name DenyAccessFromNetwork_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.13|(L1) Ensure 'Deny access to this computer from the network' to include 'Guests, Local account'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name DenyLocalLogOn_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.14|(L1) Ensure 'Deny log on locally' to include 'Guests'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name DenyRemoteDesktopServicesLogOn_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.15|(L1) Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name EnableDelegation_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.16|(L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name RemoteShutdown_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.17|(L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name GenerateSecurityAudits_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.18|(L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name ImpersonateClient_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.19|(L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name IncreaseSchedulingPriority_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.20|(L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

#===========================================================================================================================================================================
Write-EventLog -LogName "dbx-corpfleet" -Source "dbx-corpfleet" -EventID 1 -EntryType Information -Message ([string]::Join("`n", $CISBenchmarks)) -Category 1 -RawData 10,20
$CISBenchmarks = @()
$CISBenchmarks += "ENABLED/NO,CONTROL NO.,DESCRIPTION,SETTING FOUND"
#===========================================================================================================================================================================

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name LoadUnloadDeviceDrivers_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.21|(L1) Ensure 'Load and unload device drivers' is set to 'Administrators'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name LockMemory_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.22|(L1) Ensure 'Lock pages in memory' is set to 'No One'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name ManageAuditingAndSecurityLog_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.23|(L1) Ensure 'Manage auditing and security log' is set to 'Administrators'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name ModifyObjectLabel_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.24|(L1) Ensure 'Modify an object label' is set to 'No One'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name ModifyFirmwareEnvironment_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.25|(L1) Ensure 'Modify firmware environment values' is set to 'Administrators'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name ManageVolume_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.26|(L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name ProfileSingleProcess_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.27|(L1) Ensure 'Profile single process' is set to 'Administrators'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name RestoreFilesAndDirectories_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.28|(L1) Ensure 'Restore files and directories' is set to 'Administrators'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\UserRights -Name TakeOwnership_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.2.29|(L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name Accounts_EnableAdministratorAccountStatus_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.1.1|(L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name Accounts_BlockMicrosoftAccounts_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name NoConnectedUser
if ($var1 -eq 1 -and $var2 -eq 3) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.1.2|(L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name Accounts_EnableGuestAccountStatus_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.1.3|(L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name Accounts_LimitLocalAccountUseOfBlankPasswordsToConsoleLogonOnly_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LimitBlankPasswordUse
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.1.4|(L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name Accounts_RenameAdministratorAccount_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.1.5|(L1) Configure 'Accounts: Rename administrator account'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name Accounts_RenameGuestAccount_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.1.6|(L1) Configure 'Accounts: Rename guest account'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name Devices_AllowedToFormatAndEjectRemovableMedia_ProviderSet
$var2 = Get-ItemPropertyValue $noSIDinGuid\Device\LocalPoliciesSecurityOptions -Name Devices_AllowedToFormatAndEjectRemovableMedia
if ($var1 -eq 1 -and $var2 -eq "Administrators and Interactive Users") {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.4.1|(L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators and Interactive Users'|and values '$($var1) and $($var2) were found"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name InteractiveLogon_DoNotRequireCTRLALTDEL_ProviderSet 
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.7.1|(L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name InteractiveLogon_DoNotDisplayLastSignedIn_ProviderSet
$var2 = Get-ItemPropertyValue $noSIDinGuid\Device\LocalPoliciesSecurityOptions -Name InteractiveLogon_DoNotRequireCTRLALTDEL
if ($var1 -eq 1 -and $var2 -eq 0) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.7.2|(L1) Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name InteractiveLogon_MachineInactivityLimit_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name InactivityTimeoutSecs
if ($var1 -ge 1 -and $var2 -le 900) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.7.3|(L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name InteractiveLogon_MessageTextForUsersAttemptingToLogOn_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LegalNoticeText
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.7.4|(L1) Configure 'Interactive logon: Message text for users attempting to log on'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name InteractiveLogon_MessageTitleForUsersAttemptingToLogOn_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LegalNoticeCaption
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.7.5|(L1) Configure 'Interactive logon: Message title for users attempting to log on'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name MicrosoftNetworkClient_DigitallySignCommunicationsAlways_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Name RequireSecuritySignature
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.8.1|(L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name MicrosoftNetworkClient_DigitallySignCommunicationsIfServerAgrees_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Name EnableSecuritySignature
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.8.2|(L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name MicrosoftNetworkClient_SendUnencryptedPasswordToThirdPartySMBServers_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters -Name EnablePlainTextPassword
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.8.3|(L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name MicrosoftNetworkServer_DigitallySignCommunicationsAlways_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name RequireSecuritySignature
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.9.1|(L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

#===========================================================================================================================================================================
Write-EventLog -LogName "dbx-corpfleet" -Source "dbx-corpfleet" -EventID 1 -EntryType Information -Message ([string]::Join("`n", $CISBenchmarks)) -Category 1 -RawData 10,20
$CISBenchmarks = @()
$CISBenchmarks += "ENABLED/NO,CONTROL NO.,DESCRIPTION,SETTING FOUND"
#===========================================================================================================================================================================

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name MicrosoftNetworkServer_DigitallySignCommunicationsIfClientAgrees_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name EnableSecuritySignature
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.9.2|(L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name NetworkAccess_DoNotAllowAnonymousEnumerationOfSAMAccounts_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RestrictAnonymousSAM
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.10.1|(L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name NetworkAccess_DoNotAllowAnonymousEnumerationOfSAMAccountsAndShares_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RestrictAnonymous
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.10.2|(L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name NetworkAccess_RestrictAnonymousAccessToNamedPipesAndShares_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name RestrictNullSessAccess
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.10.3|(L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name NetworkAccess_RestrictClientsAllowedToMakeRemoteCallsToSAM_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RestrictRemoteSAM
if ($var1 -eq 1 -and $var2 -eq "O:BAG:BAD:(A;;RC;;;BA)") {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.10.4|(L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name NetworkAccess_RestrictAnonymousAccessToNamedPipesAndShares_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.10.5|(L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name NetworkSecurity_AllowLocalSystemToUseComputerIdentityForNTLM_ProviderSet
$var2 = Get-ItemPropertyValue $noSIDinGuid\Device\LocalPoliciesSecurityOptions -Name NetworkSecurity_AllowLocalSystemToUseComputerIdentityForNTLM
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.11.1|(L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name NetworkSecurity_AllowPKU2UAuthenticationRequests_ProviderSet
$var2 = Get-ItemPropertyValue $noSIDinGuid\Device\LocalPoliciesSecurityOptions -Name NetworkSecurity_AllowPKU2UAuthenticationRequests
if ($var1 -eq 1 -and $var2 -eq 0) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.11.2|(L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $var3 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name NetworkSecurity_DoNotStoreLANManagerHashValueOnNextPasswordChange_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name NoLMHash
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.11.3|(L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name NetworkSecurity_LANManagerAuthenticationLevel_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel
if ($var1 -eq 1 -and $var2 -eq 5) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.11.4|(L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name NetworkSecurity_MinimumSessionSecurityForNTLMSSPBasedClients_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 -Name NTLMMinClientSec
if ($var1 -eq 1 -or $var2 -eq 537395200) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.11.5|(L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name UserAccountControl_UseAdminApprovalMode_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name FilterAdministratorToken
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.17.1|(L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name UserAccountControl_BehaviorOfTheElevationPromptForAdministrators_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin
if ($var1 -eq 1 -and $var2 -eq 2) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.17.2|(L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name UserAccountControl_BehaviorOfTheElevationPromptForStandardUsers_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorUser
if ($var1 -eq 1 -and $var2 -eq 0) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.17.3|(L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name UserAccountControl_DetectApplicationInstallationsAndPromptForElevation_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableInstallerDetection
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.17.4|(L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name UserAccountControl_OnlyElevateUIAccessApplicationsThatAreInstalledInSecureLocations_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableSecureUIAPaths
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.17.5|(L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name UserAccountControl_RunAllAdministratorsInAdminApprovalMode_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.17.6|(L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name UserAccountControl_SwitchToTheSecureDesktopWhenPromptingForElevation_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name PromptOnSecureDesktop
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.17.7|(L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions -Name UserAccountControl_VirtualizeFileAndRegistryWriteFailuresToPerUserLocations_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableVirtualization
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.17.8|(L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\SystemServices -Name ConfigureXboxAccessoryManagementServiceStartupMode_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|5.1|(L1) Ensure 'Xbox Accessory Management Service (XboxGipSvc)' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\SystemServices -Name ConfigureXboxLiveAuthManagerServiceStartupMode_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|5.2|(L1) Ensure 'Xbox Live Auth Manager (XblAuthManager)' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\SystemServices -Name ConfigureXboxLiveGameSaveServiceStartupMode_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|5.3|(L1) Ensure 'Xbox Live Game Save (XblGameSave)' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\SystemServices -Name ConfigureXboxLiveNetworkingServiceStartupMode_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|5.4|(L1) Ensure 'Xbox Live Networking Service (XboxNetApiSvc)' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\DomainProfile -Name EnableFirewall
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|9.1.1|(L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\DomainProfile -Name DefaultInboundAction
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|9.1.2|(L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

#===========================================================================================================================================================================
Write-EventLog -LogName "dbx-corpfleet" -Source "dbx-corpfleet" -EventID 1 -EntryType Information -Message ([string]::Join("`n", $CISBenchmarks)) -Category 1 -RawData 10,20
$CISBenchmarks = @()
$CISBenchmarks += "ENABLED/NO,CONTROL NO.,DESCRIPTION,SETTING FOUND"
#===========================================================================================================================================================================

$var1 = Get-ItemPropertyValue HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\DomainProfile -Name DefaultOutboundAction
if ($var1 -eq 0) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|9.1.3|(L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\DomainProfile -Name DisableNotifications
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|9.1.4|(L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'Block'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\PublicProfile -Name EnableFirewall
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|9.2.1|(L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\PublicProfile -Name DefaultInboundAction
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|9.2.2|(L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\PublicProfile -Name DefaultOutboundAction
if ($var1 -eq 0) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|9.2.3|(L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\PublicProfile -Name DisableNotifications
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|9.2.4|(L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'Block'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\StandardProfile -Name EnableFirewall
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|9.3.1|(L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\StandardProfile -Name DefaultInboundAction
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|9.3.2|(L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\StandardProfile -Name DefaultOutboundAction
if ($var1 -eq 0) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|9.3.3|(L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\StandardProfile -Name DisableNotifications
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|9.3.4|(L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Block'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$auditpol = AuditPol /get /category:*

$var1 = $auditpol | where {$_ -like "*Credential Validation*"} | where {$_ -like "*Success and Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Credential Validation",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.1.1|(L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Application Group Management*"} | where {$_ -like "*Success and Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Application Group Management",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.2.1|(L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Security Group Management*"} | where {$_ -like "*Success*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Security Group Management",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.2.2|(L1) Ensure 'Audit Security Group Management' is set to include 'Success'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*User Account Management*"} | where {$_ -like "*Success and Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "User Account Management",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.2.3|(L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Plug and Play*"} | where {$_ -like "*Success*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Plug and Play",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.3.1|(L1) Ensure 'Audit PNP Activity' is set to include 'Success'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Process Creation*"} | where {$_ -like "*Success*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Process Creation",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.3.2|(L1) Ensure 'Audit Process Creation' is set to include 'Success'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Account Lockout*"} | where {$_ -like "*Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Account Lockout",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.5.1|(L1) Ensure 'Audit Account Lockout' is set to include 'Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Group Membership*"} | where {$_ -like "*Success*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Group Membership",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.5.2|(L1) Ensure 'Audit Group Membership' is set to include 'Success'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Logoff*"} | where {$_ -like "*Success*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Logoff",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.5.3|(L1) Ensure 'Audit Logoff' is set to include 'Success'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Logon*"} | where {$_ -like "*Success and Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Logon",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.5.4|(L1) Ensure 'Audit Logon' is set to 'Success and Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Other Logon/Logoff Events*"} | where {$_ -like "*Success and Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Other Logon",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.5.5|(L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Special Logon*"} | where {$_ -like "*Success*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Special Logon",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.5.6|(L1) Ensure 'Audit Special Logon' is set to include 'Success'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Detailed File Share*"} | where {$_ -like "*Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Detailed File Share",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.6.1|(L1) Ensure 'Audit Detailed File Share' is set to include 'Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*File Share*"} | where {$_ -like "*Success and Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "File Share",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.6.2|(L1) Ensure 'Audit File Share' is set to 'Success and Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Other Object Access Events*"} | where {$_ -like "*Success and Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Other Object Access",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.6.3|(L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

#===========================================================================================================================================================================
Write-EventLog -LogName "dbx-corpfleet" -Source "dbx-corpfleet" -EventID 1 -EntryType Information -Message ([string]::Join("`n", $CISBenchmarks)) -Category 1 -RawData 10,20
$CISBenchmarks = @()
$CISBenchmarks += "ENABLED/NO,CONTROL NO.,DESCRIPTION,SETTING FOUND"
#===========================================================================================================================================================================

$var1 = $auditpol | where {$_ -like "*Removable Storage*"} | where {$_ -like "*Success and Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Removable Storage",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.6.4|(L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Audit Policy Change*"} | where {$_ -like "*Success*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Audit Policy Change",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.7.1|(L1) Ensure 'Audit Audit Policy Change' is set to include 'Success'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Authentication Policy Change*"} | where {$_ -like "*Success*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Authentication Policy Change",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.7.2|(L1) Ensure 'Audit Authentication Policy Change' is set to include 'Success'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Authorization Policy Change*"} | where {$_ -like "*Success*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Authorization Policy Change",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.7.3|(L1) Ensure 'Audit Authorization Policy Change' is set to include 'Success'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*MPSSVC Rule-Level Policy Change*"} | where {$_ -like "*Success and Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "MPSSVC Rule-Level Policy Change",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.7.4|(L1) Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Other Policy Change Events*"} | where {$_ -like "*Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Other Policy Change",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.7.5|(L1) Ensure 'Audit Other Policy Change Events' is set to include 'Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Sensitive Privilege Use*"} | where {$_ -like "*Success and Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Sensitive Privilege Use",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.8.1|(L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*IPsec Driver*"} | where {$_ -like "*Success and Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "IPsec Driver",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.9.1|(L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Other System Events*"} | where {$_ -like "*Success and Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Other System Events",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.9.2|(L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Security State Change*"} | where {$_ -like "*Success*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Security State Change",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.9.3|(L1) Ensure 'Audit Security State Change' is set to include 'Success'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*Security System Extension*"} | where {$_ -like "*Success*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "Security System Extension",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.9.4|(L1) Ensure 'Audit Security System Extension' is set to include 'Success'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = $auditpol | where {$_ -like "*System Integrity*"} | where {$_ -like "*Success and Failure*"}
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$var1 = $var1 -replace "System Integrity",""
$var1 = $var1 -replace "  ",""
$CISBenchmarks += "$yes$no|17.9.5|(L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock -Name PreventEnablingLockScreenCamera_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreenCamera
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.1.1.1|(L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock -Name PreventLockScreenSlideShow_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreenSlideshow
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.1.1.2|(L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Privacy -Name AllowInputPersonalization_ProviderSet
if ($var1 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.1.2.2|(L1) Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\MSSecurityGuide -Name ApplyUACRestrictionsToLocalAccountsOnNetworkLogon_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy
if ($var1 -eq 1 -and $var2 -eq 0) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.3.1|(L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\MSSecurityGuide -Name ConfigureSMBV1ClientDriver_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10 -Name Start
if ($var1 -eq 1 -and $var2 -eq 4) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.3.2|(L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\MSSecurityGuide -Name ConfigureSMBV1Server_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Name SMB1
if ($var1 -eq 1 -or $var2 -eq 0) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.3.3|(L1) Ensure 'Configure SMB v1 server' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\MSSecurityGuide -Name EnableStructuredExceptionHandlingOverwriteProtection_ProviderSet
$var2 = Get-ItemPropertyValue $noSIDinGuid\Device\MSSecurityGuide -Name EnableStructuredExceptionHandlingOverwriteProtection
if ($var1 -eq 1 -and $var2 -eq "<enabled/>") {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.3.4|(L1) Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\MSSecurityGuide -Name WDigestAuthentication_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -Name UseLogonCredential
if ($var1 -eq 2 -and $var2 -eq 0){$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.3.5|(L1) Ensure 'WDigest Authentication' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\MSSLegacy -Name IPv6SourceRoutingProtectionLevel_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters -Name DisableIPSourceRouting
if ($var1 -eq 1 -and $var2 -eq 2) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.4.1|(L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\MSSLegacy -Name IPSourceRoutingProtectionLevel_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Name DisableIPSourceRouting
if ($var1 -eq 1 -and $var2 -eq 2) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.4.2|(L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\MSSLegacy -Name AllowTheComputerToIgnoreNetBIOSNameReleaseRequestsExceptFromWINSServers_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Name EnableICMPRedirect
if ($var1 -eq 1 -and $var2 -eq 0) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.4.3|(L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\MSSLegacy -Name AllowTheComputerToIgnoreNetBIOSNameReleaseRequestsExceptFromWINSServers_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters -Name NoNameReleaseOnDemand
if ($var1 -eq 1 -and $var2 -eq 1) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.4.4|(L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\LanmanWorkstation -Name EnableInsecureGuestLogons_ProviderSet
$var2 = Get-ItemPropertyValue $noSIDinGuid\Device\LanmanWorkstation -Name EnableInsecureGuestLogons
if ($var1 -eq 1 -and $var2 -eq 0) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.5.8.1|(L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Connectivity -Name ProhibitInstallationAndConfigurationOfNetworkBridge_ProviderSet
$var2 = Get-ItemPropertyValue $noSIDinGuid\Device\Connectivity -Name ProhibitInstallationAndConfigurationOfNetworkBridge
if ($var1 -eq 1 -and $var2 -eq "<enabled/>"){$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.5.11.2|(L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

#===========================================================================================================================================================================
Write-EventLog -LogName "dbx-corpfleet" -Source "dbx-corpfleet" -EventID 1 -EntryType Information -Message ([string]::Join("`n", $CISBenchmarks)) -Category 1 -RawData 10,20
$CISBenchmarks = @()
$CISBenchmarks += "ENABLED/NO,CONTROL NO.,DESCRIPTION,SETTING FOUND"
#===========================================================================================================================================================================

#========================================================================================================================================================================
#========================================================================================================================================================================
#========================================================================================================================================================================
#========================================================================================================================================================================
#========================================================================================================================================================================
#========================================================================================================================================================================


$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Wifi -Name AllowInternetSharing_ProviderSet
$var2 = Get-ItemPropertyValue $noSIDinGuid\Wifi -Name AllowInternetSharing
if ($var1 -eq 1 -and $var2 -eq 0) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.5.11.3|(L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Connectivity -Name HardenedUNCPaths_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths -Name \\*\NETLOGON
$var3 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths -Name \\*\SYSVOL
if ($var1 -ne $null -and $var2 -ne $null -and $var3 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.5.14.1|(L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with 'Require Mutual Authentication' and 'Require Integrity' set for all NETLOGON and SYSVOL shares'|and values '$($var1) and $($var2) and $($var3)' were found"
$var1 = $null ; $var2 = $null ; $var3 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Windows ConnectionManager -Name ProhitConnectionToNonDomainNetworksWhenConnectedToDomainAuthenticatedNetwork_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy -Name fBlockNonDomain
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.5.21.1|(L1) Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Wifi -Name AllowAutoConnectToWiFiSenseHotspots_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.5.23.2.1|(L1) Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\CredentialsDelegation -Name RemoteHostAllowsDelegationOfNonExportableCredentials_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name AllowProtectedCreds
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.4.1|(L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System -Name BootStartDriverInitialization_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch -Name DriverLoadPolicy
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.14.1|(L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Connectivity -Name DisableDownloadingOfPrintDriversOverHTTP_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers -Name DisableWebPnPDownload
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.22.1.1|(L1) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Connectivity -Name DisableInternetDownloadForWebPublishingAndOnlineOrderingWizards_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoWebServices
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.22.1.2|(L1) Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsLogon -Name DontDisplayNetworkSelectionUI_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name DontDisplayNetworkSelectionUI
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.28.1|(L1) Ensure 'Do not display network selection UI' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsLogon -Name EnumerateLocalUsersOnDomainJoinedComputers_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name EnumerateLocalUsers
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.28.2|(L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsLogon -Name DisableLockScreenAppNotifications_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name DisableLockScreenAppNotifications
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.28.3|(L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\CredentialProviders -Name BlockPicturePassword_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name BlockDomainPicturePassword
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.28.4|(L1) Ensure 'Turn off picture password sign-in' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\CredentialProviders -Name AllowPINLogon_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name AllowDomainPINLogon
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.28.5|(L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Power -Name RequirePasswordWhenComputerWakesOnBattery_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 -Name DCSettingIndex
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.34.6.3|(L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Power -Name RequirePasswordWhenComputerWakesPluggedIn_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 -Name ACSettingIndex
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.34.6.4|(L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteAssistance -Name UnsolicitedRemoteAssistance_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -Name fAllowUnsolicited
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.36.1|(L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteAssistance -Name SolicitedRemoteAssistance_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -Name fAllowToGetHelp
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.36.2|(L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteProcedureCall -Name RPCEndpointMapperClientAuthentication_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc -Name EnableAuthEpResolution
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.37.1|(L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteProcedureCall -Name RestrictUnauthenticatedRPCClients_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc -Name RestrictRemoteClients
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.37.2|(L1) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Privacy -Name LetAppsActivateWithVoiceAboveLock_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.5.1|(L1) Ensure 'Let Windows apps activate with voice while the system is locked' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\AppRuntime -Name AllowMicrosoftAccountsToBeOptional_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name MSAOptional
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.6.1|(L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Autoplay -Name DisallowAutoplayForNonVolumeDevices_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoAutoplayfornonVolume
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.8.1|(L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Autoplay -Name SetDefaultAutoRunBehavior_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoAutorun
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.8.2|(L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Autoplay -Name TurnOffAutoPlay_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutoRun
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.8.3|(L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Experience -Name AllowWindowsConsumerFeatures_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.13.1|(L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

#===========================================================================================================================================================================
Write-EventLog -LogName "dbx-corpfleet" -Source "dbx-corpfleet" -EventID 1 -EntryType Information -Message ([string]::Join("`n", $CISBenchmarks)) -Category 1 -RawData 10,20
$CISBenchmarks = @()
$CISBenchmarks += "ENABLED/NO,CONTROL NO.,DESCRIPTION,SETTING FOUND"
#===========================================================================================================================================================================

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WirelessDisplay -Name RequirePinForPairing_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.14.1|(L1) Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\CredentialsUI -Name DisablePasswordReveal_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI -Name DisablePasswordReveal
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.15.1|(L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\CredentialsUI -Name EnumerateAdministrators_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI -Name EnumerateAdministrators
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.15.2|(L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System -Name AllowTelemetry_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.16.1|(L1) Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Experience -Name DoNotShowFeedbackNotifications_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.16.3|(L1) Ensure 'Do not show feedback notifications' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System -Name AllowBuildPreview_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.16.4|(L1) Ensure 'Toggle user control over Insider builds' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeliveryOptimization -Name DODownloadMode_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.17.1|(L1) Ensure 'Download Mode' is NOT set to 'Enabled: Internet'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\EventLogService -Name ControlEventLogBehavior_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -Name Retention
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.26.1.1|(L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\EventLogService -Name SpecifyMaximumFileSizeApplicationLog_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application -Name MaxSize
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.26.1.2|(L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\EventLogService -Name SpecifyMaximumFileSizeSecurityLog_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security -Name MaxSize
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.26.2.1|(L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\EventLogService -Name SpecifyMaximumFileSizeSystemLog_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System -Name MaxSize
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.26.4.1|(L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\FileExplorer -Name TurnOffDataExecutionPreventionForExplorer_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoDataExecutionPrevention
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.30.2|(L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\FileExplorer -Name TurnOffHeapTerminationOnCorruption_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoHeapTerminationOnCorruption
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.30.3|(L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender -Name PUAProtection_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager -Name PUAProtection
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.45.14|(L1) Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender -Name AllowRealtimeMonitoring_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.45.15|(L1) Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender -Name AttackSurfaceReductionRules_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.45.4.1.1|(L1) Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender -Name AttackSurfaceReductionRules_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.45.4.1.2|(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender -Name EnableNetworkProtection_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager -Name EnableNetworkProtection
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.45.4.3.1|(L1) Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender -Name AllowBehaviorMonitoring_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager -Name AllowBehaviorMonitoring
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.45.8.1|(L1) Ensure 'Turn on behavior monitoring' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender -Name AllowFullScanRemovableDriveScanning_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager -Name AllowFullScanRemovableDriveScanning
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.45.11.1|(L1) Ensure 'Scan removable drives' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender -Name AllowEmailScanning_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager -Name AllowEmailScanning
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.45.11.2|(L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Browser -Name PreventSmartScreenPromptOverrideForFiles_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.48.1|(L1) Ensure 'Prevent bypassing Windows Defender SmartScreen prompts for files' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System -Name DisableOneDriveFileSync_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Name DisableFileSyncNGSC
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.55.1|(L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteDesktopServices -Name DoNotAllowPasswordSaving_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -Name DisablePasswordSaving
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.62.2.2|(L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteDesktopServices -Name DoNotAllowDriveRedirection_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -Name fDisableCdm
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.62.3.3.1|(L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

#===========================================================================================================================================================================
Write-EventLog -LogName "dbx-corpfleet" -Source "dbx-corpfleet" -EventID 1 -EntryType Information -Message ([string]::Join("`n", $CISBenchmarks)) -Category 1 -RawData 10,20
$CISBenchmarks = @()
$CISBenchmarks += "ENABLED/NO,CONTROL NO.,DESCRIPTION,SETTING FOUND"
#===========================================================================================================================================================================

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteDesktopServices -Name PromptForPasswordUponConnection_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -Name fPromptForPassword
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.62.3.9.1|(L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteDesktopServices -Name RequireSecureRPCCommunication_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -Name fEncryptRPCTraffic
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.62.3.9.2|(L1) Ensure 'Require secure RPC communication' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteDesktopServices -Name ClientConnectionEncryptionLevel_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -Name MinEncryptionLevel
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.62.3.9.3|(L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\InternetExplorer -Name DisableEnclosureDownloading_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds -Name DisableEnclosureDownload
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.63.1|(L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Experience -Name AllowCortana_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.64.3|(L1) Ensure 'Allow Cortana' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\AboveLock -Name AllowCortanaAboveLock_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.64.4|(L1) Ensure 'Allow Cortana above lock screen' is set to 'Blocked'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Search -Name AllowIndexingEncryptedStoresOrItems_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.64.5|(L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Search -Name AllowSearchToUseLocation_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.64.6|(L1) Ensure 'Allow search and Cortana to use location' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement -Name RequirePrivateStoreOnly_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.72.2|(L1) Ensure 'Only display the private store within the Microsoft Store' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement -Name AllowAppStoreAutoUpdate_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.72.3|(L1) Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\SmartScreen -Name EnableSmartScreenInShell_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.80.1.1|(L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Browser -Name AllowSmartScreen_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.80.2.1|(L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Browser -Name PreventSmartScreenPromptOverride_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.80.2.2|(L1) Ensure 'Prevent bypassing Windows Defender SmartScreen prompts for sites' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement -Name AllowGameDVR_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.82.1|(L1) Ensure 'Enables or disables Windows Game Recording and Broadcasting' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsInkWorkspace -Name AllowWindowsInkWorkspace_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.84.2|(L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement -Name MSIAllowUserControlOverInstall_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.85.1|(L1) Ensure 'Allow user control over installs' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement -Name MSIAlwaysInstallWithElevatedPrivileges_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.85.2|(L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsLogon -Name AllowAutomaticRestartSignOn_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableAutomaticRestartSignOn
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.86.1|(L1) Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsPowerShell -Name TurnOnPowerShellScriptBlockLogging_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.95.1|(L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteManagement -Name AllowBasicAuthentication_Client_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -Name AllowBasic
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.97.1.1|(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteManagement -Name AllowUnencryptedTraffic_Client_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -Name AllowUnencryptedTraffic
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.97.1.2|(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteManagement -Name DisallowDigestAuthentication_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client -Name AllowDigest
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.97.1.3|(L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteManagement -Name AllowBasicAuthentication_Service_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -Name AllowBasic
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.97.2.1|(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteManagement -Name AllowUnencryptedTraffic_Service_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -Name AllowUnencryptedTraffic
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.97.2.3|(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteManagement -Name DisallowStoringOfRunAsCredentials_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -Name DisableRunAs
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.97.2.4|(L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

#===========================================================================================================================================================================
Write-EventLog -LogName "dbx-corpfleet" -Source "dbx-corpfleet" -EventID 1 -EntryType Information -Message ([string]::Join("`n", $CISBenchmarks)) -Category 1 -RawData 10,20
$CISBenchmarks = @()
$CISBenchmarks += "ENABLED/NO,CONTROL NO.,DESCRIPTION,SETTING FOUND"
#===========================================================================================================================================================================

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsDefenderSecurityCenter -Name DisallowExploitProtectionOverride_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.99.2.1|(L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update -Name AllowAutoUpdate_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.102.2|(L1) Ensure 'Configure Automatic Updates' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update -Name ScheduledInstallDay_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.102.3|(L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update -Name SetDisablePauseUXAccess_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.102.4|(L1) Ensure 'Remove access to 'Pause updates' feature' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update -Name ManagePreviewBuilds_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.102.1.1|(L1) Ensure 'Manage preview builds' is set to 'Enabled: Disable preview builds'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update -Name PauseQualityUpdates_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.102.1.2|(L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\AboveLock -Name AllowToasts_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|19.5.1.1|(L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Blocked'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\$UserSid\AttachmentManager -Name DoNotPreserveZoneInformation_ProviderSet
$var2 = Get-ItemPropertyValue $RegHive\AttachmentManager -Name DoNotPreserveZoneInformation
$var3 = Get-ItemPropertyValue HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation
if ($var1 -ne $null -and $var2 -ne $null -and $var3 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|19.7.4.1|(L1) Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'|and values '$($var1) and $($var2) and $($var3)' were found"
$var1 = $null ; $var2 = $null ; $var3 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\$UserSid\AttachmentManager -Name NotifyAntivirusPrograms_ProviderSet
$var2 = Get-ItemPropertyValue $RegHive\AttachmentManager -Name NotifyAntivirusPrograms
$var3 = Get-ItemPropertyValue HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name ScanWithAntiVirus
if ($var1 -ne $null -and $var2 -ne $null -and $var3 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|19.7.4.2|(L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'|and values '$($var1) and $($var2) and $($var3)' were found"
$var1 = $null ; $var2 = $null ; $var3 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\$UserSid\Experience -Name ConfigureWindowsSpotlightOnLockScreen_ProviderSet
$var2 = Get-ItemPropertyValue $RegHive\Experience -Name ConfigureWindowsSpotlightOnLockScreen
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|19.7.8.1|(L1) Ensure 'Configure Windows spotlight on lock screen' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\$UserSid\Experience -Name AllowThirdPartySuggestionsInWindowsSpotlight_ProviderSet
$var2 = Get-ItemPropertyValue $RegHive\Experience -Name AllowThirdPartySuggestionsInWindowsSpotlight
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|19.7.8.2|(L1) Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement -Name MSIAlwaysInstallWithElevatedPrivileges_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|19.7.42.1|(L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Connectivity -Name DisableDownloadingOfPrintDriversOverHTTP_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers -Name AddPrinterDrivers
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|2.3.4.2|(L2) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Settings -Name AllowOnlineTips_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.1.3|(L2) Ensure 'Allow Online Tips' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System -Name AllowFontProviders_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.5.5.1|(L2) Ensure 'Enable Font Providers' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Notifications -Name DisallowCloudNotification_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.7.1.1|(L2) Ensure 'Turn off notifications network usage' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Connectivity -Name DiablePrintingOverHTTP_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers -Name DisableHTTPPrinting
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.22.1.3|(L2) Ensure 'Turn off printing over HTTP' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ErrorReporting -Name DisableWindowsErrorReporting_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting -Name Disabled
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.22.1.4|(L2) Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Privacy -Name AllowCrossDeviceClipboard_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.31.1|(L2) Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Privacy -Name UploadUserActivities_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.31.2|(L2) Ensure 'Allow upload of User Activities' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Privacy -Name DisableAdvertisingId_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo -Name DisabledByGroupPolicy
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.49.1|(L2) Ensure 'Turn off the advertising ID' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement -Name AllowSharedUserAppData_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.4.1|(L2) Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Camera -Name AllowCamera_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.12.1|(L2) Ensure 'Allow Use of Camera' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System -Name DisableEnterpriseAuthProxy_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.16.2|(L2) Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System -Name AllowLocation_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.39.1|(L2) Ensure 'Turn off location' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

#===========================================================================================================================================================================
Write-EventLog -LogName "dbx-corpfleet" -Source "dbx-corpfleet" -EventID 1 -EntryType Information -Message ([string]::Join("`n", $CISBenchmarks)) -Category 1 -RawData 10,20
$CISBenchmarks = @()
$CISBenchmarks += "ENABLED/NO,CONTROL NO.,DESCRIPTION,SETTING FOUND"
#===========================================================================================================================================================================

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Messaging -Name AllowMessageSync_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.43.1|(L2) Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteDesktopServices -Name AllowUsersToConnectRemotely_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services -Name fDenyTSConnections
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.62.3.2.1|(L2) Ensure 'Allow users to connect remotely by using Remote Desktop Services' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Search -Name AllowCloudSearch_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.64.2|(L2) Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Licensing -Name DisallowKMSClientOnlineAVSValidation_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.69.1|(L2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement -Name DisableStoreOriginatedApps_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.72.1|(L2) Ensure 'Disable all apps from Microsoft Store' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsInkWorkSpace -Name AllowSuggestedAppsInWindowsInkWorkspace_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.84.1|(L2) Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteManagement -Name AllowRemoteServerManagement_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service -Name AllowAutoConfig
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.97.2.2|(L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\RemoteShell -Name AllowRemoteShellAccess_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS -Name AllowRemoteShellAccess
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.98.1|(L2) Ensure 'Allow Remote Shell Access' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceInstallation -Name PreventInstallationOfMatchingDeviceIDs_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions -Name DenyDeviceIDs
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.7.1.1|(BL) Ensure 'Prevent installation of devices that match any of these device IDs' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceInstallation -Name PreventInstallationOfMatchingDeviceIDs_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs -Name 1
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.7.1.2|(BL) Ensure 'Prevent installation of devices that match any of these device IDs: Prevent installation of devices that match any of these device IDs' is set to 'PCI\CC_0C0A'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceInstallation -Name PreventInstallationOfMatchingDeviceIDs_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions -Name DenyDeviceIDsRetroactive
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.7.1.3|(BL) Ensure 'Prevent installation of devices that match any of these device IDs: Also apply to matching devices that are already installed.' is set to 'True' (checked)"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceInstallation -Name PreventInstallationOfMatchingDeviceSetupClasses_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions -Name DenyDeviceClasses
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.7.1.4|(BL) Ensure 'Prevent installation of devices using drivers that match these device setup classes' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceInstallation -Name PreventInstallationOfMatchingDeviceIDs_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions -Name DenyDeviceClassesRetroactive
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.7.1.5|(BL) Ensure 'Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed.' is set to 'True' (checked)"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DmaGuard -Name DeviceEnumerationPolicy_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.26.1|(BL) Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Power -Name AllowStandbyStatesWhenSleepingOnBattery_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab -Name DCSettingIndex
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.34.6.1|(BL) Ensure 'Allow standby states (S1-S3) when sleeping (on battery)' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Power -Name AllowStandbyWhenSleepingPluggedIn_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab -Name ACSettingIndex
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.34.6.2|(BL) Ensure 'Allow standby states (S1-S3) when sleeping (plugged in)' is set to 'Disabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name FixedDrivesRecoveryOptions_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVRecovery
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.1.1|(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name FixedDrivesRecoveryOptions_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVManageDRA
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.1.2|(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Allow data recovery agent' is set to 'Enabled: True'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name FixedDrivesRecoveryOptions_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVRecoveryPassword
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.1.3|(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Password' is set to 'Enabled: Allow 48-digit recovery password'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name FixedDrivesRecoveryOptions_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVHideRecoveryPage
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.1.4|(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name FixedDrivesRecoveryOptions_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVActiveDirectoryBackup
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.1.5|(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Save BitLocker recovery information to AD DS for fixed data drives' is set to 'Enabled: False'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name FixedDrivesRecoveryOptions_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVActiveDirectoryInfoToStore
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.1.6|(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Configure storage of BitLocker recovery information to AD DS' is set to 'Enabled: Backup recovery passwords and key packages'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name FixedDrivesRecoveryOptions_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name FDVRequireActiveDirectoryBackup
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.1.7|(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives' is set to 'Enabled: False'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name SystemDrivesRecoveryOptions_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSRecovery
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.2.1|(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name SystemDrivesRecoveryOptions_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSManageDRA
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.2.2|(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Allow data recovery agent' is set to 'Enabled: False'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

#===========================================================================================================================================================================
Write-EventLog -LogName "dbx-corpfleet" -Source "dbx-corpfleet" -EventID 1 -EntryType Information -Message ([string]::Join("`n", $CISBenchmarks)) -Category 1 -RawData 10,20
$CISBenchmarks = @()
$CISBenchmarks += "ENABLED/NO,CONTROL NO.,DESCRIPTION,SETTING FOUND"
#===========================================================================================================================================================================

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name SystemDrivesRecoveryOptions_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSRecoveryPassword
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.2.3|(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Password' is set to 'Enabled: Require 48-digit recovery password'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name SystemDrivesRecoveryOptions_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSRecoveryKey
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.2.4|(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name SystemDrivesRecoveryOptions_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSHideRecoveryPage
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.2.5|(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name SystemDrivesRecoveryOptions_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSActiveDirectoryBackup
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.2.6|(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Save BitLocker recovery information to AD DS for operating system drives' is set to 'Enabled: True'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name SystemDrivesRecoveryOptions_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSActiveDirectoryInfoToStore
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.2.7|(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Store recovery passwords and key packages'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name SystemDrivesRecoveryOptions_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name OSRequireActiveDirectoryBackup
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.2.8|(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for operating system drives' is set to 'Enabled: True'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name SystemDrivesRequireStartupAuthentication_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name UseAdvancedStartup
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.2.9|(BL) Ensure 'Require additional authentication at startup' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name SystemDrivesRequireStartupAuthentication_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name EnableBDEWithNoTPM
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.2.10|(BL) Ensure 'Require additional authentication at startup: Allow BitLocker without a compatible TPM' is set to 'Enabled: False'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name RemovableDrivesRequireEncryption_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE -Name RDVDenyWriteAccess
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.3.1|(BL) Ensure 'Deny write access to removable drives not protected by BitLocker' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker -Name RemovableDrivesRequireEncryption_ProviderSet
$var2 = Get-ItemPropertyValue HKLM:\SOFTWARE\Policies\Microsoft\FVE -Name RDVDenyCrossOrg
if ($var1 -ne $null -and $var2 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.9.11.3.2|(BL) Ensure 'Deny write access to removable drives not protected by BitLocker: Do not allow write access to devices configured in another organization' is set to 'Enabled: False'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceGuard -Name EnableVirtualizationBasedSecurity_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.5.1|(NG) Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceGuard -Name RequirePlatformSecurityFeatures_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.5.2|(NG) Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceGuard -Name LsaCfgFlags_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.5.3|(NG) Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

$var1 = Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceGuard -Name ConfigureSystemGuardLaunch_ProviderSet
if ($var1 -ne $null) {$yes = "YES"} else {$no = "NO"}
$CISBenchmarks += "$yes$no|18.8.5.4|(NG) Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'"
$var1 = $null ; $var2 = $null ; $yes = $null ; $no = $null

#===========================================================================================================================================================================
Write-EventLog -LogName "dbx-corpfleet" -Source "dbx-corpfleet" -EventID 1 -EntryType Information -Message ([string]::Join("`n", $CISBenchmarks)) -Category 1 -RawData 10,20
$CISBenchmarks = @()
$CISBenchmarks += "ENABLED/NO,CONTROL NO.,DESCRIPTION,SETTING FOUND"
#===========================================================================================================================================================================

#$CISBenchmarks






