$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"

########################################################################################################################################################
# 1. Account policies
########################################################################################################################################################

################################################## 1.1. Password Policy ##################################################
Function Set-Control1-1-1 {
    # Control 1.1.1 - Remediation Script
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "PasswordHistorySize" -Value 24
}

Function Set-Control1-1-2 {
    # Control 1.1.2 - Remediation Script
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "MaxPasswordAge" -Value 365
}

Function Set-Control1-1-3 {
    # Control 1.1.3 - Remediation Script
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "MinPasswordAge" -Value 1
}

Function Set-Control1-1-4 {
    # Control 1.1.4 - Remediation Script
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "MinPasswordLength" -Value 14
}

Function Set-Control1-1-5 {
    # Control 1.1.5 - Remediation Script
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordComplexity" -Value 1
}

Function Set-Control1-1-6 {
    # Control 1.1.6 - Remediation Script
    # Define paths
    $exportPath = "C:\temp\secpol.cfg"
    $importPath = "C:\temp\secpol.cfg"

    # Export the current local security policy
    $null = secedit /export /cfg $exportPath

    # Read the contents of the exported file
    $content = Get-Content $exportPath

    # Modify the specific setting (This is a placeholder, as the exact line is unknown)
    # Assuming 'NewPasswordLength' is the setting name, which might not be the case
    $content = $content -replace "NewPasswordLength = .*", "NewPasswordLength = 1"

    # Write the changes back to the file
    Set-Content -Path $exportPath -Value $content

    # Import the modified policy
    $null = secedit /import /cfg $importPath
}

Function Set-Control1-1-7 {
    # Control 1.1.7 - Remediation Script
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ClearTextPassword" -Value 0
}


################################################## 1.2. Account Lockout Policy ##################################################
Function Set-Control1-2-1 {
    # Control 1.2.1 - Remediation Script
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LockoutDuration" -Value 15
}

Function Set-Control1-2-2 {
    # Control 1.2.2 - Remediation Script
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LockoutThreshold" -Value 5
}

Function Set-Control1-2-3 {
    # Control 1.2.3 - Remediation Script
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LockoutObservationWindow" -Value 15
}

########################################################################################################################################################
# 2. Local Policies
########################################################################################################################################################

################################################## 2.1. Audit Policy ##################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

################################################## 2.1. User Rights Assignment ##################################################
Function Set-Control2-2-1 {
    # Control 2.2.1 - Remediation Script
    $user = "No One"
    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    (Get-Content -Path "$env:temp\secpol.cfg").Replace("SeTrustedCredManAccessPrivilege = *", "SeTrustedCredManAccessPrivilege = $user") | Set-Content "$env:temp\secpol.cfg"
    $secpol = secedit /import /cfg $env:temp\secpol.cfg /areas USER_RIGHTS
}

Function Set-Control2-2-2 {
    # Control 2.2.2 - Remediation Script
    $users = "*S-1-5-32-544,*S-1-5-32-555" # Administrators, Remote Desktop Users
    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    (Get-Content -Path "$env:temp\secpol.cfg").Replace("SeNetworkLogonRight = *", "SeNetworkLogonRight = $users") | Set-Content "$env:temp\secpol.cfg"
    $secpol = secedit /import /cfg $env:temp\secpol.cfg /areas USER_RIGHTS
}

Function Set-Control2-2-3 {
    # Control 2.2.3 - Remediation Script
    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    (Get-Content -Path "$env:temp\secpol.cfg").Replace("SeTcbPrivilege = *", "SeTcbPrivilege = ") | Set-Content "$env:temp\secpol.cfg"
    $secpol = secedit /import /cfg $env:temp\secpol.cfg /areas USER_RIGHTS
}

Function Set-Control2-2-4 {
    # Control 2.2.4 - Remediation Script
    $users = "*S-1-5-32-544,*S-1-5-19,*S-1-5-20" # Administrators, LOCAL SERVICE, NETWORK SERVICE
    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    (Get-Content -Path "$env:temp\secpol.cfg").Replace("SeIncreaseQuotaPrivilege = *", "SeIncreaseQuotaPrivilege = $users") | Set-Content "$env:temp\secpol.cfg"
    $secpol = secedit /import /cfg $env:temp\secpol.cfg /areas USER_RIGHTS
}

Function Set-Control2-2-5 {
    # Control 2.2.5 - Remediation Script
    $users = "*S-1-5-32-544,*S-1-5-32-545" # Administrators, Users
    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    (Get-Content -Path "$env:temp\secpol.cfg").Replace("SeInteractiveLogonRight = *", "SeInteractiveLogonRight = $users") | Set-Content "$env:temp\secpol.cfg"
    $secpol = secedit /import /cfg $env:temp\secpol.cfg /areas USER_RIGHTS
}

Function Set-Control2-2-6 {
    # Control 2.2.6 - Remediation Script
    $users = "*S-1-5-32-544,*S-1-5-32-555" # Administrators, Remote Desktop Users
    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    (Get-Content -Path "$env:temp\secpol.cfg").Replace("SeRemoteInteractiveLogonRight = *", "SeRemoteInteractiveLogonRight = $users") | Set-Content "$env:temp\secpol.cfg"
    $secpol = secedit /import /cfg $env:temp\secpol.cfg /areas USER_RIGHTS
}

Function Set-Control2-2-7 {
    # Control 2.2.7 - Remediation Script
    $user = "*S-1-5-32-544" # Administrators
    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    (Get-Content -Path "$env:temp\secpol.cfg").Replace("SeBackupPrivilege = *", "SeBackupPrivilege = $user") | Set-Content "$env:temp\secpol.cfg"
    $secpol = secedit /import /cfg $env:temp\secpol.cfg /areas USER_RIGHTS
}

Function Set-Control2-2-8 {
    # Control 2.2.8 - Remediation Script
    $users = "*S-1-5-32-544,*S-1-5-19" # Administrators, LOCAL SERVICE
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeSystemtimePrivilege = *", "SeSystemtimePrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-9 {
    # Control 2.2.9 - Remediation Script
    $users = "*S-1-5-32-544,*S-1-5-19,*S-1-5-32-545" # Administrators, LOCAL SERVICE, Users
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeTimeZonePrivilege = *", "SeTimeZonePrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-10 {
    # Control 2.2.10 - Remediation Script
    $user = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeCreatePagefilePrivilege = *", "SeCreatePagefilePrivilege = $user") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-11 {
    # Control 2.2.11 - Remediation Script
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeCreateTokenPrivilege = *", "SeCreateTokenPrivilege = ") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-12 {
    # Control 2.2.12 - Remediation Script
    $users = "*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6" # Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeCreateGlobalPrivilege = *", "SeCreateGlobalPrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-13 {
    # Control 2.2.13 - Remediation Script
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeCreatePermanentPrivilege = *", "SeCreatePermanentPrivilege = ") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-14 {
    # Control 2.2.14 - Remediation Script
    $users = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeCreateSymbolicLinkPrivilege = *", "SeCreateSymbolicLinkPrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-15 {
    # Control 2.2.15 - Remediation Script
    $users = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeDebugPrivilege = *", "SeDebugPrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-16 {
    # Control 2.2.16 - Remediation Script
    $users = "*S-1-5-32-546,*S-1-5-113" # Guests, Local account
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeDenyNetworkLogonRight = *", "SeDenyNetworkLogonRight = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-17 {
    # Control 2.2.17 - Remediation Script
    $user = "*S-1-5-32-546" # Guests
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeDenyBatchLogonRight = *", "SeDenyBatchLogonRight = $user") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-18 {
    # Control 2.2.18 - Remediation Script
    $user = "*S-1-5-32-546" # Guests
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeDenyServiceLogonRight = *", "SeDenyServiceLogonRight = $user") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-19 {
    # Control 2.2.19 - Remediation Script
    $user = "*S-1-5-32-546" # Guests
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeDenyInteractiveLogonRight = *", "SeDenyInteractiveLogonRight = $user") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-20 {
    # Control 2.2.20 - Remediation Script
    $users = "*S-1-5-32-546,*S-1-5-113" # Guests, Local account
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeDenyRemoteInteractiveLogonRight = *", "SeDenyRemoteInteractiveLogonRight = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-21 {
    # Control 2.2.21 - Remediation Script
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeEnableDelegationPrivilege = *", "SeEnableDelegationPrivilege = ") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-22 {
    # Control 2.2.22 - Remediation Script
    $users = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeRemoteShutdownPrivilege = *", "SeRemoteShutdownPrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-23 {
    # Control 2.2.23 - Remediation Script
    $users = "*S-1-5-19,*S-1-5-20" # LOCAL SERVICE, NETWORK SERVICE
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeAuditPrivilege = *", "SeAuditPrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-24 {
    # Control 2.2.24 - Remediation Script
    $users = "*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6" # Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeImpersonatePrivilege = *", "SeImpersonatePrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-25 {
    # Control 2.2.25 - Remediation Script
    $users = "*S-1-5-32-544,*S-1-5-90-0" # Administrators, Window Manager\Window Manager Group
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeIncreaseBasePriorityPrivilege = *", "SeIncreaseBasePriorityPrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-26 {
    # Control 2.2.26 - Remediation Script
    $user = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeLoadDriverPrivilege = *", "SeLoadDriverPrivilege = $user") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-27 {
    # Control 2.2.27 - Remediation Script
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeLockMemoryPrivilege = *", "SeLockMemoryPrivilege = ") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-28 {
    # Control 2.2.28 - Remediation Script
    $users = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeBatchLogonRight = *", "SeBatchLogonRight = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-29 {
    # Control 2.2.29 - Remediation Script
    $users = "" # Define the users or groups as per your policy
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeServiceLogonRight = *", "SeServiceLogonRight = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-30 {
    # Control 2.2.30 - Remediation Script
    $users = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeSecurityPrivilege = *", "SeSecurityPrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-31 {
    # Control 2.2.31 - Remediation Script
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeRelabelPrivilege = *", "SeRelabelPrivilege = ") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-32 {
    # Control 2.2.32 - Remediation Script
    $users = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeSystemEnvironmentPrivilege = *", "SeSystemEnvironmentPrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-33 {
    # Control 2.2.33 - Remediation Script
    $users = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeManageVolumePrivilege = *", "SeManageVolumePrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-34 {
    # Control 2.2.34 - Remediation Script
    $users = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeProfileSingleProcessPrivilege = *", "SeProfileSingleProcessPrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-35 {
    # Control 2.2.35 - Remediation Script
    $users = "*S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420" # Administrators, NT SERVICE\WdiServiceHost
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeSystemProfilePrivilege = *", "SeSystemProfilePrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-36 {
    # Control 2.2.36 - Remediation Script
    $users = "*S-1-5-19,*S-1-5-20" # LOCAL SERVICE, NETWORK SERVICE
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeAssignPrimaryTokenPrivilege = *", "SeAssignPrimaryTokenPrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-37 {
    # Control 2.2.37 - Remediation Script
    $users = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeRestorePrivilege = *", "SeRestorePrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-38 {
    # Control 2.2.38 - Remediation Script
    $users = "*S-1-5-32-544,*S-1-5-32-545" # Administrators, Users
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeShutdownPrivilege = *", "SeShutdownPrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}

Function Set-Control2-2-39 {
    # Control 2.2.39 - Remediation Script
    $users = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    (Get-Content -Path $exportPath).Replace("SeTakeOwnershipPrivilege = *", "SeTakeOwnershipPrivilege = $users") | Set-Content $exportPath
    $secpol = secedit /import /cfg $exportPath /areas USER_RIGHTS
}


################################################## 2.3. Security Options ##################################################
############################## 2.3.1 Accounts ##############################
Function Set-Control2-3-1-1 {
    # Control 2.3.1.1 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    $valueName = "Administrator"
    $valueData = 0 # Disabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

######################################################
# Circle back for Control 2.3.1.2
######################################################

Function Set-Control2-3-1-3 {
    # Control 2.3.1.3 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    $valueName = "Guest"
    $valueData = 0 # Disabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-1-4 {
    # Control 2.3.1.4 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "LimitBlankPasswordUse"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

######################################################
# Circle back for Control 2.3.1.5
######################################################

############################## 2.3.2 Audit ##############################
Function Set-Control2-3-2-1 {
    # Control 2.3.2.1 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $valueName = "SCENoApplyLegacyAuditPolicy"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-2-2 {
    # Control 2.3.2.2 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "CrashOnAuditFail"
    $valueData = 0 # Disabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

############################## 2.3.3 DCOM ##############################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 2.3.4 Devices ##############################

######################################################
# Circle back for Control 2.3.4.1
######################################################

Function Set-Control2-3-4-2 {
    # Control 2.3.4.2 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
    $valueName = "AddPrinterDrivers"
    $valueData = 0 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

############################## 2.3.5 Domain Controller ##############################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 2.3.6 Domain Member ##############################
Function Set-Control2-3-6-1 {
    # Control 2.3.6.1 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $valueName = "RequireStrongKey"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-6-2 {
    # Control 2.3.6.2 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $valueName = "SealSecureChannel"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-6-3 {
    # Control 2.3.6.3 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $valueName = "SignSecureChannel"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-6-4 {
    # Control 2.3.6.4 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $valueName = "DisablePasswordChange"
    $valueData = 0 # Disabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-6-5 {
    # Control 2.3.6.5 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $valueName = "MaximumPasswordAge"
    $valueData = 30 # 30 days

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-6-6 {
    # Control 2.3.6.6 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $valueName = "RequireStrongKey"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

############################## 2.3.7 Interactive Logon ##############################
Function Set-Control2-3-7-1 {
    # Control 2.3.7.1 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $valueName = "DisableCAD"
    $valueData = 0 # Disabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-7-2 {
    # Control 2.3.7.2 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "DontDisplayLastUserName"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-7-3 {
    # Control 2.3.7.3 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $valueName = "AccountLockoutThreshold"
    $valueData = 10 # 10 invalid logon attempts

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-7-4 {
    # Control 2.3.7.4 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "InactivityTimeoutSecs"
    $valueData = 900 # 900 seconds

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-7-5 {
    # Control 2.3.7.5 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "LegalNoticeText"
    $valueData = "Your Custom Message Here" # Replace with your organization's message

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-7-6 {
    # Control 2.3.7.6 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "LegalNoticeCaption"
    $valueData = "Your Custom Title Here" # Replace with your organization's title

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-7-7 {
    # Control 2.3.7.7 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $valueName = "CachedLogonsCount"
    $valueData = 4

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-7-8 {
    # Control 2.3.7.8 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $valueName = "PasswordExpiryWarning"
    $valueData = 10 # Example: Setting it to 10 days

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-7-9 {
    # Control 2.3.7.9 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $valueName = "ScRemoveOption"
    $valueData = "1" # 1 = Lock Workstation

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

############################## 2.3.8 Microsoft network client ##############################
Function Set-Control2-3-8-1 {
    # Control 2.3.8.1 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    $valueName = "RequireSecuritySignature"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-8-2 {
    # Control 2.3.8.2 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    $valueName = "EnableSecuritySignature"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-8-3 {
    # Control 2.3.8.3 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    $valueName = "EnablePlainTextPassword"
    $valueData = 0 # Disabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

############################## 2.3.9 Microsoft network server ##############################
Function Set-Control2-3-9-1 {
    # Control 2.3.9.1 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "AutoDisconnect"
    $valueData = 15 # 15 minutes

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-9-2 {
    # Control 2.3.9.2 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "RequireSecuritySignature"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-9-3 {
    # Control 2.3.9.3 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "EnableSecuritySignature"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-9-4 {
    # Control 2.3.9.4 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "EnableForcedLogOff"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-9-5 {
    # Control 2.3.9.5 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "SMBServerNameHardeningLevel"
    $valueData = 1 # 1 = Accept if provided by client

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

############################## 2.3.10 Network Access ##############################
Function Set-Control2-3-10-1 {
    # Control 2.3.10.1 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "TranslateNames"
    $valueData = 0 # Disabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-10-2 {
    # Control 2.3.10.2 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "RestrictAnonymousSAM"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-10-2 {
    # Control 2.3.10.2 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "RestrictAnonymousSAM"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-10-3 {
    # Control 2.3.10.3 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "RestrictAnonymous"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-10-4 {
    # Control 2.3.10.4 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "DisableDomainCreds"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-10-5 {
    # Control 2.3.10.5 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "EveryoneIncludesAnonymous"
    $valueData = 0 # Disabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-10-6 {
    # Control 2.3.10.6 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "NullSessionPipes"
    $valueData = "" # None

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-10-7 {
    # Control 2.3.10.7 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths"
    $valueName = "Machine"
    $valueData = "System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,SOFTWARE\Microsoft\Windows NT\CurrentVersion"

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-10-8 {
    # Control 2.3.10.8 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths"
    $valueName = "Machine"
    $valueData = "System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,SOFTWARE\Microsoft\OLAP Server,SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print,SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog"

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-10-9 {
    # Control 2.3.10.9 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "RestrictNullSessAccess"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-10-10 {
    # Control 2.3.10.10 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "RestrictRemoteSAM"
    $valueData = "O:BAG:BAD:(A;;RC;;;BA)" # Administrators: Remote Access: Allow

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-10-11 {
    # Control 2.3.10.11 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "NullSessionShares"
    $valueData = "" # None

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-10-12 {
    # Control 2.3.10.12 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "ForceGuest"
    $valueData = 0 # Classic - local users authenticate as themselves

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

############################## 2.3.11 Network Security ##############################
Function Set-Control2-3-11-1 {
    # Control 2.3.11.1 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "UseMachineId"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-11-2 {
    # Control 2.3.11.2 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
    $valueName = "AllowNullSessionFallback"
    $valueData = 0 # Disabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-11-3 {
    # Control 2.3.11.3 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa\pku2u"
    $valueName = "AllowOnlineID"
    $valueData = 0 # Disabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-11-4 {
    # Control 2.3.11.4 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    $valueName = "SupportedEncryptionTypes"
    $valueData = 2147483644 # AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-11-5 {
    # Control 2.3.11.5 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "NoLMHash"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-11-6 {
    # Control 2.3.11.6 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "ForceLogoffWhenHourExpire"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-11-7 {
    # Control 2.3.11.7 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "LmCompatibilityLevel"
    $valueData = 5 # Send NTLMv2 response only. Refuse LM & NTLM

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-11-8 {
    # Control 2.3.11.8 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LDAP"
    $valueName = "LDAPClientIntegrity"
    $valueData = 1 # Negotiate signing

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-11-9 {
    # Control 2.3.11.9 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
    $valueName = "NTLMMinClientSec"
    $valueData = 537395200 # Require NTLMv2 session security, Require 128-bit encryption

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-11-9 {
    # Control 2.3.11.9 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
    $valueName = "NTLMMinClientSec"
    $valueData = 537395200 # Require NTLMv2 session security, Require 128-bit encryption

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-11-10 {
    # Control 2.3.11.10 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
    $valueName = "NTLMMinServerSec"
    $valueData = 537395200 # Require NTLMv2 session security, Require 128-bit encryption

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

############################## 2.3.12 Recovery Console ##############################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 2.3.13 Shutdown ##############################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 2.3.14 Domain Member ##############################
Function Set-Control2-3-14-1 {
    # Control 2.3.14.1 - Remediation Script
    $keyPath = "HKLM:\Software\Policies\Microsoft\Cryptography"
    $valueName = "ForceKeyProtection"
    $valueData = 2 # User is prompted when the key is first used

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

############################## 2.3.15 System Objects ##############################
Function Set-Control2-3-15-1 {
    # Control 2.3.15.1 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel"
    $valueName = "ObCaseInsensitive"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-15-2 {
    # Control 2.3.15.2 - Remediation Script
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Session Manager"
    $valueName = "ProtectionMode"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

############################## 2.3.16 System Settings ##############################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 2.3.17 User Account Control ##############################
Function Set-Control2-3-17-1 {
    # Control 2.3.17.1 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "FilterAdministratorToken"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-17-2 {
    # Control 2.3.17.2 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "ConsentPromptBehaviorAdmin"
    $valueData = 2 # Prompt for consent on the secure desktop

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-17-3 {
    # Control 2.3.17.3 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "ConsentPromptBehaviorUser"
    $valueData = 0 # Automatically deny elevation requests

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-17-4 {
    # Control 2.3.17.4 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "EnableInstallerDetection"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-17-5 {
    # Control 2.3.17.5 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "EnableSecureUIAPaths"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-17-6 {
    # Control 2.3.17.6 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "EnableLUA"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-17-7 {
    # Control 2.3.17.7 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "PromptOnSecureDesktop"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}

Function Set-Control2-3-17-8 {
    # Control 2.3.17.8 - Remediation Script
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "EnableVirtualization"
    $valueData = 1 # Enabled

    Set-ItemProperty -Path $keyPath -Name $valueName -Value $valueData
}


########################################################################################################################################################
# 3. Event Log
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

########################################################################################################################################################
# 4. Restricted Groups
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

########################################################################################################################################################
# 5. Local System Services
########################################################################################################################################################
Function Set-Control5-1 {
    # Control 5.1 - Remediation Script
    $serviceName = "BTAGService"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-2 {
    # Control 5.2 - Remediation Script
    $serviceName = "bthserv"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-3 {
    # Control 5.3 - Remediation Script
    $serviceName = "Browser"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-4 {
    # Control 5.4 - Remediation Script
    $serviceName = "MapsBroker"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-5 {
    # Control 5.5 - Remediation Script
    $serviceName = "lfsvc"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-6 {
    # Control 5.6 - Remediation Script
    $serviceName = "IISADMIN"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-7 {
    # Control 5.7 - Remediation Script
    $serviceName = "irmon"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-8 {
    # Control 5.8 - Remediation Script
    $serviceName = "SharedAccess"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-9 {
    # Control 5.9 - Remediation Script
    $serviceName = "lltdsvc"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-10 {
    # Control 5.10 - Remediation Script
    $serviceName = "LxssManager"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-11 {
    # Control 5.11 - Remediation Script
    $serviceName = "FTPSVC"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-12 {
    # Control 5.12 - Remediation Script
    $serviceName = "MSiSCSI"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-13 {
    # Control 5.13 - Remediation Script
    $serviceName = "sshd"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-14 {
    # Control 5.14 - Remediation Script
    $serviceName = "PNRPsvc"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-15 {
    # Control 5.15 - Remediation Script
    $serviceName = "p2psvc"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-16 {
    # Control 5.16 - Remediation Script
    $serviceName = "p2pimsvc"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-17 {
    # Control 5.17 - Remediation Script
    $serviceName = "PNRPAutoReg"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-18 {
    # Control 5.18 - Remediation Script
    $serviceName = "Spooler"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-19 {
    # Control 5.19 - Remediation Script
    $serviceName = "wercplsupport"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-20 {
    # Control 5.20 - Remediation Script
    $serviceName = "RasAuto"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-21 {
    # Control 5.21 - Remediation Script
    $serviceName = "SessionEnv"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-22 {
    # Control 5.22 - Remediation Script
    $serviceName = "TermService"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-23 {
    # Control 5.23 - Remediation Script
    $serviceName = "UmRdpService"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-24 {
    # Control 5.24 - Remediation Script
    $serviceName = "RpcLocator"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-25 {
    # Control 5.25 - Remediation Script
    $serviceName = "RemoteRegistry"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-26 {
    # Control 5.26 - Remediation Script
    $serviceName = "RemoteAccess"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-27 {
    # Control 5.27 - Remediation Script
    $serviceName = "LanmanServer"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-28 {
    # Control 5.28 - Remediation Script
    $serviceName = "simptcp"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-29 {
    # Control 5.29 - Remediation Script
    $serviceName = "SNMP"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-30 {
    # Control 5.30 - Remediation Script
    $serviceName = "sacsvr"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-31 {
    # Control 5.31 - Remediation Script
    $serviceName = "SSDPSRV"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-32 {
    # Control 5.32 - Remediation Script
    $serviceName = "upnphost"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-33 {
    # Control 5.33 - Remediation Script
    $serviceName = "WMSvc"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-34 {
    # Control 5.34 - Remediation Script
    $serviceName = "WerSvc"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-35 {
    # Control 5.35 - Remediation Script
    $serviceName = "Wecsvc"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-36 {
    # Control 5.36 - Remediation Script
    $serviceName = "WMPNetworkSvc"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-37 {
    # Control 5.37 - Remediation Script
    $serviceName = "icssvc"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-38 {
    # Control 5.38 - Remediation Script
    $serviceName = "WpnService"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-39 {
    # Control 5.39 - Remediation Script
    $serviceName = "PushToInstall"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-40 {
    # Control 5.40 - Remediation Script
    $serviceName = "WinRM"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-41 {
    # Control 5.41 - Remediation Script
    $serviceName = "W3SVC"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-42 {
    # Control 5.42 - Remediation Script
    $serviceName = "XboxGipSvc"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-43 {
    # Control 5.43 - Remediation Script
    $serviceName = "XblAuthManager"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-44 {
    # Control 5.44 - Remediation Script
    $serviceName = "XblGameSave"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}

Function Set-Control5-45 {
    # Control 5.45 - Remediation Script
    $serviceName = "XboxNetApiSvc"
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Set-Service -Name $serviceName -StartupType Disabled
}



########################################################################################################################################################
# 6. Local Policies
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

########################################################################################################################################################
# 7. Local Policies
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

########################################################################################################################################################
# 8. Local Policies
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

########################################################################################################################################################
# 9. Windows Defender Firewall with Advanced Security (formerly Windows Firewall with Advanced Security)
########################################################################################################################################################
################################################## 9.1. Domain Profile ##################################################
Function Set-Control9-1-1 {
    # Control 9.1.1 - Remediation Script
    Set-NetFirewallProfile -Profile Domain -Enabled True
}

Function Set-Control9-1-2 {
    # Control 9.1.2 - Remediation Script
    Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block
}

Function Set-Control9-1-3 {
    # Control 9.1.3 - Remediation Script
    Set-NetFirewallProfile -Profile Domain -DefaultOutboundAction Allow
}

Function Set-Control9-1-4 {
    # Control 9.1.4 - Remediation Script
    Set-NetFirewallProfile -Profile Domain -NotificationsDisabled True
}

Function Set-Control9-1-5 {
    # Control 9.1.5 - Remediation Script
    Set-NetFirewallProfile -Profile Domain -LogFileName "%SystemRoot%\\System32\\logfiles\\firewall\\domainfw.log"
}

Function Set-Control9-1-6 {
    # Control 9.1.6 - Remediation Script
    Set-NetFirewallProfile -Profile Domain -LogMaxSizeKilobytes 16384
}

Function Set-Control9-1-7 {
    # Control 9.1.7 - Remediation Script
    Set-NetFirewallProfile -Profile Domain -LogDroppedPackets True
}

Function Set-Control9-1-8 {
    # Control 9.1.8 - Remediation Script
    Set-NetFirewallProfile -Profile Domain -LogAllowedPackets True
}

################################################## 9.2. Private Profile ##################################################
Function Set-Control9-2-1 {
    # Control 9.2.1 - Remediation Script
    Set-NetFirewallProfile -Profile Private -Enabled True
}

Function Set-Control9-2-2 {
    # Control 9.2.2 - Remediation Script
    Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block
}

Function Set-Control9-2-3 {
    # Control 9.2.3 - Remediation Script
    Set-NetFirewallProfile -Profile Private -DefaultOutboundAction Allow
}

Function Set-Control9-2-4 {
    # Control 9.2.4 - Remediation Script
    Set-NetFirewallProfile -Profile Private -NotificationsDisabled True
}

Function Set-Control9-2-5 {
    # Control 9.2.5 - Remediation Script
    Set-NetFirewallProfile -Profile Private -LogFileName "%SystemRoot%\\System32\\logfiles\\firewall\\privatefw.log"
}

Function Set-Control9-2-6 {
    # Control 9.2.6 - Remediation Script
    Set-NetFirewallProfile -Profile Private -LogMaxSizeKilobytes 16384
}

Function Set-Control9-2-7 {
    # Control 9.2.7 - Remediation Script
    Set-NetFirewallProfile -Profile Private -LogDroppedPackets True
}

Function Set-Control9-2-8 {
    # Control 9.2.8 - Remediation Script
    Set-NetFirewallProfile -Profile Private -LogAllowedPackets True
}

################################################## 9.3. Public Profile ##################################################
Function Set-Control9-3-1 {
    # Control 9.3.1 - Remediation Script
    Set-NetFirewallProfile -Profile Public -Enabled True
}

Function Set-Control9-3-2 {
    # Control 9.3.2 - Remediation Script
    Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block
}

Function Set-Control9-3-3 {
    # Control 9.3.3 - Remediation Script
    Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Allow
}

Function Set-Control9-3-4 {
    # Control 9.3.4 - Remediation Script
    Set-NetFirewallProfile -Profile Public -NotificationsDisabled True
}

Function Set-Control9-3-5 {
    # Control 9.3.5 - Remediation Script
    Set-NetFirewallProfile -Profile Public -AllowLocalPolicyMerge False
}

Function Set-Control9-3-6 {
    # Control 9.3.6 - Remediation Script
    Set-NetFirewallProfile -Profile Public -AllowLocalIPsecPolicyMerge False
}

Function Set-Control9-3-7 {
    # Control 9.3.7 - Remediation Script
    Set-NetFirewallProfile -Profile Public -LogFileName "%SystemRoot%\\System32\\logfiles\\firewall\\publicfw.log"
}

Function Set-Control9-3-8 {
    # Control 9.3.8 - Remediation Script
    Set-NetFirewallProfile -Profile Public -LogMaxSizeKilobytes 16384
}

Function Set-Control9-3-9 {
    # Control 9.3.9 - Remediation Script
    Set-NetFirewallProfile -Profile Public -LogDroppedPackets True
}

Function Set-Control9-3-10 {
    # Control 9.3.10 - Remediation Script
    Set-NetFirewallProfile -Profile Public -LogAllowedPackets True
}



########################################################################################################################################################
################################################## 10. Network List Manager Policies ###################################################################
########################################################################################################################################################


########################################################################################################################################################
################################################## 11. Wireless Network (IEEE 802.11) Policies #########################################################
########################################################################################################################################################


########################################################################################################################################################
################################################## 12. Public Key Policies #############################################################################
########################################################################################################################################################


########################################################################################################################################################
################################################## 13. Software Restriction Policies ###################################################################
########################################################################################################################################################


########################################################################################################################################################
################################################## 14. Network Access Protection NAP Client Configuration ##############################################
########################################################################################################################################################


########################################################################################################################################################
################################################## 15. Application Control Policies ####################################################################
########################################################################################################################################################


########################################################################################################################################################
################################################## 16. IP Security Policies ############################################################################
########################################################################################################################################################


########################################################################################################################################################
################################################## 17. Advanced Audit Policy Configuration #############################################################
########################################################################################################################################################
################################################## 17.1. Account Logon ##################################################
Function Set-Control17-1-1 {
    $null = AuditPol /set /subcategory:"Credential Validation" /success:enable /failure:enable
}

################################################## 17.2. Account Management ############################################################################
Function Set-Control17-2-1 {
    $null = AuditPol /set /subcategory:"Application Group Management" /success:enable /failure:enable
}

Function Set-Control17-2-2 {
    $null = AuditPol /set /subcategory:"Security Group Management" /success:enable
}

Function Set-Control17-2-3 {
    $null = AuditPol /set /subcategory:"User Account Management" /success:enable /failure:enable
}

################################################## 17.3. Detailed Tracking #############################################################################
Function Set-Control17-3-1 {
    $null = AuditPol /set /subcategory:"PNP Activity" /success:enable
}

Function Set-Control17-3-2 {
    $null = AuditPol /set /subcategory:"Process Creation" /success:enable
}


################################################## 17.4. DS Access #####################################################################################
################################################## 17.5. Logon/Logoff ##################################################################################
Function Set-Control17-5-1 {
    $null = AuditPol /set /subcategory:"Account Lockout" /failure:enable
}

Function Set-Control17-5-2 {
    $null = AuditPol /set /subcategory:"Group Membership" /success:enable
}

Function Set-Control17-5-3 {
    $null = AuditPol /set /subcategory:"Logoff" /success:enable
}

Function Set-Control17-5-4 {
    $null = AuditPol /set /subcategory:"Logon" /success:enable /failure:enable
}

Function Set-Control17-5-5 {
    $null = AuditPol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
}

Function Set-Control17-5-6 {
    $null = AuditPol /set /subcategory:"Special Logon" /success:enable
}

################################################## 17.6. Object Access #################################################################################
Function Set-Control17-6-1 {
    $null = AuditPol /set /subcategory:"Detailed File Share" /failure:enable
}

Function Set-Control17-6-2 {
    $null = AuditPol /set /subcategory:"File Share" /success:enable /failure:enable
}

Function Set-Control17-6-3 {
    $null = AuditPol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
}

Function Set-Control17-6-4 {
    $null = AuditPol /set /subcategory:"Removable Storage" /success:enable /failure:enable
}

################################################## 17.7. Policy Change #################################################################################
Function Set-Control17-7-1 {
    $null = AuditPol /set /subcategory:"Audit Policy Change" /success:enable
}

Function Set-Control17-7-2 {
    $null = AuditPol /set /subcategory:"Authentication Policy Change" /success:enable
}

Function Set-Control17-7-3 {
    $null = AuditPol /set /subcategory:"Authorization Policy Change" /success:enable
}

Function Set-Control17-7-4 {
    $null = AuditPol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
}

Function Set-Control17-7-5 {
    $null = AuditPol /set /subcategory:"Other Policy Change Events" /failure:enable
}

################################################## 17.8. Privilege Use #################################################################################
Function Set-Control17-8-1 {
    $null = AuditPol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
}

################################################## 17.9. System ########################################################################################
Function Set-Control17-9-1 {
    $null = AuditPol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
}

Function Set-Control17-9-2 {
    $null = AuditPol /set /subcategory:"Other System Events" /success:enable /failure:enable
}

Function Set-Control17-9-3 {
    $null = AuditPol /set /subcategory:"Security State Change" /success:enable
}

Function Set-Control17-9-4 {
    $null = AuditPol /set /subcategory:"Security System Extension" /success:enable
}

Function Set-Control17-9-5 {
    $null = AuditPol /set /subcategory:"System Integrity" /success:enable /failure:enable
}

########################################################################################################################################################
################################################## 18. Administrative Templates (Computer) #############################################################
########################################################################################################################################################
################################################## 18.1. Control Panel #################################################################################
############################## 18.1.1. Personalization ##############################
Function Set-Control18-1-1-1 {
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -PropertyType DWord -Force
}

Function Set-Control18-1-1-2 {
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenSlideshow" -Value 1 -PropertyType DWord -Force
}

Function Set-Control18-1-2-2 {
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Speech\Online" -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Speech\Online" -Name "AllowOnlineSpeechRecognition" -Value 0 -PropertyType DWord -Force
}

Function Set-Control18-1-3 {
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -PropertyType DWord -Force
}

################################################## 18.2. LAPS ##########################################################################################
Function Set-Control18-2-1 {
    # Installing LAPS requires downloading and running the installer
    # This function cannot automatically perform those actions
    Write-Host "Manual intervention required: Download and install LAPS from Microsoft."
}

Function Set-Control18-2-2 {
    New-Item -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd" -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd" -Name "PwdExpirationProtectionEnabled" -Value 1 -PropertyType DWord -Force
}

Function Set-Control18-2-3 {
    New-Item -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd" -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd" -Name "AdmPwdEnabled" -Value 1 -PropertyType DWord -Force
}

Function Set-Control18-2-4 {
    # Placeholder for setting password complexity; Adjust according to specific management tool or script capabilities
    Write-Host "This setting requires manual intervention or a specific management tool for configuration."
}

Function Set-Control18-2-6 {
    # Placeholder for setting password age; Adjust according to specific management tool or script capabilities
    Write-Host "This setting requires manual intervention or a specific management tool for configuration."
}

################################################## 18.3. MS Security Guide #############################################################################
Function Set-Control18-3-1 {
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0 -PropertyType DWord -Force
}

Function Set-Control18-3-2 {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4
}

Function Set-Control18-3-3 {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0
}

Function Set-Control18-3-4 {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0
}

Function Set-Control18-3-5 {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "PointAndPrint_RestrictDriverInstallationToAdministrators" -Value 1 -PropertyType DWord -Force
}

Function Set-Control18-3-6 {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" -Name "NodeType" -Value 2
}

Function Set-Control18-3-7 {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0
}

################################################## 18.4. MSS (Legacy) ##################################################################################
Function Set-Control18-4-1 {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0
}

Function Set-Control18-4-2 {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2
}

Function Set-Control18-4-3 {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2
}

Function Set-Control18-4-4 {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" -Name "DisableSavePassword" -Value 1 -PropertyType DWord -Force
}

Function Set-Control18-4-5 {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0
}

Function Set-Control18-4-6 {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -Value 300000
}

Function Set-Control18-4-7 {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -Value 1
}

Function Set-Control18-4-8 {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "PerformRouterDiscovery" -Value 0
}

Function Set-Control18-4-9 {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value 1
}

Function Set-Control18-4-10 {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScreenSaverGracePeriod" -Value "5"
}

Function Set-Control18-4-11 {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "TcpMaxDataRetransmissions" -Value 3
}

Function Set-Control18-4-12 {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Value 3
}

Function Set-Control18-4-13 {
    # Assuming the value needs to be set as a percentage
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" -Name "WarningLevel" -Value 90
}

################################################## 18.5. Network #######################################################################################
############################## 18.5.1. Background Intelligent Transfer Service (BITS) ##################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.5.2. BranchCache #####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.5.3. DirectAccess Client Experience Settings #########################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.5.4. DNS Client ######################################################################################################
Function Set-Control18-5-4-1 {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DoHSetting" -Value 2
}

Function Set-Control18-5-4-2 {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0
}


############################## 18.5.5. Fonts ###########################################################################################################
Function Set-Control18-5-5-1 {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableFontProviders" -Value 0
}

############################## 18.5.6. Hotspot Authentication ##########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.5.7. Lanman Server ###################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.5.8. Lanman Workstation ##############################################################################################
Function Set-Control18-5-8-1 {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value 0
}

############################## 18.5.9. Link-Layer Topology Discovery #################################################################################
Function Set-Control18-5-9-1 {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -Name "AllowLLTDIOOnDomain" -Value 0
}

############################## 18.5.10. Microsoft Peer-to-Peer Networking Services #################################################################################
############################## 18.5.10.1. Peer Name Resolution Protocol #################################################################################
Function Set-Control18-5-10-2 {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -Name "Disabled" -Value 1
}

############################## 18.5.11. Network Connections #################################################################################
############################## 18.5.11.1. Windows Defender Firewall (formerly Windows Firewall) #################################################################################
Function Set-Control18-5-11-2 {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge_NLA" -Value 0
}

Function Set-Control18-5-11-3 {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Value 0
}

Function Set-Control18-5-11-4 {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_StdDomainUserSetLocation" -Value 1
}

############################## 18.5.12. Network Connectivity Status Indicator ##########################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.5.13. Network Isolation ##############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.5.14. Network Provider ###############################################################################################
Function Set-Control18-5-14-1 {
    # Control 18.5.14.1 - Remediation Script
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\NETLOGON" -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -PropertyType String -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\SYSVOL" -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -PropertyType String -Force
}

############################## 18.5.15. Offline Files ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.5.16. QoS Packet Scheduler ###########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.5.17. SNMP ###########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.5.18. SSL Configuration Settings #####################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.5.19. TCPIP Settings #################################################################################################
############################## 18.5.19.1. IPv6 Transition Technologies #################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.5.19.2. Parameters ###################################################################################################
Function Set-Control18-5-19-2-1 {
    # Control 18.5.19.2.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -Value 0xff
}

############################## 18.5.20. Windows Connect Now ############################################################################################
Function Set-Control18-5-20-1 {
    # Control 18.5.20.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars" -Value 0
}

Function Set-Control18-5-20-2 {
    # Control 18.5.20.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Value 1
}

############################## 18.5.21. Windows Connection Manager #####################################################################################
Function Set-Control18-5-21-1 {
    # Control 18.5.21.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value 3
}

Function Set-Control18-5-21-2 {
    # Control 18.5.21.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fBlockNonDomain" -Value 1
}

############################## 18.5.22. Wireless Display ###############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.5.23. WLAN Service ###################################################################################################
Function Set-Control18-5-23-2-1 {
    # Control 18.5.23.2.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "AutoConnectToWiFiSenseHotspots" -Value 0
}


############################## 18.5.23.1. WLAN Media Cost ##############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.5.23.2. WLAN Settings ################################################################################################
################################################## 18.6. Printers ######################################################################################
Function Set-Control18-6-1 {
    # Control 18.6.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "AllowPrintSpoolerToAcceptClientConnections" -Value 0
}

Function Set-Control18-6-2 {
    # Control 18.6.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -Value 1
}

Function Set-Control18-6-3 {
    # Control 18.6.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnUpdate" -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -Value 1
}

################################################## 18.7. Start Menu and Taskbar ########################################################################
############################## 18.7.1. Notifications ###################################################################################################
Function Set-Control18-7-1-1 {
    # Control 18.7.1.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1
}

################################################## 18.8. System ########################################################################################
############################## 18.8.1. Access-Denied Assistance ########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.2. App-V ###########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.3. Audit Process Creation ##########################################################################################
Function Set-Control18-8-3-1 {
    # Control 18.8.3.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
}

############################## 18.8.4. Credentials Delegation ##########################################################################################
Function Set-Control18-8-4-1 {
    # Control 18.8.4.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "EncryptionOracleRemediation" -Value 2
}

Function Set-Control18-8-4-2 {
    # Control 18.8.4.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -Value 1
}

############################## 18.8.5. Device Guard ####################################################################################################
Function Set-Control18-8-5-1 {
    # Control 18.8.5.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
}

Function Set-Control18-8-5-2 {
    # Control 18.8.5.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 3
}

Function Set-Control18-8-5-3 {
    # Control 18.8.5.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedProtection" -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 1
}

Function Set-Control18-8-5-4 {
    # Control 18.8.5.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequireUEFIMemoryAttributesTable" -Value 1
}

Function Set-Control18-8-5-5 {
    # Control 18.8.5.5 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Value 2
}

Function Set-Control18-8-5-6 {
    # Control 18.8.5.6 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableSecureLaunch" -Value 1
}

############################## 18.8.6. Device Health Attestation Service ###############################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.7. Device Installation #############################################################################################
############################## 18.8.7.1. Device Installation Restrictions ##############################################################################
Function Set-Control18-8-7-1-1 {
    # Control 18.8.7.1.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDs" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDsRetroactive" -Value 1
}

Function Set-Control18-8-7-1-2 {
    # Control 18.8.7.1.2 - Remediation Script
    # This script assumes that the DenyDeviceIDs key exists and is an array. Adjustments may be needed based on actual registry structure.
    $deviceID = "PCI\CC_0C0A"
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
    $propertyName = "DenyDeviceIDs"

    # Check if the property exists and create if not
    if (!(Test-Path -Path $path -Name $propertyName)) {
        New-ItemProperty -Path $path -Name $propertyName -Value $deviceID -PropertyType MultiString
    } else {
        $currentValue = Get-ItemProperty -Path $path -Name $propertyName
        if ($currentValue -notcontains $deviceID) {
            $newValues = $currentValue + $deviceID
            Set-ItemProperty -Path $path -Name $propertyName -Value $newValues
        }
    }
}

Function Set-Control18-8-7-1-3 {
    # Control 18.8.7.1.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDsRetroactive" -Value 1
}

Function Set-Control18-8-7-1-4 {
    # Control 18.8.7.1.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClasses" -Value 1
}

Function Set-Control18-8-7-1-5 {
    # Control 18.8.7.1.5 - Remediation Script
    $classGUIDs = "{d48179be-ec20-11d1-b6b8-00c04fa372a7}`,`"{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}`,`"{c06ff265-ae09-48f0-812c-16753d7cba83}`,`"{6bdd1fc1-810f-11d0-bec7-08002be2092f}"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClasses" -Value $classGUIDs
}

Function Set-Control18-8-7-1-6 {
    # Control 18.8.7.1.6 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClassesRetroactive" -Value 1
}

Function Set-Control18-8-7-2 {
    # Control 18.8.7.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1
}

############################## 18.8.8. Device Redirection ##############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.9. Disk NV Cache ###################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.10. Disk Quotas ####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.11. Display ########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.12. Distributed COM ################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.13. Driver Installation ############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.14. Early Launch Antimalware #######################################################################################
Function Set-Control18-8-14-1 {
    # Control 18.8.14.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value 3
}

############################## 18.8.15. Enhanced Storage Access ########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.16. File Classification Infrastructure #############################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.17. File Share Shadow Copy Agent ###################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.18. File Share Shadow Copy Provider ################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.19. Filesystem (formerly NTFS Filesystem) ##########################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.20. Folder Redirection #############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.21. Group Policy ###################################################################################################
############################## 18.8.21.1. Logging and tracing ##########################################################################################
Function Set-Control18-8-21-2 {
    # Control 18.8.21.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy" -Name "NoBackgroundPolicy" -Value 0
}

Function Set-Control18-8-21-3 {
    # Control 18.8.21.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy" -Name "NoGPOListChanges" -Value 0
}

Function Set-Control18-8-21-4 {
    # Control 18.8.21.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0
}

Function Set-Control18-8-21-5 {
    # Control 18.8.21.5 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableBkGndGroupPolicy" -Value 0
}

############################## 18.8.22. Internet Communication Management ##############################################################################
############################## 18.8.22.1. Internet Communication settings ##############################################################################
Function Set-Control18-8-22-1-1 {
    # Control 18.8.22.1.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value 1
}

Function Set-Control18-8-22-1-2 {
    # Control 18.8.22.1.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value 1
}

Function Set-Control18-8-22-1-3 {
    # Control 18.8.22.1.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1
}

Function Set-Control18-8-22-1-4 {
    # Control 18.8.22.1.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value 1
}

Function Set-Control18-8-22-1-5 {
    # Control 18.8.22.1.5 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -Name "ExitOnMSICW" -Value 1
}

Function Set-Control18-8-22-1-6 {
    # Control 18.8.22.1.6 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoWebServices" -Value 1
}

Function Set-Control18-8-22-1-7 {
    # Control 18.8.22.1.7 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -Value 1
}

Function Set-Control18-8-22-1-8 {
    # Control 18.8.22.1.8 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" -Name "NoRegistration" -Value 1
}

Function Set-Control18-8-22-1-9 {
    # Control 18.8.22.1.9 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" -Name "DisableContentFileUpdates" -Value 1
}

Function Set-Control18-8-22-1-10 {
    # Control 18.8.22.1.10 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoOnlinePrintsWizard" -Value 1
}

Function Set-Control18-8-22-1-11 {
    # Control 18.8.22.1.11 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoPublishingWizard" -Value 1
}

Function Set-Control18-8-22-1-12 {
    # Control 18.8.22.1.12 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -Value 0
}

Function Set-Control18-8-22-1-13 {
    # Control 18.8.22.1.13 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0
}

Function Set-Control18-8-22-1-14 {
    # Control 18.8.22.1.14 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1
}

############################## 18.8.23. iSCSI ##########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.24. KDC ############################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.25. Kerberos #######################################################################################################
Function Set-Control18-8-25-1 {
    # Control 18.8.25.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceRegistration" -Name "EnableCertAuth" -Value 1
}

############################## 18.8.26 Kernel DMA Protection ###########################################################################################
Function Set-Control18-8-26-1 {
    # Control 18.8.26.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" -Name "DeviceEnumerationPolicy" -Value 2
}

############################## 18.8.27 Locale Services #################################################################################################
Function Set-Control18-8-27-1 {
    # Control 18.8.27.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Name "BlockUserInputMethodsForSignIn" -Value 1
}

############################## 18.8.28 Logon ###########################################################################################################
Function Set-Control18-8-28-1 {
    # Control 18.8.28.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayLastUserName" -Value 1
}

Function Set-Control18-8-28-2 {
    # Control 18.8.28.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value 1
}

Function Set-Control18-8-28-3 {
    # Control 18.8.28.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -Value 1
}

Function Set-Control18-8-28-4 {
    # Control 18.8.28.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnumerateLocalUsers" -Value 0
}

Function Set-Control18-8-28-5 {
    # Control 18.8.28.5 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value 1
}

Function Set-Control18-8-28-6 {
    # Control 18.8.28.6 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockDomainPicturePassword" -Value 1
}

Function Set-Control18-8-28-7 {
    # Control 18.8.28.7 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -Value 0
}

############################## 18.8.29 Mitigation Options ##############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.30 Net Logon #######################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.31 OS Policies #####################################################################################################
Function Set-Control18-8-31-1 {
    # Control 18.8.31.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value 0
}

Function Set-Control18-8-31-2 {
    # Control 18.8.31.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0
}

############################## 18.8.32 Performance Control Panel #######################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.33 PIN Complexity ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.34 Power Management ################################################################################################
############################## 18.8.34.1 Button Settings ###############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.34.2 Energy Saver Settings #########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.34.3 Hard Disk Settings ############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.34.4 Notification Settings #########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.34.5 Power Throttling Settings #####################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.34.6 Sleep Settings ################################################################################################
Function Set-Control18-8-34-6-1 {
    # Control 18.8.34.6.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "DCSettingIndex" -Value 0
}

Function Set-Control18-8-34-6-2 {
    # Control 18.8.34.6.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -Value 0
}

Function Set-Control18-8-34-6-3 {
    # Control 18.8.34.6.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -Name "DCSettingIndex" -Value 0
}

Function Set-Control18-8-34-6-4 {
    # Control 18.8.34.6.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -Name "ACSettingIndex" -Value 0
}

Function Set-Control18-8-34-6-5 {
    # Control 18.8.34.6.5 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "DCSettingIndex" -Value 1
}

Function Set-Control18-8-34-6-6 {
    # Control 18.8.34.6.6 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "ACSettingIndex" -Value 1
}

############################## 18.8.35 Recovery ########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.36 Remote Assistance ###############################################################################################
Function Set-Control18-8-36-1 {
    # Control 18.8.36.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value 0
}

Function Set-Control18-8-36-2 {
    # Control 18.8.36.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0
}

############################## 18.8.37 Remote Procedure Call ###########################################################################################
Function Set-Control18-8-37-1 {
    # Control 18.8.37.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1
}

Function Set-Control18-8-37-2 {
    # Control 18.8.37.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -Value 1
}

############################## 18.8.38 Removable Storage Access ########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.39 Scripts #########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.40 Security Account Manager ########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.41 Server Manager ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.42 Service Control Manager Settings ################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.43 Shutdown ########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.44 Shutdown Options ################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.45 Storage Health ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.46 Storage Sense ###################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.47 System Restore ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.48 Troubleshooting and Diagnostics #################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.48.1 Application Compatibility Diagnostics #########################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.48.2 Corrupted File Recovery #######################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.48.3 Disk Diagnostic ###############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.48.4 Fault Tolerant Heap ###########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.48.5 Microsoft Support Diagnostic Tool #############################################################################
Function Set-Control18-8-48-5-1 {
    # Control 18.8.48.5.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "DisableQueryRemoteServer" -Value 1
}

############################## 18.8.48.6 MSI Corrupted File Recovery ###################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.48.7 Scheduled Maintenance #########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.48.8 Scripted Diagnostics ##########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.48.9 Windows Boot Performance Diagnostics ##########################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.48.10 Windows Memory Leak Diagnosis ################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.48.11 Windows Performance PerfTrack ################################################################################
Function Set-Control18-8-48-11-1 {
    # Control 18.8.48.11.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Performance\PerfTrack" -Name "ScenarioExecutionEnabled" -Value 0
}

############################## 18.8.49 Trusted Platform Module Services ################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.50 User Profiles ###################################################################################################
Function Set-Control18-8-50-1 {
    # Control 18.8.50.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1
}

############################## 18.8.51 Windows File Protection #########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.52 Windows HotStart ################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.53 Windows Time Service ############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.53.1 Time Providers ################################################################################################
Function Set-Control18-8-53-1-1 {
    # Control 18.8.53.1.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -Name "Enabled" -Value 1
}

Function Set-Control18-8-53-1-2 {
    # Control 18.8.53.1.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" -Name "Enabled" -Value 0
}

################################################## 18.9 Windows Components #############################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.1 Active Directory Federation Services #############################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.2 ActiveX Installer Service ########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.3 Add features to Windows 8 / 8.1 / 10 (formerly Windows Anytime Upgrade) ##########################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.4 App Package Deployment ###########################################################################################
Function Set-Control18-9-4-1 {
    # Control 18.9.4.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAppData" -Value 0
}

Function Set-Control18-9-4-2 {
    # Control 18.9.4.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "AllowAllTrustedApps" -Value 0
}

############################## 18.9.5 App Privacy ######################################################################################################
Function Set-Control18-9-5-1 {
    # Control 18.9.5.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Value 2
}

############################## 18.9.6 App runtime ######################################################################################################
Function Set-Control18-9-6-1 {
    # Control 18.9.6.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "MSAOptional" -Value 1
}

Function Set-Control18-9-6-2 {
    # Control 18.9.6.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "BlockHostedAppAccessWinRT" -Value 1
}

############################## 18.9.7 Application Compatibility ########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.8 AutoPlay Policies ################################################################################################
Function Set-Control18-9-8-1 {
    # Control 18.9.8.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1
}

Function Set-Control18-9-8-2 {
    # Control 18.9.8.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutorun" -Value 1
}

Function Set-Control18-9-8-3 {
    # Control 18.9.8.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
}

############################## 18.9.9 Backup ###########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.10 Biometrics ######################################################################################################
############################## 18.9.10.1 Facial Features ###############################################################################################
Function Set-Control18-9-10-1-1 {
    # Control 18.9.10.1.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value 1
}

Function Set-Control18-9-11-1-2 {
    # Control 18.9.11.1.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecovery" -Value 1
    # Note: Additional configuration may be required to specify recovery methods, such as recovery password and recovery key.
}

Function Set-Control18-9-11-1-3 {
    # Control 18.9.11.1.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVManageDRA" -Value 1
}

Function Set-Control18-9-11-1-4 {
    # Control 18.9.11.1.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecoveryPassword" -Value 1
}

Function Set-Control18-9-11-1-5 {
    # Control 18.9.11.1.5 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecoveryKey" -Value 1
}

Function Set-Control18-9-11-1-6 {
    # Control 18.9.11.1.6 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVHideRecoveryPage" -Value 1
}

Function Set-Control18-9-11-1-7 {
    # Control 18.9.11.1.7 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVSaveToAD" -Value 0
}

Function Set-Control18-9-11-1-8 {
    # Control 18.9.11.1.8 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryBackup" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryInfoToStore" -Value 1 # This enables the backup of both recovery passwords and key packages.
}

Function Set-Control18-9-11-1-9 {
    # Control 18.9.11.1.9 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRequireActiveDirectoryBackup" -Value 0
}

Function Set-Control18-9-11-1-10 {
    # Control 18.9.11.1.10 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVHardwareEncryption" -Value 0
}

Function Set-Control18-9-11-1-11 {
    # Control 18.9.11.1.11 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVPassphrase" -Value 0
}

Function Set-Control18-9-11-1-12 {
    # Control 18.9.11.1.12 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVSmartCard" -Value 1
}

Function Set-Control18-9-11-1-13 {
    # Control 18.9.11.1.13 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVSmartCardRequired" -Value 1
}

Function Set-Control18-9-11-2-1 {
    # Control 18.9.11.2.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseEnhancedPin" -Value 1
}

Function Set-Control18-9-11-2-2 {
    # Control 18.9.11.2.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EnableSecureBootForIntegrity" -Value 1
}

Function Set-Control18-9-11-2-3 {
    # Control 18.9.11.2.3 - Remediation Script
    # This setting involves multiple values and may require additional configuration not fully covered by this script.
}

Function Set-Control18-9-11-2-4 {
    # Control 18.9.11.2.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "OmitDRA" -Value 1
}

Function Set-Control18-9-11-2-5 {
    # Control 18.9.11.2.5 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "RecoveryPassword" -Value 1
}

Function Set-Control18-9-11-2-6 {
    # Control 18.9.11.2.6 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "RecoveryKey" -Value 0
}

Function Set-Control18-9-11-2-7 {
    # Control 18.9.11.2.7 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "HideRecoveryPage" -Value 1
}

Function Set-Control18-9-11-2-8 {
    # Control 18.9.11.2.8 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "OSActiveDirectoryBackup" -Value 1
}

Function Set-Control18-9-11-2-9 {
    # Control 18.9.11.2.9 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "OSActiveDirectoryInfoToStore" -Value 3
}

Function Set-Control18-9-11-2-10 {
    # Control 18.9.11.2.10 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "OSRequireActiveDirectoryBackup" -Value 1
}

Function Set-Control18-9-11-2-11 {
    # Control 18.9.11.2.11 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "OSEnableHardwareEncryption" -Value 0
}

Function Set-Control18-9-11-2-12 {
    # Control 18.9.11.2.12 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "OSPassphrase" -Value 0
}

Function Set-Control18-9-11-2-13 {
    # Control 18.9.11.2.13 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseAdvancedStartup" -Value 1
}

Function Set-Control18-9-11-2-14 {
    # Control 18.9.11.2.14 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseAdvancedStartupWithoutTPM" -Value 0
}

Function Set-Control18-9-11-3-1 {
    # Control 18.9.11.3.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDV" -Name "RDVAllowCrossVersionAccess" -Value 0
}

Function Set-Control18-9-11-3-2 {
    # Control 18.9.11.3.2 - Remediation Script
    # Enabling this policy involves creating the key and setting multiple values, which are not fully detailed in this script.
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery"
    If (!(Test-Path $path)) {
        New-Item -Path $path -Force
    }
    # Further specific sub-settings need to be defined as per organization's recovery policy requirements.
}

Function Set-Control18-9-11-3-3 {
    # Control 18.9.11.3.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery" -Name "RDVManageDRA" -Value 1
}

Function Set-Control18-9-11-3-4 {
    # Control 18.9.11.3.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery" -Name "RDVRecoveryPassword" -Value 0
}

Function Set-Control18-9-11-3-5 {
    # Control 18.9.11.3.5 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery" -Name "RDVRecoveryKey" -Value 0
}

Function Set-Control18-9-11-3-6 {
    # Control 18.9.11.3.6 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery" -Name "RDVHideRecoveryPage" -Value 1
}

Function Set-Control18-9-11-3-7 {
    # Control 18.9.11.3.7 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery" -Name "RDVActiveDirectoryBackup" -Value 0
}

Function Set-Control18-9-11-3-8 {
    # Control 18.9.11.3.8 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery" -Name "RDVActiveDirectoryInfoToStore" -Value 3
}

Function Set-Control18-9-11-3-9 {
    # Control 18.9.11.3.9 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery" -Name "RDVRequireActiveDirectoryBackup" -Value 0
}

Function Set-Control18-9-11-3-10 {
    # Control 18.9.11.3.10 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDV" -Name "RDVHardwareEncryption" -Value 0
}

Function Set-Control18-9-11-3-11 {
    # Control 18.9.11.3.11 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDV" -Name "RDVPassphrase" -Value 0
}

Function Set-Control18-9-11-3-12 {
    # Control 18.9.11.3.12 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDV" -Name "RDVSmartCard" -Value 1
}

Function Set-Control18-9-11-3-13 {
    # Control 18.9.11.3.13 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDV" -Name "RDVSmartCardRequired" -Value 1
}

Function Set-Control18-9-11-3-14 {
    # Control 18.9.11.3.14 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDV" -Name "DenyWriteAccess" -Value 1
}

Function Set-Control18-9-11-3-15 {
    # Control 18.9.11.3.15 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDV" -Name "DenyCrossOrgWriteAccess" -Value 0
}

Function Set-Control18-9-11-4 {
    # Control 18.9.11.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "DisableNewDMADevicesWhenLocked" -Value 1
}

############################## 18.9.12 Camera ##########################################################################################################
Function Set-Control18-9-12-1 {
    # Control 18.9.12.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Camera" -Name "AllowCamera" -Value 0
}

############################## 18.9.13 Chat ############################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
############################## 18.9.14 Cloud Content ###################################################################################################
Function Set-Control18-9-14-1 {
    # Control 18.9.14.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1
}

Function Set-Control18-9-14-2 {
    # Control 18.9.14.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudOptimizedContent" -Value 1
}

Function Set-Control18-9-14-3 {
    # Control 18.9.14.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1
}

############################## 18.9.15 Connect #########################################################################################################
Function Set-Control18-9-15-1 {
    # Control 18.9.15.1 - Remediation Script
    # Note: This setting requires choosing between 'First Time' (1) and 'Always' (2).
    # This example sets it to 'Always' for maximum security.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value 2
}

############################## 18.9.16 Credential User Interface #######################################################################################
Function Set-Control18-9-16-1 {
    # Control 18.9.16.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value 1
}

Function Set-Control18-9-16-2 {
    # Control 18.9.16.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LUA" -Name "EnumerateAdministrators" -Value 0
}

Function Set-Control18-9-16-3 {
    # Control 18.9.16.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "NoLocalPasswordResetQuestions" -Value 1
}

############################## 18.9.17 Data Collection and Preview Builds ##############################################################################
Function Set-Control18-9-17-1 {
    # Control 18.9.17.1 - Remediation Script
    # Setting to '0' for "Diagnostic data off (not recommended)". Change the value to '1' for "Send required diagnostic data".
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
}

Function Set-Control18-9-17-2 {
    # Control 18.9.17.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableEnterpriseAuthProxy" -Value 1
}

Function Set-Control18-9-17-3 {
    # Control 18.9.17.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneSettings" -Name "DisableDownloads" -Value 1
}

Function Set-Control18-9-17-4 {
    # Control 18.9.17.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1
}

Function Set-Control18-9-17-5 {
    # Control 18.9.17.5 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneSettings" -Name "EnableAuditing" -Value 1
}

Function Set-Control18-9-17-6 {
    # Control 18.9.17.6 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -Value 1
}

Function Set-Control18-9-17-7 {
    # Control 18.9.17.7 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DisableDeviceCollection" -Value 1
}

Function Set-Control18-9-17-8 {
    # Control 18.9.17.8 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value 0
}

############################## 18.9.18 Delivery Optimization ###########################################################################################
Function Set-Control18-9-18-1 {
    # Control 18.9.18.1 - Remediation Script
    # This script intentionally left blank as setting a specific Download Mode other than 'Internet' requires knowing the desired alternative mode.
}

############################## 18.9.19 Desktop Gadgets #################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.20 Desktop Window Manager ##########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.21 Device and Driver Compatibility #################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.22 Device Registration (formerly Workplace Join) ###################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.23 Digital Locker ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.24 Edge UI #########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.25 EMET ############################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.26 Event Forwarding ################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.27 Event Log Service ###############################################################################################
############################## 18.9.27.1 Application ###################################################################################################
Function Set-Control18-9-27-1-1 {
    # Control 18.9.27.1.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "Retention" -Value "0"
}

############################## 18.9.27.2 Security ######################################################################################################
Function Set-Control18-9-27-2-1 {
    # Control 18.9.27.2.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "Retention" -Value "0"
}

Function Set-Control18-9-27-2-2 {
    # Control 18.9.27.2.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxSize" -Value 196608
}

############################## 18.9.27.3 Setup #########################################################################################################
Function Set-Control18-9-27-3-1 {
    # Control 18.9.27.3.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "Retention" -Value "0"
}

Function Set-Control18-9-27-3-2 {
    # Control 18.9.27.3.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "MaxSize" -Value 32768
}

############################## 18.9.27.4 System ########################################################################################################
Function Set-Control18-9-27-4-1 {
    # Control 18.9.27.4.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "Retention" -Value "0"
}

Function Set-Control18-9-27-4-2 {
    # Control 18.9.27.4.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "MaxSize" -Value 32768
}

############################## 18.9.28 Event Logging ###################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.29 Event Viewer ####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.30 Family Safety (formerly Parental Controls) ######################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.31 File Explorer (formerly Windows Explorer) #######################################################################
############################## 18.9.31.1 Previous Versions #############################################################################################
Function Set-Control18-9-31-2 {
    # Control 18.9.31.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Value 0
}

Function Set-Control18-9-31-3 {
    # Control 18.9.31.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoHeapTerminationOnCorruption" -Value 0
}

Function Set-Control18-9-31-4 {
    # Control 18.9.31.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "PreXPSP2ShellProtocolBehavior" -Value 0
}

############################## 18.9.32 File History ####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.33 Find My Device ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.34 Game Explorer ###################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.35 Handwriting #####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.36 HomeGroup #######################################################################################################
Function Set-Control18-9-36-1 {
    # Control 18.9.36.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -Value 1
}

############################## 18.9.37 Human Presence ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.38 Import Video ####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.39 Internet Explorer ###############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.40 Internet Information Services ###################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.41 Location and Sensors ############################################################################################
Function Set-Control18-9-41-1 {
    # Control 18.9.41.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1
}

############################## 18.9.42 Maintenance Scheduler ###########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.43 Maps ############################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.44 MDM #############################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.45 Messaging #######################################################################################################
Function Set-Control18-9-45-1 {
    # Control 18.9.45.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Value 0
}

############################## 18.9.46 Microsoft account ###############################################################################################
Function Set-Control18-9-46-1 {
    # Control 18.9.46.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockMicrosoftAccounts" -Value 1
}

############################## 18.9.47 Microsoft Defender Antivirus (formerly Windows Defender and Windows Defender Antivirus) #########################
############################## 18.9.47.1 Client Interface ##############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.47.2 Device Control ################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.47.3 Exclusions ####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.47.4 MAPS ##########################################################################################################
Function Set-Control18-9-47-4-1 {
    # Control 18.9.47.4.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Value 0
}

Function Set-Control18-9-47-4-2 {
    # Control 18.9.47.4.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 0
}

############################## 18.9.47.5 Microsoft Defender Exploit Guard (formerly Windows Defender Exploit Guard) ####################################
############################## 18.9.47.5.1 Attack Surface Reduction ####################################################################################
Function Set-Control18-9-47-5-1-1 {
    # Control 18.9.47.5.1.1 - Remediation Script
    # Setting ASR rules requires specifying the individual rule IDs and their desired states, which is beyond this simple template's scope.
}

Function Set-Control18-9-47-5-1-2 {
    # Control 18.9.47.5.1.2 - Remediation Script
    # This script is a placeholder. Setting ASR rules individually requires specifying each rule ID and its state.
}

############################## 18.9.47.5.2 Controlled Folder Access ####################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.47.5.3 Network Protection ##########################################################################################
Function Set-Control18-9-47-5-3-1 {
    # Control 18.9.47.5.3.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 1
}

############################## 18.9.47.6 MpEngine ######################################################################################################
Function Set-Control18-9-47-6-1 {
    # Control 18.9.47.6.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -Value 1
}

############################## 18.9.47.7 Network Inspection System #####################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.47.8 Quarantine ####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.47.9 Real-time Protection ##########################################################################################
Function Set-Control18-9-47-9-1 {
    # Control 18.9.47.9.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanningNetworkFiles" -Value 0
}

Function Set-Control18-9-47-9-2 {
    # Control 18.9.47.9.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0
}

Function Set-Control18-9-47-9-3 {
    # Control 18.9.47.9.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0
}

Function Set-Control18-9-47-9-4 {
    # Control 18.9.47.9.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScriptScanning" -Value 0
}

############################## 18.9.47.10 Remediation ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.47.11 Reporting ####################################################################################################
Function Set-Control18-9-47-11-1 {
    # Control 18.9.47.11.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Value 1
}

############################## 18.9.47.12 Scan #########################################################################################################
Function Set-Control18-9-47-12-1 {
    # Control 18.9.47.12.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRemovableDriveScanning" -Value 0
}

Function Set-Control18-9-47-12-2 {
    # Control 18.9.47.12.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableEmailScanning" -Value 0
}

############################## 18.9.47.13 Security Intelligence Updates (formerly Signature Updates) ###################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.47.14 Threats ######################################################################################################
Function Set-Control18-9-47-15 {
    # Control 18.9.47.15 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "PUAProtection" -Value 1
}

Function Set-Control18-9-47-16 {
    # Control 18.9.47.16 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0
}

############################## 18.9.48 Microsoft Defender Application Guard (formerly Windows Defender Application Guard) ##############################
Function Set-Control18-9-48-1 {
    # Control 18.9.48.1 (First Instance) - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AuditProcessCreation" -Value 1
}

Function Set-Control18-9-48-2 {
    # Control 18.9.48.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowCameraAndMicrophoneRedirection" -Value 0
}

Function Set-Control18-9-48-3 {
    # Control 18.9.48.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowPersistence" -Value 0
}

Function Set-Control18-9-48-4 {
    # Control 18.9.48.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowFileSave" -Value 0
}

Function Set-Control18-9-48-5 {
    # Control 18.9.48.5 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "ClipboardRedirection" -Value 1
}

Function Set-Control18-9-48-6 {
    # Control 18.9.48.6 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "ConfigSecurityLevel" -Value 1
}

############################## 18.9.49 Microsoft Defender Exploit Guard (formerly Windows Defender Exploit Guard) ######################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.50 Microsoft Edge ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.51 Microsoft FIDO Authentication ###################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.52 Microsoft Secondary Authentication Factor #######################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.53 Microsoft User Experience Virtualization ########################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.54 NetMeeting ######################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.55 Network Access Protection #######################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.56 Network Projector ###############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.57 News and interests ##############################################################################################
Function Set-Control18-9-57-1 {
    # Control 18.9.57.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0
}

############################## 18.9.58 OneDrive (formerly SkyDrive) ####################################################################################
Function Set-Control18-9-58-1 {
    # Control 18.9.58.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1
}

############################## 18.9.59 Online Assistance ###############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.60 OOBE ############################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.61 Password Synchronization ########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.62 Portable Operating System #######################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.63 Presentation Settings ###########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.64 Push To Install #################################################################################################
Function Set-Control18-9-64-1 {
    # Control 18.9.64.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PushToInstall" -Name "DisablePushToInstall" -Value 1
}

############################## 18.9.65 Remote Desktop Services (formerly Terminal Services) ############################################################
############################## 18.9.65.1 RD Licensing (formerly TS Licensing) ##########################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.65.2 Remote Desktop Connection Client ##############################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.65.2.1 RemoteFX USB Device Redirection #############################################################################
Function Set-Control18-9-65-2-2 {
    # Control 18.9.65.2.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Value 1
}

############################## 18.9.65.3 Remote Desktop Session Host (formerly Terminal Server) ########################################################
############################## 18.9.65.3.1 Application Compatibility ###################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.65.3.2 Connections #################################################################################################
Function Set-Control18-9-65-3-2-1 {
    # Control 18.9.65.3.2.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDenyTSConnections" -Value 1
}

############################## 18.9.65.3.3 Device and Resource Redirection #############################################################################
Function Set-Control18-9-65-3-3-1 {
    # Control 18.9.65.3.3.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisableUARedirection" -Value 1
}

Function Set-Control18-9-65-3-3-2 {
    # Control 18.9.65.3.3.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -Value 1
}

Function Set-Control18-9-65-3-3-3 {
    # Control 18.9.65.3.3.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Value 1
}

Function Set-Control18-9-65-3-3-4 {
    # Control 18.9.65.3.3.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableLocationRedirection" -Value 1
}

Function Set-Control18-9-65-3-3-5 {
    # Control 18.9.65.3.3.5 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableLPT" -Value 1
}

Function Set-Control18-9-65-3-3-6 {
    # Control 18.9.65.3.3.6 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisablePNPRedir" -Value 1
}

############################## 18.9.65.3.4 Licensing ###################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.65.3.5 Printer Redirection #########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.65.3.6 Profiles ####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.65.3.7 RD Connection Broker (formerly TS Connection Broker) ########################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.65.3.8 Remote Session Environment ##################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.65.3.9 Security ####################################################################################################
Function Set-Control18-9-65-3-9-1 {
    # Control 18.9.65.3.9.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fPromptForPassword" -Value 1
}

Function Set-Control18-9-65-3-9-2 {
    # Control 18.9.65.3.9.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value 1
}

Function Set-Control18-9-65-3-9-3 {
    # Control 18.9.65.3.9.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "SecurityLayer" -Value 2
}

Function Set-Control18-9-65-3-9-4 {
    # Control 18.9.65.3.9.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "UserAuthentication" -Value 1
}

Function Set-Control18-9-65-3-9-5 {
    # Control 18.9.65.3.9.5 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Value 3
}

############################## 18.9.65.3.10 Session Time Limits ########################################################################################
Function Set-Control18-9-65-3-10-1 {
    # Control 18.9.65.3.10.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Value 900000
}

Function Set-Control18-9-65-3-10-2 {
    # Control 18.9.65.3.10.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxDisconnectionTime" -Value 60000
}

############################## 18.9.65.3.11 Temporary folders ##########################################################################################
Function Set-Control18-9-65-3-11-1 {
    # Control 18.9.65.3.11.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DeleteTempDirsOnExit" -Value 1
}

############################## 18.9.66 RSS Feeds #######################################################################################################
Function Set-Control18-9-66-1 {
    # Control 18.9.66.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -Value 1
}

############################## 18.9.67 Search ##########################################################################################################
Function Set-Control18-9-67-2 {
    # Control 18.9.67.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0
}

Function Set-Control18-9-67-3 {
    # Control 18.9.67.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0
}

Function Set-Control18-9-67-4 {
    # Control 18.9.67.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value 0
}

Function Set-Control18-9-67-5 {
    # Control 18.9.67.5 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Value 0
}

Function Set-Control18-9-67-6 {
    # Control 18.9.67.6 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0
}

############################## 18.9.67.1 OCR ###########################################################################################################
############################## 18.9.68 Security Center #################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.69 Server for NIS ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.70 Shutdown Options ################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.71 Smart Card ######################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.72 Software Protection Platform ####################################################################################
Function Set-Control18-9-72-1 {
    # Control 18.9.72.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Software Protection Platform" -Name "NoGenTicket" -Value 1
}

############################## 18.9.73 Sound Recorder ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.74 Speech ##########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.75 Store ###########################################################################################################
Function Set-Control18-9-75-1 {
    # Control 18.9.75.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableStoreApps" -Value 0
}

Function Set-Control18-9-75-2 {
    # Control 18.9.75.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RequirePrivateStoreOnly" -Value 1
}

Function Set-Control18-9-75-3 {
    # Control 18.9.75.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2
}

Function Set-Control18-9-75-4 {
    # Control 18.9.75.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -Value 1
}

Function Set-Control18-9-75-5 {
    # Control 18.9.75.5 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Value 1
}

############################## 18.9.76 Sync your settings ##############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.77 Tablet PC #######################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.78 Task Scheduler ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.79 Tenant Restrictions #############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.80 Text Input ######################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.81 Widgets #########################################################################################################
Function Set-Control18-9-81-1 {
    # Control 18.9.81.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "AllowNewsAndInterests" -Value 0
}

############################## 18.9.82 Windows Calendar ################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.83 Windows Color System ############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.84 Windows Customer Experience Improvement Program #################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.85 Windows Defender SmartScreen ####################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.85.1 Explorer ######################################################################################################
Function Set-Control18-9-85-1-1 {
    # Control 18.9.85.1.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Block"
}

############################## 18.9.85.2 Microsoft Edge ################################################################################################
Function Set-Control18-9-85-2-1 {
    # Control 18.9.85.2.1 - Remediation Script
    # This script assumes a generic approach to enable SmartScreen.
    # Adjust the registry path and value as necessary based on specific policy requirements.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1
}

Function Set-Control18-9-85-2-2 {
    # Control 18.9.85.2.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PreventOverrideForFilesInShell" -Value 1
}

############################## 18.9.86 Windows Error Reporting #########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.87 Windows Game Recording and Broadcasting #########################################################################
Function Set-Control18-9-87-1 {
    # Control 18.9.87.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0
}

############################## 18.9.88 Windows Hello for Business (formerly Microsoft Passport for Work) ###############################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.89 Windows Ink Workspace ###########################################################################################
Function Set-Control18-9-89-1 {
    # Control 18.9.89.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0
}

Function Set-Control18-9-89-2 {
    # Control 18.9.89.2 - Remediation Script
    # This function needs to disable or restrict Windows Ink Workspace based on organizational policy.
    # Disabling Windows Ink Workspace completely:
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 0
    # OR to restrict access above the lock screen, ensure compliance and update policy documentation accordingly.
}

############################## 18.9.90 Windows Installer ###############################################################################################
Function Set-Control18-9-90-1 {
    # Control 18.9.90.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "EnableUserControl" -Value 0
}

Function Set-Control18-9-90-2 {
    # Control 18.9.90.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0
}

Function Set-Control18-9-90-3 {
    # Control 18.9.90.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "SafeForScripting" -Value 0
}

############################## 18.9.91 Windows Logon Options ###########################################################################################
Function Set-Control18-9-91-1 {
    # Control 18.9.91.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Value 0
}

############################## 18.9.92 Windows Mail ####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.93 Windows Media Center ############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.94 Windows Media Digital Rights Management #########################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.95 Windows Media Player ############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.96 Windows Meeting Space ###########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.97 Windows Messenger ###############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.98 Windows Mobility Center #########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.99 Windows Movie Maker #############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.100 Windows PowerShell #############################################################################################
Function Set-Control18-9-100-1 {
    # Control 18.9.100.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
}

Function Set-Control18-9-100-2 {
    # Control 18.9.100.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 0
}

############################## 18.9.101 Windows Reliability Analysis ###################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.102 Windows Remote Management (WinRM) ##############################################################################
############################## 18.9.102.1 WinRM Client #################################################################################################
Function Set-Control18-9-102-1-1 {
    # Control 18.9.102.1.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value 0
}

Function Set-Control18-9-102-1-2 {
    # Control 18.9.102.1.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic" -Value 0
}

Function Set-Control18-9-102-1-3 {
    # Control 18.9.102.1.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Value 0
}

############################## 18.9.102.2 WinRM Service ################################################################################################
Function Set-Control18-9-102-2-1 {
    # Control 18.9.102.2.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Value 0
}

Function Set-Control18-9-102-2-2 {
    # Control 18.9.102.2.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowRemoteShellAccess" -Value 0
}

Function Set-Control18-9-102-2-3 {
    # Control 18.9.102.2.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Value 0
}

Function Set-Control18-9-102-2-4 {
    # Control 18.9.102.2.4 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs" -Value 1
}

############################## 18.9.103 Windows Remote Shell ###########################################################################################
Function Set-Control18-9-103-1 {
    # Control 18.9.103.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess" -Value 0
}

############################## 18.9.104 Windows Sandbox ################################################################################################
Function Set-Control18-9-104-1 {
    # Control 18.9.104.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowClipboardRedirection" -Value 0
}

Function Set-Control18-9-104-2 {
    # Control 18.9.104.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowNetworking" -Value 0
}

############################## 18.9.105 Windows Security (formerly Windows Defender Security Center) ###################################################
############################## 18.9.105.1 Account protection ###########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.105.2 App and browser protection ###################################################################################
Function Set-Control18-9-105-2-1 {
    # Control 18.9.105.2.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Name "DisallowExploitProtectionOverride" -Value 1
}

############################## 18.9.106 Windows SideShow ###############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.107 Windows System Resource Manager ################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.108 Windows Update #################################################################################################
############################## 18.9.108.1 Legacy Policies ##############################################################################################
Function Set-Control18-9-108-1-1 {
    # Control 18.9.108.1.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 0
}

############################## 18.9.108.2 Manage end user experience ###################################################################################
Function Set-Control18-9-108-2-1 {
    # Control 18.9.108.2.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0
}

Function Set-Control18-9-108-2-2 {
    # Control 18.9.108.2.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0
}

Function Set-Control18-9-108-2-3 {
    # Control 18.9.108.2.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetDisablePauseUXAccess" -Value 1
}

############################## 18.9.108.3 Manage updates offered from Windows Server Update Service ####################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.108.4 Manage updates offered from Windows Update (formerly Defer Windows Updates and Windows Update for Business) ##
Function Set-Control18-9-108-4-1 {
    # Control 18.9.108.4.1 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -Value 0
}

Function Set-Control18-9-108-4-2 {
    # Control 18.9.108.4.2 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Value 180
}

Function Set-Control18-9-108-4-3 {
    # Control 18.9.108.4.3 - Remediation Script
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Value 0
}



########################################################################################################################################################
################################################## 19. Administrative Templates (User) #################################################################
########################################################################################################################################################
############################## 19.1 Control Panel ######################################################################################################
############################## 19.1.1 Add or Remove Programs ###########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.1.2 Display ##########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.1.3 Personalization (formerly Desktop Themes) ########################################################################
Function Set-Control19-1-3-1 {
    # Control 19.1.3.1 - Remediation Script
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveActive" -Value "1"
}

Function Set-Control19-1-3-2 {
    # Control 19.1.3.2 - Remediation Script
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Value "1"
}

Function Set-Control19-1-3-3 {
    # Control 19.1.3.3 - Remediation Script
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value "900"
}

############################## 19.2 Desktop ############################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.3 Network ############################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.4 Shared Folders #####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.5 Start Menu and Taskbar #############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.5.1 Notifications ####################################################################################################
Function Set-Control19-5-1-1 {
    # Control 19.5.1.1 - Remediation Script
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableLockScreenAppNotifications" -Value 1
}

############################## 19.6 System #############################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.6.1 Ctrl+Alt+Del Options #############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.6.2 Display ##########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.6.3 Driver Installation ##############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.6.4 Folder Redirection ###############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.6.5 Group Policy #####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.6.6 Internet Communication Management ################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.6.6.1 Internet Communication settings ################################################################################
Function Set-Control19-6-6-1-1 {
    # Control 19.6.6.1.1 - Remediation Script
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0" -Name "NoImplicitFeedback" -Value 1
}

############################## 19.7 Windows Components #################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.1 Add features to Windows 8 / 8.1 / 10 (formerly Windows Anytime Upgrade) ##########################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.2 App runtime ######################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.3 Application Compatibility ########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.4 Attachment Manager ###############################################################################################
Function Set-Control19-7-4-1 {
    # Control 19.7.4.1 - Remediation Script
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 2
}

Function Set-Control19-7-4-2 {
    # Control 19.7.4.2 - Remediation Script
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -Value 3
}

############################## 19.7.5 AutoPlay Policies ################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.6 Backup ###########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.7 Calculator #######################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.8 Cloud Content ####################################################################################################
Function Set-Control19-7-8-1 {
    # Control 19.7.8.1 - Remediation Script
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "ConfigureWindowsSpotlight" -Value 0
}

Function Set-Control19-7-8-2 {
    # Control 19.7.8.2 - Remediation Script
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Value 1
}

Function Set-Control19-7-8-3 {
    # Control 19.7.8.3 - Remediation Script
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1
}

Function Set-Control19-7-8-4 {
    # Control 19.7.8.4 - Remediation Script
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1
}

Function Set-Control19-7-8-5 {
    # Control 19.7.8.5 - Remediation Script
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableSpotlightOnDesktop" -Value 1
}

############################## 19.7.9 Credential User Interface ########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.10 Data Collection and Preview Builds ##############################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.11 Desktop Gadgets #################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.12 Desktop Window Manager ##########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.13 Digital Locker ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.14 Edge UI #########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.15 File Explorer (formerly Windows Explorer) #######################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.16 File Revocation #################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.17 IME #############################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.18 Import Video ####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.19 Instant Search ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.20 Internet Explorer ###############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.21 Location and Sensors ############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.22 Microsoft Edge ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.23 Microsoft Management Console ####################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.24 Microsoft User Experience Virtualization ########################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.25 Multitasking ####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.26 NetMeeting ######################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.27 Network Projector ###############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.28 Network Sharing #################################################################################################
Function Set-Control19-7-28-1 {
    # Control 19.7.28.1 - Remediation Script
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Network Sharing" -Name "NoInplaceSharing" -Value 1
}

############################## 19.7.29 OOBE ############################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.30 Presentation Settings ###########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.31 Remote Desktop Services (formerly Terminal Services) ############################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.32 RSS Feeds #######################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.33 Search ##########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.34 Sound Recorder ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.35 Store ###########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.36 Tablet PC #######################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.37 Task Scheduler ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.38 Windows Calendar ################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.39 Windows Color System ############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.40 Windows Defender SmartScreen ####################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.41 Windows Error Reporting #########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.42 Windows Hello for Business (formerly Microsoft Passport for Work) ###############################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.43 Windows Installer ###############################################################################################
Function Set-Control19-7-43-1 {
    # Control 19.7.43.1 - Remediation Script
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0
}

############################## 19.7.44 Windows Logon Options ###########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.45 Windows Mail ####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.46 Windows Media Center ############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.47 Windows Media Player ############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.47.1 Networking ####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 19.7.47.2 Playback ######################################################################################################
Function Set-Control19-7-47-2-1 {
    # Control 19.7.47.2.1 - Remediation Script
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCodecDownload" -Value 1
}




Set-Control1-1-1
Set-Control1-1-2
Set-Control1-1-3
Set-Control1-1-4
Set-Control1-1-5
Set-Control1-1-6
Set-Control1-1-7
Set-Control1-2-1
Set-Control1-2-2
Set-Control1-2-3
Set-Control2-2-1
Set-Control2-2-2
Set-Control2-2-3
Set-Control2-2-4
Set-Control2-2-5
Set-Control2-2-6
Set-Control2-2-7
Set-Control2-2-7
Set-Control2-2-8
Set-Control2-2-9
Set-Control2-2-10
Set-Control2-2-11
Set-Control2-2-12
Set-Control2-2-13
Set-Control2-2-14
Set-Control2-2-15
Set-Control2-2-16
Set-Control2-2-17
Set-Control2-2-18
Set-Control2-2-19
Set-Control2-2-20
Set-Control2-2-21
Set-Control2-2-22
Set-Control2-2-23
Set-Control2-2-24
Set-Control2-2-25
Set-Control2-2-26
Set-Control2-2-27
Set-Control2-2-28
Set-Control2-2-29
Set-Control2-2-30
Set-Control2-2-31
Set-Control2-2-32
Set-Control2-2-33
Set-Control2-2-34
Set-Control2-2-35
Set-Control2-2-36
Set-Control2-2-37
Set-Control2-2-38
Set-Control2-2-39
Set-Control2-3-1-1
Set-Control2-3-1-3
Set-Control2-3-1-4
Set-Control2-3-1-5
Set-Control2-3-2-1
Set-Control2-3-2-2
Set-Control2-3-4-2
Set-Control2-3-6-1
Set-Control2-3-6-2
Set-Control2-3-6-3
Set-Control2-3-6-4
Set-Control2-3-6-5
Set-Control2-3-6-6
Set-Control2-3-7-1
Set-Control2-3-7-2
Set-Control2-3-7-3
Set-Control2-3-7-4
Set-Control2-3-7-5
Set-Control2-3-7-6
Set-Control2-3-7-7
Set-Control2-3-7-8
Set-Control2-3-7-9
Set-Control2-3-8-1
Set-Control2-3-8-2
Set-Control2-3-8-3
Set-Control2-3-9-1
Set-Control2-3-9-2
Set-Control2-3-9-3
Set-Control2-3-9-4
Set-Control2-3-9-5
Set-Control2-3-10-1
Set-Control2-3-10-2
Set-Control2-3-10-3
Set-Control2-3-10-4
Set-Control2-3-10-5
Set-Control2-3-10-6
Set-Control2-3-10-7
Set-Control2-3-10-8
Set-Control2-3-10-9
Set-Control2-3-10-10
Set-Control2-3-10-11
Set-Control2-3-10-12
Set-Control2-3-11-1
Set-Control2-3-11-2
Set-Control2-3-11-3
Set-Control2-3-11-4
Set-Control2-3-11-5
Set-Control2-3-11-6
Set-Control2-3-11-7
Set-Control2-3-11-8
Set-Control2-3-11-9
Set-Control2-3-11-10
Set-Control2-3-14-1
Set-Control2-3-15-1
Set-Control2-3-15-2
Set-Control2-3-17-1
Set-Control2-3-17-2
Set-Control2-3-17-3
Set-Control2-3-17-4
Set-Control2-3-17-5
Set-Control2-3-17-6
Set-Control2-3-17-7
Set-Control2-3-17-8
Set-Control5-1
Set-Control5-2
Set-Control5-3
Set-Control5-4
Set-Control5-5
Set-Control5-6
Set-Control5-7
Set-Control5-8
Set-Control5-9
Set-Control5-10
Set-Control5-11
Set-Control5-12
Set-Control5-13
Set-Control5-14
Set-Control5-15
Set-Control5-16
Set-Control5-17
Set-Control5-18
Set-Control5-19
Set-Control5-20
Set-Control5-21
Set-Control5-22
Set-Control5-23
Set-Control5-24
Set-Control5-25
Set-Control5-26
Set-Control5-27
Set-Control5-28
Set-Control5-29
Set-Control5-30
Set-Control5-31
Set-Control5-32
Set-Control5-33
Set-Control5-34
Set-Control5-35
Set-Control5-36
Set-Control5-37
Set-Control5-38
Set-Control5-39
Set-Control5-40
Set-Control9-1-1
Set-Control9-1-2
Set-Control9-1-3
Set-Control9-1-4
Set-Control9-1-5
Set-Control9-1-6
Set-Control9-1-7
Set-Control9-1-8
Set-Control9-2-1
Set-Control9-2-2
Set-Control9-2-3
Set-Control9-2-4
Set-Control9-2-5
Set-Control9-2-6
Set-Control9-2-7
Set-Control9-2-8
Set-Control9-3-1
Set-Control9-3-2
Set-Control9-3-3
Set-Control9-3-4
Set-Control9-3-5
Set-Control9-3-6
Set-Control9-3-7
Set-Control9-3-8
Set-Control9-3-9
Set-Control9-3-10
Set-Control17-1-1
Set-Control17-2-1
Set-Control17-2-2
Set-Control17-2-3
Set-Control17-3-1
Set-Control17-3-2
Set-Control17-5-1
Set-Control17-5-2
Set-Control17-5-3
Set-Control17-5-4
Set-Control17-5-5
Set-Control17-5-6
Set-Control17-6-1
Set-Control17-6-2
Set-Control17-6-3
Set-Control17-6-4
Set-Control17-7-1
Set-Control17-7-2
Set-Control17-7-3
Set-Control17-7-4
Set-Control17-7-5
Set-Control17-8-1
Set-Control17-9-1
Set-Control17-9-2
Set-Control17-9-3
Set-Control17-9-4
Set-Control17-9-5
Set-Control18-1-1-1
Set-Control18-1-1-2
Set-Control18-2-2
Set-Control18-2-3
Set-Control18-2-4
Set-Control18-2-5
Set-Control18-2-6
Set-Control18-3-1
Set-Control18-3-2
Set-Control18-3-3
Set-Control18-3-4
Set-Control18-3-5
Set-Control18-3-6
Set-Control18-3-7
Set-Control18-4-1
Set-Control18-4-2
Set-Control18-4-3
Set-Control18-4-4
Set-Control18-4-5
Set-Control18-4-6
Set-Control18-4-7
Set-Control18-4-8
Set-Control18-4-9
Set-Control18-4-10
Set-Control18-4-11
Set-Control18-4-12
Set-Control18-4-13
Set-Control18-5-4-1
Set-Control18-5-4-2
Set-Control18-5-5-1
Set-Control18-5-8-1
Set-Control18-5-9-1
Set-Control18-5-9-2
Set-Control18-5-10-2
Set-Control18-5-11-2
Set-Control18-5-11-3
Set-Control18-5-11-4
Set-Control18-5-14-1
Set-Control18-5-19-2-1
Set-Control18-5-20-1
Set-Control18-5-20-2
Set-Control18-5-21-1
Set-Control18-5-21-2
Set-Control18-5-23-2-1
Set-Control18-6-1
Set-Control18-6-2
Set-Control18-6-3
Set-Control18-7-1-1
Set-Control18-8-3-1
Set-Control18-8-4-1
Set-Control18-8-4-2
Set-Control18-8-5-1
Set-Control18-8-5-2
Set-Control18-8-5-3
Set-Control18-8-5-4
Set-Control18-8-5-5
Set-Control18-8-5-6
Set-Control18-8-7-1-1
Set-Control18-8-7-1-2
Set-Control18-8-7-1-3
Set-Control18-8-7-1-4
Set-Control18-8-7-1-5
Set-Control18-8-7-1-6
Set-Control18-8-7-2
Set-Control18-8-14-1
Set-Control18-8-21-2
Set-Control18-8-21-3
Set-Control18-8-21-4
Set-Control18-8-21-5
Set-Control18-8-22-1-1
Set-Control18-8-22-1-2
Set-Control18-8-22-1-3
Set-Control18-8-22-1-4
Set-Control18-8-22-1-5
Set-Control18-8-22-1-6
Set-Control18-8-22-1-7
Set-Control18-8-22-1-8
Set-Control18-8-22-1-9
Set-Control18-8-22-1-10
Set-Control18-8-22-1-11
Set-Control18-8-22-1-12
Set-Control18-8-22-1-13
Set-Control18-8-22-1-14
Set-Control18-8-25-1
Set-Control18-8-26-1
Set-Control18-8-27-1
Set-Control18-8-28-1
Set-Control18-8-28-2
Set-Control18-8-28-3
Set-Control18-8-28-4
Set-Control18-8-28-5
Set-Control18-8-28-6
Set-Control18-8-28-7
Set-Control18-8-31-1
Set-Control18-8-31-2
Set-Control18-8-34-6-1
Set-Control18-8-34-6-2
Set-Control18-8-34-6-3
Set-Control18-8-34-6-4
Set-Control18-8-34-6-5
Set-Control18-8-34-6-6
Set-Control18-8-36-1
Get-Control18-8-36-2
Get-Control18-8-37-1
Get-Control18-8-48-5-1
Get-Control18-8-48-11-1
Get-Control18-8-50-1
Get-Control18-8-53-1-1
Get-Control18-8-53-1-2
Get-Control18-9-4-1
Get-Control18-9-4-2
Get-Control18-9-5-1
Get-Control18-9-6-1
Get-Control18-9-6-2
Get-Control18-9-8-1
Get-Control18-9-8-2
Get-Control18-9-8-3
Get-Control18-9-10-1-1
Get-Control18-9-11-1-1
Get-Control18-9-11-1-2
Get-Control18-9-11-1-3
Get-Control18-9-11-1-4
Get-Control18-9-11-1-5
Get-Control18-9-11-1-6
Get-Control18-9-11-1-7
Get-Control18-9-11-1-8
Get-Control18-9-11-1-9
Get-Control18-9-11-1-10
Get-Control18-9-11-1-11
Get-Control18-9-11-1-12
Get-Control18-9-11-1-13
Get-Control18-9-11-2-1
Get-Control18-9-11-2-2
Get-Control18-9-11-2-3
Get-Control18-9-11-2-4
Get-Control18-9-11-2-5
Get-Control18-9-11-2-6
Get-Control18-9-11-2-7
Get-Control18-9-11-2-8
Get-Control18-9-11-2-9
Get-Control18-9-11-2-10
Get-Control18-9-11-2-11
Get-Control18-9-11-2-12
Get-Control18-9-11-2-13
Get-Control18-9-11-2-14
Get-Control18-9-11-3-1
Get-Control18-9-11-3-2
Get-Control18-9-11-3-3
Get-Control18-9-11-3-3
Get-Control18-9-11-3-4
Get-Control18-9-11-3-5
Get-Control18-9-11-3-6
Get-Control18-9-11-3-7
Get-Control18-9-11-3-8
Get-Control18-9-11-3-9
Get-Control18-9-11-3-10
Get-Control18-9-11-3-11
Get-Control18-9-11-3-12
Get-Control18-9-11-3-13
Get-Control18-9-11-3-14
Get-Control18-9-11-3-15
Get-Control18-9-11-4
Get-Control18-9-12-1
Get-Control18-9-14-1
Get-Control18-9-14-2
Get-Control18-9-14-3
Get-Control18-9-15-1
Get-Control18-9-16-1
Get-Control18-9-16-2
Get-Control18-9-16-3
Get-Control18-9-17-1
Get-Control18-9-17-2
Get-Control18-9-17-3
Get-Control18-9-17-4
Get-Control18-9-17-5
Get-Control18-9-17-6
Get-Control18-9-17-7
Get-Control18-9-17-8
Get-Control18-9-18-1
Get-Control18-9-27-1-1
Get-Control18-9-27-1-2
Get-Control18-9-27-2-1
Get-Control18-9-27-2-2
Get-Control18-9-27-3-1
Get-Control18-9-27-3-2
Get-Control18-9-27-4-1
Get-Control18-9-27-4-2
Get-Control18-9-31-2
Set-Control18-9-31-3
Set-Control18-9-31-4
Set-Control18-9-36-1
Set-Control18-9-41-1
Set-Control18-9-45-1
Set-Control18-9-46-1
Set-Control18-9-47-4-1
Set-Control18-9-47-4-2
Set-Control18-9-47-5-1-1
Set-Control18-9-47-5-1-2
Set-Control18-9-47-5-3-1
Set-Control18-9-47-6-1
Set-Control18-9-47-9-1
Set-Control18-9-47-9-2
Set-Control18-9-47-9-3
Set-Control18-9-47-9-4
Set-Control18-9-47-11-1
Set-Control18-9-47-12-1
Set-Control18-9-47-12-2
Set-Control18-9-47-15
Set-Control18-9-47-16
Set-Control18-9-48-1
Set-Control18-9-48-2
Set-Control18-9-48-3
Set-Control18-9-48-4
Set-Control18-9-48-5
Set-Control18-9-48-6
Set-Control18-9-57-1
Set-Control18-9-58-1
Set-Control18-9-64-1
Set-Control18-9-65-2-2
Set-Control18-9-65-3-2-1
Set-Control18-9-65-3-3-1
Set-Control18-9-65-3-3-2
Set-Control18-9-65-3-3-3
Set-Control18-9-65-3-3-4
Set-Control18-9-65-3-3-5
Set-Control18-9-65-3-3-6
Set-Control18-9-65-3-9-1
Set-Control18-9-65-3-9-2
Set-Control18-9-65-3-9-3
Set-Control18-9-65-3-9-4
Set-Control18-9-65-3-9-5
Set-Control18-9-65-3-10-1
Set-Control18-9-65-3-10-2
Set-Control18-9-65-3-11-1
Set-Control18-9-66-1
Set-Control18-9-67-2
Set-Control18-9-67-3
Set-Control18-9-67-4
Set-Control18-9-67-5
Set-Control18-9-67-6
Set-Control18-9-72-1
Set-Control18-9-75-1
Set-Control18-9-75-2
Set-Control18-9-75-3
Set-Control18-9-75-4
Set-Control18-9-75-5
Set-Control18-9-81-1
Set-Control18-9-85-1-1
Set-Control18-9-85-2-1
Set-Control18-9-85-2-2
Set-Control18-9-87-1
Set-Control18-9-89-1
Set-Control18-9-89-2
Set-Control18-9-90-1
Set-Control18-9-90-2
Set-Control18-9-90-3
Set-Control18-9-91-1
Set-Control18-9-100-1
Set-Control18-9-100-2
Set-Control18-9-102-1-1
Set-Control18-9-102-1-2
Set-Control18-9-102-1-3
Set-Control18-9-102-2-1
Set-Control18-9-102-2-2
Set-Control18-9-102-2-3
Set-Control18-9-102-2-4
Set-Control18-9-103-1
Set-Control18-9-104-1
Set-Control18-9-104-2
Set-Control18-9-105-2-1
Set-Control18-9-108-1-1
Set-Control18-9-108-2-1
Set-Control18-9-108-2-2
Set-Control18-9-108-2-3
Set-Control18-9-108-4-1
Set-Control18-9-108-4-2
Set-Control18-9-108-4-3
Set-Control19-1-3-1
Set-Control19-1-3-2
Set-Control19-1-3-3
Set-Control19-5-1-1
Set-Control19-6-6-1-1
Set-Control19-7-4-1
Set-Control19-7-4-2
Set-Control19-7-8-1
Set-Control19-7-8-2
Set-Control19-7-8-3
Set-Control19-7-8-4
Set-Control19-7-8-5
Set-Control19-7-28-1
Set-Control19-7-43-1
Set-Control19-7-47-2-1
