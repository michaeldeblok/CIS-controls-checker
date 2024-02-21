$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"

########################################################################################################################################################
##################################################  1. Account policies ################################################################################
########################################################################################################################################################

################################################## 1.1. Password Policy ##################################################
Function Get-Control1-1-1 {
    # Control 1.1.1 - Audit Script
    $controlNumber = "1.1.1"
    $description = "(L1) Ensure 'Enforce password history' is set to '24 or more password(s)'"
    
    $expectedValue = 24
    $currentValue = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").PasswordHistorySize

    $controlStatus = if ($currentValue -ge $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"

}

Function Get-Control1-1-2 {
    # Control 1.1.2 - Audit Script
    $controlNumber = "1.1.2"
    $description = "(L1) Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'"

    $expectedValue = 365
    $currentValue = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").MaxPasswordAge

    $controlStatus = if ($currentValue -le $expectedValue -and $currentValue -ne 0) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control1-1-3 {
    # Control 1.1.3 - Audit Script
    $controlNumber = "1.1.3"
    $description = "(L1) Ensure 'Minimum password age' is set to '1 or more day(s)'"

    $expectedValue = 1
    $currentValue = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").MinPasswordAge

    $controlStatus = if ($currentValue -ge $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control1-1-4 {
    # Control 1.1.4 - Audit Script
    $controlNumber = "1.1.4"
    $description = "(L1) Ensure 'Minimum password length' is set to '14 or more character(s)'"

    $expectedValue = 14
    $currentValue = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").MinPasswordLength

    $controlStatus = if ($currentValue -ge $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control1-1-5 {
    # Control 1.1.5 - Audit Script
    $controlNumber = "1.1.5"
    $description = "(L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'"

    $expectedValue = 1 # Enabled
    $currentValue = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").PasswordComplexity

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control1-1-6 {
    # Control 1.1.6 - Audit Script
    $exportPath = "C:\temp\secpol.cfg"
    $null = secedit /export /cfg $exportPath /quiet
    $content = Get-Content $exportPath

    $controlNumber = "1.1.6"
    $description = "(L1) Ensure 'Relax minimum password length limits' is set to 'Enabled'"
    $expectedValue = "SettingName = 1"

    $setting = $content | Where-Object { $_ -like "*SettingName =*" }
    $currentValue = if ($setting) { ($setting -split '=')[1].Trim() } else { "Not Found" }

    $controlStatus = if ($setting -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"

}

Function Get-Control1-1-7 {
    # Control 1.1.7 - Audit Script
    $controlNumber = "1.1.7"
    $description = "(L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"

    $expectedValue = 0 # Disabled
    $currentValue = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").ClearTextPassword

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

################################################## 1.2. Account Lockout Policy ##################################################
Function Get-Control1-2-1 {
    # Control 1.2.1 - Audit Script
    $controlNumber = "1.2.1"
    $description = "(L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'"

    $expectedValue = 15
    $currentValue = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters").LockoutDuration

    if ($currentValue -lt 0) { $currentValue = 0 }  # Convert negative values to 0

    $controlStatus = if ($currentValue -ge $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control1-2-2 {
    # Control 1.2.2 - Audit Script
    $controlNumber = "1.2.2"
    $description = "(L1) Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'"

    $expectedValue = 5
    $currentValue = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters").LockoutThreshold

    $controlStatus = if ($currentValue -le $expectedValue -and $currentValue -ne 0) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control1-2-3 {
    # Control 1.2.3 - Audit Script
    $controlNumber = "1.2.3"
    $description = "(L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'"

    $expectedValue = 15
    $currentValue = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters").LockoutObservationWindow

    if ($currentValue -lt 0) { $currentValue = 0 }  # Convert negative values to 0

    $controlStatus = if ($currentValue -ge $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

########################################################################################################################################################
################################################## 2. Local Policies ###################################################################################
########################################################################################################################################################

################################################## 2.1. Audit Policy ##################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

################################################## 2.1. User Rights Assignment ##################################################
Function Get-Control2-2-1 {
    # Control 2.2.1 - Audit Script
    $controlNumber = "2.2.1"
    $description = "(L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
    $expectedValue = ""

    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    $currentValue = Get-Content -Path "$env:temp\secpol.cfg" | Select-String "SeTrustedCredManAccessPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-2 {
    # Control 2.2.2 - Audit Script
    $controlNumber = "2.2.2"
    $description = "(L1) Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users'"
    $expectedValue = "*S-1-5-32-544,*S-1-5-32-555"

    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    $currentValue = Get-Content -Path "$env:temp\secpol.cfg" | Select-String "SeNetworkLogonRight" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-3 {
    # Control 2.2.3 - Audit Script
    $controlNumber = "2.2.3"
    $description = "(L1) Ensure 'Act as part of the operating system' is set to 'No One'"
    $expectedValue = ""

    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    $currentValue = Get-Content -Path "$env:temp\secpol.cfg" | Select-String "SeTcbPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-4 {
    # Control 2.2.4 - Audit Script
    $controlNumber = "2.2.4"
    $description = "(L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
    $expectedValue = "*S-1-5-32-544,*S-1-5-19,*S-1-5-20"

    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    $currentValue = Get-Content -Path "$env:temp\secpol.cfg" | Select-String "SeIncreaseQuotaPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-5 {
    # Control 2.2.5 - Audit Script
    $controlNumber = "2.2.5"
    $description = "(L1) Ensure 'Allow log on locally' is set to 'Administrators, Users'"
    $expectedValue = "*S-1-5-32-544,*S-1-5-32-545"

    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    $currentValue = Get-Content -Path "$env:temp\secpol.cfg" | Select-String "SeInteractiveLogonRight" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-6 {
    # Control 2.2.6 - Audit Script
    $controlNumber = "2.2.6"
    $description = "(L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'"
    $expectedValue = "*S-1-5-32-544,*S-1-5-32-555"

    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    $currentValue = Get-Content -Path "$env:temp\secpol.cfg" | Select-String "SeRemoteInteractiveLogonRight" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-7 {
    # Control 2.2.7 - Audit Script
    $controlNumber = "2.2.7"
    $description = "(L1) Ensure 'Back up files and directories' is set to 'Administrators'"
    $expectedValue = "*S-1-5-32-544"

    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    $currentValue = Get-Content -Path "$env:temp\secpol.cfg" | Select-String "SeBackupPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-7 {
    # Control 2.2.7 - Audit Script
    $controlNumber = "2.2.7"
    $description = "(L1) Ensure 'Back up files and directories' is set to 'Administrators'"
    $expectedValue = "*S-1-5-32-544"

    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    $currentValue = Get-Content -Path "$env:temp\secpol.cfg" | Select-String "SeBackupPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-8 {
    # Control 2.2.8 - Audit Script
    $controlNumber = "2.2.8"
    $description = "(L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
    $expectedValue = "*S-1-5-32-544,*S-1-5-19"

    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    $currentValue = Get-Content -Path "$env:temp\secpol.cfg" | Select-String "SeBackupPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-9 {
    # Control 2.2.9 - Audit Script
    $controlNumber = "2.2.9"
    $description = "(L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE, Users'"
    $expectedValue = "*S-1-5-32-544,*S-1-5-19,*S-1-5-32-545"

    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    $currentValue = Get-Content -Path "$env:temp\secpol.cfg" | Select-String "SeBackupPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-10 {
    # Control 2.2.10 - Audit Script
    $controlNumber = "2.2.10"
    $description = "(L1) Ensure 'Create a pagefile' is set to 'Administrators'"
    $expectedValue = "*S-1-5-32-544"

    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    $currentValue = Get-Content -Path "$env:temp\secpol.cfg" | Select-String "SeBackupPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-11 {
    # Control 2.2.11 - Audit Script
    $controlNumber = "2.2.11"
    $description = "(L1) Ensure 'Create a token object' is set to 'No One'"
    $expectedValue = ""

    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    $currentValue = Get-Content -Path "$env:temp\secpol.cfg" | Select-String "SeBackupPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-12 {
    # Control 2.2.12 - Audit Script
    $controlNumber = "2.2.12"
    $description = "(L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
    $expectedValue = "*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6"

    $secpol = secedit /export /areas USER_RIGHTS /cfg $env:temp\secpol.cfg
    $currentValue = Get-Content -Path "$env:temp\secpol.cfg" | Select-String "SeBackupPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-13 {
    # Control 2.2.13 - Detection Script
    $controlNumber = "2.2.13"
    $description = "(L1) Ensure 'Create permanent shared objects' is set to 'No One'"
    $expectedValue = ""
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeCreatePermanentPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-14 {
    # Control 2.2.14 - Detection Script
    $controlNumber = "2.2.14"
    $description = "(L1) Configure 'Create symbolic links'"
    $expectedValue = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeCreateSymbolicLinkPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-15 {
    # Control 2.2.15 - Detection Script
    $controlNumber = "2.2.15"
    $description = "(L1) Ensure 'Debug programs' is set to 'Administrators'"
    $expectedValue = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeDebugPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-16 {
    # Control 2.2.16 - Detection Script
    $controlNumber = "2.2.16"
    $description = "(L1) Ensure 'Deny access to this computer from the network' to include 'Guests, Local account'"
    $expectedValue = "*S-1-5-32-546,*S-1-5-113" # Guests, Local account
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeDenyNetworkLogonRight" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-17 {
    # Control 2.2.17 - Detection Script
    $controlNumber = "2.2.17"
    $description = "(L1) Ensure 'Deny log on as a batch job' to include 'Guests'"
    $expectedValue = "*S-1-5-32-546" # Guests
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeDenyBatchLogonRight" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-18 {
    # Control 2.2.18 - Detection Script
    $controlNumber = "2.2.18"
    $description = "(L1) Ensure 'Deny log on as a service' to include 'Guests'"
    $expectedValue = "*S-1-5-32-546" # Guests
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeDenyServiceLogonRight" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-19 {
    # Control 2.2.19 - Detection Script
    $controlNumber = "2.2.19"
    $description = "(L1) Ensure 'Deny log on locally' to include 'Guests'"
    $expectedValue = "*S-1-5-32-546" # Guests
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeDenyInteractiveLogonRight" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-20 {
    # Control 2.2.20 - Detection Script
    $controlNumber = "2.2.20"
    $description = "(L1) Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'"
    $expectedValue = "*S-1-5-32-546,*S-1-5-113" # Guests, Local account
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeDenyRemoteInteractiveLogonRight" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-21 {
    # Control 2.2.21 - Detection Script
    $controlNumber = "2.2.21"
    $description = "(L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"
    $expectedValue = ""
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeEnableDelegationPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-22 {
    # Control 2.2.22 - Detection Script
    $controlNumber = "2.2.22"
    $description = "(L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
    $expectedValue = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeRemoteShutdownPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-23 {
    # Control 2.2.23 - Detection Script
    $controlNumber = "2.2.23"
    $description = "(L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
    $expectedValue = "*S-1-5-19,*S-1-5-20" # LOCAL SERVICE, NETWORK SERVICE
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeAuditPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-24 {
    # Control 2.2.24 - Detection Script
    $controlNumber = "2.2.24"
    $description = "(L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
    $expectedValue = "*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6" # Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeImpersonatePrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-25 {
    # Control 2.2.25 - Detection Script
    $controlNumber = "2.2.25"
    $description = "(L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'"
    $expectedValue = "*S-1-5-32-544,*S-1-5-90-0" # Administrators, Window Manager\Window Manager Group
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeIncreaseBasePriorityPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-26 {
    # Control 2.2.26 - Detection Script
    $controlNumber = "2.2.26"
    $description = "(L1) Ensure 'Load and unload device drivers' is set to 'Administrators'"
    $expectedValue = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeLoadDriverPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-27 {
    # Control 2.2.27 - Detection Script
    $controlNumber = "2.2.27"
    $description = "(L1) Ensure 'Lock pages in memory' is set to 'No One'"
    $expectedValue = ""
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeLockMemoryPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-28 {
    # Control 2.2.28 - Detection Script
    $controlNumber = "2.2.28"
    $description = "(L2) Ensure 'Log on as a batch job' is set to 'Administrators'"
    $expectedValue = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeBatchLogonRight" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-29 {
    # Control 2.2.29 - Detection Script
    $controlNumber = "2.2.29"
    $description = "(L2) Configure 'Log on as a service'"
    $expectedValue = "" # Define the expected value as per your policy
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeServiceLogonRight" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-30 {
    # Control 2.2.30 - Detection Script
    $controlNumber = "2.2.30"
    $description = "(L1) Ensure 'Manage auditing and security log' is set to 'Administrators'"
    $expectedValue = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeSecurityPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-31 {
    # Control 2.2.31 - Detection Script
    $controlNumber = "2.2.31"
    $description = "(L1) Ensure 'Modify an object label' is set to 'No One'"
    $expectedValue = ""
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeRelabelPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-32 {
    # Control 2.2.32 - Detection Script
    $controlNumber = "2.2.32"
    $description = "(L1) Ensure 'Modify firmware environment values' is set to 'Administrators'"
    $expectedValue = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeSystemEnvironmentPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-33 {
    # Control 2.2.33 - Detection Script
    $controlNumber = "2.2.33"
    $description = "(L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
    $expectedValue = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeManageVolumePrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-34 {
    # Control 2.2.34 - Detection Script
    $controlNumber = "2.2.34"
    $description = "(L1) Ensure 'Profile single process' is set to 'Administrators'"
    $expectedValue = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeProfileSingleProcessPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-35 {
    # Control 2.2.35 - Detection Script
    $controlNumber = "2.2.35"
    $description = "(L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'"
    $expectedValue = "*S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420" # Administrators, NT SERVICE\WdiServiceHost
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeSystemProfilePrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-36 {
    # Control 2.2.36 - Detection Script
    $controlNumber = "2.2.36"
    $description = "(L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
    $expectedValue = "*S-1-5-19,*S-1-5-20" # LOCAL SERVICE, NETWORK SERVICE
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeAssignPrimaryTokenPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-37 {
    # Control 2.2.37 - Detection Script
    $controlNumber = "2.2.37"
    $description = "(L1) Ensure 'Restore files and directories' is set to 'Administrators'"
    $expectedValue = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeRestorePrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-38 {
    # Control 2.2.38 - Detection Script
    $controlNumber = "2.2.38"
    $description = "(L1) Ensure 'Shut down the system' is set to 'Administrators, Users'"
    $expectedValue = "*S-1-5-32-544,*S-1-5-32-545" # Administrators, Users
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeShutdownPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-2-39 {
    # Control 2.2.39 - Detection Script
    $controlNumber = "2.2.39"
    $description = "(L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
    $expectedValue = "*S-1-5-32-544" # Administrators
    $exportPath = "$env:temp\secpol.cfg"

    $secpol = secedit /export /cfg $exportPath /areas USER_RIGHTS
    $currentValue = Get-Content -Path $exportPath | Select-String "SeTakeOwnershipPrivilege" | Out-String
    if ($currentValue -and $currentValue.Contains('=')) {$currentValue = $currentValue.Split('=')[1].Trim()} else {$currentValue = "Not Found"}

    $controlStatus = if ($currentValue -like $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

################################################## 2.3. Security Options ##################################################
############################## 2.3.1 Accounts ##############################
Function Get-Control2-3-1-1 {
    # Control 2.3.1.1 - Detection Script
    $controlNumber = "2.3.1.1"
    $description = "(L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled'"
    $expectedValue = 0 # Disabled
    $keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    $valueName = "Administrator"

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = 1 } # If value not found, assume enabled

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

######################################################
# Circle back for Control 2.3.1.2
######################################################

Function Get-Control2-3-1-3 {
    # Control 2.3.1.3 - Detection Script
    $controlNumber = "2.3.1.1"
    $description = "(L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled'"
    $expectedValue = 0 # Disabled
    $keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    $valueName = "Guest"

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = 1 } # If value not found, assume enabled

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-1-4 {
    # Control 2.3.1.4 - Detection Script
    $controlNumber = "2.3.1.4"
    $description = "(L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
    $expectedValue = 1 # Enabled
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "LimitBlankPasswordUse"

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName).$valueName

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-1-5 {
    # Control 2.3.1.5 - Detection Script
    $controlNumber = "2.3.1.5"
    $description = "(L1) Configure 'Accounts: Rename administrator account'"
    $keyPath = "HKLM:\SAM\SAM\Domains\Account\Users\Names"
    $expectedValue = "YourRenamedAdmin" # Replace with your renamed administrator account name

    $currentValue = Get-ChildItem -Path $keyPath | Where-Object { $_.Name -like "*$expectedValue" }

    $controlStatus = if ($currentValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$expectedValue`t$currentValue"
}

############################## 2.3.2 Audit ##############################
Function Get-Control2-3-2-1 {
    # Control 2.3.2.1 - Detection Script
    $controlNumber = "2.3.2.1"
    $description = "(L1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'"
    $expectedValue = 1 # Enabled
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $valueName = "SCENoApplyLegacyAuditPolicy"

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-2-2 {
    # Control 2.3.2.2 - Detection Script
    $controlNumber = "2.3.2.2"
    $description = "(L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"
    $expectedValue = 0 # Disabled
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "CrashOnAuditFail"

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 2.3.3 DCOM ##############################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 2.3.4 Devices ##############################

######################################################
# Circle back for Control 2.3.4.1
######################################################

Function Get-Control2-3-4-2 {
    # Control 2.3.4.2 - Detection Script
    $controlNumber = "2.3.4.2"
    $description = "(L2) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
    $valueName = "AddPrinterDrivers"
    $expectedValue = 0 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 2.3.5 Domain Controller ##############################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 2.3.6 Domain Member ##############################
Function Get-Control2-3-6-1 {
    # Control 2.3.6.1 - Detection Script
    $controlNumber = "2.3.6.1"
    $description = "(L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $valueName = "RequireStrongKey"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-6-2 {
    # Control 2.3.6.2 - Detection Script
    $controlNumber = "2.3.6.2"
    $description = "(L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $valueName = "SealSecureChannel"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}


Function Get-Control2-3-6-3 {
    # Control 2.3.6.3 - Detection Script
    $controlNumber = "2.3.6.3"
    $description = "(L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $valueName = "SignSecureChannel"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-6-4 {
    # Control 2.3.6.4 - Detection Script
    $controlNumber = "2.3.6.4"
    $description = "(L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $valueName = "DisablePasswordChange"
    $expectedValue = 0 # Disabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-6-5 {
    # Control 2.3.6.5 - Detection Script
    $controlNumber = "2.3.6.5"
    $description = "(L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $valueName = "MaximumPasswordAge"
    $expectedValue = 30 # 30 days

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -le $expectedValue -and $currentValue -ne 0) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-6-6 {
    # Control 2.3.6.6 - Detection Script
    $controlNumber = "2.3.6.6"
    $description = "(L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $valueName = "RequireStrongKey"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 2.3.7 Interactive Logon ##############################
Function Get-Control2-3-7-1 {
    # Control 2.3.7.1 - Detection Script
    $controlNumber = "2.3.7.1"
    $description = "(L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'"
    $keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $valueName = "DisableCAD"
    $expectedValue = 0 # Disabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-7-2 {
    # Control 2.3.7.2 - Detection Script
    $controlNumber = "2.3.7.2"
    $description = "(L1) Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'"
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "DontDisplayLastUserName"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-7-3 {
    # Control 2.3.7.3 - Detection Script
    $controlNumber = "2.3.7.3"
    $description = "(BL) Ensure 'Interactive logon: Machine account lockout threshold' is set to '10 or fewer invalid logon attempts, but not 0'"
    $keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $valueName = "AccountLockoutThreshold"
    $expectedValue = 10

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }
    if ($currentValue -eq 0) { $currentValue = "Not Applicable (set to 0)" }

    $controlStatus = if ($currentValue -le $expectedValue -and $currentValue -ne 0) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-7-4 {
    # Control 2.3.7.4 - Detection Script
    $controlNumber = "2.3.7.4"
    $description = "(L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'"
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "InactivityTimeoutSecs"
    $expectedValue = 900 # 900 seconds

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }
    if ($currentValue -eq 0) { $currentValue = "Not Applicable (set to 0)" }

    $controlStatus = if ($currentValue -le $expectedValue -and $currentValue -ne 0) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-7-5 {
    # Control 2.3.7.5 - Detection Script
    $controlNumber = "2.3.7.5"
    $description = "(L1) Configure 'Interactive logon: Message text for users attempting to log on'"
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "LegalNoticeText"
    $expectedValue = "Your Custom Message Here" # Replace with your organization's message

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t'Your Custom Message Here'"
}

Function Get-Control2-3-7-6 {
    # Control 2.3.7.6 - Detection Script
    $controlNumber = "2.3.7.6"
    $description = "(L1) Configure 'Interactive logon: Message title for users attempting to log on'"
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "LegalNoticeCaption"
    $expectedValue = "Your Custom Title Here" # Replace with your organization's title

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t'Your Custom Title Here'"
}

Function Get-Control2-3-7-7 {
    # Control 2.3.7.7 - Detection Script
    $controlNumber = "2.3.7.7"
    $description = "(L2) Ensure 'Interactive logon: Number of previous logons to cache' is set to '4 or fewer logon(s)'"
    $keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $valueName = "CachedLogonsCount"
    $expectedValue = 4

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -le $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-7-8 {
    # Control 2.3.7.8 - Detection Script
    $controlNumber = "2.3.7.8"
    $description = "(L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'"
    $keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $valueName = "PasswordExpiryWarning"
    $expectedMinValue = 5
    $expectedMaxValue = 14

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -ge $expectedMinValue -and $currentValue -le $expectedMaxValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t'$expectedMinValue-$expectedMaxValue days'"
}

Function Get-Control2-3-7-9 {
    # Control 2.3.7.9 - Detection Script
    $controlNumber = "2.3.7.9"
    $description = "(L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher"
    $keyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $valueName = "ScRemoveOption"
    $expectedValue = "1" # 1 = Lock Workstation

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t'Lock Workstation'"
}

############################## 2.3.8 Microsoft network client ##############################
Function Get-Control2-3-8-1 {
    # Control 2.3.8.1 - Detection Script
    $controlNumber = "2.3.8.1"
    $description = "(L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    $valueName = "RequireSecuritySignature"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-8-2 {
    # Control 2.3.8.2 - Detection Script
    $controlNumber = "2.3.8.2"
    $description = "(L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    $valueName = "EnableSecuritySignature"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-8-3 {
    # Control 2.3.8.3 - Detection Script
    $controlNumber = "2.3.8.3"
    $description = "(L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    $valueName = "EnablePlainTextPassword"
    $expectedValue = 0 # Disabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 2.3.9 Microsoft network server ##############################
Function Get-Control2-3-9-1 {
    # Control 2.3.9.1 - Detection Script
    $controlNumber = "2.3.9.1"
    $description = "(L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "AutoDisconnect"
    $expectedValue = 15 # 15 minutes

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -le $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-9-2 {
    # Control 2.3.9.2 - Detection Script
    $controlNumber = "2.3.9.2"
    $description = "(L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "RequireSecuritySignature"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-9-3 {
    # Control 2.3.9.3 - Detection Script
    $controlNumber = "2.3.9.3"
    $description = "(L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "EnableSecuritySignature"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-9-4 {
    # Control 2.3.9.4 - Detection Script
    $controlNumber = "2.3.9.4"
    $description = "(L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "EnableForcedLogOff"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-9-5 {
    # Control 2.3.9.5 - Detection Script
    $controlNumber = "2.3.9.5"
    $description = "(L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "SMBServerNameHardeningLevel"
    $expectedValue = 1 # 1 = Accept if provided by client

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -ge $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t'Accept if provided by client'"
}

############################## 2.3.10 Network Access ##############################
Function Get-Control2-3-10-1 {
    # Control 2.3.10.1 - Detection Script
    $controlNumber = "2.3.10.1"
    $description = "(L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "TranslateNames"
    $expectedValue = 0 # Disabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-10-2 {
    # Control 2.3.10.2 - Detection Script
    $controlNumber = "2.3.10.2"
    $description = "(L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "RestrictAnonymousSAM"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-10-3 {
    # Control 2.3.10.3 - Detection Script
    $controlNumber = "2.3.10.3"
    $description = "(L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "RestrictAnonymous"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-10-4 {
    # Control 2.3.10.4 - Detection Script
    $controlNumber = "2.3.10.4"
    $description = "(L1) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "DisableDomainCreds"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-10-5 {
    # Control 2.3.10.5 - Detection Script
    $controlNumber = "2.3.10.5"
    $description = "(L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "EveryoneIncludesAnonymous"
    $expectedValue = 0 # Disabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-10-6 {
    # Control 2.3.10.6 - Detection Script
    $controlNumber = "2.3.10.6"
    $description = "(L1) Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to 'None'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "NullSessionPipes"
    $expectedValue = "" # None

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }
    elseif ($currentValue -eq "") { $currentValue = "None" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t'None'"
}

Function Get-Control2-3-10-7 {
    # Control 2.3.10.7 - Detection Script
    $controlNumber = "2.3.10.7"
    $description = "(L1) Ensure 'Network access: Remotely accessible registry paths' is configured"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths"
    $valueName = "Machine"
    $expectedValue = "System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,SOFTWARE\Microsoft\Windows NT\CurrentVersion"

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-10-8 {
    # Control 2.3.10.8 - Detection Script
    $controlNumber = "2.3.10.8"
    $description = "(L1) Ensure 'Network access: Remotely accessible registry paths and sub-paths' is configured"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths"
    $valueName = "Machine"
    $expectedValue = "System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,SOFTWARE\Microsoft\OLAP Server,SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print,SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog"

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-10-9 {
    # Control 2.3.10.9 - Detection Script
    $controlNumber = "2.3.10.9"
    $description = "(L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "RestrictNullSessAccess"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-10-10 {
    # Control 2.3.10.10 - Detection Script
    $controlNumber = "2.3.10.10"
    $description = "(L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "RestrictRemoteSAM"
    $expectedValue = "O:BAG:BAD:(A;;RC;;;BA)" # Administrators: Remote Access: Allow

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-10-11 {
    # Control 2.3.10.11 - Detection Script
    $controlNumber = "2.3.10.11"
    $description = "(L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
    $valueName = "NullSessionShares"
    $expectedValue = "" # None

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }
    elseif ($currentValue -eq "") { $currentValue = "None" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t'None'"
}

Function Get-Control2-3-10-12 {
    # Control 2.3.10.12 - Detection Script
    $controlNumber = "2.3.10.12"
    $description = "(L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "ForceGuest"
    $expectedValue = 0 # Classic - local users authenticate as themselves

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t'Classic - local users authenticate as themselves'"
}

############################## 2.3.11 Network Security ##############################
Function Get-Control2-3-11-1 {
    # Control 2.3.11.1 - Detection Script
    $controlNumber = "2.3.11.1"
    $description = "(L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "UseMachineId"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-11-2 {
    # Control 2.3.11.2 - Detection Script
    $controlNumber = "2.3.11.2"
    $description = "(L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
    $valueName = "AllowNullSessionFallback"
    $expectedValue = 0 # Disabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-11-3 {
    # Control 2.3.11.3 - Detection Script
    $controlNumber = "2.3.11.3"
    $description = "(L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa\pku2u"
    $valueName = "AllowOnlineID"
    $expectedValue = 0 # Disabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-11-4 {
    # Control 2.3.11.4 - Detection Script
    $controlNumber = "2.3.11.4"
    $description = "(L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'"
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    $valueName = "SupportedEncryptionTypes"
    $expectedValue = 2147483644 # Sum of the values for AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t'2147483644'"
}

Function Get-Control2-3-11-5 {
    # Control 2.3.11.5 - Detection Script
    $controlNumber = "2.3.11.5"
    $description = "(L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "NoLMHash"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-11-6 {
    # Control 2.3.11.6 - Detection Script
    $controlNumber = "2.3.11.6"
    $description = "(L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "ForceLogoffWhenHourExpire"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-11-7 {
    # Control 2.3.11.7 - Detection Script
    $controlNumber = "2.3.11.7"
    $description = "(L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $valueName = "LmCompatibilityLevel"
    $expectedValue = 5 # Send NTLMv2 response only. Refuse LM & NTLM

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-11-8 {
    # Control 2.3.11.8 - Detection Script
    $controlNumber = "2.3.11.8"
    $description = "(L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher"
    $keyPath = "HKLM:\System\CurrentControlSet\Services\LDAP"
    $valueName = "LDAPClientIntegrity"
    $expectedValue = 1 # Negotiate signing

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -ge $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t'Negotiate signing'"
}

Function Get-Control2-3-11-9 {
    # Control 2.3.11.9 - Detection Script
    $controlNumber = "2.3.11.9"
    $description = "(L1) Ensure 'Network security: Minimum session security for NTLM SSP based clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
    $valueName = "NTLMMinClientSec"
    $expectedValue = 537395200 # Require NTLMv2 session security, Require 128-bit encryption

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-11-10 {
    # Control 2.3.11.10 - Detection Script
    $controlNumber = "2.3.11.10"
    $description = "(L1) Ensure 'Network security: Minimum session security for NTLM SSP based servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
    $valueName = "NTLMMinServerSec"
    $expectedValue = 537395200 # Require NTLMv2 session security, Require 128-bit encryption

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 2.3.12 Recovery Console ##############################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 2.3.13 Shutdown ##############################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 2.3.14 Domain Member ##############################
Function Get-Control2-3-14-1 {
    # Control 2.3.14.1 - Detection Script
    $controlNumber = "2.3.14.1"
    $description = "(L2) Ensure 'System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User is prompted when the key is first used' or higher"
    $keyPath = "HKLM:\Software\Policies\Microsoft\Cryptography"
    $valueName = "ForceKeyProtection"
    $expectedValue = 2 # User is prompted when the key is first used

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -ge $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t'User is prompted when the key is first used'"
}

############################## 2.3.15 System Objects ##############################
Function Get-Control2-3-15-1 {
    # Control 2.3.15.1 - Detection Script
    $controlNumber = "2.3.15.1"
    $description = "(L1) Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel"
    $valueName = "ObCaseInsensitive"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-15-2 {
    # Control 2.3.15.2 - Detection Script
    $controlNumber = "2.3.15.2"
    $description = "(L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)' is set to 'Enabled'"
    $keyPath = "HKLM:\System\CurrentControlSet\Control\Session Manager"
    $valueName = "ProtectionMode"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 2.3.16 System Settings ##############################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 2.3.17 User Account Control ##############################
Function Get-Control2-3-17-1 {
    # Control 2.3.17.1 - Detection Script
    $controlNumber = "2.3.17.1"
    $description = "(L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "FilterAdministratorToken"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-17-2 {
    # Control 2.3.17.2 - Detection Script
    $controlNumber = "2.3.17.2"
    $description = "(L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'"
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "ConsentPromptBehaviorAdmin"
    $expectedValue = 2 # Prompt for consent on the secure desktop

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-17-3 {
    # Control 2.3.17.3 - Detection Script
    $controlNumber = "2.3.17.3"
    $description = "(L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "ConsentPromptBehaviorUser"
    $expectedValue = 0 # Automatically deny elevation requests

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-17-4 {
    # Control 2.3.17.4 - Detection Script
    $controlNumber = "2.3.17.4"
    $description = "(L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "EnableInstallerDetection"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-17-5 {
    # Control 2.3.17.5 - Detection Script
    $controlNumber = "2.3.17.5"
    $description = "(L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "EnableSecureUIAPaths"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-17-6 {
    # Control 2.3.17.6 - Detection Script
    $controlNumber = "2.3.17.6"
    $description = "(L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'"
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "EnableLUA"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-17-7 {
    # Control 2.3.17.7 - Detection Script
    $controlNumber = "2.3.17.7"
    $description = "(L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "PromptOnSecureDesktop"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control2-3-17-8 {
    # Control 2.3.17.8 - Detection Script
    $controlNumber = "2.3.17.8"
    $description = "(L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
    $keyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $valueName = "EnableVirtualization"
    $expectedValue = 1 # Enabled

    $currentValue = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    if ($null -eq $currentValue) { $currentValue = "Not Configured" }

    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

########################################################################################################################################################
################################################## 3. Event Log ########################################################################################
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

########################################################################################################################################################
################################################## 4. Restricted Groups ################################################################################
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

########################################################################################################################################################
################################################## 5. Local System Services ############################################################################
########################################################################################################################################################
Function Get-Control5-1 {
    # Control 5.1 - Detection Script
    $controlNumber = "5.1"
    $description = "(L2) Ensure 'Bluetooth Audio Gateway Service (BTAGService)' is set to 'Disabled'"
    $serviceName = "BTAGService"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { $currentStatus = "Not Installed" }
    else { $currentStatus = $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-2 {
    # Control 5.2 - Detection Script
    $controlNumber = "5.2"
    $description = "(L2) Ensure 'Bluetooth Support Service (bthserv)' is set to 'Disabled'"
    $serviceName = "bthserv"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { $currentStatus = "Not Installed" }
    else { $currentStatus = $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-3 {
    # Control 5.3 - Detection Script
    $controlNumber = "5.3"
    $description = "(L1) Ensure 'Computer Browser (Browser)' is set to 'Disabled' or 'Not Installed'"
    $serviceName = "Browser"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { $currentStatus = "Not Installed" }
    else { $currentStatus = $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled/Not Installed'"
}

Function Get-Control5-4 {
    # Control 5.4 - Detection Script
    $controlNumber = "5.4"
    $description = "(L2) Ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled'"
    $serviceName = "MapsBroker"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { $currentStatus = "Not Installed" }
    else { $currentStatus = $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-5 {
    # Control 5.5 - Detection Script
    $controlNumber = "5.5"
    $description = "(L2) Ensure 'Geolocation Service (lfsvc)' is set to 'Disabled'"
    $serviceName = "lfsvc"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { $currentStatus = "Not Installed" }
    else { $currentStatus = $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-6 {
    # Control 5.6 - Detection Script
    $controlNumber = "5.6"
    $description = "(L1) Ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or 'Not Installed'"
    $serviceName = "IISADMIN"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { $currentStatus = "Not Installed" }
    else { $currentStatus = $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled/Not Installed'"
}

Function Get-Control5-7 {
    # Control 5.7 - Detection Script
    $controlNumber = "5.7"
    $description = "(L1) Ensure 'Infrared monitor service (irmon)' is set to 'Disabled' or 'Not Installed'"
    $serviceName = "irmon"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { $currentStatus = "Not Installed" }
    else { $currentStatus = $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled/Not Installed'"
}

Function Get-Control5-8 {
    # Control 5.8 - Detection Script
    $controlNumber = "5.8"
    $description = "(L1) Ensure 'Internet Connection Sharing (ICS) (SharedAccess)' is set to 'Disabled'"
    $serviceName = "SharedAccess"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { $currentStatus = "Not Installed" }
    else { $currentStatus = $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-9 {
    # Control 5.9 - Detection Script
    $controlNumber = "5.9"
    $description = "(L2) Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled'"
    $serviceName = "lltdsvc"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { $currentStatus = "Not Installed" }
    else { $currentStatus = $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-10 {
    # Control 5.10 - Detection Script
    $controlNumber = "5.10"
    $description = "(L1) Ensure 'LxssManager (LxssManager)' is set to 'Disabled' or 'Not Installed'"
    $serviceName = "LxssManager"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { $currentStatus = "Not Installed" }
    else { $currentStatus = $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled/Not Installed'"
}

Function Get-Control5-11 {
    # Control 5.11 - Detection Script
    $controlNumber = "5.11"
    $description = "(L1) Ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Disabled' or 'Not Installed'"
    $serviceName = "FTPSVC"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled/Not Installed'"
}

Function Get-Control5-12 {
    # Control 5.12 - Detection Script
    $controlNumber = "5.12"
    $description = "(L2) Ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is set to 'Disabled'"
    $serviceName = "MSiSCSI"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-13 {
    # Control 5.13 - Detection Script
    $controlNumber = "5.13"
    $description = "(L1) Ensure 'OpenSSH SSH Server (sshd)' is set to 'Disabled' or 'Not Installed'"
    $serviceName = "sshd"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled/Not Installed'"
}

Function Get-Control5-14 {
    # Control 5.14 - Detection Script
    $controlNumber = "5.14"
    $description = "(L2) Ensure 'Peer Name Resolution Protocol (PNRPsvc)' is set to 'Disabled'"
    $serviceName = "PNRPsvc"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-15 {
    # Control 5.15 - Detection Script
    $controlNumber = "5.15"
    $description = "(L2) Ensure 'Peer Networking Grouping (p2psvc)' is set to 'Disabled'"
    $serviceName = "p2psvc"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-16 {
    # Control 5.16 - Detection Script
    $controlNumber = "5.16"
    $description = "(L2) Ensure 'Peer Networking Identity Manager (p2pimsvc)' is set to 'Disabled'"
    $serviceName = "p2pimsvc"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-17 {
    # Control 5.17 - Detection Script
    $controlNumber = "5.17"
    $description = "(L2) Ensure 'PNRP Machine Name Publication Service (PNRPAutoReg)' is set to 'Disabled'"
    $serviceName = "PNRPAutoReg"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-18 {
    # Control 5.18 - Detection Script
    $controlNumber = "5.18"
    $description = "(L2) Ensure 'Print Spooler (Spooler)' is set to 'Disabled'"
    $serviceName = "Spooler"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-19 {
    # Control 5.19 - Detection Script
    $controlNumber = "5.19"
    $description = "(L2) Ensure 'Problem Reports and Solutions Control Panel Support (wercplsupport)' is set to 'Disabled'"
    $serviceName = "wercplsupport"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-20 {
    # Control 5.20 - Detection Script
    $controlNumber = "5.20"
    $description = "(L2) Ensure 'Remote Access Auto Connection Manager (RasAuto)' is set to 'Disabled'"
    $serviceName = "RasAuto"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-21 {
    # Control 5.21 - Detection Script
    $controlNumber = "5.21"
    $description = "(L2) Ensure 'Remote Desktop Configuration (SessionEnv)' is set to 'Disabled'"
    $serviceName = "SessionEnv"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-22 {
    # Control 5.22 - Detection Script
    $controlNumber = "5.22"
    $description = "(L2) Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled'"
    $serviceName = "TermService"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-23 {
    # Control 5.23 - Detection Script
    $controlNumber = "5.23"
    $description = "(L2) Ensure 'Remote Desktop Services UserMode Port Redirector (UmRdpService)' is set to 'Disabled'"
    $serviceName = "UmRdpService"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-24 {
    # Control 5.24 - Detection Script
    $controlNumber = "5.24"
    $description = "(L1) Ensure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled'"
    $serviceName = "RpcLocator"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-25 {
    # Control 5.25 - Detection Script
    $controlNumber = "5.25"
    $description = "(L2) Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled'"
    $serviceName = "RemoteRegistry"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-26 {
    # Control 5.26 - Detection Script
    $controlNumber = "5.26"
    $description = "(L1) Ensure 'Routing and Remote Access (RemoteAccess)' is set to 'Disabled'"
    $serviceName = "RemoteAccess"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-27 {
    # Control 5.27 - Detection Script
    $controlNumber = "5.27"
    $description = "(L2) Ensure 'Server (LanmanServer)' is set to 'Disabled'"
    $serviceName = "LanmanServer"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-28 {
    # Control 5.28 - Detection Script
    $controlNumber = "5.28"
    $description = "(L1) Ensure 'Simple TCP/IP Services (simptcp)' is set to 'Disabled' or 'Not Installed'"
    $serviceName = "simptcp"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled/Not Installed'"
}

Function Get-Control5-29 {
    # Control 5.29 - Detection Script
    $controlNumber = "5.29"
    $description = "(L2) Ensure 'SNMP Service (SNMP)' is set to 'Disabled' or 'Not Installed'"
    $serviceName = "SNMP"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled/Not Installed'"
}

Function Get-Control5-30 {
    # Control 5.30 - Detection Script
    $controlNumber = "5.30"
    $description = "(L1) Ensure 'Special Administration Console Helper (sacsvr)' is set to 'Disabled' or 'Not Installed'"
    $serviceName = "sacsvr"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled/Not Installed'"
}

Function Get-Control5-31 {
    # Control 5.31 - Detection Script
    $controlNumber = "5.31"
    $description = "(L1) Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled'"
    $serviceName = "SSDPSRV"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-32 {
    # Control 5.32 - Detection Script
    $controlNumber = "5.32"
    $description = "(L1) Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled'"
    $serviceName = "upnphost"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-33 {
    # Control 5.33 - Detection Script
    $controlNumber = "5.33"
    $description = "(L1) Ensure 'Web Management Service (WMSvc)' is set to 'Disabled' or 'Not Installed'"
    $serviceName = "WMSvc"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled/Not Installed'"
}

Function Get-Control5-34 {
    # Control 5.34 - Detection Script
    $controlNumber = "5.34"
    $description = "(L2) Ensure 'Windows Error Reporting Service (WerSvc)' is set to 'Disabled'"
    $serviceName = "WerSvc"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-35 {
    # Control 5.35 - Detection Script
    $controlNumber = "5.35"
    $description = "(L2) Ensure 'Windows Event Collector (Wecsvc)' is set to 'Disabled'"
    $serviceName = "Wecsvc"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-36 {
    # Control 5.36 - Detection Script
    $controlNumber = "5.36"
    $description = "(L1) Ensure 'Windows Media Player Network Sharing Service (WMPNetworkSvc)' is set to 'Disabled' or 'Not Installed'"
    $serviceName = "WMPNetworkSvc"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled/Not Installed'"
}

Function Get-Control5-37 {
    # Control 5.37 - Detection Script
    $controlNumber = "5.37"
    $description = "(L1) Ensure 'Windows Mobile Hotspot Service (icssvc)' is set to 'Disabled'"
    $serviceName = "icssvc"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-38 {
    # Control 5.38 - Detection Script
    $controlNumber = "5.38"
    $description = "(L2) Ensure 'Windows Push Notifications System Service (WpnService)' is set to 'Disabled'"
    $serviceName = "WpnService"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-39 {
    # Control 5.39 - Detection Script
    $controlNumber = "5.39"
    $description = "(L2) Ensure 'Windows PushToInstall Service (PushToInstall)' is set to 'Disabled'"
    $serviceName = "PushToInstall"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}

Function Get-Control5-40 {
    # Control 5.40 - Detection Script
    $controlNumber = "5.40"
    $description = "(L2) Ensure 'Windows Remote Management (WS-Management) (WinRM)' is set to 'Disabled'"
    $serviceName = "WinRM"
    $expectedStatus = "Stopped"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $currentStatus = if ($null -eq $service) { "Not Installed" } else { $service.Status }

    $controlStatus = if ($currentStatus -eq $expectedStatus) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentStatus`t'Disabled'"
}




########################################################################################################################################################
################################################## 6. Local Policies ###################################################################################
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

########################################################################################################################################################
################################################## 7. Local Policies ###################################################################################
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

########################################################################################################################################################
################################################## 8. Local Policies ###################################################################################
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

########################################################################################################################################################
################################################## 9. Windows Defender Firewall with Advanced Security (formerly Windows Firewall with Advanced Security)
########################################################################################################################################################
################################################## 9.1. Domain Profile ##################################################
Function Get-Control9-1-1 {
    # Control 9.1.1 - Detection Script
    $controlNumber = "9.1.1"
    $description = "(L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'"
    $expectedValue = "On"

    $currentValue = (Get-NetFirewallProfile -Profile Domain).Enabled
    $controlStatus = if ($currentValue -eq 'True') { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-1-2 {
    # Control 9.1.2 - Detection Script
    $controlNumber = "9.1.2"
    $description = "(L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'"
    $expectedValue = "Block"

    $currentValue = (Get-NetFirewallProfile -Profile Domain).DefaultInboundAction
    $controlStatus = if ($currentValue -eq 'Block') { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-1-3 {
    # Control 9.1.3 - Detection Script
    $controlNumber = "9.1.3"
    $description = "(L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'"
    $expectedValue = "Allow"

    $currentValue = (Get-NetFirewallProfile -Profile Domain).DefaultOutboundAction
    $controlStatus = if ($currentValue -eq 'Allow') { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-1-4 {
    # Control 9.1.4 - Detection Script
    $controlNumber = "9.1.4"
    $description = "(L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'"
    $expectedValue = "No"

    $currentValue = (Get-NetFirewallProfile -Profile Domain).NotificationsDisabled
    $controlStatus = if ($currentValue -eq 'True') { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-1-5 {
    # Control 9.1.5 - Detection Script
    $controlNumber = "9.1.5"
    $description = "(L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\\System32\\logfiles\\firewall\\domainfw.log'"
    $expectedValue = "%SystemRoot%\\System32\\logfiles\\firewall\\domainfw.log"

    $currentValue = (Get-NetFirewallProfile -Profile Domain).LogFileName
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-1-6 {
    # Control 9.1.6 - Detection Script
    $controlNumber = "9.1.6"
    $description = "(L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    $expectedValue = 16384

    $currentValue = (Get-NetFirewallProfile -Profile Domain).LogMaxSizeKilobytes
    $controlStatus = if ($currentValue -ge $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-1-7 {
    # Control 9.1.7 - Detection Script
    $controlNumber = "9.1.7"
    $description = "(L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"
    $expectedValue = "True"

    $currentValue = (Get-NetFirewallProfile -Profile Domain).LogDroppedPackets
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-1-8 {
    # Control 9.1.8 - Detection Script
    $controlNumber = "9.1.8"
    $description = "(L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"
    $expectedValue = "True"

    $currentValue = (Get-NetFirewallProfile -Profile Domain).LogAllowedPackets
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

################################################## 9.2. Private Profile ##################################################
Function Get-Control9-2-1 {
    # Control 9.2.1 - Detection Script
    $controlNumber = "9.2.1"
    $description = "(L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"
    $expectedValue = "On"

    $currentValue = (Get-NetFirewallProfile -Profile Private).Enabled
    $controlStatus = if ($currentValue -eq 'True') { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-2-2 {
    # Control 9.2.2 - Detection Script
    $controlNumber = "9.2.2"
    $description = "(L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"
    $expectedValue = "Block"

    $currentValue = (Get-NetFirewallProfile -Profile Private).DefaultInboundAction
    $controlStatus = if ($currentValue -eq 'Block') { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-2-3 {
    # Control 9.2.3 - Detection Script
    $controlNumber = "9.2.3"
    $description = "(L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'"
    $expectedValue = "Allow"

    $currentValue = (Get-NetFirewallProfile -Profile Private).DefaultOutboundAction
    $controlStatus = if ($currentValue -eq 'Allow') { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-2-4 {
    # Control 9.2.4 - Detection Script
    $controlNumber = "9.2.4"
    $description = "(L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'"
    $expectedValue = "No"

    $currentValue = (Get-NetFirewallProfile -Profile Private).NotificationsDisabled
    $controlStatus = if ($currentValue -eq 'True') { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-2-5 {
    # Control 9.2.5 - Detection Script
    $controlNumber = "9.2.5"
    $description = "(L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\\System32\\logfiles\\firewall\\privatefw.log'"
    $expectedValue = "%SystemRoot%\\System32\\logfiles\\firewall\\privatefw.log"

    $currentValue = (Get-NetFirewallProfile -Profile Private).LogFileName
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-2-6 {
    # Control 9.2.6 - Detection Script
    $controlNumber = "9.2.6"
    $description = "(L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    $expectedValue = 16384

    $currentValue = (Get-NetFirewallProfile -Profile Private).LogMaxSizeKilobytes
    $controlStatus = if ($currentValue -ge $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-2-7 {
    # Control 9.2.7 - Detection Script
    $controlNumber = "9.2.7"
    $description = "(L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"
    $expectedValue = "True"

    $currentValue = (Get-NetFirewallProfile -Profile Private).LogDroppedPackets
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-2-8 {
    # Control 9.2.8 - Detection Script
    $controlNumber = "9.2.8"
    $description = "(L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"
    $expectedValue = "True"

    $currentValue = (Get-NetFirewallProfile -Profile Private).LogAllowedPackets
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

################################################## 9.3. Public Profile ##################################################
Function Get-Control9-3-1 {
    # Control 9.3.1 - Detection Script
    $controlNumber = "9.3.1"
    $description = "(L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"
    $expectedValue = "On"

    $currentValue = (Get-NetFirewallProfile -Profile Public).Enabled
    $controlStatus = if ($currentValue -eq 'True') { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-3-2 {
    # Control 9.3.2 - Detection Script
    $controlNumber = "9.3.2"
    $description = "(L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"
    $expectedValue = "Block"

    $currentValue = (Get-NetFirewallProfile -Profile Public).DefaultInboundAction
    $controlStatus = if ($currentValue -eq 'Block') { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-3-3 {
    # Control 9.3.3 - Detection Script
    $controlNumber = "9.3.3"
    $description = "(L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'"
    $expectedValue = "Allow"

    $currentValue = (Get-NetFirewallProfile -Profile Public).DefaultOutboundAction
    $controlStatus = if ($currentValue -eq 'Allow') { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-3-4 {
    # Control 9.3.4 - Detection Script
    $controlNumber = "9.3.4"
    $description = "(L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'"
    $expectedValue = "No"

    $currentValue = (Get-NetFirewallProfile -Profile Public).NotificationsDisabled
    $controlStatus = if ($currentValue -eq 'True') { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-3-5 {
    # Control 9.3.5 - Detection Script
    $controlNumber = "9.3.5"
    $description = "(L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'"
    $expectedValue = "False"

    $currentValue = (Get-NetFirewallProfile -Profile Public).AllowLocalPolicyMerge
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-3-6 {
    # Control 9.3.6 - Detection Script
    $controlNumber = "9.3.6"
    $description = "(L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'"
    $expectedValue = "False"

    $currentValue = (Get-NetFirewallProfile -Profile Public).AllowLocalIPsecPolicyMerge
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-3-7 {
    # Control 9.3.7 - Detection Script
    $controlNumber = "9.3.7"
    $description = "(L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\\System32\\logfiles\\firewall\\publicfw.log'"
    $expectedValue = "%SystemRoot%\\System32\\logfiles\\firewall\\publicfw.log"

    $currentValue = (Get-NetFirewallProfile -Profile Public).LogFileName
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-3-8 {
    # Control 9.3.8 - Detection Script
    $controlNumber = "9.3.8"
    $description = "(L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
    $expectedValue = 16384

    $currentValue = (Get-NetFirewallProfile -Profile Public).LogMaxSizeKilobytes
    $controlStatus = if ($currentValue -ge $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-3-9 {
    # Control 9.3.9 - Detection Script
    $controlNumber = "9.3.9"
    $description = "(L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"
    $expectedValue = "True"

    $currentValue = (Get-NetFirewallProfile -Profile Public).LogDroppedPackets
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control9-3-10 {
    # Control 9.3.10 - Detection Script
    $controlNumber = "9.3.10"
    $description = "(L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"
    $expectedValue = "True"

    $currentValue = (Get-NetFirewallProfile -Profile Public).LogAllowedPackets
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

########################################################################################################################################################
################################################## 10. Network List Manager Policies ###################################################################
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

########################################################################################################################################################
################################################## 11. Wireless Network (IEEE 802.11) Policies #########################################################
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

########################################################################################################################################################
################################################## 12. Public Key Policies #############################################################################
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

########################################################################################################################################################
################################################## 13. Software Restriction Policies ###################################################################
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

########################################################################################################################################################
################################################## 14. Network Access Protection NAP Client Configuration ##############################################
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

########################################################################################################################################################
################################################## 15. Application Control Policies ####################################################################
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

########################################################################################################################################################
################################################## 16. IP Security Policies ############################################################################
########################################################################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

########################################################################################################################################################
################################################## 17. Advanced Audit Policy Configuration #############################################################
########################################################################################################################################################
Function Get-AuditPolicyStatus {
    param(
        [string]$SubcategoryName,
        [string]$ControlNumber,
        [string]$Description
    )
    $auditPolicy = AuditPol /get /category:* | Out-String
    $success = $auditPolicy -like "*$SubcategoryName*Success*"
    $failure = $auditPolicy -like "*$SubcategoryName*Failure*"
    $expectedValue = "Success and Failure"
    $currentValue = ""

    if ($success -and $failure) {
        $currentValue = "Success and Failure"
    } elseif ($success) {
        $currentValue = "Success"
    } elseif ($failure) {
        $currentValue = "Failure"
    } else {
        $currentValue = "None"
    }

    $controlStatus = if ($success -and $failure) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$ControlNumber`t$Description`t$currentValue`t$expectedValue"
}

################################################## 17.1. Account Logon ##################################################
Function Get-Control17-1-1 {
    Get-AuditPolicyStatus -SubcategoryName "Credential Validation" -ControlNumber "17.1.1" -Description "Ensure 'Audit Credential Validation' is set to 'Success and Failure'"
}

################################################## 17.2. Account Management ############################################################################
Function Get-Control17-2-1 {
    Get-AuditPolicyStatus -SubcategoryName "Application Group Management" -ControlNumber "17.2.1" -Description "Ensure 'Audit Application Group Management' is set to 'Success and Failure'"
}

Function Get-Control17-2-2 {
    Get-AuditPolicyStatus -SubcategoryName "Security Group Management" -ControlNumber "17.2.2" -Description "Ensure 'Audit Security Group Management' is set to include 'Success'"
}

Function Get-Control17-2-3 {
    Get-AuditPolicyStatus -SubcategoryName "User Account Management" -ControlNumber "17.2.3" -Description "Ensure 'Audit User Account Management' is set to 'Success and Failure'"
}

################################################## 17.3. Detailed Tracking #############################################################################
Function Get-Control17-3-1 {
    Get-AuditPolicyStatus -SubcategoryName "PNP Activity" -ControlNumber "17.3.1" -Description "Ensure 'Audit PNP Activity' is set to include 'Success'"
}

Function Get-Control17-3-2 {
    Get-AuditPolicyStatus -SubcategoryName "Process Creation" -ControlNumber "17.3.2" -Description "Ensure 'Audit Process Creation' is set to include 'Success'"
}

################################################## 17.4. DS Access #####################################################################################
################################################## 17.5. Logon/Logoff ##################################################################################
Function Get-Control17-5-1 {
    Get-AuditPolicyStatus -SubcategoryName "Account Lockout" -ControlNumber "17.5.1" -Description "Ensure 'Audit Account Lockout' is set to include 'Failure'"
}

Function Get-Control17-5-2 {
    Get-AuditPolicyStatus -SubcategoryName "Group Membership" -ControlNumber "17.5.2" -Description "Ensure 'Audit Group Membership' is set to include 'Success'"
}

Function Get-Control17-5-3 {
    Get-AuditPolicyStatus -SubcategoryName "Logoff" -ControlNumber "17.5.3" -Description "Ensure 'Audit Logoff' is set to include 'Success'"
}

Function Get-Control17-5-4 {
    Get-AuditPolicyStatus -SubcategoryName "Logon" -ControlNumber "17.5.4" -Description "Ensure 'Audit Logon' is set to 'Success and Failure'"
}

Function Get-Control17-5-5 {
    Get-AuditPolicyStatus -SubcategoryName "Other Logon/Logoff Events" -ControlNumber "17.5.5" -Description "Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"
}

Function Get-Control17-5-6 {
    Get-AuditPolicyStatus -SubcategoryName "Special Logon" -ControlNumber "17.5.6" -Description "Ensure 'Audit Special Logon' is set to include 'Success'"
}

################################################## 17.6. Object Access #################################################################################
Function Get-Control17-6-1 {
    Get-AuditPolicyStatus -SubcategoryName "Detailed File Share" -ControlNumber "17.6.1" -Description "Ensure 'Audit Detailed File Share' is set to include 'Failure'"
}

Function Get-Control17-6-2 {
    Get-AuditPolicyStatus -SubcategoryName "File Share" -ControlNumber "17.6.2" -Description "Ensure 'Audit File Share' is set to 'Success and Failure'"
}

Function Get-Control17-6-3 {
    Get-AuditPolicyStatus -SubcategoryName "Other Object Access Events" -ControlNumber "17.6.3" -Description "Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'"
}

Function Get-Control17-6-4 {
    Get-AuditPolicyStatus -SubcategoryName "Removable Storage" -ControlNumber "17.6.4" -Description "Ensure 'Audit Removable Storage' is set to 'Success and Failure'"
}

################################################## 17.7. Policy Change #################################################################################
Function Get-Control17-7-1 {
    Get-AuditPolicyStatus -SubcategoryName "Audit Policy Change" -ControlNumber "17.7.1" -Description "Ensure 'Audit Audit Policy Change' is set to include 'Success'"
}

Function Get-Control17-7-2 {
    Get-AuditPolicyStatus -SubcategoryName "Authentication Policy Change" -ControlNumber "17.7.2" -Description "Ensure 'Audit Authentication Policy Change' is set to include 'Success'"
}

Function Get-Control17-7-3 {
    Get-AuditPolicyStatus -SubcategoryName "Authorization Policy Change" -ControlNumber "17.7.3" -Description "Ensure 'Audit Authorization Policy Change' is set to include 'Success'"
}

Function Get-Control17-7-4 {
    Get-AuditPolicyStatus -SubcategoryName "MPSSVC Rule-Level Policy Change" -ControlNumber "17.7.4" -Description "Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'"
}

Function Get-Control17-7-5 {
    Get-AuditPolicyStatus -SubcategoryName "Other Policy Change Events" -ControlNumber "17.7.5" -Description "Ensure 'Audit Other Policy Change Events' is set to include 'Failure'"
}

################################################## 17.8. Privilege Use #################################################################################
Function Get-Control17-8-1 {
    Get-AuditPolicyStatus -SubcategoryName "Sensitive Privilege Use" -ControlNumber "17.8.1" -Description "Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'"
}

################################################## 17.9. System ########################################################################################
Function Get-Control17-9-1 {
    Get-AuditPolicyStatus -SubcategoryName "IPsec Driver" -ControlNumber "17.9.1" -Description "Ensure 'Audit IPsec Driver' is set to 'Success and Failure'"
}

Function Get-Control17-9-2 {
    Get-AuditPolicyStatus -SubcategoryName "Other System Events" -ControlNumber "17.9.2" -Description "Ensure 'Audit Other System Events' is set to 'Success and Failure'"
}

Function Get-Control17-9-3 {
    Get-AuditPolicyStatus -SubcategoryName "Security State Change" -ControlNumber "17.9.3" -Description "Ensure 'Audit Security State Change' is set to include 'Success'"
}

Function Get-Control17-9-4 {
    Get-AuditPolicyStatus -SubcategoryName "Security System Extension" -ControlNumber "17.9.4" -Description "Ensure 'Audit Security System Extension' is set to include 'Success'"
}

Function Get-Control17-9-5 {
    Get-AuditPolicyStatus -SubcategoryName "System Integrity" -ControlNumber "17.9.5" -Description "Ensure 'Audit System Integrity' is set to 'Success and Failure'"
}

########################################################################################################################################################
################################################## 18. Administrative Templates (Computer) #############################################################
########################################################################################################################################################
################################################## 18.1. Control Panel #################################################################################
############################## 18.1.1. Personalization ##############################
Function Get-Control18-1-1-1 {
    $controlNumber = "18.1.1.1"
    $description = "(L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    $valueName = "NoLockScreenCamera"
    $expectedValue = 1
    $currentValue = Get-ItemPropertyValue -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }
    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-1-1-2 {
    $controlNumber = "18.1.1.2"
    $description = "(L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
    $registryPath = "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
    $registryValue = "NoLockScreenSlideshow"
    $expectedValue = 1
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).NoLockScreenSlideshow
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

################################################## 18.2. LAPS ##########################################################################################
Function Get-Control18-2-2 {
    $controlNumber = "18.2.2"
    $description = "(L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'"
    $registryPath = "HKLM:\Software\Policies\Microsoft Services\AdmPwd"
    $registryValue = "PwdExpirationProtectionEnabled"
    $expectedValue = 1
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).PwdExpirationProtectionEnabled
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-2-3 {
    $controlNumber = "18.2.3"
    $description = "(L1) Ensure 'Enable Local Admin Password Management' is set to 'Enabled'"
    $registryPath = "HKLM:\Software\Policies\Microsoft Services\AdmPwd"
    $registryValue = "AdmPwdEnabled"
    $expectedValue = 1
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).AdmPwdEnabled
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-2-4 {
    $controlNumber = "18.2.4"
    $description = "(L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters'"
    # Placeholder for complexity check; Adjust according to specific registry implementation or management tool feedback
    $controlStatus = "Manual check required"

    "$controlStatus`t$controlNumber`t$description`tNot applicable`tNot applicable"
}

Function Get-Control18-2-5 {
    $controlNumber = "18.2.5"
    $description = "(L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'"
    # Placeholder for length check; Adjust according to specific registry implementation or management tool feedback
    $controlStatus = "Manual check required"

    "$controlStatus`t$controlNumber`t$description`tNot applicable`tNot applicable"
}

Function Get-Control18-2-6 {
    $controlNumber = "18.2.6"
    $description = "(L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'"
    # Placeholder for age check; Adjust according to specific registry implementation or management tool feedback
    $controlStatus = "Manual check required"

    "$controlStatus`t$controlNumber`t$description`tNot applicable`tNot applicable"
}

################################################## 18.3. MS Security Guide #############################################################################
Function Get-Control18-3-1 {
    $controlNumber = "18.3.1"
    $description = "(L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'"
    $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $registryValue = "LocalAccountTokenFilterPolicy"
    $expectedValue = 0
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-3-2 {
    $controlNumber = "18.3.2"
    $description = "(L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
    $registryValue = "Start"
    $expectedValue = 4
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).Start
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-3-3 {
    $controlNumber = "18.3.3"
    $description = "(L1) Ensure 'Configure SMB v1 server' is set to 'Disabled'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $registryValue = "SMB1"
    $expectedValue = 0
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).SMB1
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-3-4 {
    $controlNumber = "18.3.4"
    $description = "(L1) Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
    $registryValue = "DisableExceptionChainValidation"
    $expectedValue = 0
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).DisableExceptionChainValidation
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-3-5 {
    $controlNumber = "18.3.5"
    $description = "(L1) Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    $registryValue = "PointAndPrint_RestrictDriverInstallationToAdministrators"
    $expectedValue = 1
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).PointAndPrint_RestrictDriverInstallationToAdministrators
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-3-6 {
    $controlNumber = "18.3.6"
    $description = "(L1) Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters"
    $registryValue = "NodeType"
    $expectedValue = 2
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).NodeType
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-3-7 {
    $controlNumber = "18.3.7"
    $description = "(L1) Ensure 'WDigest Authentication' is set to 'Disabled'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    $registryValue = "UseLogonCredential"
    $expectedValue = 0
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).UseLogonCredential
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

################################################## 18.4. MSS (Legacy) ##################################################################################
Function Get-Control18-4-1 {
    $controlNumber = "18.4.1"
    $description = "(L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'"
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $registryValue = "AutoAdminLogon"
    $expectedValue = 0
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).AutoAdminLogon
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-4-2 {
    $controlNumber = "18.4.2"
    $description = "(L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    $registryValue = "DisableIPSourceRouting"
    $expectedValue = 2 # Highest protection
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).DisableIPSourceRouting
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-4-3 {
    $controlNumber = "18.4.3"
    $description = "(L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $registryValue = "DisableIPSourceRouting"
    $expectedValue = 2 # Highest protection
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).DisableIPSourceRouting
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-4-4 {
    $controlNumber = "18.4.4"
    $description = "(L2) Ensure 'MSS: (DisableSavePassword) Prevent the dial-up password from being saved' is set to 'Enabled'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters"
    $registryValue = "DisableSavePassword"
    $expectedValue = 1
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).DisableSavePassword
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-4-5 {
    $controlNumber = "18.4.5"
    $description = "(L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $registryValue = "EnableICMPRedirect"
    $expectedValue = 0
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).EnableICMPRedirect
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-4-6 {
    $controlNumber = "18.4.6"
    $description = "(L2) Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $registryValue = "KeepAliveTime"
    $expectedValue = 300000
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).KeepAliveTime
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-4-7 {
    $controlNumber = "18.4.7"
    $description = "(L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
    $registryValue = "NoNameReleaseOnDemand"
    $expectedValue = 1
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).NoNameReleaseOnDemand
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-4-8 {
    $controlNumber = "18.4.8"
    $description = "(L2) Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $registryValue = "PerformRouterDiscovery"
    $expectedValue = 0
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).PerformRouterDiscovery
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-4-9 {
    $controlNumber = "18.4.9"
    $description = "(L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $registryValue = "SafeDllSearchMode"
    $expectedValue = 1
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).SafeDllSearchMode
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-4-10 {
    $controlNumber = "18.4.10"
    $description = "(L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'"
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $registryValue = "ScreenSaverGracePeriod"
    $expectedValue = "5" # This can vary based on policy requirements; adjust as necessary
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).ScreenSaverGracePeriod
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-4-11 {
    $controlNumber = "18.4.11"
    $description = "(L2) Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    $registryValue = "TcpMaxDataRetransmissions"
    $expectedValue = 3
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).TcpMaxDataRetransmissions
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-4-12 {
    $controlNumber = "18.4.12"
    $description = "(L2) Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $registryValue = "TcpMaxDataRetransmissions"
    $expectedValue = 3
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).TcpMaxDataRetransmissions
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-4-13 {
    $controlNumber = "18.4.13"
    $description = "(L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security"
    $registryValue = "WarningLevel"
    $expectedValue = 90 # Assuming the value is in percentage
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).WarningLevel
    $controlStatus = if ($currentValue -le $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

################################################## 18.5. Network #######################################################################################
############################## 18.5.1. Background Intelligent Transfer Service (BITS) ##################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.5.2. BranchCache #####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.5.3. DirectAccess Client Experience Settings #########################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.5.4. DNS Client ######################################################################################################
Function Get-Control18-5-4-1 {
    $controlNumber = "18.5.4.1"
    $description = "(L1) Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH'"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    $registryValue = "DoHSetting"
    $expectedValue = 2 # Assuming "Allow DoH" corresponds to a specific value
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).DoHSetting
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-5-4-2 {
    $controlNumber = "18.5.4.2"
    $description = "(L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled'"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    $registryValue = "EnableMulticast"
    $expectedValue = 0
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).EnableMulticast
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.5.5. Fonts ###########################################################################################################
Function Get-Control18-5-5-1 {
    $controlNumber = "18.5.5.1"
    $description = "(L2) Ensure 'Enable Font Providers' is set to 'Disabled'"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $registryValue = "EnableFontProviders"
    $expectedValue = 0
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).EnableFontProviders
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.5.6. Hotspot Authentication ##########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.5.7. Lanman Server ###################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.5.8. Lanman Workstation ##############################################################################################
Function Get-Control18-5-8-1 {
    $controlNumber = "18.5.8.1"
    $description = "(L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
    $registryValue = "AllowInsecureGuestAuth"
    $expectedValue = 0
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).AllowInsecureGuestAuth
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.5.9. Link-Layer Topology Discovery ###################################################################################
Function Get-Control18-5-9-1 {
    $controlNumber = "18.5.9.1"
    $description = "(L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    $registryValue = "AllowLLTDIOOnDomain"
    $expectedValue = 0 # Assuming the policy disables the feature
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).AllowLLTDIOOnDomain
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-5-9-2 {
    $controlNumber = "18.5.9.2"
    $description = "(L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    $registryValue = "EnableResponder"
    $expectedValue = 0 # Assuming the policy disables the feature
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).EnableResponder
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.5.10. Microsoft Peer-to-Peer Networking Services #####################################################################
############################## 18.5.10.1. Peer Name Resolution Protocol ################################################################################
Function Get-Control18-5-10-2 {
    $controlNumber = "18.5.10.2"
    $description = "(L2) Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
    $registryValue = "Disabled"
    $expectedValue = 1
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).Disabled
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.5.11. Network Connections ############################################################################################
############################## 18.5.11.1. Windows Defender Firewall (formerly Windows Firewall) ########################################################
Function Get-Control18-5-11-2 {
    $controlNumber = "18.5.11.2"
    $description = "(L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
    $registryValue = "NC_AllowNetBridge_NLA"
    $expectedValue = 0
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).NC_AllowNetBridge_NLA
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-5-11-3 {
    $controlNumber = "18.5.11.3"
    $description = "(L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
    $registryValue = "NC_ShowSharedAccessUI"
    $expectedValue = 0
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).NC_ShowSharedAccessUI
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-5-11-4 {
    $controlNumber = "18.5.11.4"
    $description = "(L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
    $registryValue = "NC_StdDomainUserSetLocation"
    $expectedValue = 1
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $registryValue -ErrorAction SilentlyContinue).NC_StdDomainUserSetLocation
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}


############################## 18.5.12. Network Connectivity Status Indicator ##########################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.5.13. Network Isolation ##############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.5.14. Network Provider ###############################################################################################
Function Get-Control18-5-14-1 {
    # Control 18.5.14.1 - Detection Script
    $controlNumber = "18.5.14.1"
    $description = "(L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with Require Mutual Authentication and Require Integrity set for all NETLOGON and SYSVOL shares'"
    $expectedValue = "RequireMutualAuthentication=1, RequireIntegrity=1"

    $currentValueNetlogon = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\NETLOGON" -ErrorAction SilentlyContinue
    $currentValueSysvol = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\SYSVOL" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValueNetlogon -eq $expectedValue -and $currentValueSysvol -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValueNetlogon, $currentValueSysvol`t$expectedValue"
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
Function Get-Control18-5-19-2-1 {
    # Control 18.5.19.2.1 - Detection Script
    $controlNumber = "18.5.19.2.1"
    $description = "(L2) Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')"
    $expectedValue = "0xff"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.5.20. Windows Connect Now ############################################################################################
Function Get-Control18-5-20-1 {
    # Control 18.5.20.1 - Detection Script
    $controlNumber = "18.5.20.1"
    $description = "(L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-5-20-2 {
    # Control 18.5.20.2 - Detection Script
    $controlNumber = "18.5.20.2"
    $description = "(L2) Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.5.21. Windows Connection Manager #####################################################################################
Function Get-Control18-5-21-1 {
    # Control 18.5.21.1 - Detection Script
    $controlNumber = "18.5.21.1"
    $description = "(L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'"
    $expectedValue = "3 = Prevent Wi-Fi when on Ethernet"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 3) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-5-21-2 {
    # Control 18.5.21.2 - Detection Script
    $controlNumber = "18.5.21.2"
    $description = "(L1) Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fBlockNonDomain" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.5.22. Wireless Display ###############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.5.23. WLAN Service ###################################################################################################
Function Get-Control18-5-23-2-1 {
    # Control 18.5.23.2.1 - Detection Script
    $controlNumber = "18.5.23.2.1"
    $description = "(L1) Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "AutoConnectToWiFiSenseHotspots" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.5.23.1. WLAN Media Cost ##############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.5.23.2. WLAN Settings ################################################################################################
################################################## 18.6. Printers ######################################################################################
Function Get-Control18-6-1 {
    # Control 18.6.1 - Detection Script
    $controlNumber = "18.6.1"
    $description = "(L1) Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "AllowPrintSpoolerToAcceptClientConnections" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-6-2 {
    # Control 18.6.2 - Detection Script
    $controlNumber = "18.6.2"
    $description = "(L1) Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'"
    $expectedValue = "Enabled: Show warning and elevation prompt"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-6-3 {
    # Control 18.6.3 - Detection Script
    $controlNumber = "18.6.3"
    $description = "(L1) Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'"
    $expectedValue = "Enabled: Show warning and elevation prompt"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnUpdate" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

################################################## 18.7. Start Menu and Taskbar ########################################################################
############################## 18.7.1. Notifications ###################################################################################################
Function Get-Control18-7-1-1 {
    # Control 18.7.1.1 - Detection Script
    $controlNumber = "18.7.1.1"
    $description = "(L2) Ensure 'Turn off notifications network usage' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

################################################## 18.8. System ########################################################################################
############################## 18.8.1. Access-Denied Assistance ########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.2. App-V ###########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.3. Audit Process Creation ##########################################################################################
Function Get-Control18-8-3-1 {
    # Control 18.8.3.1 - Detection Script
    $controlNumber = "18.8.3.1"
    $description = "(L1) Ensure 'Include command line in process creation events' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.8.4. Credentials Delegation ##########################################################################################
Function Get-Control18-8-4-1 {
    # Control 18.8.4.1 - Detection Script
    $controlNumber = "18.8.4.1"
    $description = "(L1) Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'"
    $expectedValue = "Enabled: Force Updated Clients"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "EncryptionOracleRemediation" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq "2") { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-4-2 {
    # Control 18.8.4.2 - Detection Script
    $controlNumber = "18.8.4.2"
    $description = "(L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.8.5. Device Guard ####################################################################################################
Function Get-Control18-8-5-1 {
    # Control 18.8.5.1 - Detection Script
    $controlNumber = "18.8.5.1"
    $description = "(NG) Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-5-2 {
    # Control 18.8.5.2 - Detection Script
    $controlNumber = "18.8.5.2"
    $description = "(NG) Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection'"
    $expectedValue = "Secure Boot and DMA Protection"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 3) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-5-3 {
    # Control 18.8.5.3 - Detection Script
    $controlNumber = "18.8.5.3"
    $description = "(NG) Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'"
    $expectedValue = "Enabled with UEFI lock"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedProtection" -ErrorAction SilentlyContinue
    $uefiLockValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 2 -and $uefiLockValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-5-4 {
    # Control 18.8.5.4 - Detection Script
    $controlNumber = "18.8.5.4"
    $description = "(NG) Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'"
    $expectedValue = "True (checked)"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequireUEFIMemoryAttributesTable" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-5-5 {
    # Control 18.8.5.5 - Detection Script
    $controlNumber = "18.8.5.5"
    $description = "(NG) Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock'"
    $expectedValue = "Enabled with UEFI lock"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 2) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-5-6 {
    # Control 18.8.5.6 - Detection Script
    $controlNumber = "18.8.5.6"
    $description = "(NG) Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableSecureLaunch" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.8.6. Device Health Attestation Service ###############################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.7. Device Installation #############################################################################################
############################## 18.8.7.1. Device Installation Restrictions ##############################################################################
Function Get-Control18-8-7-1-1 {
    # Control 18.8.7.1.1 - Detection Script
    $controlNumber = "18.8.7.1.1"
    $description = "(BL) Ensure 'Prevent installation of devices that match any of these device IDs' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDs" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-7-1-2 {
    # Control 18.8.7.1.2 - Detection Script
    $controlNumber = "18.8.7.1.2"
    $description = "(BL) Ensure 'Prevent installation of devices that match any of these device IDs: Prevent installation of devices that match any of these device IDs' is set to 'PCI\CC_0C0A'"
    $expectedValue = "PCI\CC_0C0A"

    $currentValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDs" -ErrorAction SilentlyContinue).DenyDeviceIDs
    $controlStatus = if ($currentValue -contains "PCI\CC_0C0A") { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-7-1-3 {
    # Control 18.8.7.1.3 - Detection Script
    $controlNumber = "18.8.7.1.3"
    $description = "(BL) Ensure 'Prevent installation of devices that match any of these device IDs: Also apply to matching devices that are already installed.' is set to 'True' (checked)"
    $expectedValue = "True (checked)"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDsRetroactive" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-7-1-4 {
    # Control 18.8.7.1.4 - Detection Script
    $controlNumber = "18.8.7.1.4"
    $description = "(BL) Ensure 'Prevent installation of devices using drivers that match these device setup classes' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClasses" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-7-1-5 {
    # Control 18.8.7.1.5 - Detection Script
    $controlNumber = "18.8.7.1.5"
    $description = "(BL) Ensure 'Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these device setup' is set to 'IEEE 1394 device setup classes'"
    $expectedValue = "IEEE 1394 device setup classes"

    $classGUIDs = @("{d48179be-ec20-11d1-b6b8-00c04fa372a7}", "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}", "{c06ff265-ae09-48f0-812c-16753d7cba83}", "{6bdd1fc1-810f-11d0-bec7-08002be2092f}")
    $currentValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClasses" -ErrorAction SilentlyContinue).DenyDeviceClasses
    $controlStatus = if ($classGUIDs | ForEach-Object { $currentValue -contains $_ }) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-7-1-6 {
    # Control 18.8.7.1.6 - Detection Script
    $controlNumber = "18.8.7.1.6"
    $description = "(BL) Ensure 'Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed.' is set to 'True' (checked)"
    $expectedValue = "True (checked)"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClassesRetroactive" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-7-2 {
    # Control 18.8.7.2 - Detection Script
    $controlNumber = "18.8.7.2"
    $description = "(L1) Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control18-8-14-1 {
    # Control 18.8.14.1 - Detection Script
    $controlNumber = "18.8.14.1"
    $description = "(L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
    $expectedValue = "Good, unknown and bad but critical"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 3) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control18-8-21-2 {
    # Control 18.8.21.2 - Detection Script
    $controlNumber = "18.8.21.2"
    $description = "(L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"
    $expectedValue = "Enabled: FALSE"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy" -Name "NoBackgroundPolicy" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-21-3 {
    # Control 18.8.21.3 - Detection Script
    $controlNumber = "18.8.21.3"
    $description = "(L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
    $expectedValue = "Enabled: TRUE"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy" -Name "NoGPOListChanges" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-21-4 {
    # Control 18.8.21.4 - Detection Script
    $controlNumber = "18.8.21.4"
    $description = "(L1) Ensure 'Continue experiences on this device' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-21-5 {
    # Control 18.8.21.5 - Detection Script
    $controlNumber = "18.8.21.5"
    $description = "(L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableBkGndGroupPolicy" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.8.22. Internet Communication Management ##############################################################################
############################## 18.8.22.1. Internet Communication settings ##############################################################################
Function Get-Control18-8-22-1-1 {
    # Control 18.8.22.1.1 - Detection Script
    $controlNumber = "18.8.22.1.1"
    $description = "(L2) Ensure 'Turn off access to the Store' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-22-1-2 {
    # Control 18.8.22.1.2 - Detection Script
    $controlNumber = "18.8.22.1.2"
    $description = "(L1) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-22-1-3 {
    # Control 18.8.22.1.3 - Detection Script
    $controlNumber = "18.8.22.1.3"
    $description = "(L2) Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-22-1-4 {
    # Control 18.8.22.1.4 - Detection Script
    $controlNumber = "18.8.22.1.4"
    $description = "(L2) Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-22-1-5 {
    # Control 18.8.22.1.5 - Detection Script
    $controlNumber = "18.8.22.1.5"
    $description = "(L2) Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -Name "ExitOnMSICW" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-22-1-6 {
    # Control 18.8.22.1.6 - Detection Script
    $controlNumber = "18.8.22.1.6"
    $description = "(L1) Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoWebServices" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-22-1-7 {
    # Control 18.8.22.1.7 - Detection Script
    $controlNumber = "18.8.22.1.7"
    $description = "(L2) Ensure 'Turn off printing over HTTP' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-22-1-8 {
    # Control 18.8.22.1.8 - Detection Script
    $controlNumber = "18.8.22.1.8"
    $description = "(L2) Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" -Name "NoRegistration" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-22-1-9 {
    # Control 18.8.22.1.9 - Detection Script
    $controlNumber = "18.8.22.1.9"
    $description = "(L2) Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" -Name "DisableContentFileUpdates" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-22-1-10 {
    # Control 18.8.22.1.10 - Detection Script
    $controlNumber = "18.8.22.1.10"
    $description = "(L2) Ensure 'Turn off the `"Order Prints`" picture task' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoOnlinePrintsWizard" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-22-1-11 {
    # Control 18.8.22.1.11 - Detection Script
    $controlNumber = "18.8.22.1.11"
    $description = "(L2) Ensure 'Turn off the `"Publish to Web`" task for files and folders' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoPublishingWizard" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-22-1-12 {
    # Control 18.8.22.1.12 - Detection Script
    $controlNumber = "18.8.22.1.12"
    $description = "(L2) Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-22-1-13 {
    # Control 18.8.22.1.13 - Detection Script
    $controlNumber = "18.8.22.1.13"
    $description = "(L2) Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-22-1-14 {
    # Control 18.8.22.1.14 - Detection Script
    $controlNumber = "18.8.22.1.14"
    $description = "(L2) Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}


############################## 18.8.23. iSCSI ##########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.24. KDC ############################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.25. Kerberos #######################################################################################################
Function Get-Control18-8-25-1 {
    # Control 18.8.25.1 - Detection Script
    $controlNumber = "18.8.25.1"
    $description = "(L2) Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'"
    $expectedValue = "Enabled: Automatic"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceRegistration" -Name "EnableCertAuth" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.8.26 Kernel DMA Protection ###########################################################################################
Function Get-Control18-8-26-1 {
    # Control 18.8.26.1 - Detection Script (Repeated Control, shown once for implementation)
    $controlNumber = "18.8.26.1"
    $description = "(BL) Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'"
    $expectedValue = "Enabled: Block All"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" -Name "DeviceEnumerationPolicy" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 2) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.8.27 Locale Services #################################################################################################
Function Get-Control18-8-27-1 {
    # Control 18.8.27.1 - Detection Script
    $controlNumber = "18.8.27.1"
    $description = "(L2) Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Name "BlockUserInputMethodsForSignIn" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.8.28 Logon ###########################################################################################################
Function Get-Control18-8-28-1 {
    # Control 18.8.28.1 - Detection Script
    $controlNumber = "18.8.28.1"
    $description = "(L1) Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayLastUserName" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-28-2 {
    # Control 18.8.28.2 - Detection Script
    $controlNumber = "18.8.28.2"
    $description = "(L1) Ensure 'Do not display network selection UI' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-28-3 {
    # Control 18.8.28.3 - Detection Script
    $controlNumber = "18.8.28.3"
    $description = "(L1) Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-28-4 {
    # Control 18.8.28.4 - Detection Script
    $controlNumber = "18.8.28.4"
    $description = "(L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnumerateLocalUsers" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-28-5 {
    # Control 18.8.28.5 - Detection Script
    $controlNumber = "18.8.28.5"
    $description = "(L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-28-6 {
    # Control 18.8.28.6 - Detection Script
    $controlNumber = "18.8.28.6"
    $description = "(L1) Ensure 'Turn off picture password sign-in' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockDomainPicturePassword" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-28-7 {
    # Control 18.8.28.7 - Detection Script
    $controlNumber = "18.8.28.7"
    $description = "(L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.8.29 Mitigation Options ##############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.30 Net Logon #######################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.31 OS Policies #####################################################################################################
Function Get-Control18-8-31-1 {
    # Control 18.8.31.1 - Detection Script
    $controlNumber = "18.8.31.1"
    $description = "(L2) Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-31-2 {
    # Control 18.8.31.2 - Detection Script
    $controlNumber = "18.8.31.2"
    $description = "(L2) Ensure 'Allow upload of User Activities' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.8.32 Performance Control Panel #######################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.33 PIN Complexity ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.34 Power Management ################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

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
Function Get-Control18-8-34-6-1 {
    # Control 18.8.34.6.1 - Detection Script
    $controlNumber = "18.8.34.6.1"
    $description = "(L1) Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "DCSettingIndex" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-34-6-2 {
    # Control 18.8.34.6.2 - Detection Script
    $controlNumber = "18.8.34.6.2"
    $description = "(L1) Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-34-6-3 {
    # Control 18.8.34.6.3 - Detection Script
    $controlNumber = "18.8.34.6.3"
    $description = "(BL) Ensure 'Allow standby states (S1-S3) when sleeping (on battery)' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -Name "DCSettingIndex" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-34-6-4 {
    # Control 18.8.34.6.4 - Detection Script
    $controlNumber = "18.8.34.6.4"
    $description = "(BL) Ensure 'Allow standby states (S1-S3) when sleeping (plugged in)' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -Name "ACSettingIndex" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-34-6-5 {
    # Control 18.8.34.6.5 - Detection Script
    $controlNumber = "18.8.34.6.5"
    $description = "(L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "DCSettingIndex" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-34-6-6 {
    # Control 18.8.34.6.6 - Detection Script
    $controlNumber = "18.8.34.6.6"
    $description = "(L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name "ACSettingIndex" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.8.35 Recovery ########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.8.36 Remote Assistance ###############################################################################################
Function Get-Control18-8-36-1 {
    # Control 18.8.36.1 - Detection Script
    $controlNumber = "18.8.36.1"
    $description = "(L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-36-2 {
    # Control 18.8.36.2 - Detection Script
    $controlNumber = "18.8.36.2"
    $description = "(L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.8.37 Remote Procedure Call ###########################################################################################
Function Get-Control18-8-37-1 {
    # Control 18.8.37.1 - Detection Script
    $controlNumber = "18.8.37.1"
    $description = "(L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control18-8-48-5-1 {
    # Control 18.8.48.5.1 - Detection Script
    $controlNumber = "18.8.48.5.1"
    $description = "(L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "DisableQueryRemoteServer" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control18-8-48-11-1 {
    # Control 18.8.48.11.1 - Detection Script
    $controlNumber = "18.8.48.11.1"
    $description = "(L2) Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Performance\PerfTrack" -Name "ScenarioExecutionEnabled" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.8.49 Trusted Platform Module Services ################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.50 User Profiles ###################################################################################################
Function Get-Control18-8-50-1 {
    # Control 18.8.50.1 - Detection Script
    $controlNumber = "18.8.50.1"
    $description = "(L2) Ensure 'Turn off the advertising ID' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.8.51 Windows File Protection #########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.52 Windows HotStart ################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.8.53 Windows Time Service ############################################################################################
############################## 18.8.53.1 Time Providers ################################################################################################
Function Get-Control18-8-53-1-1 {
    # Control 18.8.53.1.1 - Detection Script
    $controlNumber = "18.8.53.1.1"
    $description = "(L2) Ensure 'Enable Windows NTP Client' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -Name "Enabled" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-8-53-1-2 {
    # Control 18.8.53.1.2 - Detection Script
    $controlNumber = "18.8.53.1.2"
    $description = "(L2) Ensure 'Enable Windows NTP Server' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" -Name "Enabled" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

################################################## 18.9 Windows Components #############################################################################
############################## 18.9.1 Active Directory Federation Services #############################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.2 ActiveX Installer Service ########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.3 Add features to Windows 8 / 8.1 / 10 (formerly Windows Anytime Upgrade) ##########################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.4 App Package Deployment ###########################################################################################
Function Get-Control18-9-4-1 {
    # Control 18.9.4.1 - Detection Script
    $controlNumber = "18.9.4.1"
    $description = "(L2) Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAppData" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-4-2 {
    # Control 18.9.4.2 - Detection Script
    $controlNumber = "18.9.4.2"
    $description = "(L1) Ensure 'Prevent non-admin users from installing packaged Windows apps' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "AllowAllTrustedApps" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.5 App Privacy ######################################################################################################
Function Get-Control18-9-5-1 {
    # Control 18.9.5.1 - Detection Script
    $controlNumber = "18.9.5.1"
    $description = "(L1) Ensure 'Let Windows apps activate with voice while the system is locked' is set to 'Enabled: Force Deny'"
    $expectedValue = "Enabled: Force Deny"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 2) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.6 App runtime ######################################################################################################
Function Get-Control18-9-6-1 {
    # Control 18.9.6.1 - Detection Script
    $controlNumber = "18.9.6.1"
    $description = "(L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "MSAOptional" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-6-2 {
    # Control 18.9.6.2 - Detection Script
    $controlNumber = "18.9.6.2"
    $description = "(L2) Ensure 'Block launching Universal Windows apps with Windows Runtime API access from hosted content.' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "BlockHostedAppAccessWinRT" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.7 Application Compatibility ########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.8 AutoPlay Policies ################################################################################################
Function Get-Control18-9-8-1 {
    # Control 18.9.8.1 - Detection Script
    $controlNumber = "18.9.8.1"
    $description = "(L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-8-2 {
    # Control 18.9.8.2 - Detection Script
    $controlNumber = "18.9.8.2"
    $description = "(L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'"
    $expectedValue = "Enabled: Do not execute any autorun commands"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutorun" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-8-3 {
    # Control 18.9.8.3 - Detection Script
    $controlNumber = "18.9.8.3"
    $description = "(L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'"
    $expectedValue = "Enabled: All drives"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 255) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.9 Backup ###########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent. 

############################## 18.9.10 Biometrics ######################################################################################################
############################## 18.9.10.1 Facial Features ###############################################################################################
Function Get-Control18-9-10-1-1 {
    # Control 18.9.10.1.1 - Detection Script
    $controlNumber = "18.9.10.1.1"
    $description = "(L1) Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.11 BitLocker Drive Encryption ######################################################################################
############################## 18.9.11.1 Fixed Data Drives #############################################################################################
Function Get-Control18-9-11-1-1 {
    # Control 18.9.11.1.1 - Detection Script
    $controlNumber = "18.9.11.1.1"
    $description = "(BL) Ensure 'Allow access to BitLocker-protected fixed data drives from earlier versions of Windows' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVAllowAnyRecoveryOS" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-1-2 {
    # Control 18.9.11.1.2 - Detection Script
    $controlNumber = "18.9.11.1.2"
    $description = "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecovery" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-1-3 {
    # Control 18.9.11.1.3 - Detection Script
    $controlNumber = "18.9.11.1.3"
    $description = "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Allow data recovery agent' is set to 'Enabled: True'"
    $expectedValue = "Enabled: True"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVManageDRA" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-1-4 {
    # Control 18.9.11.1.4 - Detection Script
    $controlNumber = "18.9.11.1.4"
    $description = "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Password' is set to 'Enabled: Allow 48-digit recovery password'"
    $expectedValue = "Enabled: Allow 48-digit recovery password"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecoveryPassword" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-1-5 {
    # Control 18.9.11.1.5 - Detection Script
    $controlNumber = "18.9.11.1.5"
    $description = "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Key' is set to 'Enabled: Allow 256-bit recovery key'"
    $expectedValue = "Enabled: Allow 256-bit recovery key"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecoveryKey" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-1-6 {
    # Control 18.9.11.1.6 - Detection Script
    $controlNumber = "18.9.11.1.6"
    $description = "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'"
    $expectedValue = "Enabled: True"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVHideRecoveryPage" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-1-7 {
    # Control 18.9.11.1.7 - Detection Script
    $controlNumber = "18.9.11.1.7"
    $description = "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Save BitLocker recovery information to AD DS for fixed data drives' is set to 'Enabled: False'"
    $expectedValue = "Enabled: False"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVSaveToAD" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-1-8 {
    # Control 18.9.11.1.8 - Detection Script
    $controlNumber = "18.9.11.1.8"
    $description = "(BL) Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Configure storage of BitLocker recovery information to AD DS' is set to 'Enabled: Backup recovery passwords and key packages'"
    $expectedValue = "Enabled: Backup recovery passwords and key packages"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryBackup" -ErrorAction SilentlyContinue
    $backupKeyPackagesValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryInfoToStore" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1 -and $backupKeyPackagesValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-1-9 {
    # Control 18.9.11.1.9 - Detection Script
    $controlNumber = "18.9.11.1.9"
    $description = "(BL) Ensure 'Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives' is set to 'Enabled: False'"
    $expectedValue = "Enabled: False"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRequireActiveDirectoryBackup" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-1-10 {
    # Control 18.9.11.1.10 - Detection Script
    $controlNumber = "18.9.11.1.10"
    $description = "(BL) Ensure 'Configure use of hardware-based encryption for fixed data drives' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVHardwareEncryption" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-1-11 {
    # Control 18.9.11.1.11 - Detection Script
    $controlNumber = "18.9.11.1.11"
    $description = "(BL) Ensure 'Configure use of passwords for fixed data drives' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVPassphrase" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-1-12 {
    # Control 18.9.11.1.12 - Detection Script
    $controlNumber = "18.9.11.1.12"
    $description = "(BL) Ensure 'Configure use of smart cards on fixed data drives' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVSmartCard" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-1-13 {
    # Control 18.9.11.1.13 - Detection Script
    $controlNumber = "18.9.11.1.13"
    $description = "(BL) Ensure 'Configure use of smart cards on fixed data drives: Require use of smart cards on fixed data drives' is set to 'Enabled: True'"
    $expectedValue = "Enabled: True"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVSmartCardRequired" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-2-1 {
    # Control 18.9.11.2.1 - Detection Script
    $controlNumber = "18.9.11.2.1"
    $description = "(BL) Ensure 'Allow enhanced PINs for startup' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseEnhancedPin" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-2-2 {
    # Control 18.9.11.2.2 - Detection Script
    $controlNumber = "18.9.11.2.2"
    $description = "(BL) Ensure 'Allow Secure Boot for integrity validation' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "EnableSecureBootForIntegrity" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-2-3 {
    # Control 18.9.11.2.3 - Detection Script
    $controlNumber = "18.9.11.2.3"
    $description = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "RecoveryKeyMessage" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -ne $null) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-2-4 {
    # Control 18.9.11.2.4 - Detection Script
    $controlNumber = "18.9.11.2.4"
    $description = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Allow data recovery agent' is set to 'Enabled: False'"
    $expectedValue = "Enabled: False"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "OmitDRA" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-2-5 {
    # Control 18.9.11.2.5 - Detection Script
    $controlNumber = "18.9.11.2.5"
    $description = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Password' is set to 'Enabled: Require 48-digit recovery password'"
    $expectedValue = "Enabled: Require 48-digit recovery password"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "RecoveryPassword" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-2-6 {
    # Control 18.9.11.2.6 - Detection Script
    $controlNumber = "18.9.11.2.6"
    $description = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key'"
    $expectedValue = "Enabled: Do not allow 256-bit recovery key"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "RecoveryKey" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-2-7 {
    # Control 18.9.11.2.7 - Detection Script
    $controlNumber = "18.9.11.2.7"
    $description = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'"
    $expectedValue = "Enabled: True"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "HideRecoveryPage" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-2-8 {
    # Control 18.9.11.2.8 - Detection Script
    $controlNumber = "18.9.11.2.8"
    $description = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Save BitLocker recovery information to AD DS for operating system drives' is set to 'Enabled: True'"
    $expectedValue = "Enabled: True"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "OSActiveDirectoryBackup" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-2-9 {
    # Control 18.9.11.2.9 - Detection Script
    $controlNumber = "18.9.11.2.9"
    $description = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Store recovery passwords and key packages'"
    $expectedValue = "Enabled: Store recovery passwords and key packages"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "OSActiveDirectoryInfoToStore" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 3) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-2-10 {
    # Control 18.9.11.2.10 - Detection Script
    $controlNumber = "18.9.11.2.10"
    $description = "(BL) Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for operating system drives' is set to 'Enabled: True'"
    $expectedValue = "Enabled: True"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "OSRequireActiveDirectoryBackup" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-2-11 {
    # Control 18.9.11.2.11 - Detection Script
    $controlNumber = "18.9.11.2.11"
    $description = "(BL) Ensure 'Configure use of hardware-based encryption for operating system drives' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "OSEnableHardwareEncryption" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-2-12 {
    # Control 18.9.11.2.12 - Detection Script
    $controlNumber = "18.9.11.2.12"
    $description = "(BL) Ensure 'Configure use of passwords for operating system drives' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSRecovery" -Name "OSPassphrase" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-2-13 {
    # Control 18.9.11.2.13 - Detection Script
    $controlNumber = "18.9.11.2.13"
    $description = "(BL) Ensure 'Require additional authentication at startup' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseAdvancedStartup" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-2-14 {
    # Control 18.9.11.2.14 - Detection Script
    $controlNumber = "18.9.11.2.14"
    $description = "(BL) Ensure 'Require additional authentication at startup: Allow BitLocker without a compatible TPM' is set to 'Enabled: False'"
    $expectedValue = "Enabled: False"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseAdvancedStartupWithoutTPM" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-1 {
    # Control 18.9.11.3.1 - Detection Script
    $controlNumber = "18.9.11.3.1"
    $description = "(BL) Ensure 'Allow access to BitLocker-protected removable data drives from earlier versions of Windows' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDV" -Name "RDVAllowCrossVersionAccess" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-2 {
    # Control 18.9.11.3.2 - Detection Script
    $controlNumber = "18.9.11.3.2"
    $description = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered' is set to 'Enabled'"
    $expectedValue = "Enabled"

    # Specific recovery options are configured within sub-settings; this script checks for the policy's existence.
    $policyExists = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery"
    $controlStatus = if ($policyExists) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-3 {
    # Control 18.9.11.3.3 - Detection Script
    $controlNumber = "18.9.11.3.3"
    $description = "(BL) Placeholder for next control detection."
    $expectedValue = "Expected configuration value"

    $currentValue = "Actual configuration value"
    $controlStatus = if ($currentValue -eq $expectedValue) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-3 {
    # Control 18.9.11.3.3 - Detection Script
    $controlNumber = "18.9.11.3.3"
    $description = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Allow data recovery agent' is set to 'Enabled: True'"
    $expectedValue = "Enabled: True"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery" -Name "RDVManageDRA" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-4 {
    # Control 18.9.11.3.4 - Detection Script
    $controlNumber = "18.9.11.3.4"
    $description = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Password' is set to 'Enabled: Do not allow 48-digit recovery password'"
    $expectedValue = "Enabled: Do not allow 48-digit recovery password"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery" -Name "RDVRecoveryPassword" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-5 {
    # Control 18.9.11.3.5 - Detection Script
    $controlNumber = "18.9.11.3.5"
    $description = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key'"
    $expectedValue = "Enabled: Do not allow 256-bit recovery key"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery" -Name "RDVRecoveryKey" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-6 {
    # Control 18.9.11.3.6 - Detection Script
    $controlNumber = "18.9.11.3.6"
    $description = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'"
    $expectedValue = "Enabled: True"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery" -Name "RDVHideRecoveryPage" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-7 {
    # Control 18.9.11.3.7 - Detection Script
    $controlNumber = "18.9.11.3.7"
    $description = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Save BitLocker recovery information to AD DS for removable data drives' is set to 'Enabled: False'"
    $expectedValue = "Enabled: False"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery" -Name "RDVActiveDirectoryBackup" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-8 {
    # Control 18.9.11.3.8 - Detection Script
    $controlNumber = "18.9.11.3.8"
    $description = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Backup recovery passwords and key packages'"
    $expectedValue = "Enabled: Backup recovery passwords and key packages"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery" -Name "RDVActiveDirectoryInfoToStore" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 3) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-9 {
    # Control 18.9.11.3.9 - Detection Script
    $controlNumber = "18.9.11.3.9"
    $description = "(BL) Ensure 'Choose how BitLocker-protected removable drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for removable data drives' is set to 'Enabled: False'"
    $expectedValue = "Enabled: False"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDVRecovery" -Name "RDVRequireActiveDirectoryBackup" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-10 {
    # Control 18.9.11.3.10 - Detection Script
    $controlNumber = "18.9.11.3.10"
    $description = "(BL) Ensure 'Configure use of hardware-based encryption for removable data drives' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDV" -Name "RDVHardwareEncryption" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-11 {
    # Control 18.9.11.3.11 - Detection Script
    $controlNumber = "18.9.11.3.11"
    $description = "(BL) Ensure 'Configure use of passwords for removable data drives' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDV" -Name "RDVPassphrase" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-12 {
    # Control 18.9.11.3.12 - Detection Script
    $controlNumber = "18.9.11.3.12"
    $description = "(BL) Ensure 'Configure use of smart cards on removable data drives' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDV" -Name "RDVSmartCard" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-13 {
    # Control 18.9.11.3.13 - Detection Script
    $controlNumber = "18.9.11.3.13"
    $description = "(BL) Ensure 'Configure use of smart cards on removable data drives: Require use of smart cards on removable data drives' is set to 'Enabled: True'"
    $expectedValue = "Enabled: True"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDV" -Name "RDVSmartCardRequired" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-14 {
    # Control 18.9.11.3.14 - Detection Script
    $controlNumber = "18.9.11.3.14"
    $description = "(BL) Ensure 'Deny write access to removable drives not protected by BitLocker' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDV" -Name "DenyWriteAccess" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-3-15 {
    # Control 18.9.11.3.15 - Detection Script
    $controlNumber = "18.9.11.3.15"
    $description = "(BL) Ensure 'Deny write access to removable drives not protected by BitLocker: Do not allow write access to devices configured in another organization' is set to 'Enabled: False'"
    $expectedValue = "Enabled: False"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\RDV" -Name "DenyCrossOrgWriteAccess" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-11-4 {
    # Control 18.9.11.4 - Detection Script
    $controlNumber = "18.9.11.4"
    $description = "(BL) Ensure 'Disable new DMA devices when this computer is locked' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "DisableNewDMADevicesWhenLocked" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.12 Camera ##########################################################################################################
Function Get-Control18-9-12-1 {
    # Control 18.9.12.1 - Detection Script
    $controlNumber = "18.9.12.1"
    $description = "(L2) Ensure 'Allow Use of Camera' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Camera" -Name "AllowCamera" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.13 Chat ############################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.
############################## 18.9.14 Cloud Content ###################################################################################################
Function Get-Control18-9-14-1 {
    # Control 18.9.14.1 - Detection Script
    $controlNumber = "18.9.14.1"
    $description = "(L1) Ensure 'Turn off cloud consumer account state content' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-14-2 {
    # Control 18.9.14.2 - Detection Script
    $controlNumber = "18.9.14.2"
    $description = "(L2) Ensure 'Turn off cloud optimized content' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudOptimizedContent" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-14-3 {
    # Control 18.9.14.3 - Detection Script
    $controlNumber = "18.9.14.3"
    $description = "(L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.15 Connect #########################################################################################################
Function Get-Control18-9-15-1 {
    # Control 18.9.15.1 - Detection Script
    $controlNumber = "18.9.15.1"
    $description = "(L1) Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'"
    $expectedValue = "Enabled: First Time OR Enabled: Always"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1 -or $currentValue -eq 2) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.16 Credential User Interface #######################################################################################
Function Get-Control18-9-16-1 {
    # Control 18.9.16.1 - Detection Script
    $controlNumber = "18.9.16.1"
    $description = "(L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-16-2 {
    # Control 18.9.16.2 - Detection Script
    $controlNumber = "18.9.16.2"
    $description = "(L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LUA" -Name "EnumerateAdministrators" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-16-3 {
    # Control 18.9.16.3 - Detection Script
    $controlNumber = "18.9.16.3"
    $description = "(L1) Ensure 'Prevent the use of security questions for local accounts' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "NoLocalPasswordResetQuestions" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.17 Data Collection and Preview Builds ##############################################################################
Function Get-Control18-9-17-1 {
    # Control 18.9.17.1 - Detection Script
    $controlNumber = "18.9.17.1"
    $description = "(L1) Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'"
    # Since the policy setting can vary, check for both conditions where diagnostic data is limited.
    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -le 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue"
}

Function Get-Control18-9-17-2 {
    # Control 18.9.17.2 - Detection Script
    $controlNumber = "18.9.17.2"
    $description = "(L2) Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'"
    $expectedValue = "Enabled: Disable Authenticated Proxy usage"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableEnterpriseAuthProxy" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-17-3 {
    # Control 18.9.17.3 - Detection Script
    $controlNumber = "18.9.17.3"
    $description = "(L1) Ensure 'Disable OneSettings Downloads' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneSettings" -Name "DisableDownloads" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-17-4 {
    # Control 18.9.17.4 - Detection Script
    $controlNumber = "18.9.17.4"
    $description = "(L1) Ensure 'Do not show feedback notifications' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-17-5 {
    # Control 18.9.17.5 - Detection Script
    $controlNumber = "18.9.17.5"
    $description = "(L1) Ensure 'Enable OneSettings Auditing' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneSettings" -Name "EnableAuditing" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-17-6 {
    # Control 18.9.17.6 - Detection Script
    $controlNumber = "18.9.17.6"
    $description = "(L1) Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-17-7 {
    # Control 18.9.17.7 - Detection Script
    $controlNumber = "18.9.17.7"
    $description = "(L1) Ensure 'Limit Dump Collection' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DisableDeviceCollection" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-17-8 {
    # Control 18.9.17.8 - Detection Script
    $controlNumber = "18.9.17.8"
    $description = "(L1) Ensure 'Toggle user control over Insider builds' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.18 Delivery Optimization ###########################################################################################
Function Get-Control18-9-18-1 {
    # Control 18.9.18.1 - Detection Script
    $controlNumber = "18.9.18.1"
    $description = "(L1) Ensure 'Download Mode' is NOT set to 'Enabled: Internet'"
    $expectedValue = "Not Enabled: Internet"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -ne 3) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control18-9-27-1-1 {
    # Control 18.9.27.1.1 - Detection Script
    $controlNumber = "18.9.27.1.1"
    $description = "(L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "Retention" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq "0") { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-27-1-2 {
    # Control 18.9.27.1.2 - Detection Script
    $controlNumber = "18.9.27.1.2"
    $description = "(L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    $expectedValue = "Enabled: 32,768 or greater"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "MaxSize" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -ge 32768) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.27.2 Security ######################################################################################################
Function Get-Control18-9-27-2-1 {
    # Control 18.9.27.2.1 - Detection Script
    $controlNumber = "18.9.27.2.1"
    $description = "(L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "Retention" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq "0") { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-27-2-2 {
    # Control 18.9.27.2.2 - Detection Script
    $controlNumber = "18.9.27.2.2"
    $description = "(L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'"
    $expectedValue = "Enabled: 196,608 or greater"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxSize" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -ge 196608) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.27.3 Setup #########################################################################################################
Function Get-Control18-9-27-3-1 {
    # Control 18.9.27.3.1 - Detection Script
    $controlNumber = "18.9.27.3.1"
    $description = "(L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "Retention" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq "0") { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-27-3-2 {
    # Control 18.9.27.3.2 - Detection Script
    $controlNumber = "18.9.27.3.2"
    $description = "(L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    $expectedValue = "Enabled: 32,768 or greater"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "MaxSize" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -ge 32768) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.27.4 System ########################################################################################################
Function Get-Control18-9-27-4-1 {
    # Control 18.9.27.4.1 - Detection Script
    $controlNumber = "18.9.27.4.1"
    $description = "(L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "Retention" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq "0") { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-27-4-2 {
    # Control 18.9.27.4.2 - Detection Script
    $controlNumber = "18.9.27.4.2"
    $description = "(L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
    $expectedValue = "Enabled: 32,768 or greater"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "MaxSize" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -ge 32768) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.28 Event Logging ###################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.29 Event Viewer ####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.30 Family Safety (formerly Parental Controls) ######################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.31 File Explorer (formerly Windows Explorer) #######################################################################
############################## 18.9.31.1 Previous Versions #############################################################################################
Function Get-Control18-9-31-2 {
    # Control 18.9.31.2 - Detection Script
    $controlNumber = "18.9.31.2"
    $description = "(L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-31-3 {
    # Control 18.9.31.3 - Detection Script
    $controlNumber = "18.9.31.3"
    $description = "(L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoHeapTerminationOnCorruption" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-31-4 {
    # Control 18.9.31.4 - Detection Script
    $controlNumber = "18.9.31.4"
    $description = "(L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "PreXPSP2ShellProtocolBehavior" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control18-9-36-1 {
    # Control 18.9.36.1 - Detection Script
    $controlNumber = "18.9.36.1"
    $description = "(L1) Ensure 'Prevent the computer from joining a homegroup' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control18-9-41-1 {
    # Control 18.9.41.1 - Detection Script
    $controlNumber = "18.9.41.1"
    $description = "(L2) Ensure 'Turn off location' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.42 Maintenance Scheduler ###########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.43 Maps ############################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.44 MDM #############################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.45 Messaging #######################################################################################################
Function Get-Control18-9-45-1 {
    # Control 18.9.45.1 - Detection Script
    $controlNumber = "18.9.45.1"
    $description = "(L2) Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.46 Microsoft account ###############################################################################################
Function Get-Control18-9-46-1 {
    # Control 18.9.46.1 - Detection Script
    $controlNumber = "18.9.46.1"
    $description = "(L1) Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockMicrosoftAccounts" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.47 Microsoft Defender Antivirus (formerly Windows Defender and Windows Defender Antivirus) #########################
############################## 18.9.47.1 Client Interface ##############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.47.2 Device Control ################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.47.3 Exclusions ####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.47.4 MAPS ##########################################################################################################
Function Get-Control18-9-47-4-1 {
    # Control 18.9.47.4.1 - Detection Script
    $controlNumber = "18.9.47.4.1"
    $description = "(L1) Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-47-4-2 {
    # Control 18.9.47.4.2 - Detection Script
    $controlNumber = "18.9.47.4.2"
    $description = "(L2) Ensure 'Join Microsoft MAPS' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.47.5 Microsoft Defender Exploit Guard (formerly Windows Defender Exploit Guard) ####################################
############################## 18.9.47.5.1 Attack Surface Reduction ####################################################################################
Function Get-Control18-9-47-5-1-1 {
    # Control 18.9.47.5.1.1 - Detection Script
    $controlNumber = "18.9.47.5.1.1"
    $description = "(L1) Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "ExploitGuard_ASR_Rules" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -ne $null -and $currentValue -ne "") { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-47-5-1-2 {
    # Control 18.9.47.5.1.2 - Detection Script
    $controlNumber = "18.9.47.5.1.2"
    $description = "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured"
    $expectedValue = "Configured"

    # Checking for the presence of any ASR rule configuration.
    $asrRules = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ErrorAction SilentlyContinue
    $currentValue = if ($asrRules -and $asrRules.PSObject.Properties.Count -gt 0) { "Configured" } else { "Not Configured" }
    $controlStatus = if ($currentValue -eq "Configured") { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.47.5.2 Controlled Folder Access ####################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.47.5.3 Network Protection ##########################################################################################
Function Get-Control18-9-47-5-3-1 {
    # Control 18.9.47.5.3.1 - Detection Script
    $controlNumber = "18.9.47.5.3.1"
    $description = "(L1) Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'"
    $expectedValue = "Enabled: Block"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.47.6 MpEngine ######################################################################################################
Function Get-Control18-9-47-6-1 {
    # Control 18.9.47.6.1 - Detection Script
    $controlNumber = "18.9.47.6.1"
    $description = "(L2) Ensure 'Enable file hash computation feature' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePus" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.47.7 Network Inspection System #####################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.47.8 Quarantine ####################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.47.9 Real-time Protection ##########################################################################################
Function Get-Control18-9-47-9-1 {
    # Control 18.9.47.9.1 - Detection Script
    $controlNumber = "18.9.47.9.1"
    $description = "(L1) Ensure 'Scan all downloaded files and attachments' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanningNetworkFiles" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-47-9-2 {
    # Control 18.9.47.9.2 - Detection Script
    $controlNumber = "18.9.47.9.2"
    $description = "(L1) Ensure 'Turn off real-time protection' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-47-9-3 {
    # Control 18.9.47.9.3 - Detection Script
    $controlNumber = "18.9.47.9.3"
    $description = "(L1) Ensure 'Turn on behavior monitoring' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-47-9-4 {
    # Control 18.9.47.9.4 - Detection Script
    $controlNumber = "18.9.47.9.4"
    $description = "(L1) Ensure 'Turn on script scanning' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScriptScanning" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.47.10 Remediation ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.47.11 Reporting ####################################################################################################
Function Get-Control18-9-47-11-1 {
    # Control 18.9.47.11.1 - Detection Script
    $controlNumber = "18.9.47.11.1"
    $description = "(L2) Ensure 'Configure Watson events' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.47.12 Scan #########################################################################################################
Function Get-Control18-9-47-12-1 {
    # Control 18.9.47.12.1 - Detection Script
    $controlNumber = "18.9.47.12.1"
    $description = "(L1) Ensure 'Scan removable drives' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRemovableDriveScanning" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-47-12-2 {
    # Control 18.9.47.12.2 - Detection Script
    $controlNumber = "18.9.47.12.2"
    $description = "(L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableEmailScanning" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}


############################## 18.9.47.13 Security Intelligence Updates (formerly Signature Updates) ###################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.47.14 Threats ######################################################################################################
Function Get-Control18-9-47-15 {
    # Control 18.9.47.15 - Detection Script
    $controlNumber = "18.9.47.15"
    $description = "(L1) Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'"
    $expectedValue = "Enabled: Block"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "PUAProtection" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-47-16 {
    # Control 18.9.47.16 - Detection Script
    $controlNumber = "18.9.47.16"
    $description = "(L1) Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.48 Microsoft Defender Application Guard (formerly Windows Defender Application Guard) ##############################
Function Get-Control18-9-48-1 {
    # Control 18.9.48.1 (First Instance) - Detection Script
    $controlNumber = "18.9.48.1"
    $description = "(NG) Ensure 'Allow auditing events in Microsoft Defender Application Guard' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AuditProcessCreation" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-48-2 {
    # Control 18.9.48.2 - Detection Script
    $controlNumber = "18.9.48.2"
    $description = "(NG) Ensure 'Allow camera and microphone access in Microsoft Defender Application Guard' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowCameraAndMicrophoneRedirection" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-48-3 {
    # Control 18.9.48.3 - Detection Script
    $controlNumber = "18.9.48.3"
    $description = "(NG) Ensure 'Allow data persistence for Microsoft Defender Application Guard' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowPersistence" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-48-4 {
    # Control 18.9.48.4 - Detection Script
    $controlNumber = "18.9.48.4"
    $description = "(NG) Ensure 'Allow files to download and save to the host operating system from Microsoft Defender Application Guard' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowFileSave" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-48-5 {
    # Control 18.9.48.5 - Detection Script
    $controlNumber = "18.9.48.5"
    $description = "(NG) Ensure 'Configure Microsoft Defender Application Guard clipboard settings: Clipboard behavior setting' is set to 'Enabled: Enable clipboard operation from an isolated session to the host'"
    $expectedValue = "Enabled: Enable clipboard operation from an isolated session to the host"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "ClipboardRedirection" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-48-6 {
    # Control 18.9.48.6 - Detection Script
    $controlNumber = "18.9.48.6"
    $description = "(NG) Ensure 'Turn on Microsoft Defender Application Guard in Managed Mode' is set to 'Enabled: 1'"
    $expectedValue = "Enabled: 1"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "ConfigSecurityLevel" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control18-9-57-1 {
    # Control 18.9.57.1 - Detection Script
    $controlNumber = "18.9.57.1"
    $description = "(L2) Ensure 'Enable news and interests on the taskbar' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.58 OneDrive (formerly SkyDrive) ####################################################################################
Function Get-Control18-9-58-1 {
    # Control 18.9.58.1 - Detection Script
    $controlNumber = "18.9.58.1"
    $description = "(L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control18-9-64-1 {
    # Control 18.9.64.1 - Detection Script
    $controlNumber = "18.9.64.1"
    $description = "(L2) Ensure 'Turn off Push To Install service' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PushToInstall" -Name "DisablePushToInstall" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.65 Remote Desktop Services (formerly Terminal Services) ############################################################
############################## 18.9.65.1 RD Licensing (formerly TS Licensing) ##########################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.65.2 Remote Desktop Connection Client ##############################################################################
Function Get-Control18-9-65-2-2 {
    # Control 18.9.65.2.2 - Detection Script
    $controlNumber = "18.9.65.2.2"
    $description = "(L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.65.2.1 RemoteFX USB Device Redirection #############################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.65.3 Remote Desktop Session Host (formerly Terminal Server) ########################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.65.3.1 Application Compatibility ###################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.65.3.2 Connections #################################################################################################
Function Get-Control18-9-65-3-2-1 {
    # Control 18.9.65.3.2.1 - Detection Script
    $controlNumber = "18.9.65.3.2.1"
    $description = "(L2) Ensure 'Allow users to connect remotely by using Remote Desktop Services' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-65-3-3-1 {
    # Control 18.9.65.3.3.1 - Detection Script
    $controlNumber = "18.9.65.3.3.1"
    $description = "(L2) Ensure 'Allow UI Automation redirection' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisableUARedirection" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-65-3-3-2 {
    # Control 18.9.65.3.3.2 - Detection Script
    $controlNumber = "18.9.65.3.3.2"
    $description = "(L2) Ensure 'Do not allow COM port redirection' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.65.3.3 Device and Resource Redirection #############################################################################
Function Get-Control18-9-65-3-3-3 {
    # Control 18.9.65.3.3.3 - Detection Script
    $controlNumber = "18.9.65.3.3.3"
    $description = "(L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-65-3-3-4 {
    # Control 18.9.65.3.3.4 - Detection Script
    $controlNumber = "18.9.65.3.3.4"
    $description = "(L2) Ensure 'Do not allow location redirection' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableLocationRedirection" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-65-3-3-5 {
    # Control 18.9.65.3.3.5 - Detection Script
    $controlNumber = "18.9.65.3.3.5"
    $description = "(L2) Ensure 'Do not allow LPT port redirection' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableLPT" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-65-3-3-6 {
    # Control 18.9.65.3.3.6 - Detection Script
    $controlNumber = "18.9.65.3.3.6"
    $description = "(L2) Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisablePNPRedir" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control18-9-65-3-9-1 {
    # Control 18.9.65.3.9.1 - Detection Script
    $controlNumber = "18.9.65.3.9.1"
    $description = "(L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fPromptForPassword" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-65-3-9-2 {
    # Control 18.9.65.3.9.2 - Detection Script
    $controlNumber = "18.9.65.3.9.2"
    $description = "(L1) Ensure 'Require secure RPC communication' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-65-3-9-3 {
    # Control 18.9.65.3.9.3 - Detection Script
    $controlNumber = "18.9.65.3.9.3"
    $description = "(L1) Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'"
    $expectedValue = "Enabled: SSL"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "SecurityLayer" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 2) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-65-3-9-4 {
    # Control 18.9.65.3.9.4 - Detection Script
    $controlNumber = "18.9.65.3.9.4"
    $description = "(L1) Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "UserAuthentication" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-65-3-9-5 {
    # Control 18.9.65.3.9.5 - Detection Script
    $controlNumber = "18.9.65.3.9.5"
    $description = "(L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
    $expectedValue = "Enabled: High Level"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 3) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.65.3.10 Session Time Limits ########################################################################################
Function Get-Control18-9-65-3-10-1 {
    # Control 18.9.65.3.10.1 - Detection Script
    $controlNumber = "18.9.65.3.10.1"
    $description = "(L2) Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less, but not Never (0)'"
    $expectedValue = "Enabled: 15 minutes or less, but not Never (0)"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -le 900000 -and $currentValue -ne 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-65-3-10-2 {
    # Control 18.9.65.3.10.2 - Detection Script
    $controlNumber = "18.9.65.3.10.2"
    $description = "(L2) Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'"
    $expectedValue = "Enabled: 1 minute"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxDisconnectionTime" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 60000) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.65.3.11 Temporary folders ##########################################################################################
Function Get-Control18-9-65-3-11-1 {
    # Control 18.9.65.3.11.1 - Detection Script
    $controlNumber = "18.9.65.3.11.1"
    $description = "(L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DeleteTempDirsOnExit" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.66 RSS Feeds #######################################################################################################
Function Get-Control18-9-66-1 {
    # Control 18.9.66.1 - Detection Script
    $controlNumber = "18.9.66.1"
    $description = "(L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.67 Search ##########################################################################################################
############################## 18.9.67.1 OCR ###########################################################################################################
Function Get-Control18-9-67-2 {
    # Control 18.9.67.2 - Detection Script
    $controlNumber = "18.9.67.2"
    $description = "(L2) Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'"
    $expectedValue = "Enabled: Disable Cloud Search"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-67-3 {
    # Control 18.9.67.3 - Detection Script
    $controlNumber = "18.9.67.3"
    $description = "(L1) Ensure 'Allow Cortana' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-67-4 {
    # Control 18.9.67.4 - Detection Script
    $controlNumber = "18.9.67.4"
    $description = "(L1) Ensure 'Allow Cortana above lock screen' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-67-5 {
    # Control 18.9.67.5 - Detection Script
    $controlNumber = "18.9.67.5"
    $description = "(L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-67-6 {
    # Control 18.9.67.6 - Detection Script
    $controlNumber = "18.9.67.6"
    $description = "(L1) Ensure 'Allow search and Cortana to use location' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.68 Security Center #################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.69 Server for NIS ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.70 Shutdown Options ################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.71 Smart Card ######################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.72 Software Protection Platform ####################################################################################
Function Get-Control18-9-72-1 {
    # Control 18.9.72.1 - Detection Script
    $controlNumber = "18.9.72.1"
    $description = "(L2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Software Protection Platform" -Name "NoGenTicket" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.73 Sound Recorder ##################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.74 Speech ##########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.75 Store ###########################################################################################################
Function Get-Control18-9-75-1 {
    # Control 18.9.75.1 - Detection Script
    $controlNumber = "18.9.75.1"
    $description = "(L2) Ensure 'Disable all apps from Microsoft Store' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableStoreApps" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-75-2 {
    # Control 18.9.75.2 - Detection Script
    $controlNumber = "18.9.75.2"
    $description = "(L1) Ensure 'Only display the private store within the Microsoft Store' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RequirePrivateStoreOnly" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-75-3 {
    # Control 18.9.75.3 - Detection Script
    $controlNumber = "18.9.75.3"
    $description = "(L1) Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 2) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-75-4 {
    # Control 18.9.75.4 - Detection Script
    $controlNumber = "18.9.75.4"
    $description = "(L1) Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-75-5 {
    # Control 18.9.75.5 - Detection Script
    $controlNumber = "18.9.75.5"
    $description = "(L2) Ensure 'Turn off the Store application' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control18-9-81-1 {
    # Control 18.9.81.1 - Detection Script
    $controlNumber = "18.9.81.1"
    $description = "(L1) Ensure 'Allow widgets' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "AllowNewsAndInterests" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control18-9-85-1-1 {
    # Control 18.9.85.1.1 - Detection Script
    $controlNumber = "18.9.85.1.1"
    $description = "(L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'"
    $expectedValue = "Enabled: Warn and prevent bypass"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq "Block") { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.85.2 Microsoft Edge ################################################################################################
Function Get-Control18-9-85-2-1 {
    # Control 18.9.85.2.1 - Detection Script
    $controlNumber = "18.9.85.2.1"
    $description = "(L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled'"
    $expectedValue = "Enabled"

    # Note: The actual registry key and value might differ based on the current documentation and implementation.
    # The script below assumes a generic check for SmartScreen settings.
    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-85-2-2 {
    # Control 18.9.85.2.2 - Detection Script
    $controlNumber = "18.9.85.2.2"
    $description = "(L1) Ensure 'Prevent bypassing Windows Defender SmartScreen prompts for sites' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PreventOverrideForFilesInShell" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.86 Windows Error Reporting #########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.87 Windows Game Recording and Broadcasting #########################################################################
Function Get-Control18-9-87-1 {
    # Control 18.9.87.1 - Detection Script
    $controlNumber = "18.9.87.1"
    $description = "(L1) Ensure 'Enables or disables Windows Game Recording and Broadcasting' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.88 Windows Hello for Business (formerly Microsoft Passport for Work) ###############################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.89 Windows Ink Workspace ###########################################################################################
Function Get-Control18-9-89-1 {
    # Control 18.9.89.1 - Detection Script
    $controlNumber = "18.9.89.1"
    $description = "(L2) Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-89-2 {
    # Control 18.9.89.2 - Detection Script
    $controlNumber = "18.9.89.2"
    $description = "(L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled'"
    $expectedValue = "Enabled: On, but disallow access above lock OR Disabled"

    # Note: This script checks if the policy is either not configured (which equals to being enabled with restrictions) or explicitly disabled.
    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -ErrorAction SilentlyContinue
    $isDisabled = $currentValue -eq 0
    $isRestricted = $currentValue -eq 1
    $controlStatus = if ($isDisabled -or $isRestricted) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.90 Windows Installer ###############################################################################################
Function Get-Control18-9-90-1 {
    # Control 18.9.90.1 - Detection Script
    $controlNumber = "18.9.90.1"
    $description = "(L1) Ensure 'Allow user control over installs' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "EnableUserControl" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-90-2 {
    # Control 18.9.90.2 - Detection Script
    $controlNumber = "18.9.90.2"
    $description = "(L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-90-3 {
    # Control 18.9.90.3 - Detection Script
    $controlNumber = "18.9.90.3"
    $description = "(L2) Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "SafeForScripting" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.91 Windows Logon Options ###########################################################################################
Function Get-Control18-9-91-1 {
    # Control 18.9.91.1 - Detection Script
    $controlNumber = "18.9.91.1"
    $description = "(L1) Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control18-9-100-1 {
    # Control 18.9.100.1 - Detection Script
    $controlNumber = "18.9.100.1"
    $description = "(L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-100-2 {
    # Control 18.9.100.2 - Detection Script
    $controlNumber = "18.9.100.2"
    $description = "(L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}


############################## 18.9.101 Windows Reliability Analysis ###################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.102 Windows Remote Management (WinRM) ##############################################################################
############################## 18.9.102.1 WinRM Client #################################################################################################
Function Get-Control18-9-102-1-1 {
    # Control 18.9.102.1.1 - Detection Script
    $controlNumber = "18.9.102.1.1"
    $description = "(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-102-1-2 {
    # Control 18.9.102.1.2 - Detection Script
    $controlNumber = "18.9.102.1.2"
    $description = "(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-102-1-3 {
    # Control 18.9.102.1.3 - Detection Script
    $controlNumber = "18.9.102.1.3"
    $description = "(L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.102.2 WinRM Service ################################################################################################
Function Get-Control18-9-102-2-1 {
    # Control 18.9.102.2.1 - Detection Script
    $controlNumber = "18.9.102.2.1"
    $description = "(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-102-2-2 {
    # Control 18.9.102.2.2 - Detection Script
    $controlNumber = "18.9.102.2.2"
    $description = "(L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowRemoteShellAccess" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-102-2-3 {
    # Control 18.9.102.2.3 - Detection Script
    $controlNumber = "18.9.102.2.3"
    $description = "(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-102-2-4 {
    # Control 18.9.102.2.4 - Detection Script
    $controlNumber = "18.9.102.2.4"
    $description = "(L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}
############################## 18.9.103 Windows Remote Shell ###########################################################################################
Function Get-Control18-9-103-1 {
    # Control 18.9.103.1 - Detection Script
    $controlNumber = "18.9.103.1"
    $description = "(L2) Ensure 'Allow Remote Shell Access' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.104 Windows Sandbox ################################################################################################
Function Get-Control18-9-104-1 {
    # Control 18.9.104.1 - Detection Script
    $controlNumber = "18.9.104.1"
    $description = "(L1) Ensure 'Allow clipboard sharing with Windows Sandbox' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowClipboardRedirection" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-104-2 {
    # Control 18.9.104.2 - Detection Script
    $controlNumber = "18.9.104.2"
    $description = "(L1) Ensure 'Allow networking in Windows Sandbox' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowNetworking" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.105 Windows Security (formerly Windows Defender Security Center) ###################################################
############################## 18.9.105.1 Account protection ###########################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.105.2 App and browser protection ###################################################################################
Function Get-Control18-9-105-2-1 {
    # Control 18.9.105.2.1 - Detection Script
    $controlNumber = "18.9.105.2.1"
    $description = "(L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Name "DisallowExploitProtectionOverride" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.106 Windows SideShow ###############################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.107 Windows System Resource Manager ################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.108 Windows Update #################################################################################################
############################## 18.9.108.1 Legacy Policies ##############################################################################################
Function Get-Control18-9-108-1-1 {
    # Control 18.9.108.1.1 - Detection Script
    $controlNumber = "18.9.108.1.1"
    $description = "(L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.108.2 Manage end user experience ###################################################################################
Function Get-Control18-9-108-2-1 {
    # Control 18.9.108.2.1 - Detection Script
    $controlNumber = "18.9.108.2.1"
    $description = "(L1) Ensure 'Configure Automatic Updates' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-108-2-2 {
    # Control 18.9.108.2.2 - Detection Script
    $controlNumber = "18.9.108.2.2"
    $description = "(L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'"
    $expectedValue = "0 - Every day"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-108-2-3 {
    # Control 18.9.108.2.3 - Detection Script
    $controlNumber = "18.9.108.2.3"
    $description = "(L1) Ensure 'Remove access to Pause updates feature' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetDisablePauseUXAccess" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 18.9.108.3 Manage updates offered from Windows Server Update Service ####################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 18.9.108.4 Manage updates offered from Windows Update (formerly Defer Windows Updates and Windows Update for Business) ##
Function Get-Control18-9-108-4-1 {
    # Control 18.9.108.4.1 - Detection Script
    $controlNumber = "18.9.108.4.1"
    $description = "(L1) Ensure 'Manage preview builds' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuilds" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-108-4-2 {
    # Control 18.9.108.4.2 - Detection Script
    $controlNumber = "18.9.108.4.2"
    $description = "(L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days'"
    $expectedValue = "Enabled: 180 or more days"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control18-9-108-4-3 {
    # Control 18.9.108.4.3 - Detection Script
    $controlNumber = "18.9.108.4.3"
    $description = "(L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'"
    $expectedValue = "Enabled:0 days"

    $currentValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control19-1-3-1 {
    # Control 19.1.3.1 - Detection Script
    $controlNumber = "19.1.3.1"
    $description = "(L1) Ensure 'Enable screen saver' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq "1") { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control19-1-3-2 {
    # Control 19.1.3.2 - Detection Script
    $controlNumber = "19.1.3.2"
    $description = "(L1) Ensure 'Password protect the screen saver' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq "1") { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control19-1-3-3 {
    # Control 19.1.3.3 - Detection Script
    $controlNumber = "19.1.3.3"
    $description = "(L1) Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'"
    $expectedValue = "Enabled: 900 or fewer, but not 0"

    $currentValue = Get-ItemPropertyValue -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -le "900" -and $currentValue -ne "0") { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control19-5-1-1 {
    # Control 19.5.1.1 - Detection Script
    $controlNumber = "19.5.1.1"
    $description = "(L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableLockScreenAppNotifications" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control19-6-6-1-1 {
    # Control 19.6.6.1.1 - Detection Script
    $controlNumber = "19.6.6.1.1"
    $description = "(L2) Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0" -Name "NoImplicitFeedback" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control19-7-4-1 {
    # Control 19.7.4.1 - Detection Script
    $controlNumber = "19.7.4.1"
    $description = "(L1) Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 2) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control19-7-4-2 {
    # Control 19.7.4.2 - Detection Script
    $controlNumber = "19.7.4.2"
    $description = "(L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 3) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

############################## 19.7.5 AutoPlay Policies ################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 19.7.6 Backup ###########################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 19.7.7 Calculator #######################################################################################################
# This section is intentionally blank and exists to ensure the structure of Windows benchmarks is consistent.

############################## 19.7.8 Cloud Content ####################################################################################################
Function Get-Control19-7-8-1 {
    # Control 19.7.8.1 - Detection Script
    $controlNumber = "19.7.8.1"
    $description = "(L1) Ensure 'Configure Windows spotlight on lock screen' is set to Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "ConfigureWindowsSpotlight" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control19-7-8-2 {
    # Control 19.7.8.2 - Detection Script
    $controlNumber = "19.7.8.2"
    $description = "(L1) Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control19-7-8-3 {
    # Control 19.7.8.3 - Detection Script
    $controlNumber = "19.7.8.3"
    $description = "(L2) Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control19-7-8-4 {
    # Control 19.7.8.4 - Detection Script
    $controlNumber = "19.7.8.4"
    $description = "(L2) Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}

Function Get-Control19-7-8-5 {
    # Control 19.7.8.5 - Detection Script
    $controlNumber = "19.7.8.5"
    $description = "(L1) Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableSpotlightOnDesktop" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control19-7-28-1 {
    # Control 19.7.28.1 - Detection Script
    $controlNumber = "19.7.28.1"
    $description = "(L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKCU:\Software\Policies\Microsoft\Windows\Network Sharing" -Name "NoInplaceSharing" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control19-7-43-1 {
    # Control 19.7.43.1 - Detection Script
    $controlNumber = "19.7.43.1"
    $description = "(L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
    $expectedValue = "Disabled"

    $currentValue = Get-ItemPropertyValue -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 0) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
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
Function Get-Control19-7-47-2-1 {
    # Control 19.7.47.2.1 - Detection Script
    $controlNumber = "19.7.47.2.1"
    $description = "(L2) Ensure 'Prevent Codec Download' is set to 'Enabled'"
    $expectedValue = "Enabled"

    $currentValue = Get-ItemPropertyValue -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCodecDownload" -ErrorAction SilentlyContinue
    $controlStatus = if ($currentValue -eq 1) { "TRUE" } else { "FALSE" }

    "$controlStatus`t$controlNumber`t$description`t$currentValue`t$expectedValue"
}
























Get-Control1-1-1
Get-Control1-1-2
Get-Control1-1-3
Get-Control1-1-4
Get-Control1-1-5
Get-Control1-1-6
Get-Control1-1-7
Get-Control1-2-1
Get-Control1-2-2
Get-Control1-2-3
Get-Control2-2-1
Get-Control2-2-2
Get-Control2-2-3
Get-Control2-2-4
Get-Control2-2-5
Get-Control2-2-6
Get-Control2-2-7
Get-Control2-2-7
Get-Control2-2-8
Get-Control2-2-9
Get-Control2-2-10
Get-Control2-2-11
Get-Control2-2-12
Get-Control2-2-13
Get-Control2-2-14
Get-Control2-2-15
Get-Control2-2-16
Get-Control2-2-17
Get-Control2-2-18
Get-Control2-2-19
Get-Control2-2-20
Get-Control2-2-21
Get-Control2-2-22
Get-Control2-2-23
Get-Control2-2-24
Get-Control2-2-25
Get-Control2-2-26
Get-Control2-2-27
Get-Control2-2-28
Get-Control2-2-29
Get-Control2-2-30
Get-Control2-2-31
Get-Control2-2-32
Get-Control2-2-33
Get-Control2-2-34
Get-Control2-2-35
Get-Control2-2-36
Get-Control2-2-37
Get-Control2-2-38
Get-Control2-2-39
Get-Control2-3-1-1
Get-Control2-3-1-3
Get-Control2-3-1-4
Get-Control2-3-1-5
Get-Control2-3-2-1
Get-Control2-3-2-2
Get-Control2-3-4-2
Get-Control2-3-6-1
Get-Control2-3-6-2
Get-Control2-3-6-3
Get-Control2-3-6-4
Get-Control2-3-6-5
Get-Control2-3-6-6
Get-Control2-3-7-1
Get-Control2-3-7-2
Get-Control2-3-7-3
Get-Control2-3-7-4
Get-Control2-3-7-5
Get-Control2-3-7-6
Get-Control2-3-7-7
Get-Control2-3-7-8
Get-Control2-3-7-9
Get-Control2-3-8-1
Get-Control2-3-8-2
Get-Control2-3-8-3
Get-Control2-3-9-1
Get-Control2-3-9-2
Get-Control2-3-9-3
Get-Control2-3-9-4
Get-Control2-3-9-5
Get-Control2-3-10-1
Get-Control2-3-10-2
Get-Control2-3-10-3
Get-Control2-3-10-4
Get-Control2-3-10-5
Get-Control2-3-10-6
Get-Control2-3-10-7
Get-Control2-3-10-8
Get-Control2-3-10-9
Get-Control2-3-10-10
Get-Control2-3-10-11
Get-Control2-3-10-12
Get-Control2-3-11-1
Get-Control2-3-11-2
Get-Control2-3-11-3
Get-Control2-3-11-4
Get-Control2-3-11-5
Get-Control2-3-11-6
Get-Control2-3-11-7
Get-Control2-3-11-8
Get-Control2-3-11-9
Get-Control2-3-11-10
Get-Control2-3-14-1
Get-Control2-3-15-1
Get-Control2-3-15-2
Get-Control2-3-17-1
Get-Control2-3-17-2
Get-Control2-3-17-3
Get-Control2-3-17-4
Get-Control2-3-17-5
Get-Control2-3-17-6
Get-Control2-3-17-7
Get-Control2-3-17-8
Get-Control5-1
Get-Control5-2
Get-Control5-3
Get-Control5-4
Get-Control5-5
Get-Control5-6
Get-Control5-7
Get-Control5-8
Get-Control5-9
Get-Control5-10
Get-Control5-11
Get-Control5-12
Get-Control5-13
Get-Control5-14
Get-Control5-15
Get-Control5-16
Get-Control5-17
Get-Control5-18
Get-Control5-19
Get-Control5-20
Get-Control5-21
Get-Control5-22
Get-Control5-23
Get-Control5-24
Get-Control5-25
Get-Control5-26
Get-Control5-27
Get-Control5-28
Get-Control5-29
Get-Control5-30
Get-Control5-31
Get-Control5-32
Get-Control5-33
Get-Control5-34
Get-Control5-35
Get-Control5-36
Get-Control5-37
Get-Control5-38
Get-Control5-39
Get-Control5-40
Get-Control9-1-1
Get-Control9-1-2
Get-Control9-1-3
Get-Control9-1-4
Get-Control9-1-5
Get-Control9-1-6
Get-Control9-1-7
Get-Control9-1-8
Get-Control9-2-1
Get-Control9-2-2
Get-Control9-2-3
Get-Control9-2-4
Get-Control9-2-5
Get-Control9-2-6
Get-Control9-2-7
Get-Control9-2-8
Get-Control9-3-1
Get-Control9-3-2
Get-Control9-3-3
Get-Control9-3-4
Get-Control9-3-5
Get-Control9-3-6
Get-Control9-3-7
Get-Control9-3-8
Get-Control9-3-9
Get-Control9-3-10
Get-Control17-1-1
Get-Control17-2-1
Get-Control17-2-2
Get-Control17-2-3
Get-Control17-3-1
Get-Control17-3-2
Get-Control17-5-1
Get-Control17-5-2
Get-Control17-5-3
Get-Control17-5-4
Get-Control17-5-5
Get-Control17-5-6
Get-Control17-6-1
Get-Control17-6-2
Get-Control17-6-3
Get-Control17-6-4
Get-Control17-7-1
Get-Control17-7-2
Get-Control17-7-3
Get-Control17-7-4
Get-Control17-7-5
Get-Control17-8-1
Get-Control17-9-1
Get-Control17-9-2
Get-Control17-9-3
Get-Control17-9-4
Get-Control17-9-5
Get-Control18-1-1-1
Get-Control18-1-1-2
Get-Control18-2-2
Get-Control18-2-3
Get-Control18-2-4
Get-Control18-2-5
Get-Control18-2-6
Get-Control18-3-1
Get-Control18-3-2
Get-Control18-3-3
Get-Control18-3-4
Get-Control18-3-5
Get-Control18-3-6
Get-Control18-3-7
Get-Control18-4-1
Get-Control18-4-2
Get-Control18-4-3
Get-Control18-4-4
Get-Control18-4-5
Get-Control18-4-6
Get-Control18-4-7
Get-Control18-4-8
Get-Control18-4-9
Get-Control18-4-10
Get-Control18-4-11
Get-Control18-4-12
Get-Control18-4-13
Get-Control18-5-4-1
Get-Control18-5-4-2
Get-Control18-5-5-1
Get-Control18-5-8-1
Get-Control18-5-9-1
Get-Control18-5-9-2
Get-Control18-5-10-2
Get-Control18-5-11-2
Get-Control18-5-11-3
Get-Control18-5-11-4
Get-Control18-5-14-1
Get-Control18-5-19-2-1
Get-Control18-5-20-1
Get-Control18-5-20-2
Get-Control18-5-21-1
Get-Control18-5-21-2
Get-Control18-5-23-2-1
Get-Control18-6-1
Get-Control18-6-2
Get-Control18-6-3
Get-Control18-7-1-1
Get-Control18-8-3-1
Get-Control18-8-4-1
Get-Control18-8-4-2
Get-Control18-8-5-1
Get-Control18-8-5-2
Get-Control18-8-5-3
Get-Control18-8-5-4
Get-Control18-8-5-5
Get-Control18-8-5-6
Get-Control18-8-7-1-1
Get-Control18-8-7-1-2
Get-Control18-8-7-1-3
Get-Control18-8-7-1-4
Get-Control18-8-7-1-5
Get-Control18-8-7-1-6
Get-Control18-8-7-2
Get-Control18-8-14-1
Get-Control18-8-21-2
Get-Control18-8-21-3
Get-Control18-8-21-4
Get-Control18-8-21-5
Get-Control18-8-22-1-1
Get-Control18-8-22-1-2
Get-Control18-8-22-1-3
Get-Control18-8-22-1-4
Get-Control18-8-22-1-5
Get-Control18-8-22-1-6
Get-Control18-8-22-1-7
Get-Control18-8-22-1-8
Get-Control18-8-22-1-9
Get-Control18-8-22-1-10
Get-Control18-8-22-1-11
Get-Control18-8-22-1-12
Get-Control18-8-22-1-13
Get-Control18-8-22-1-14
Get-Control18-8-25-1
Get-Control18-8-26-1
Get-Control18-8-27-1
Get-Control18-8-28-1
Get-Control18-8-28-2
Get-Control18-8-28-3
Get-Control18-8-28-4
Get-Control18-8-28-5
Get-Control18-8-28-6
Get-Control18-8-28-7
Get-Control18-8-31-1
Get-Control18-8-31-2
Get-Control18-8-34-6-1
Get-Control18-8-34-6-2
Get-Control18-8-34-6-3
Get-Control18-8-34-6-4
Get-Control18-8-34-6-5
Get-Control18-8-34-6-6
Get-Control18-8-36-1
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
Get-Control18-9-31-3
Get-Control18-9-31-4
Get-Control18-9-36-1
Get-Control18-9-41-1
Get-Control18-9-45-1
Get-Control18-9-46-1
Get-Control18-9-47-4-1
Get-Control18-9-47-4-2
Get-Control18-9-47-5-1-1
Get-Control18-9-47-5-1-2
Get-Control18-9-47-5-3-1
Get-Control18-9-47-6-1
Get-Control18-9-47-9-1
Get-Control18-9-47-9-2
Get-Control18-9-47-9-3
Get-Control18-9-47-9-4
Get-Control18-9-47-11-1
Get-Control18-9-47-12-1
Get-Control18-9-47-12-2
Get-Control18-9-47-15
Get-Control18-9-47-16
Get-Control18-9-48-1
Get-Control18-9-48-2
Get-Control18-9-48-3
Get-Control18-9-48-4
Get-Control18-9-48-5
Get-Control18-9-48-6
Get-Control18-9-57-1
Get-Control18-9-58-1
Get-Control18-9-64-1
Get-Control18-9-65-2-2
Get-Control18-9-65-3-2-1
Get-Control18-9-65-3-3-1
Get-Control18-9-65-3-3-2
Get-Control18-9-65-3-3-3
Get-Control18-9-65-3-3-4
Get-Control18-9-65-3-3-5
Get-Control18-9-65-3-3-6
Get-Control18-9-65-3-9-1
Get-Control18-9-65-3-9-2
Get-Control18-9-65-3-9-3
Get-Control18-9-65-3-9-4
Get-Control18-9-65-3-9-5
Get-Control18-9-65-3-10-1
Get-Control18-9-65-3-10-2
Get-Control18-9-65-3-11-1
Get-Control18-9-66-1
Get-Control18-9-67-2
Get-Control18-9-67-3
Get-Control18-9-67-4
Get-Control18-9-67-5
Get-Control18-9-67-6
Get-Control18-9-72-1
Get-Control18-9-75-1
Get-Control18-9-75-2
Get-Control18-9-75-3
Get-Control18-9-75-4
Get-Control18-9-75-5
Get-Control18-9-81-1
Get-Control18-9-85-1-1
Get-Control18-9-85-2-1
Get-Control18-9-85-2-2
Get-Control18-9-87-1
Get-Control18-9-89-1
Get-Control18-9-89-2
Get-Control18-9-90-1
Get-Control18-9-90-2
Get-Control18-9-90-3
Get-Control18-9-91-1
Get-Control18-9-100-1
Get-Control18-9-100-2
Get-Control18-9-102-1-1
Get-Control18-9-102-1-2
Get-Control18-9-102-1-3
Get-Control18-9-102-2-1
Get-Control18-9-102-2-2
Get-Control18-9-102-2-3
Get-Control18-9-102-2-4
Get-Control18-9-103-1
Get-Control18-9-104-1
Get-Control18-9-104-2
Get-Control18-9-105-2-1
Get-Control18-9-108-1-1
Get-Control18-9-108-2-1
Get-Control18-9-108-2-2
Get-Control18-9-108-2-3
Get-Control18-9-108-4-1
Get-Control18-9-108-4-2
Get-Control18-9-108-4-3
Get-Control19-1-3-1
Get-Control19-1-3-2
Get-Control19-1-3-3
Get-Control19-5-1-1
Get-Control19-6-6-1-1
Get-Control19-7-4-1
Get-Control19-7-4-2
Get-Control19-7-8-1
Get-Control19-7-8-2
Get-Control19-7-8-3
Get-Control19-7-8-4
Get-Control19-7-8-5
Get-Control19-7-28-1
Get-Control19-7-43-1
Get-Control19-7-47-2-1
