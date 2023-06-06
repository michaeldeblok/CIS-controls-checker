

New-Item "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
New-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name NoToastApplicationNotificationOnLockScreen -Value "1"
Write-Host "19.5.1.1; (L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'" -ForeGroundColor Cyan


New-Item "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0"
New-ItemProperty "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0" -Name NoImplicitFeedback -Value "1"
Write-Host "19.6.6.1.1; (L2) Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'" -ForeGroundColor Cyan


New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name SaveZoneInformation -Value "2"
Write-Host "19.7.4.1; (L1) Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'" -ForeGroundColor Cyan


New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name ScanWithAntiVirus -Value "3"
Write-Host "19.7.4.2; (L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'" -ForeGroundColor Cyan


New-Item "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
New-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name ConfigureWindowsSpotlight -Value "2"
Write-Host "19.7.8.1; (L1) Ensure 'Configure Windows spotlight on lock screen' is set to Disabled'" -ForeGroundColor Cyan


New-Item "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
New-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableThirdPartySuggestions -Value "1"
Write-Host "19.7.8.2; (L1) Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'" -ForeGroundColor Cyan


New-Item "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
New-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableTailoredExperiencesWithDiagnosticData -Value "1"
Write-Host "19.7.8.3; (L2) Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'" -ForeGroundColor Cyan


New-Item "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
New-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsSpotlightFeatures -Value "1"
Write-Host "19.7.8.4; (L2) Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'" -ForeGroundColor Cyan


New-Item "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
New-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableSpotlightCollectionOnDesktop -Value "1"
Write-Host "19.7.8.5; (L1) Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled'" -ForeGroundColor Cyan


New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoInplaceSharing -Value "1"
Write-Host "19.7.28.1; (L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'" -ForeGroundColor Cyan


New-Item "HKCU:\Software\Policies\Microsoft\Windows\Installer"
New-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -Value "0"
Write-Host "19.7.43.1; (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'" -ForeGroundColor Cyan


New-Item "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer"
New-ItemProperty "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name PreventCodecDownload -Value "1"
Write-Host "19.7.47.2.1; (L2) Ensure 'Prevent Codec Download' is set to 'Enabled'" -ForeGroundColor Cyan

