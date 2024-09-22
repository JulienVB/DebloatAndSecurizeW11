##Debloat+Security Script by jvb##
##
##V2.1
##
#Requires -RunAsAdministrator
##
$infomsg = "`r`n" +
"###########################################################################################`r`n" +
"### Windows 10/11 Hardening V2.1 (Vanbelle J.) ###`r`n" +
"###########################################################################################`r`n"
Write-Host $infomsg
##
#Disable Telemetry
##
Write-Output "Disabling Telemetry..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
##
#Uninstall all pre-installed apps
##
#Prevents "Suggested Applications" returning
New-Item -Force  "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
##
# Disable Windows Copilot for the current user
New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Type DWord -Value 1
##
# Disable Windows Copilot for all users
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Type DWord -Value 1
##
# Hide the Copilot button and disable its functionality for the current user
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Type DWord -Value 0
##
# Output a confirmation message
Write-Output "The Copilot button has been disabled and hidden from the taskbar."
 
#Uninstall the Copilot application
Get-AppxPackage *Windows.Copilot* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Copilot* | Remove-AppxPackage
 
# Output a confirmation message
Write-Output "The Copilot application has been uninstalled."

Write-Output "Kill OneDrive process"
Stop-Process -Force -Name "OneDrive.exe"
Stop-Process -Force -Name "explorer.exe"

Write-Output "Remove OneDrive"
 if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
     & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
 }
 if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
     & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
 }

Write-Output "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
#check if directory is empty before removing:
 If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
     Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
 }

Write-Output "Disable OneDrive via Group Policies"
Mkdir -Force  "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
Set-ItemProperty "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

Write-Output "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

Write-Output "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

Write-Output "Removing startmenu entry"
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

Write-Output "Removing scheduled task"
 Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

Write-Output "Restarting explorer"
Start-Process "explorer.exe"

Write-Output "Waiting for explorer to complete loading"
Start-Sleep 10

#Remove Bloatware Windows Apps
#Weather App
Write-Output "Removing Weather App"
Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.BingWeather" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
#Money App
Write-Output "Removing Money App"
Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.BingFinance" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
#Sports App
Write-Output "Removing Sports App"
Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.BingSports" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
#Twitter App
Write-Output "Removing Twitter App"
Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*.Twitter" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
#XBOX App
Write-Output "Removing XBOX App"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.XboxApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
#Sway App
Write-Output "Removing Sway App"
Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.Office.Sway" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
#Onenote App
Write-Output "Removing Onenote App"
Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.Office.OneNote" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
#Get Office App
Write-Output "Removing Get Office App"
Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.MicrosoftOfficeHub" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
#Get Skype App
Write-Output "Removing skype App"
Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.SkypeApp" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
##Uninstall Cortana
Get-AppxPackage *Microsoft.549981C3F5F10* | Remove-AppxPackage
##Removing all leftover's apps
$confirmation = Read-Host "Do you want to delete ALL Windows pre-installed apps ?(y/n)"
if ($confirmation -eq 'y') {
    Write-Output "Removing all apps remaining..."
	Get-AppxPackage -allusers | Remove-AppxPackage -erroraction 'silentlycontinue'
	Write-Output "All pre-installed apps deleted !"
}
##
#Disable Xbox related scheduled tasks
Write-Output "Disable Xbox related scheduled tasks"
Get-ScheduledTask -TaskPath "\Microsoft\XblGameSave\" | Disable-ScheduledTask
##
#Set google as main HomePage on MS Edge
##
$registryPath = 'HKLM:\Software\Policies\Microsoft\Edge' 
$regpath = 'HKLM:\Software\Policies\Microsoft\Edge\RestoreOnStartupURLs' 
$value = 0x00000004 
$URL= 'https://www.google.be/' 

Set-Location $registrypath 
New-Item -Name RestoreOnStartupURLs -Force 
Set-Itemproperty -Path $regpath -Name 1 -Value $URL  
 
Write-Host "The homepage has been set as: $URL" 
##
###################### Harden options ###########################
##
$infomsg1 = "`r`n" +
"###########################################################################################`r`n" +
"### Software Hardening ###`r`n" +
"###########################################################################################`r`n"
Write-Host $infomsg1
#Disable WIFI Sense
Write-Output "Disabling Wi-Fi Sense..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type Dword -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type Dword -Value 0
Write-Output "Disabling Bing Search in Start Menu..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
Write-Output "Disabling Location Tracking..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
Write-Output "Disabling Tailored Experiences..."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
Write-Output "Disabling Advertising ID..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
#Disable Autorun
Write-Output "Disabling Autorun for all drives..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
#Disable Fast Boot
Write-Output "Disabling Fast Startup..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
#Basic authentication for RSS feeds over HTTP must not be used.
New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer" -Name "Feeds" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Name "AllowBasicAuthInClear" -Type "DWORD" -Value 0 -Force
#AutoComplete feature for forms must be disallowed.
New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "Main Criteria" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "Use FormSuggest" -Type "String" -Value no -Force
New-Item -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\" -Name "Main Criteria" -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "Use FormSuggest" -Type "String" -Value no -Force
#Turn on the auto-complete feature for user names and passwords on forms must be disabled.
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "FormSuggest PW Ask" -Type "String" -Value no -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "FormSuggest PW Ask" -Type "String" -Value no -Force
#Zone information must be preserved when saving attachments.
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name "Main Criteria" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name "SaveZoneInformation" -Type "DWORD" -Value 2 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name "SaveZoneInformation" -Type "DWORD" -Value 2 -Force
#Toast notifications to the lock screen must be turned off.
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\" -Name "PushNotifications" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" -Name "NoToastApplicationNotificationOnLockScreen" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" -Name "NoToastApplicationNotificationOnLockScreen" -Type "DWORD" -Value 1 -Force
#Windows 10 should be configured to prevent users from receiving suggestions for third-party or additional applications.
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "CloudContent" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Type "DWORD" -Value 1 -Force
#Windows 10 must be configured to prevent Windows apps from being activated by voice while the system is locked.
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "AppPrivacy" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\" -Name "LetAppsActivateWithVoice" -Type "DWORD" -Value 2 -Force
#The Windows Explorer Preview pane must be disabled for Windows 10.
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "Explorer" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoReadingPane" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoReadingPane" -Type "DWORD" -Value 1 -Force
#Disable NetBIOS by updating Registry
#http://blog.dbsnet.fr/disable-netbios-with-powershell#:~:text=Disabling%20NetBIOS%20over%20TCP%2FIP,connection%2C%20then%20set%20NetbiosOptions%20%3D%202
$key = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $key | ForEach-Object { 
    Write-Host("Modify $key\$($_.pschildname)")
    $NetbiosOptions_Value = (Get-ItemProperty "$key\$($_.pschildname)").NetbiosOptions
    Write-Host("NetbiosOptions updated value is $NetbiosOptions_Value")
    }
#Block Untrusted Fonts
#https://adsecurity.org/?p=3299
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" -Name "MitigationOptions" -Type "DWORD" -Value "1000000000000" -Force
#Disable Hibernate
powercfg -h off
##
#Windows Defender Hardening
##
#Enable Windows Defender Application Control
#Enable real-time monitoring
Write-Host "Enable real-time monitoring"
Set-MpPreference -DisableRealtimeMonitoring 0
#Enable sample submission
Write-Host "Enable sample submission"
Set-MpPreference -SubmitSamplesConsent 1
#Enable checking signatures before scanning
Write-Host "Enable checking signatures before scanning"
Set-MpPreference -CheckForSignaturesBeforeRunningScan 1
#Enable behavior monitoring
Write-Host "Enable behavior monitoring"
Set-MpPreference -DisableBehaviorMonitoring 0
#Enable IOAV protection
Write-Host "Enable IOAV protection"
Set-MpPreference -DisableIOAVProtection 0
#Enable script scanning
Write-Host "Enable script scanning"
Set-MpPreference -DisableScriptScanning 0
#Enable removable drive scanning
Write-Host "Enable removable drive scanning"
Set-MpPreference -DisableRemovableDriveScanning 0
#Enable Block at first sight
Write-Host "Enable Block at first sight"
Set-MpPreference -DisableBlockAtFirstSeen 0
#Enable potentially unwanted 
Write-Host "Enable potentially unwanted apps"
Set-MpPreference -PUAProtection Enabled
#Schedule signature updates every 8 hours
Write-Host "Schedule signature updates every 8 hours"
Set-MpPreference -SignatureUpdateInterval 8
#Enable archive scanning
Write-Host "Enable archive scanning"
Set-MpPreference -DisableArchiveScanning 0
#Enable email scanning
Write-Host "Enable email scanning"
Set-MpPreference -DisableEmailScanning 0
#Enable File Hash Computation
Write-Host "Enable File Hash Computation"
Set-MpPreference -EnableFileHashComputation 1
#Enable Intrusion Prevention System
Write-Host "Enable Intrusion Prevention System"
Set-MpPreference -DisableIntrusionPreventionSystem $false
#Set cloud block level to 'High'
Write-Host "Set cloud block level to 'High'"
Set-MpPreference -CloudBlockLevel High
#Set cloud block timeout to 1 minute
Write-Host "Set cloud block timeout to 1 minute"
Set-MpPreference -CloudExtendedTimeout 50
Write-Host "Updating Windows Defender Exploit Guard settings"
#Enabling Controlled Folder Access and setting to block mode
Write-Host "Enabling Controlled Folder Access and setting to block mode"
Set-MpPreference -EnableControlledFolderAccess Enabled 

#Enable Cloud-delivered Protections
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

#Enable Windows Defender Attack Surface Reduction Rules
#https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/enable-attack-surface-reduction
#https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction
#Block executable content from email client and webmail
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
#Block all Office applications from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
#Block Office applications from creating executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
#Block Office applications from injecting code into other processes
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
#Block JavaScript or VBScript from launching downloaded executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
#Block execution of potentially obfuscated scripts
Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
#Block Win32 API calls from Office macros
Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
#Block executable files from running unless they meet a prevalence, age, or trusted list criterion
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions AuditMode
#Use advanced protection against ransomware
Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions Enabled
#Block credential stealing from the Windows local security authority subsystem
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
#Block process creations originating from PSExec and WMI commands
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions AuditMode
#Block untrusted and unsigned processes that run from USB
Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
#Block Office communication application from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
#Block Adobe Reader from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
#Block persistence through WMI event subscription
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
##
#Disable SHA1
##
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" -Force -Name Enabled -Type "DWORD" -Value 0x00000000
##
#SMB Optimizations + Hardening
Write-Output "SMB Optimizations"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DisableBandwidthThrottling" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "FileInfoCacheEntriesMax" -Type "DWORD" -Value 1024 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DirectoryCacheEntriesMax" -Type "DWORD" -Value 1024 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "FileNotFoundCacheEntriesMax" -Type "DWORD" -Value 2048 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type "DWORD" -Value 20 -Force
Set-SmbServerConfiguration -EnableMultiChannel $true -Force 
Set-SmbServerConfiguration -MaxChannelPerSession 16 -Force
Set-SmbServerConfiguration -ServerHidden $False -AnnounceServer $False -Force
Set-SmbServerConfiguration -EnableLeasing $false -Force
Set-SmbClientConfiguration -EnableLargeMtu $true -Force
Set-SmbClientConfiguration -EnableMultiChannel $true -Force
        
#SMB Hardening
Write-Output "SMB Hardening"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "RestrictAnonymousSAM" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" -Value 256 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "RestrictAnonymous" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Type "DWORD" -Value 1 -Force
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart
Set-SmbClientConfiguration -RequireSecuritySignature $True -Force
Set-SmbClientConfiguration -EnableSecuritySignature $True -Force
Set-SmbServerConfiguration -EncryptData $True -Force 
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force 
##
#Enable Windows Defender
##
Write-Output "Enabling Windows Defender..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
	}
##
#Disable Copilot
##
Write-Output "Disabling Windows Copilot on the system"
reg add HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot /v "TurnOffWindowsCopilot" /t REG_DWORD /f /d 1
##
#Turn off multicast name resolution
##
Write-Output "Turn off multicast name resolution"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "DWORD" -Value 1 -Force
##
#Disable insecure guest logons
##
Write-Output "Disable insecure guest logons"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\" -Name "LanmanWorkstation" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Type "DWORD" -Value 0 -Force
##
#Turn off Microsoft Peer-to-Peer Networking Services
##
Write-Output "Turn off Microsoft Peer-to-Peer Networking Services"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -Name "Disabled" -Type "DWORD" -Value 1 -Force
##
#Prevent enabling lock screen camera
##
Write-Output "Prevent enabling lock screen camera"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\" -Name "Personalization" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Type "DWORD" -Value 1 -Force
##
#Package Point and print - Approved servers
##
Write-Output "Package Point and print - Approved servers"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\" -Name "Printers" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "PackagePointAndPrint" -Type "DWORD" -Value 1 -Force
##
#Only use Package Point and print
##
Write-Output "Only use Package Point and print"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "PackagePointAndPrintOnly" -Type "DWORD" -Value 1 -Force
##
#Disable delegating default credentials
##
Write-Output "Disable delegating default credentials"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\" -Name "CredentialsDelegation" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowDefaultCredentials" -Type "DWORD" -Value 0 -Force
##
#Remote host allows delegation of non-exportable credentials
##
Write-Output "Disable remote host allows delegation of non-exportable credentials"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -Type "DWORD" -Value 1 -Force
##
#Prevent installation of devices using drivers that match d48179be-ec20-11d1-b6b8-00c04fa372a7 (SBP-2 drive)
##
Write-Output "Prevent installation of devices using drivers that match d48179be-ec20-11d1-b6b8-00c04fa372a7 (SBP-2 drive)"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\" -Name "DeviceInstall" -Force
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\" -Name "Restrictions" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClasses" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClassesRetroactive" -Type "DWORD" -Value 1 -Force
##
#Turn On Virtualization Based Security
##
Write-Output "Turn On Virtualization Based Security"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\" -Name "DeviceGuard" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Type "DWORD" -Value 3 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Type "DWORD" -Value 1 -Force
##
#Boot-Start Driver Initialization Policy
##
Write-Output "Boot-Start Driver Initialization Policy"
New-Item -Path "HKLM:\System\CurrentControlSet\Policies\" -Name "EarlyLaunch" -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Type "DWORD" -Value 3 -Force
##
#Do not display network selection UI
##
Write-Output "Do not display network selection UI"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type "DWORD" -Value 1 -Force
##
#Turn off app notifications on the lock screen
##
Write-Output "Turn off app notifications on the lock screen"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Type "DWORD" -Value 1 -Force
##
#Turn off convenience PIN sign-in
##
Write-Output "Turn off convenience PIN sign-in"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -Type "DWORD" -Value 0 -Force
##
#Disable Clipboard synchronization across devices
##
Write-Output "Disable Clipboard synchronization across devices"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Type "DWORD" -Value 0 -Force
##
#Disable Remote Assistance
##
Write-Output "Disable Remote Assistance"
Set-ItemProperty -Path "HKLM:\SOFTWARE\policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Type "DWORD" -Value 0 -Force
##
#Enable RPC Endpoint Mapper Client Authentication
##
Write-Output "Enable RPC Endpoint Mapper Client Authentication"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\" -Name "Rpc" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Type "DWORD" -Value 1 -Force
##
#Restrict Unauthenticated RPC clients
##
Write-Output "Restrict Unauthenticated RPC clients"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -Type "DWORD" -Value 2 -Force
##
#Turn off downloading of print drivers over HTTP
##
Write-Output "Turn off downloading of print drivers over HTTP"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Type "DWORD" -Value 1 -Force
##
#Turn off the Windows Messenger Customer Experience Improvement Program
##
Write-Output "Turn off the Windows Messenger Customer Experience Improvement Program"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Messenger" -Force
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\" -Name "Client" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client\" -Name "CEIP" -Type "DWORD" -Value 2 -Force
##
#Turn off Internet download for Web publishing and online ordering wizards
##
Write-Output "Turn off Internet download for Web publishing and online ordering wizards"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -Type "DWORD" -Value 1 -Force
##
#Turn off Help Experience Improvement Program
##
Write-Output "Turn off Help Experience Improvement Program"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Assistance" -Force
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Assistance\" -Name "Client" -Force
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Assistance\Client\" -Name "1.0" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" -Name "NoImplicitFeedback" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" -Name "NoExplicitFeedback" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" -Name "NoOnlineAssist" -Type "DWORD" -Value 1 -Force
##
#MSS Hardening
##
Write-Output "MSS Hardening"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Type "DWORD" -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Type "DWORD" -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" -Name "NoNameReleaseOnDemand" -Type "DWORD" -Value 1 -Force
##
#Turn on PowerShell Script Block Logging
##
Write-Output "Turn on PowerShell Script Block Logging"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "PowerShell" -Force
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Name "EnableScriptBlockLogging" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Name "EnableScriptBlockInvocationLogging" -Type "DWORD" -Value 1 -Force
##
#Turn off notifications network usage
##
Write-Output "Turn off notifications network usage"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Type "DWORD" -Value 1 -Force
##
#Untrusted Font Blocking
##
Write-Output "Untrusted Font Blocking"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\" -Name "MitigationOptions" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions" -Name "MitigationOptions_FontBocking" -Type "String" -Value 1000000000000 -Force
##
#Do not display the password reveal button
##
Write-Output "Do not display the password reveal button"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\" -Name "CredUI" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Type "DWORD" -Value 1 -Force
##
#Disable enumerate administrator accounts on elevation
##
Write-Output "Disable enumerate administrator accounts on elevation"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Name "EnumerateAdministrators" -Type "DWORD" -Value 0 -Force
##
#Do not show Windows Tips
##
Write-Output "Do not show Windows Tips"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type "DWORD" -Value 1 -Force
##
#Turn off Microsoft consumer experiences
##
Write-Output "Turn off Microsoft consumer experiences"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type "DWORD" -Value 1 -Force
##
#Enable LSA Protection
##
Write-Output "Enable LSA Protection"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Type "DWORD" -Value 1 -Force
##
#NetBIOS Node Type 2
##
Write-Output "NetBIOS Node Type 2"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Type "DWORD" -Value 2 -Force
##
#Turn off Autoplay
##
Write-Output "Turn off Autoplay"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type "DWORD" -Value 255 -Force
##
#Disallow Autoplay for non-volume devices
##
Write-Output "Disallow Autoplay for non-volume devices"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoplayfornonVolume" -Type "DWORD" -Value 1 -Force
##
#Set the default behavior for AutoRun
##
Write-Output "Set the default behavior for AutoRun"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Type "DWORD" -Value 1 -Force
##
#Disable Windows Ink
##
Write-Output "Disable Windows Ink"
New-Item -Path "HKLM:\Software\Policies\Microsoft\" -Name "WindowsInkWorkspace" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\" -Name "AllowWindowsInkWorkspace" -Type "DWORD" -Value 0 -Force
##
#Disable Sign-in and lock last interactive user automatically after a restart
##
Write-Output "Sign-in and lock last interactive user automatically after a restart"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" -Name "DisableAutomaticRestartSignOn" -Type "DWORD" -Value 1 -Force
##
#WinRM Client Hardening
##
Write-Output "WinRM Client Hardening"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\" -Name "WinRM" -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\" -Name "Client" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Name "AllowBasic" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Name "AllowUnencryptedTraffic" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Name "AllowDigest" -Type "DWORD" -Value 0 -Force
##
#WinRM Service Hardening
##
Write-Output "WinRM Service Hardening"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\" -Name "Service" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\" -Name "AllowAutoConfig" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\" -Name "AllowBasic" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\" -Name "AllowUnencryptedTraffic" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\" -Name "DisableRunAs" -Type "DWORD" -Value 1 -Force
##
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "WinRS" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess" -Type "DWORD" -Value 0 -Force
##
#Disable Cloud Search
##
Write-Output "Disable Cloud Search"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Type "DWORD" -Value 0 -Force
##
#Disable Cortana Search
##
Write-Output "Disable Cortana Search"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type "DWORD" -Value 0 -Force
##
#Disable Cortana above lock screen
##
Write-Output "Disable Cortana above log screen"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Type "DWORD" -Value 0 -Force
##
#Disable indexing of encrypted files
##
Write-Output "Disable indexing of encrypted files"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Type "DWORD" -Value 0 -Force
##
#Disable usage of location by Search
##
Write-Output "Disable usage of location by Search"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Type "DWORD" -Value 0 -Force
##
#Set Search shared information on Anonymous
##
Write-Output "Set Search shared information on Anonymous"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchPrivacy" -Type "DWORD" -Value 3 -Force
##
#Disable News & Interests in task bar
##
Write-Output "Disable News & Interests in task bar"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\" -Name "Windows Feeds" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type "DWORD" -Value 0 -Force
##
$infomsg2 = "`r`n" +
"###########################################################################################`r`n" +
"### Windows Firewall Hardening ###`r`n" +
"###########################################################################################`r`n"
Write-Host $infomsg2
##
#Delete UPnP FW rule
##
Write-Output "Delete UPnP FW rule"
netsh advfirewall firewall delete rule name="Cast to Device UPnP Events (TCP-In)"
##
#Disable various FW rules
##
Write-Output "Disabling various obscur Firewall Rules..."
Disable-NetFirewallRule -DisplayName "MSN Weather"
Disable-NetFirewallRule -DisplayName "Films & TV"
Disable-NetFirewallRule -DisplayName "Feedback Hub"
Disable-NetFirewallRule -DisplayName "Microsoft To Do"
Disable-NetFirewallRule -DisplayName "Store Experience Host"
Disable-NetFirewallRule -DisplayName "Windows Media Player"
Disable-NetFirewallRule -DisplayName "Network Discovery for Teredo (SSDP-In)"
Disable-NetFirewallRule -DisplayName "Desktop App Web Viewer"
Disable-NetFirewallRule -DisplayName "Delivery Optimization (TCP-In)"
Disable-NetFirewallRule -DisplayName "Delivery Optimization (UDP-In)"
Disable-NetFirewallRule -DisplayName "Microsoft Edge (mDNS-In)"
Disable-NetFirewallRule -DisplayName "Microsoft Media Foundation Network Source IN [TCP 554]"
Disable-NetFirewallRule -DisplayName "Microsoft Media Foundation Network Source IN [UDP 5004-5009]"
Disable-NetFirewallRule -DisplayName "Network Discovery for Teredo (UPnP-In)"
Disable-NetFirewallRule -DisplayName "Proximity sharing over TCP (TCP sharing-In)"
Disable-NetFirewallRule -DisplayName "Wireless Display (TCP-In)"
Disable-NetFirewallRule -DisplayName "Wireless Display Infrastructure Back Channel (TCP-In)"
Disable-NetFirewallRule -DisplayName "Core Networking - IPv6 (IPv6-In)"
Disable-NetFirewallRule -DisplayName "Start"
Disable-NetFirewallRule -DisplayName "Your account"
Disable-NetFirewallRule -DisplayName "Connected User Experiences and Telemetry"
Disable-NetFirewallRule -DisplayName "Get Help"
Disable-NetFirewallRule -DisplayName "Microsoft family features"
Disable-NetFirewallRule -DisplayName "Microsoft Clipchamp"
Disable-NetFirewallRule -DisplayName "Microsoft content"
Disable-NetFirewallRule -DisplayName "Microsoft People"
Disable-NetFirewallRule -DisplayName "Microsoft Tips"
Disable-NetFirewallRule -DisplayName "Take a Test"
Disable-NetFirewallRule -DisplayName "Windows Web Experience Pack"
Disable-NetFirewallRule -DisplayName "Xbox Game UI"
Disable-NetFirewallRule -DisplayName "Xbox Identity Provider"
Disable-NetFirewallRule -DisplayName "Windows Calculator"
Disable-NetFirewallRule -DisplayName "Windows Camera"
Disable-NetFirewallRule -DisplayName "News"
Disable-NetFirewallRule -DisplayName "NcsiUwpApp"
Disable-NetFirewallRule -DisplayName "Narrator"
Disable-NetFirewallRule -DisplayName "mDNS (UDP-Out)"
Disable-NetFirewallRule -DisplayName "Proximity sharing over TCP (TCP sharing-Out)"
Disable-NetFirewallRule -DisplayName "Core Networking - IPv6 (IPv6-Out)"
Disable-NetFirewallRule -DisplayName "Wireless Display (TCP-Out)"
Disable-NetFirewallRule -DisplayName "Wireless Display (UDP-Out)"
Disable-NetFirewallRule -DisplayName "Recommended Troubleshooting Client (HTTP/HTTPS Out)"
Disable-NetFirewallRule -DisplayName "Windows Terminal"
Disable-NetFirewallRule -DisplayName "Windows Shell Experience"
Disable-NetFirewallRule -DisplayName "Core Networking - Teredo (UDP-Out)"
Disable-NetFirewallRule -DisplayName "AllJoyn Router (TCP-In)"
Disable-NetFirewallRule -DisplayName "AllJoyn Router (UDP-In)"
Disable-NetFirewallRule -DisplayName "AllJoyn Router (TCP-Out)"
Disable-NetFirewallRule -DisplayName "AllJoyn Router (UDP-Out)"
##
#Disable mDNS
##
Write-Output "Disabling Multicast DNS"
$path='HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
$property = 'EnableMDNS'
$value = 0
New-ItemProperty -Path $Path -Name $property -Value $value -PropertyType DWORD -Force 
##
Write-Output "Disabling Multicast DNS Firewall Rule"
Disable-NetFirewallRule -DisplayName "mDNS (UDP-In)"
##
#Disable IPv6
##
Write-Output "Disabling IPv6 on all network adapters !"
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
##
#Block-TCP-NetBIOS 
##
Write-Output "Block-TCP-NetBIOS"
New-NetFirewallRule -DisplayName "Block-TCP-NetBIOS" -Direction Inbound -Action Block -Protocol TCP -LocalPort 137
Write-Output "Block-UDP-NetBIOS"
New-NetFirewallRule -DisplayName "Block-UDP-NetBIOS" -Direction Inbound -Action Block -Protocol UDP -LocalPort 137
##
##
$infomsg2 = "`r`n" +
"###########################################################################################`r`n" +
"### Services Hardening ###`r`n" +
"###########################################################################################`r`n"
Write-Host $infomsg2
Write-Output "Disabling non-critical Windows services"
Set-Service -StartupType Disabled DiagTrack
Set-Service -StartupType Disabled DPS
Set-Service -StartupType Disabled lfsvc
Set-Service -StartupType Disabled iphlpsvc
Set-Service -StartupType Disabled InstallService
Set-Service -StartupType Disabled SSDPSRV
Set-Service -StartupType Disabled XboxGipSvc
Set-Service -StartupType Disabled XblAuthManager
Set-Service -StartupType Disabled XblGameSave
Set-Service -StartupType Disabled XboxNetApiSvc
Set-Service -StartupType Disabled WebClient
Set-Service -StartupType Disabled Spooler
##
##
$infomsg3 = "`r`n" +
"###########################################################################################`r`n" +
"### Hardening & Security tweaks done ! ###`r`n" +
"###########################################################################################`r`n"
Write-Host $infomsg3 -foregroundcolor "green"
Read-Host -Prompt "Press any key to restart the computer..."
Restart-Computer
