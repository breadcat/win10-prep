
rem intro
@echo off
title Windows 10 Prep Script
pushd "%~dp0"
cls
echo.
echo  :: Windows 10 Prep Script
echo.
echo     Please review and be aware of what this script does before running it.
echo     There is no uninstaller, and backups won't be created.
echo.
rem check permissions
net session >nul 2>&1
if %errorLevel% == 0 (
    echo     You won't be prompted any further.
    echo     Press [enter] to begin.
    echo.
    set /p=
) else (
    echo     This script requires administrator rights.
    echo     Press any key to exit
    pause >nul
    exit
)

rem Process
<NUL set /p=:: System Tweaks... 
call :system_tweaks > nul
echo done
<NUL set /p=:: Registry Tweaks... 
call :registry_tweaks > nul
echo done
<NUL set /p=:: Removing Software... 
call :remove_software > nul
echo done
<NUL set /p=:: Installing Software... 
call :install_software > nul
echo done
<NUL set /p=:: Clean Up... 
call :cleanup > nul
echo done

rem complete
echo.
echo  :: Script complete
echo.
echo     Restart whenever you fancy.
echo     Press [enter] to exit.
echo.
set /p=
:eof
exit

:system_tweaks
rem enable f8 boot menu
bcdedit /set {default} bootmenupolicy legacy
rem enable admin account
net user Administrator /active:yes
rem label system drive
label %systemdrive%System
rem disable hibernation, removing hiberfil.sys
powercfg -h off
rem change ntp server addresses and resync time
w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"
w32tm /resync /nowait
rem don't require signin after wakeup
powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 0
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 0
rem batch file shortcuts
echo cls> %windir%\system32\clear.bat
echo robocopy . . /s /move> %windir%\system32\empties.bat
echo findstr %1> %windir%\system32\grep.bat
echo dir /b> %windir%\system32\ls.bat
echo del %1> %windir%\system32\rm.bat
echo exit> %windir%\system32\x.bat
exit /b %errorlevel%

:registry_tweaks
rem disable lock screen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreen /t REG_DWORD /d 1 /f
rem maximum mouse speed
reg add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "20" /f
rem disable hiding of unused tray icons
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d 0 /f
rem disable snap assist
rem reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SnapAssist" /t REG_DWORD /d "0" /f
rem show hidden files in explorer
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
rem show file extensions in explorer
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
rem disable advertising maybe
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
rem disable notification centre in tray
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
rem disable action centre
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d 0 /f
rem open explorer to this pc instead of quick access
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f
rem rename 'this pc' to 'computer'
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /ve /t REG_SZ /d "Computer" /f
rem disable recent documents in quick access in explorer
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f
rem fix photo viewer associations in ltsb
reg add "HKCR\Applications\photoviewer.dll\shell\open" /v "MuiVerb" /t REG_SZ /d "@photoviewer.dll,-3043" /f
reg add "HKCR\Applications\photoviewer.dll\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll\", ImageView_Fullscreen %%1" /f
reg add "HKCR\Applications\photoviewer.dll\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
reg add "HKCR\Applications\photoviewer.dll\shell\print\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll\", ImageView_Fullscreen %%1" /f
reg add "HKCR\Applications\photoviewer.dll\shell\print\DropTarget" /v "Clsid" /t REG_SZ /d "{60fd46de-f830-4894-a628-6fa81bc0190d}" /f
for %%x in (bmp gif ico jpeg jpg png tiff) do reg add "HKCU\Software\Classes\.%%x" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
rem support win32calc if exists
if exist %windir%\System32\win32calc.exe reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe" /v "Debugger" /t REG_SZ /d "\"%SystemRoot%\System32\win32calc.exe\"" /f
if exist %windir%\System32\win32calc.exe reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe" /v "Debugger" /t REG_SZ /d "\"%SystemRoot%\System32\win32calc.exe\"" /f
rem notepad file associations
for %%x in (cfg conf cpp cue go json md nfo nfo-orig patch php ps1 sh srt toml yml) do reg add "HKCR\.%%x" /ve /t REG_SZ /d "txtfile" /f
rem disable various services
for %%x in (AppMgmt CscService DiagTrack dmwappushservice DusmSvc HomeGroupListener HomeGroupProvider lfsvc PcaSvc ProtectedStorage RemoteRegistry SCardSvr SCPolicySvc seclogon Spooler WebClient wercplsupport WerSvc WMPNetworkSvc wscsvc WSearch) do reg add "HKLM\SYSTEM\CurrentControlSet\Services\%%x" /v "Start" /t REG_DWORD /d "4" /f
rem attempt to disable some online search 'features'
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchSafeSearch" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventRemoteQueries" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /ve /t REG_SZ /d "" /f
rem rename computer name from unique gibberish to Username-PC
reg add "HKCU\Volatile Environment" /v "LOGONSERVER" /t REG_SZ /d "\\%username%-PC" /f
reg add "HKCU\Volatile Environment" /v "USERDOMAIN" /t REG_SZ /d "%username%-PC" /f
reg add "HKCU\Volatile Environment" /v "USERDOMAIN_ROAMINGPROFILE" /t REG_SZ /d "%username%-PC" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "LastComputerName" /t REG_SZ /d "%username%-PC" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\ComputerName\ActiveComputerName" /v "ComputerName" /t REG_SZ /d "%username%-PC" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\ComputerName\ComputerName" /v "ComputerName" /t REG_SZ /d "%username%-PC" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "Hostname" /t REG_SZ /d "%username%-PC" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "NV Hostname" /t REG_SZ /d "%username%-PC" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Hostname" /t REG_SZ /d "%username%-PC" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NV Hostname" /t REG_SZ /d "%username%-PC" /f
rem add take ownership to context menu
reg add "HKCR\*\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKCR\*\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
reg add "HKCR\*\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
reg add "HKCR\*\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
reg add "HKCR\*\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
reg add "HKCR\Directory\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKCR\Directory\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
reg add "HKCR\Directory\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
reg add "HKCR\Directory\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
reg add "HKCR\Directory\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
rem disable auto-detection of installers and updates to elevate
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f
rem enable auto completion in explorer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v "Append Completion" /t REG_SZ /d "yes" /f
rem hide ' - shortcut' text on shortcuts
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "link" /t REG_BINARY /d "00000000" /f
rem show application names in taskbar
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarGlomLevel" /t REG_DWORD /d "2" /f
rem disable aero shake
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "NoWindowMinimizingShortcuts" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f
rem add control panel icon view to my computer
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{21EC2020-3AEA-1069-A2DD-08002B30309D}" /f
rem add recycle bin icon to my computer
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{645FF040-5081-101B-9F08-00AA002F954E}" /f
rem disable aggressive update reboot behaviour
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "ForcedReboot" /t REG_DWORD /d "0" /f
rem hide all desktop icons
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideIcons" /t REG_DWORD /d "1" /f
rem hide task view icon in taskbar
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f
rem hide search icon in taskbar
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f
rem hide cortana icon in taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d "0" /f
rem small taskbar icon size
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSmallIcons" /t REG_DWORD /d "1" /f
rem have a stab at disabling telemetry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
rem windows updates directly from windows instead of local network
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f
rem disable accessibility keys
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f
rem fixes "this folder is shared with other people" popup when files are created by cygwin
reg delete "HKCR\Directory\shellex\CopyHookHandlers\Sharing" /f
rem reduce menu show delay
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "75" /f
rem auto close non-responding applications on shutdown
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
reg add "HKLM\SYSTEM\ControlSet001\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
reg add "HKLM\SYSTEM\ControlSet002\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
rem disable system restore
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t REG_DWORD /d "1" /f
rem disable animations
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f
rem disable lock screen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d "1" /f
rem blank desktop background
reg add "HKCU\Control Panel\Desktop" /v "Wallpaper" /t REG_SZ /d "" /f
reg add "HKCU\Control Panel\Colors" /v "Background" /t REG_SZ /d "76 74 72" /f
rem blank login background
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d "1" /f
rem disable admin shares
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "0" /f
rem allow access to guest shares
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "AllowInsecureGuestAuth" /t REG_DWORD /d "1" /f
rem minimise explorer ribbon by default, ugh what a mess
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" /v "QatItems" /t REG_BINARY /d "3c7369713a637573746f6d554920786d6c6e733a7369713d22687474703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f77696e646f77732f323030392f726962626f6e2f716174223e3c7369713a726962626f6e206d696e696d697a65643d2274727565223e3c7369713a71617420706f736974696f6e3d2230223e3c7369713a736861726564436f6e74726f6c733e3c7369713a636f6e74726f6c206964513d227369713a3136313238222076697369626c653d2266616c73652220617267756d656e743d223022202f3e3c7369713a636f6e74726f6c206964513d227369713a3136313239222076697369626c653d2266616c73652220617267756d656e743d223022202f3e3c7369713a636f6e74726f6c206964513d227369713a3132333532222076697369626c653d2266616c73652220617267756d656e743d223022202f3e3c7369713a636f6e74726f6c206964513d227369713a3132333834222076697369626c653d22747275652220617267756d656e743d223022202f3e3c7369713a636f6e74726f6c206964513d227369713a3132333336222076697369626c653d22747275652220617267756d656e743d223022202f3e3c7369713a636f6e74726f6c206964513d227369713a3132333537222076697369626c653d2266616c73652220617267756d656e743d223022202f3e3c2f7369713a736861726564436f6e74726f6c733e3c2f7369713a7161743e3c2f7369713a726962626f6e3e3c2f7369713a637573746f6d55493e" /f
rem remap altgr key to lalt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layout" /v "Scancode Map" /t REG_BINARY /d "000000000000000002000000380038e000000000" /f
rem support redshift experimental builds
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ICM" /v "GdiIcmGammaRange" /t REG_DWORD /d "256" /f
rem remove people icon in taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d "0" /f
rem remove 3d objects folder
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
rem disable win10 game bar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
rem enable numlock on boot
reg add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f
rem disable sound scheme
reg add "HKCU\Control Panel\Sound" /v "Beep" /t REG_SZ /d "no" /f
reg add "HKCU\AppEvents\Schemes" /ve /t REG_SZ /d ".None" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\.Default\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\MailBeep\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\SystemHand\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current" /ve /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current" /ve /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v "DisableStartupSound" /t REG_DWORD /d "1" /f
rem disable wallpaper compression
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "256" /f
rem disable action centre quick actions
reg add "HKLM\SOFTWARE\Microsoft\Shell\ActionCenter\Quick Actions" /v "PinnedQuickActionSlotCount" /t REG_DWORD /d "0" /f
rem disable bing search results
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
rem disable location tracking
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d "0" /f
rem disable IE first run popup
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "1" /f
rem verbose status messages
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system" /v "verbosestatus" /t REG_DWORD /d "1" /f
exit /b %errorlevel%

:remove_software
rem remove onedrive, remove explorer tree item
tasklist /FI "IMAGENAME eq onedrive.exe" 2>NUL | find /I /N "onedrive.exe">NUL
if "%ERRORLEVEL%"=="0" echo taskkill /f /im onedrive.exe
if exist "%windir%\system32\onedrivesetup.exe" "%windir%\system32\onedrivesetup.exe" /uninstall
if exist "%windir%\syswow64\onedrivesetup.exe" "%windir%\syswow64\onedrivesetup.exe" /uninstall
reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
if exist "%userprofile%\OneDrive" rd /s /q "%userprofile%\OneDrive"
if exist "%localappdata%\Microsoft\OneDrive" rd /s /q "%localappdata%\Microsoft\OneDrive"
if exist "%programdata%\Microsoft OneDrive" rd /s /q "%programdata%\Microsoft OneDrive"
rem remove internet explorer 11
dism /online /disable-feature /featurename:Internet-Explorer-Optional-amd64 /NoRestart
rem remove silverlight (https://support.microsoft.com/en-us/kb/2608523)
reg delete HKLM\Software\Microsoft\Silverlight /f
reg delete HKCR\Installer\Products\D7314F9862C648A4DB8BE2A5B47BE100 /f
reg delete HKLM\SOFTWARE\Classes\Installer\Products\D7314F9862C648A4DB8BE2A5B47BE100 /f
reg delete HKCR\TypeLib\{283C8576-0726-4DBC-9609-3F855162009A} /f
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\install.exe /f
reg delete HKCR\AgControl.AgControl /f
reg delete HKCR\AgControl.AgControl.5.1 /f
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{89F4137D-6C26-4A84-BDB8-2E5A4BB71E00} /f
reg delete HKCU\SOFTWARE\AppDataLow\Software\Microsoft\Silverlight /f
if exist "%programfiles%\Microsoft Silverlight" rd /s /q "%programfiles%\Microsoft Silverlight"
if exist "%programfiles(x86)%\Microsoft Silverlight" rd /s /q "%programfiles(x86)%\Microsoft Silverlight"
rem remove adobe flash
if exist "%windir%\System32\Macromed" takeown /f "%windir%\System32\Macromed" /r /d y
if exist "%windir%\System32\Macromed\Flash\*.*" takeown /f "%windir%\System32\Macromed\Flash\*.*"
if exist "%windir%\SysWOW64\FlashPlayerApp.exe" takeown /f "%windir%\SysWOW64\FlashPlayerApp.exe" /r /d y
if exist "%windir%\SysWOW64\FlashPlayerCPLApp.cpl" takeown /f "%windir%\SysWOW64\FlashPlayerCPLApp.cpl" /r /d y
if exist "%windir%\SysWOW64\Macromed" takeown /f "%windir%\SysWOW64\Macromed" /r /d y
if exist "%windir%\SysWOW64\Macromed\Flash\*.*" takeown /f "%windir%\SysWOW64\Macromed\Flash\*.*"
if exist "%windir%\System32\Macromed" icacls "%windir%\System32\Macromed" /grant administrators:F /t
if exist "%windir%\SysWOW64\FlashPlayerApp.exe" icacls "%windir%\SysWOW64\FlashPlayerApp.exe" /grant administrators:F /t
if exist "%windir%\SysWOW64\FlashPlayerCPLApp.cpl" icacls "%windir%\SysWOW64\FlashPlayerCPLApp.cpl" /grant administrators:F /t
if exist "%windir%\SysWOW64\Macromed" icacls "%windir%\SysWOW64\Macromed" /grant administrators:F /t
if exist "%appdata%\Adobe" rd /s /q "%appdata%\Adobe"
if exist "%windir%\System32\Macromed" rd /s /q "%windir%\System32\Macromed"
if exist "%windir%\SysWOW64\Macromed" rd /s /q "%windir%\SysWOW64\Macromed"
if exist "%appdata%\Macromedia\Flash Player" rd /s /q "%appdata%\Macromedia\Flash Player"
if exist "%windir%\SysWOW64\FlashPlayerApp.exe" del "%windir%\SysWOW64\FlashPlayerApp.exe"
if exist "%windir%\SysWOW64\FlashPlayerCPLApp.cpl" del "%windir%\SysWOW64\FlashPlayerCPLApp.cpl"
exit /b %errorlevel%

:install_software
rem install just-install
msiexec /i https://just-install.github.io/stable/just-install.msi
rem install packages, individually for better error handling
rem essentials
just-install 7zip
just-install autohotkey
just-install ffmpeg
just-install firefox
just-install notepad2-mod
just-install putty
just-install rclone
just-install rclone-browser
just-install sumatrapdf
just-install syncthing
just-install winfsp
just-install youtube-dl
rem tools
just-install github
rem games
just-install retroarch
just-install steam
just-install teamspeak
rem add ahk-assistant if it exists
if exist %userprofile%\Vault\src\ahka\ahk-assistant.ahk reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "AHK Assistant" /t REG_SZ /d "%userprofile%\Vault\src\ahka\ahk-assistant.ahk" /f
rem install .net3, generally useful
DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart
rem install directplay, useful for old GTA games
dism /Online /enable-feature /FeatureName:"DirectPlay" /All /NoRestart
rem 7zip associations and use windows icon
reg add "HKCU\SOFTWARE\Classes\Applications\7zFM.exe\shell\open\command" /ve /t REG_SZ /d "\"%programfiles%\7-Zip\7zFM.exe\" \"%%1\"" /f
reg add "HKCR\7z_auto_file\DefaultIcon" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\system32\zipfldr.dll" /f
rem add irfanview shortcode
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\irfanview.exe" /v "Path" /t REG_SZ /d "%programfiles%\IrfanView\\" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\irfanview.exe" /ve /t REG_SZ /d "%programfiles%\IrfanView\i_view64.exe" /f
rem allow irfanview to edit ini file
if exist "%programfiles%\IrfanView" icacls "%programfiles%\IrfanView" /grant Everyone:(OI)(CI)F
rem add mumble short code
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\mumble.exe" /v "Path" /t REG_SZ /d "%programfiles(x86)%\Mumble\\" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\mumble.exe" /ve /t REG_SZ /d "%programfiles(x86)%\Mumble\mumble.exe" /f
rem agree to procmon eula
reg add "HKCU\SOFTWARE\Sysinternals\Process Monitor" /v "EulaAccepted" /t REG_DWORD /d "1" /f
rem add steam shortcode
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\steam.exe" /v "Path" /t REG_SZ /d "%programfiles(x86)%\Steam\\" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\steam.exe" /ve /t REG_SZ /d "%programfiles(x86)%\Steam\Steam.exe" /f
rem move syncthing binaries up a directory
dir /a:d /b "%programfiles%\Syncthing" > "syncthing-ver.tmp"
set /p syncthing-ver=<"syncthing-ver.tmp"
move "%programfiles%\Syncthing\%syncthing-ver%\*" "%programfiles%\Syncthing\"
rd /s /q "%programfiles%\Syncthing\%syncthing-ver%"
del "syncthing-ver.tmp"
rem move rclone binaries (similar to syncthing)
dir /a:d /b "%programfiles%\Rclone" > "rclone-ver.tmp"
set /p rclone-ver=<"rclone-ver.tmp"
move "%programfiles%\Rclone\%rclone-ver%\*" "%programfiles%\Rclone\"
rd /s /q "%programfiles%\Rclone\%rclone-ver%"
del "rclone-ver.tmp"
rem allow syncthing to auto update
icacls "%programfiles%\Syncthing" /grant Everyone:(OI)(CI)F
rem add syncthing autostart entry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Syncthing" /t REG_SZ /d "\"%programfiles%\Syncthing\syncthing.exe\" -no-console -no-browser" /f
rem add syncthing firewall rule
netsh advfirewall firewall add rule name="Syncthing" dir=in action=allow program="%programfiles%\Syncthing\syncthing.exe" enable=yes
rem install webp codec
cd "%temp%"
@powershell Invoke-WebRequest https://storage.googleapis.com/downloads.webmproject.org/releases/webp/WebpCodecSetup.exe -OutFile WebpCodecSetup.exe
"%programfiles%\7-Zip\7z.exe" x %temp%\WebpCodecSetup.exe -aoa
ren %temp%\.rsrc\0\MSIFILE\10 10.msi && msiexec /i %temp%\.rsrc\0\MSIFILE\10.msi /qn /norestart
rd /s /q ".rsrc" && del ".data" ".rdata" ".reloc" ".text" "CERTIFICATE" "WebpCodecSetup.exe"
exit /b %errorlevel%

:cleanup
if exist "%userprofile%\Desktop\*.lnk" del "%userprofile%\Desktop\*.lnk"
if exist "%allusersprofile%\Desktop\*.lnk" del "%allusersprofile%\Desktop\*.lnk"
if exist "%userprofile%\Desktop\*.appref-ms" del "%userprofile%\Desktop\*.appref-ms"
if exist "%allusersprofile%\Desktop\*.appref-ms" del "%allusersprofile%\Desktop\*.appref-ms"
if exist "%public%\Desktop\*.lnk" del "%public%\Desktop\*.lnk"
if exist "%public%\Desktop\*.lnk" del "%public%\Desktop\*.lnk"
exit /b %errorlevel%
