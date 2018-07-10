rem disable lock screen
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreen /t REG_DWORD /d 1 /f
rem maximum mouse speed
reg add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "20" /f
rem disable hiding of unused tray icons
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d 0 /f
rem disable snap assist
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SnapAssist" /t REG_DWORD /d "0" /f
rem show hidden files in explorer
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
rem show file extensions in explorer
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
rem disable notification centre in tray
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
rem disable action centre
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d 0 /f
rem open explorer to this pc instead of quick access
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f
rem disable windows defender sample submission
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 0 /f
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
reg add "HKCU\Software\Classes\.bmp" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.gif" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.ico" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.jpeg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.jpg" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.png" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.tiff" /ve /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
rem notepad file associations
reg add "HKCR\.cfg" /ve /t REG_SZ /d "txtfile" /f
reg add "HKCR\.cpp" /ve /t REG_SZ /d "txtfile" /f
reg add "HKCR\.cue" /ve /t REG_SZ /d "txtfile" /f
reg add "HKCR\.go" /ve /t REG_SZ /d "txtfile" /f
reg add "HKCR\.json" /ve /t REG_SZ /d "txtfile" /f
reg add "HKCR\.nfo" /ve /t REG_SZ /d "txtfile" /f
reg add "HKCR\.nfo-orig" /ve /t REG_SZ /d "txtfile" /f
reg add "HKCR\.patch" /ve /t REG_SZ /d "txtfile" /f
reg add "HKCR\.sh" /ve /t REG_SZ /d "txtfile" /f
reg add "HKCR\.srt" /ve /t REG_SZ /d "txtfile" /f
reg add "HKCR\.toml" /ve /t REG_SZ /d "txtfile" /f
reg add "HKCR\.yml" /ve /t REG_SZ /d "txtfile" /f
rem disable various services
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppMgmt" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CscService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupListener" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\HomeGroupProvider" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvr" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TrkWks" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WebClient" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "4" /f
rem rename computer name from unique gibberish to Username-PC
reg add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "NV Hostname" /t REG_SZ /d "%username%-PC" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "Hostname" /t REG_SZ /d "%username%-PC" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NV Hostname" /t REG_SZ /d "%username%-PC" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Hostname" /t REG_SZ /d "%username%-PC" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\ComputerName\ComputerName" /v "ComputerName" /t REG_SZ /d "%username%-PC" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\ComputerName\ActiveComputerName" /v "ComputerName" /t REG_SZ /d "%username%-PC" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "LastComputerName" /t REG_SZ /d "%username%-PC" /f
reg add "HKCU\Volatile Environment" /v "LOGONSERVER" /t REG_SZ /d "\\%username%-PC" /f
reg add "HKCU\Volatile Environment" /v "USERDOMAIN" /t REG_SZ /d "%username%-PC" /f
reg add "HKCU\Volatile Environment" /v "USERDOMAIN_ROAMINGPROFILE" /t REG_SZ /d "%username%-PC" /f
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
reg dd "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v "Append Completion" /t REG_SZ /d "yes" /f
rem hide ' - shortcut' text on shortcuts
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "link" /t REG_BINARY /d "00000000" /f
rem show application names in taskbar
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarGlomLevel" /t REG_DWORD /d "2" /f
rem disable aero shake
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "NoWindowMinimizingShortcuts" /t REG_DWORD /d "1" /f
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
rem small taskbar icon size
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSmallIcons" /t REG_DWORD /d "1" /f
rem have a stab at disabling telemetry
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
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
rem don't search online
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
rem disable admin shares
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "0" /f
rem minimise explorer ribbon by default, ugh what a mess
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" /v "QatItems" /t REG_BINARY /d "3c7369713a637573746f6d554920786d6c6e733a7369713d22687474703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f77696e646f77732f323030392f726962626f6e2f716174223e3c7369713a726962626f6e206d696e696d697a65643d2274727565223e3c7369713a71617420706f736974696f6e3d2230223e3c7369713a736861726564436f6e74726f6c733e3c7369713a636f6e74726f6c206964513d227369713a3136313238222076697369626c653d2266616c73652220617267756d656e743d223022202f3e3c7369713a636f6e74726f6c206964513d227369713a3136313239222076697369626c653d2266616c73652220617267756d656e743d223022202f3e3c7369713a636f6e74726f6c206964513d227369713a3132333532222076697369626c653d2266616c73652220617267756d656e743d223022202f3e3c7369713a636f6e74726f6c206964513d227369713a3132333834222076697369626c653d22747275652220617267756d656e743d223022202f3e3c7369713a636f6e74726f6c206964513d227369713a3132333336222076697369626c653d22747275652220617267756d656e743d223022202f3e3c7369713a636f6e74726f6c206964513d227369713a3132333537222076697369626c653d2266616c73652220617267756d656e743d223022202f3e3c2f7369713a736861726564436f6e74726f6c733e3c2f7369713a7161743e3c2f7369713a726962626f6e3e3c2f7369713a637573746f6d55493e" /f
rem remap altgr key to lalt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layout" /v "Scancode Map" /t REG_BINARY /d "000000000000000002000000380038e000000000" /f
rem support redshift experimental builds
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ICM" /v "GdiIcmGammaRange" /t REG_DWORD /d "256" /f