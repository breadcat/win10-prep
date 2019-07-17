rem install just-install
msiexec /i https://just-install.github.io/stable/just-install.msi
rem install packages, individually for better error handling
rem essentials
just-install 7zip
just-install autohotkey
just-install firefox
just-install irfanview
just-install notepad2-mod
just-install putty
just-install rclone
just-install sumatrapdf
just-install syncthing
just-install winfsp
rem tools
just-install autoruns
just-install filezilla
just-install github
just-install kodi
just-install openvpn
just-install rufus
just-install sshfs-win
just-install winscp
rem games
just-install battlenet
just-install discord
just-install epic-games-launcher
just-install origin
just-install parsec
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
icacls "%programfiles%\IrfanView" /grant Everyone:(OI)(CI)F
rem add mumble short code
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\mumble.exe" /v "Path" /t REG_SZ /d "%programfiles(x86)%\Mumble\\" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\mumble.exe" /ve /t REG_SZ /d "%programfiles(x86)%\Mumble\mumble.exe" /f
rem agree to procmon eula
reg add "HKCU\SOFTWARE\Sysinternals\Process Monitor" /v "EulaAccepted" /t REG_DWORD /d "1" /f
rem add steam shortcode
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\steam.exe" /v "Path" /t REG_SZ /d "%programfiles(x86)%\Steam\\" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\steam.exe" /ve /t REG_SZ /d "%programfiles(x86)%\Steam\Steam.exe" /f
rem move syncthing binaries up a directory
dir /b "%programfiles%\Syncthing" > "syncthing-ver.tmp"
set /p syncthing-ver=<"syncthing-ver.tmp"
move "%programfiles%\Syncthing\%syncthing-ver%\*" "%programfiles%\Syncthing\"
rd /s /q "%programfiles%\Syncthing\%syncthing-ver%"
del "syncthing-ver.tmp"
rem move rclone binaries (similar to syncthing)
dir /b "%programfiles%\Rclone" > "rclone-ver.tmp"
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
@powershell Invoke-WebRequest https://storage.googleapis.com/downloads.webmproject.org/releases/webp/WebpCodecSetup.exe -OutFile WebpCodecSetup.exe
"%programfiles%\7-Zip\7z.exe" x %temp%\WebpCodecSetup.exe
ren %temp%\.rsrc\0\MSIFILE\1 1.msi && msiexec /i %temp%\.rsrc\0\MSIFILE\1.msi /quiet /qn /norestart
ren %temp%\.rsrc\0\MSIFILE\10 10.msi && msiexec /i %temp%\.rsrc\0\MSIFILE\10.msi /quiet /qn /norestart
rd /s /q %temp%\.rsrc
rem mpv bootstrapper download and install
cd "%temp%"
@powershell Invoke-WebRequest "https://downloads.sourceforge.net/project/mpv-player-windows/bootstrapper.zip" -OutFile "mpv.zip" -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox
"%programfiles%\7-Zip\7z.exe" x "mpv.zip" -o"%programfiles%\mpv" && del "mpv.zip"
cd "%programfiles%\mpv" && cmd /k "updater.bat" && cmd /k "installer\mpv-install.bat"
