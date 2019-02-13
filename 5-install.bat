rem install applications
msiexec /i https://just-install.github.io/stable/just-install.msi
just-install 7zip autohotkey autoruns firefox flux geforce-experience github imageglass mumble notepad2-mod parsec procmon putty rclone retroarch rufus steam sumatrapdf syncthing
rem random 7z binary to extract packages
cd %temp%
@powershell Invoke-WebRequest http://www.7-zip.org/a/7z1701.msi -OutFile 7z1701.msi
msiexec /a %temp%\7z1701.msi /qb TARGETDIR=%temp%\7z1701\
rem add ahk-assistant if it exists
if exist %userprofile%\Vault\src\ahka\ahk-assistant.ahk reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "AHK Assistant" /t REG_SZ /d "%userprofile%\Vault\src\ahka\ahk-assistant.ahk" /f
rem install .net3, generally useful
DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart
rem install directplay, useful for old GTA games
dism /Online /enable-feature /FeatureName:"DirectPlay" /All /NoRestart
rem 7zip associations and use windows icon
reg add "HKCU\SOFTWARE\Classes\Applications\7zFM.exe\shell\open\command" /ve /t REG_SZ /d "\"%programfiles%\7-Zip\7zFM.exe\" \"%%1\"" /f
reg add "HKCR\7z_auto_file\DefaultIcon" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\system32\zipfldr.dll" /f
rem flux location
reg add "HKCU\SOFTWARE\Michael Herf\flux\Preferences" /v "Latitude" /t REG_DWORD /d "5369" /f
reg add "HKCU\SOFTWARE\Michael Herf\flux\Preferences" /v "Longitude" /t REG_DWORD /d "4294967118" /f
rem add mumble short code
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\mumble.exe" /v "Path" /t REG_SZ /d "%ProgramFiles(x86)%\Mumble\\" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\mumble.exe" /ve /t REG_SZ /d "%ProgramFiles(x86)%\Mumble\mumble.exe" /f
rem putty colour scheme
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour0" /t REG_SZ /d "197,200,198" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour1" /t REG_SZ /d "197,200,198" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour2" /t REG_SZ /d "29,31,33" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour3" /t REG_SZ /d "29,31,33" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour4" /t REG_SZ /d "29,31,33" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour5" /t REG_SZ /d "197,200,198" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour6" /t REG_SZ /d "40,42,46" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour7" /t REG_SZ /d "55,59,65" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour8" /t REG_SZ /d "165,66,66" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour9" /t REG_SZ /d "204,102,102" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour10" /t REG_SZ /d "140,148,64" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour11" /t REG_SZ /d "181,189,104" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour12" /t REG_SZ /d "222,147,95" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour13" /t REG_SZ /d "240,198,116" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour14" /t REG_SZ /d "95,129,157" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour15" /t REG_SZ /d "129,162,190" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour16" /t REG_SZ /d "133,103,143" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour17" /t REG_SZ /d "178,148,187" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour18" /t REG_SZ /d "94,141,135" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour19" /t REG_SZ /d "138,190,183" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour20" /t REG_SZ /d "112,120,128" /f
reg add "HKCU\Software\SimonTatham\PuTTY\Sessions\Default%%20Settings" /v "Colour21" /t REG_SZ /d "197,200,198" /f
rem agree to procmon eula
reg add "HKCU\SOFTWARE\Sysinternals\Process Monitor" /v "EulaAccepted" /t REG_DWORD /d "1" /f
rem add steam shortcode
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\steam.exe" /v "Path" /t REG_SZ /d "%ProgramFiles(x86)%\Steam\\" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\steam.exe" /ve /t REG_SZ /d "%ProgramFiles(x86)%\Steam\Steam.exe" /f
rem move syncthing binaries up a directory
dir /b "%programfiles%\Syncthing" > "syncthing-ver.tmp"
set /p syncthing-ver=<"syncthing-ver.tmp"
move "%programfiles%\Syncthing\%syncthing-ver%\*" "%programfiles%\Syncthing\"
rd /s /q "%programfiles%\Syncthing\%syncthing-ver%"
del "syncthing-ver.tmp"
rem allow syncthing to auto update
icacls "%programfiles%\Syncthing" /grant Everyone:(OI)(CI)F
rem add syncthing autostart entry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Syncthing" /t REG_SZ /d "\"%programfiles%\Syncthing\syncthing.exe\" -no-console -no-browser" /f
rem add syncthing firewall rule
netsh advfirewall firewall add rule name="Syncthing" dir=in action=allow program="%programfiles%\Syncthing\syncthing.exe" enable=yes
rem install webp codec
@powershell Invoke-WebRequest https://storage.googleapis.com/downloads.webmproject.org/releases/webp/WebpCodecSetup.exe -OutFile WebpCodecSetup.exe
%temp%\7z1701\Files\7-Zip\7z.exe x %temp%\WebpCodecSetup.exe
ren %temp%\.rsrc\0\MSIFILE\1 1.msi
ren %temp%\.rsrc\0\MSIFILE\10 10.msi
msiexec /i %temp%\.rsrc\0\MSIFILE\1.msi /quiet /qn /norestart
msiexec /i %temp%\.rsrc\0\MSIFILE\10.msi /quiet /qn /norestart
rd /s /q %temp%\.rsrc
rem mpv download, unpack and
mkdir "%ProgramFiles%\mpv"
@powershell Invoke-WebRequest https://mpv.srsfckn.biz/mpv-x86_64-20171225.7z -OutFile mpv.7z
@powershell Invoke-WebRequest https://raw.githubusercontent.com/rossy/mpv-install/master/mpv-document.ico -OutFile mpv-document.ico
%temp%\7z1701\Files\7-Zip\7z.exe x %temp%\mpv.7z -o"%ProgramFiles%\mpv"
move mpv-document.ico %ProgramFiles%\mpv\mpv-document.ico