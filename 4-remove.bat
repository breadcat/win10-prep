rem applications
rem remove onedrive, remove explorer tree item
taskkill /f /im onedrive.exe
if exist "%windir%\system32\onedrivesetup.exe" "%windir%\system32\onedrivesetup.exe" /uninstall
if exist "%windir%\syswow64\onedrivesetup.exe" "%windir%\syswow64\onedrivesetup.exe" /uninstall
reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
rd /s /q "%userprofile%\OneDrive"
rd /s /q "%localappdata%\Microsoft\OneDrive"
rd /s /q "%programdata%\Microsoft OneDrive"
rem remove internet explorer 11
dism /online /disable-feature /featurename:Internet-Explorer-Optional-amd64 /NoRestart
rem remove silverlight (https://support.microsoft.com/en-us/kb/2608523)
reg delete HKLM\Software\Microsoft\Silverlight /f
reg delete HKEY_CLASSES_ROOT\Installer\Products\D7314F9862C648A4DB8BE2A5B47BE100 /f
reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\D7314F9862C648A4DB8BE2A5B47BE100 /f
reg delete HKEY_CLASSES_ROOT\TypeLib\{283C8576-0726-4DBC-9609-3F855162009A} /f
reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\install.exe /f
reg delete HKEY_CLASSES_ROOT\AgControl.AgControl /f
reg delete HKEY_CLASSES_ROOT\AgControl.AgControl.5.1 /f
reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{89F4137D-6C26-4A84-BDB8-2E5A4BB71E00} /f
reg delete HKEY_CURRENT_USER\SOFTWARE\AppDataLow\Software\Microsoft\Silverlight /f
rmdir /s /q "%ProgramFiles%\Microsoft Silverlight"
rmdir /s /q "%ProgramFiles(x86)%\Microsoft Silverlight"
rem remove adobe flash
takeown /f "%windir%\System32\Macromed" /r /d y
takeown /f "%windir%\System32\Macromed\Flash\*.*"
takeown /f "%windir%\SysWOW64\FlashPlayerApp.exe" /r /d y
takeown /f "%windir%\SysWOW64\FlashPlayerCPLApp.cpl" /r /d y
takeown /f "%windir%\SysWOW64\Macromed" /r /d y
takeown /f "%windir%\SysWOW64\Macromed\Flash\*.*"
icacls "%windir%\System32\Macromed" /grant administrators:F /t
icacls "%windir%\SysWOW64\FlashPlayerApp.exe" /grant administrators:F /t
icacls "%windir%\SysWOW64\FlashPlayerCPLApp.cpl" /grant administrators:F /t
icacls "%windir%\SysWOW64\Macromed" /grant administrators:F /t
rd /s /q "%appdata%\Adobe"
rd /s /q "%windir%\System32\Macromed"
rd /s /q "%windir%\SysWOW64\Macromed"
rd /s /q "%appdata%\Macromedia\Flash Player"
del "%windir%\SysWOW64\FlashPlayerApp.exe"
del "%windir%\SysWOW64\FlashPlayerCPLApp.cpl"