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