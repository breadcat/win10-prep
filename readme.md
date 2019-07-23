# Win10 Prep Script

Script to automate tweaking Windows 10 LTSC-N to a useful workstation.

Entirely built for personal use, but hopefully somebody may find the contents useful.

## Install
```
@powershell Invoke-WebRequest https://github.com/breadcat/win10-prep/archive/master.zip -OutFile "win10-prep.zip" ; Expand-Archive -Path "win10-prep.zip"
@powershell Start-Process "win10-prep\win10-prep-master\0-win10prep.bat" -Verb runAs
```