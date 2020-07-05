# Win10 Prep Script

Script to automate tweaking Windows 10 into a useful workstation.

Entirely built for personal use, but hopefully somebody may find the contents useful.

## Install
```
@powershell Invoke-WebRequest https://github.com/breadcat/win10-prep/archive/master.zip -UseBasicParsing -OutFile "win10-prep.zip" ; Expand-Archive -Path "win10-prep.zip"
@powershell Start-Process "win10-prep\win10-prep-master\win10-prep.bat" -Verb runAs
```