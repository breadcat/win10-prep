
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
call "1-tweaks.bat" > nul
echo done
<NUL set /p=:: Registry Tweaks... 
call "2-registry.bat" > nul
echo done
<NUL set /p=:: Removing Programs... 
call "3-remove.bat" > nul
echo done
<NUL set /p=:: Install Programs... 
call "4-install.bat" > nul
echo done
<NUL set /p=:: Clean Up... 
call "5-clean.bat" > nul
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