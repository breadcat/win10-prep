
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
<NUL set /p=:: Activating Windows... 
call "1-activation.bat" > nul
echo done
<NUL set /p=:: System Tweaks... 
call "2-tweaks.bat" > nul
echo done
<NUL set /p=:: Registry Tweaks... 
call "3-registry.bat" > nul
echo done
<NUL set /p=:: Removing Programs... 
call "4-remove.bat" > nul
echo done
<NUL set /p=:: Install Programs... 
call "5-install.bat" > nul
echo done
<NUL set /p=:: Mounting Network... 
call "6-network.bat" > nul
echo done
<NUL set /p=:: Windows Updates... 
call "7-install.bat" > nul
echo done
<NUL set /p=:: Clean Up... 
call "8-clean.bat" > nul
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