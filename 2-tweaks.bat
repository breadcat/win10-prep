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