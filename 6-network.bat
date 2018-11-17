rem connect to network shares
set server=atlas
ping -n 1 %server% | find "TTL=" >nul 
if errorlevel 0 ( goto connect ) else ( goto no_connect )

:connect
net use Z: \\%server%\media /USER:%username% /PERSISTENT:YES
net use Y: \\%server%\vault /USER:%username% /PERSISTENT:YES
net use X: \\%server%\downloads /USER:%username% /PERSISTENT:YES

:no_connect
:eof