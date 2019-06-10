ping -n 1 minskio.co.uk | find "TTL=" >nul 
if errorlevel 0 ( slmgr/skms minskio.co.uk && slmgr/ato ) else ( echo server did not respond to ping requests)