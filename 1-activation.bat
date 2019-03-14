rem activate windows, requires local KMS server and windows 10 enterprise ltsc, no exceptions
rem generic keys: https://docs.microsoft.com/en-us/windows-server/get-started/kmsclientkeys
slmgr/ipk QFFDN-GRT3P-VKWWX-X7T3R-8B639
ping -n 1 192.168.1.3 | find "TTL=" >nul 
if errorlevel 0 ( slmgr/skms 192.168.1.3 && slmgr/ato ) else ( echo no local kms server found)