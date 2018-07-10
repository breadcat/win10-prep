rem activate windows, requires local KMS server and windows 10 enterprise ltsb-n, no exceptions
rem generic keys: https://technet.microsoft.com/en-us/library/jj612867.aspx
slmgr/ipk QFFDN-GRT3P-VKWWX-X7T3R-8B639
ping -n 1 minskio.co.uk | find "TTL=" >nul 
if errorlevel 0 ( slmgr/skms minskio.co.uk && slmgr/ato ) else ( echo no local kms server found)